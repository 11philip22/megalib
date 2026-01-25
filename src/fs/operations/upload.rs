//! Upload operations.

use futures::io::Cursor;
use futures::stream::{self, StreamExt};
use rand::RngCore;
use serde_json::json;

#[cfg(not(target_arch = "wasm32"))]
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};

use super::utils::{get_chunk_size, upload_checksum};
use crate::base64::base64url_encode;
use crate::crypto::aes::{
    aes128_cbc_encrypt, aes128_ctr_encrypt, chunk_mac_calculate, meta_mac_calculate,
};
use crate::crypto::keys::pack_node_key;
use crate::error::{MegaError, Result};
use crate::fs::node::Node;
use crate::fs::upload_state::UploadState;
#[cfg(not(target_arch = "wasm32"))]
use crate::fs::upload_state::calculate_file_hash;
use crate::session::Session;

impl Session {
    /// Upload a node attribute (thumbnail, preview) to MEGA's attribute storage.
    ///
    /// This is used internally when `enable_previews(true)` is set, but can also
    /// be called directly for custom attributes.
    ///
    /// # Arguments
    /// * `data` - Raw attribute data (e.g., JPEG thumbnail bytes)
    /// * `attr_type` - Attribute type: "0" = thumbnail (128x128), "1" = preview  
    /// * `node_key` - The 16-byte file key used to encrypt the attribute
    ///
    /// # Returns
    /// Handle string like "0*ABC123" that can be added to file's `fa` field.
    pub async fn upload_node_attribute(
        &mut self,
        data: &[u8],
        attr_type: &str,
        node_key: &[u8; 16],
    ) -> Result<String> {
        // Pad data to multiple of 16 bytes
        let pad_len = if data.len() % 16 == 0 {
            0
        } else {
            16 - (data.len() % 16)
        };
        let mut padded = data.to_vec();
        padded.extend(std::iter::repeat(0u8).take(pad_len));

        // Get upload URL via a:ufa API
        let response = self
            .api_mut()
            .request(json!({
                "a": "ufa",
                "s": padded.len(),
                "ssl": 0
            }))
            .await?;

        let upload_url = response
            .get("p")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MegaError::Custom("Failed to get attribute upload URL".to_string()))?;

        // Encrypt data with AES-CBC using node key
        let encrypted = aes128_cbc_encrypt(&padded, node_key);

        // Upload encrypted data
        let client = reqwest::Client::new();
        let upload_response = client
            .post(upload_url)
            .header("Content-Type", "application/octet-stream")
            .body(encrypted)
            .send()
            .await
            .map_err(MegaError::RequestError)?;

        if !upload_response.status().is_success() {
            return Err(MegaError::Custom(format!(
                "Attribute upload failed: {}",
                upload_response.status()
            )));
        }

        // Get handle from response (should be 8 bytes raw)
        let handle_bytes = upload_response
            .bytes()
            .await
            .map_err(MegaError::RequestError)?;

        if handle_bytes.len() != 8 {
            return Err(MegaError::Custom(format!(
                "Invalid attribute handle length: {}",
                handle_bytes.len()
            )));
        }

        // Base64 encode the handle
        let handle_b64 = base64url_encode(&handle_bytes);

        // Return in format "type*handle"
        Ok(format!("{}*{}", attr_type, handle_b64))
    }

    /// Upload a file to a directory.
    ///
    /// This method is only available on native targets (not WASM).
    /// For WASM, use `upload_from_bytes` or `upload_from_reader` instead.
    ///
    /// # Arguments
    /// * `local_path` - Path to the local file to upload
    /// * `remote_parent_path` - Path to the remote parent directory
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn upload<P: AsRef<std::path::Path>>(
        &mut self,
        local_path: P,
        remote_parent_path: &str,
    ) -> Result<Node> {
        let path = local_path.as_ref();
        let file_name = path
            .file_name()
            .ok_or_else(|| MegaError::Custom("Invalid file path".to_string()))?
            .to_string_lossy()
            .to_string();

        let metadata = tokio::fs::metadata(path)
            .await
            .map_err(|e| MegaError::Custom(format!("Failed to get metadata: {}", e)))?;
        let file_size = metadata.len();

        let parent_node = self.stat(remote_parent_path).ok_or_else(|| {
            MegaError::Custom(format!(
                "Parent directory not found: {}",
                remote_parent_path
            ))
        })?;
        let parent_handle = parent_node.handle.clone();

        // 1. Get upload URL
        // [{a:u, s:<SIZE>, ssl:0}]
        // Ensure upgraded keys are present before uploading (for shared parent handling).
        self.ensure_keys_attribute().await?;

        let response = self
            .api_mut()
            .request(json!({
                "a": "u",
                "s": file_size,
                "ssl": 0
            }))
            .await?;

        let upload_url = response
            .get("p")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MegaError::Custom("Failed to get upload URL".to_string()))?
            .to_string();

        // Generate encryption keys
        let (file_key, nonce) = {
            let mut rng = rand::thread_rng();
            let mut file_key = [0u8; 16];
            let mut nonce = [0u8; 8];
            rng.fill_bytes(&mut file_key);
            rng.fill_bytes(&mut nonce);
            (file_key, nonce)
        };

        // Create state (without file hash - not saving to disk)
        let state = crate::fs::upload_state::UploadState::new(
            upload_url,
            file_key,
            nonce,
            file_size,
            file_name,
            parent_handle,
            String::new(), // Empty hash - not resumable
        );

        // Delegate to internal upload with no state persistence
        self.upload_internal(path, state, None).await
    }

    /// Upload a file with resume support.
    ///
    /// This method saves upload state to a temporary file after each chunk,
    /// allowing uploads to be resumed if interrupted. The state file is
    /// automatically deleted on successful completion.
    ///
    /// This method is only available on native targets (not WASM).
    ///
    /// # Arguments
    /// * `local_path` - Path to the local file to upload
    /// * `remote_parent_path` - Path to the remote parent directory
    ///
    /// # Example
    /// ```no_run
    /// # use megalib::Session;
    /// # async fn example() -> megalib::error::Result<()> {
    /// let mut session = Session::login("user@example.com", "password").await?;
    /// session.refresh().await?;
    ///
    /// // This upload can be safely interrupted and resumed
    /// let node = session.upload_resumable("largefile.zip", "/Root").await?;
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn upload_resumable<P: AsRef<std::path::Path>>(
        &mut self,
        local_path: P,
        remote_parent_path: &str,
    ) -> Result<Node> {
        let path = local_path.as_ref();
        let state_path = UploadState::state_file_path(path);

        // Check for existing state file
        if let Some(existing_state) = UploadState::load(&state_path)? {
            // Verify the state is valid
            let current_hash = calculate_file_hash(path)?;

            if existing_state.file_hash == current_hash && existing_state.is_likely_valid() {
                // Resume from existing state
                match self
                    .upload_internal(path, existing_state, Some(&state_path))
                    .await
                {
                    Ok(node) => return Ok(node),
                    Err(_e) => {
                        // println!(
                        //     "  ! Resume failed: {}. Restarting upload from scratch...",
                        //     _e
                        // );
                        // Delete invalid state and fall through to fresh upload
                        UploadState::delete(&state_path)?;
                    }
                }
            } else {
                // State is invalid (different file or expired), delete and start fresh
                UploadState::delete(&state_path)?;
            }
        }

        // Start fresh upload
        let file_name = path
            .file_name()
            .ok_or_else(|| MegaError::Custom("Invalid file path".to_string()))?
            .to_string_lossy()
            .to_string();

        let metadata = tokio::fs::metadata(path)
            .await
            .map_err(|e| MegaError::Custom(format!("Failed to get metadata: {}", e)))?;
        let file_size = metadata.len();

        let parent_node = self.stat(remote_parent_path).ok_or_else(|| {
            MegaError::Custom(format!(
                "Parent directory not found: {}",
                remote_parent_path
            ))
        })?;
        let parent_handle = parent_node.handle.clone();

        // Get upload URL
        let response = self
            .api_mut()
            .request(json!({
                "a": "u",
                "s": file_size,
                "ssl": 0
            }))
            .await?;

        let upload_url = response
            .get("p")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MegaError::Custom("Failed to get upload URL".to_string()))?
            .to_string();

        // Generate encryption keys
        let (file_key, nonce) = {
            let mut rng = rand::thread_rng();
            let mut file_key = [0u8; 16];
            let mut nonce = [0u8; 8];
            use rand::RngCore;
            rng.fill_bytes(&mut file_key);
            rng.fill_bytes(&mut nonce);
            (file_key, nonce)
        };

        // Calculate file hash for verification
        let file_hash = calculate_file_hash(path)?;

        // Create initial state
        let state = UploadState::new(
            upload_url,
            file_key,
            nonce,
            file_size,
            file_name,
            parent_handle,
            file_hash,
        );

        // Save initial state
        state.save(&state_path)?;

        // Continue with stateful upload
        self.upload_internal(path, state, Some(&state_path)).await
    }

    /// Upload data from a byte slice to a directory.
    ///
    /// This method is useful for uploading in-memory data without writing to disk first.
    /// It's particularly suitable for WASM environments where filesystem access is not available.
    ///
    /// Note: This method does NOT support resume (the data must be re-provided if interrupted).
    /// For large uploads that need resume support, use `upload_resumable` with a file path.
    ///
    /// # Arguments
    /// * `data` - The bytes to upload
    /// * `file_name` - Name for the uploaded file on MEGA
    /// * `remote_parent_path` - Path to the remote parent directory
    ///
    /// # Example
    /// ```no_run
    /// # use megalib::Session;
    /// # async fn example() -> megalib::error::Result<()> {
    /// let mut session = Session::login("user@example.com", "password").await?;
    /// session.refresh().await?;
    ///
    /// let data = b"Hello, MEGA!";
    /// let node = session.upload_from_bytes(data, "hello.txt", "/Root").await?;
    /// println!("Uploaded: {} ({} bytes)", node.name, node.size);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn upload_from_bytes(
        &mut self,
        data: &[u8],
        file_name: &str,
        remote_parent_path: &str,
    ) -> Result<Node> {
        self.upload_from_reader(
            Cursor::new(data.to_vec()),
            file_name,
            data.len() as u64,
            remote_parent_path,
        )
        .await
    }

    /// Upload data from an async reader to a directory.
    ///
    /// This method accepts any type implementing `AsyncRead + AsyncSeek + Unpin + Send`,
    /// enabling uploads from various sources like in-memory buffers, network streams,
    /// or custom data sources. Particularly useful for WASM environments.
    ///
    /// Note: This method does NOT support resume. The reader is consumed during upload,
    /// and if the upload is interrupted, you must provide a fresh reader to retry.
    /// For large file uploads that need resume support, use `upload_resumable` instead.
    ///
    /// Note: Preview/thumbnail generation is not supported for stream uploads since
    /// the data source may not be seekable after reading.
    ///
    /// # Arguments
    /// * `reader` - Async reader providing the data
    /// * `file_name` - Name for the uploaded file on MEGA
    /// * `file_size` - Total size of the data in bytes
    /// * `remote_parent_path` - Path to the remote parent directory
    ///
    /// # Example
    /// ```no_run
    /// # use megalib::Session;
    /// use futures::io::Cursor;
    /// # async fn example() -> megalib::error::Result<()> {
    /// let mut session = Session::login("user@example.com", "password").await?;
    /// session.refresh().await?;
    ///
    /// let data = vec![0u8; 1024]; // 1KB of zeros
    /// let cursor = Cursor::new(data);
    /// let node = session.upload_from_reader(cursor, "zeros.bin", 1024, "/Root").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn upload_from_reader<R>(
        &mut self,
        reader: R,
        file_name: &str,
        file_size: u64,
        remote_parent_path: &str,
    ) -> Result<Node>
    where
        R: futures::io::AsyncRead + futures::io::AsyncSeek + Unpin + Send,
    {
        let parent_node = self.stat(remote_parent_path).ok_or_else(|| {
            MegaError::Custom(format!(
                "Parent directory not found: {}",
                remote_parent_path
            ))
        })?;
        let parent_handle = parent_node.handle.clone();

        // Get upload URL
        let response = self
            .api_mut()
            .request(json!({
                "a": "u",
                "s": file_size,
                "ssl": 0
            }))
            .await?;

        let upload_url = response
            .get("p")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MegaError::Custom("Failed to get upload URL".to_string()))?
            .to_string();

        // Generate encryption keys
        let (file_key, nonce) = {
            let mut rng = rand::thread_rng();
            let mut file_key = [0u8; 16];
            let mut nonce = [0u8; 8];
            rng.fill_bytes(&mut file_key);
            rng.fill_bytes(&mut nonce);
            (file_key, nonce)
        };

        // Create state (no file hash needed - not resumable)
        let state = crate::fs::upload_state::UploadState::new(
            upload_url,
            file_key,
            nonce,
            file_size,
            file_name.to_string(),
            parent_handle,
            String::new(),
        );

        self.upload_internal_stream(reader, state).await
    }

    /// Internal method to upload with optional state tracking.
    #[cfg(not(target_arch = "wasm32"))]
    async fn upload_internal(
        &mut self,
        path: &std::path::Path,
        mut state: crate::fs::upload_state::UploadState,
        state_path: Option<&std::path::Path>,
    ) -> Result<Node> {
        let file_name = state.file_name.clone();
        let file_key = state.file_key;
        let nonce = state.nonce;
        let file_size = state.file_size;
        let parent_handle = state.parent_handle.clone();
        let upload_url = state.upload_url.clone();

        let mut file = tokio::fs::File::open(path)
            .await
            .map_err(|e| MegaError::Custom(format!("Failed to open file: {}", e)))?;

        // Calculate starting chunk index based on existing MACs
        let chunk_index = state.chunk_macs.len();
        let mut offset = state.offset;
        let mut chunk_macs = state.chunk_macs.clone();

        // If resume state indicates complete upload (offset == file_size),
        // we might have missed the handle if the process crashed before finalization.
        // Rewind by one chunk to force re-upload and get the handle again.
        if offset == file_size && file_size > 0 {
            if !chunk_macs.is_empty() {
                chunk_macs.pop();

                // Recalculate offset from remaining chunks
                let mut new_offset = 0;
                for i in 0..chunk_macs.len() {
                    new_offset += get_chunk_size(i, new_offset, file_size);
                }
                offset = new_offset;
            }
        }

        // Seek to resume position
        if offset > 0 {
            file.seek(std::io::SeekFrom::Start(offset))
                .await
                .map_err(|e| MegaError::Custom(format!("Failed to seek: {}", e)))?;
        }

        let mut upload_handle = String::new();

        // Create chunk list for parallel processing
        let mut chunks = Vec::new();
        let mut iter_offset = offset;
        let mut iter_index = chunk_index;

        while iter_offset < file_size {
            let chunk_size = get_chunk_size(iter_index, iter_offset, file_size);
            chunks.push((iter_index, iter_offset, chunk_size));
            iter_offset += chunk_size;
            iter_index += 1;
        }

        let path_buf = path.to_path_buf();
        let workers = self.workers();

        let mut stream = stream::iter(chunks)
            .map(|(_index, chunk_offset, chunk_size)| {
                let path = path_buf.clone();
                let file_key = file_key;
                let nonce = nonce;
                let upload_url = upload_url.clone();
                let file_name_clone = file_name.clone();

                async move {
                    // Open file for this chunk
                    let mut file = tokio::fs::File::open(&path)
                        .await
                        .map_err(|e| MegaError::Custom(format!("Failed to open file: {}", e)))?;

                    file.seek(std::io::SeekFrom::Start(chunk_offset))
                        .await
                        .map_err(|e| MegaError::Custom(format!("Failed to seek: {}", e)))?;

                    let mut buffer = vec![0u8; chunk_size as usize];
                    file.read_exact(&mut buffer)
                        .await
                        .map_err(|e| MegaError::Custom(format!("Read error: {}", e)))?;

                    // Calculate chunk MAC
                    let mut mac_iv = [0u8; 16];
                    mac_iv[..8].copy_from_slice(&nonce);
                    mac_iv[8..].copy_from_slice(&nonce);

                    let chunk_mac = chunk_mac_calculate(&buffer, &file_key, &mac_iv);

                    // Encrypt chunk
                    let encrypted_chunk =
                        aes128_ctr_encrypt(&buffer, &file_key, &nonce, chunk_offset);

                    // Upload chunk
                    let checksum = upload_checksum(&encrypted_chunk);
                    let chunk_url = format!("{}/{}?c={}", upload_url, chunk_offset, checksum);

                    let client = reqwest::Client::new();
                    let response = client
                        .post(&chunk_url)
                        .body(encrypted_chunk)
                        .send()
                        .await
                        .map_err(MegaError::RequestError)?;

                    if !response.status().is_success() {
                        return Err(MegaError::Custom(format!(
                            "Chunk upload failed: {}",
                            response.status()
                        )));
                    }

                    let response_text = response.text().await.map_err(MegaError::RequestError)?;
                    let handle = if !response_text.starts_with("-") && !response_text.is_empty() {
                        Some(response_text)
                    } else {
                        None
                    };

                    Ok((
                        chunk_mac,
                        chunk_offset + chunk_size,
                        handle,
                        file_name_clone,
                    ))
                }
            })
            .buffered(workers); // Run up to 'workers' chunks in parallel, return in order

        while let Some(result) = stream.next().await {
            match result {
                Ok((chunk_mac, new_offset, handle, fname)) => {
                    if let Some(h) = handle {
                        upload_handle = h;
                    }

                    // Update state - because we used .buffered(), results come in original order
                    chunk_macs.push(chunk_mac);
                    offset = new_offset;

                    // Save state
                    if let Some(sp) = state_path {
                        state.chunk_macs = chunk_macs.clone();
                        state.offset = offset;
                        state.save(sp)?;
                    }

                    // Report progress
                    let progress =
                        crate::progress::TransferProgress::new(offset, file_size, &fname);
                    if !self.report_progress(&progress) {
                        // Save state before cancelling
                        if let Some(sp) = state_path {
                            state.chunk_macs = chunk_macs.clone();
                            state.offset = offset;
                            let _ = state.save(sp);
                        }
                        return Err(MegaError::Custom("Upload cancelled by user".to_string()));
                    }
                }
                Err(e) => {
                    // Save state before returning error
                    if let Some(sp) = state_path {
                        state.chunk_macs = chunk_macs.clone();
                        state.offset = offset;
                        let _ = state.save(sp);
                    }
                    return Err(e);
                }
            }
        }

        if upload_handle.is_empty() {
            return Err(MegaError::Custom(
                "Did not receive upload handle".to_string(),
            ));
        }

        // Generate preview if enabled
        let file_attr = if self.previews_enabled() {
            if let Some(thumbnail_result) = crate::preview::generate_thumbnail(&path) {
                match thumbnail_result {
                    Ok(thumbnail_data) => {
                        match self
                            .upload_node_attribute(&thumbnail_data, "0", &file_key)
                            .await
                        {
                            Ok(handle) => Some(handle),
                            Err(_) => None,
                        }
                    }
                    Err(_) => None,
                }
            } else {
                None
            }
        } else {
            None
        };

        // Delegate to shared finalization logic
        let node = self
            .finalize_upload(
                &upload_handle,
                &chunk_macs,
                &file_key,
                &nonce,
                &file_name,
                &parent_handle,
                file_attr,
            )
            .await?;

        // Delete state file on success
        if let Some(sp) = state_path {
            UploadState::delete(sp)?;
        }

        Ok(node)
    }

    /// Internal method to upload from an async reader (sequential, no resume support).
    async fn upload_internal_stream<R>(&mut self, mut reader: R, state: UploadState) -> Result<Node>
    where
        R: futures::io::AsyncRead + futures::io::AsyncSeek + Unpin + Send,
    {
        use futures::io::AsyncReadExt;

        let file_name = state.file_name.clone();
        let file_key = state.file_key;
        let nonce = state.nonce;
        let file_size = state.file_size;
        let parent_handle = state.parent_handle.clone();
        let upload_url = state.upload_url.clone();

        let mut chunk_macs: Vec<[u8; 16]> = Vec::new();
        let mut offset: u64 = 0;
        let mut chunk_index: usize = 0;
        let mut upload_handle = String::new();

        // Sequential upload - read chunks one at a time from the stream
        while offset < file_size {
            let chunk_size = get_chunk_size(chunk_index, offset, file_size);
            let mut buffer = vec![0u8; chunk_size as usize];

            reader
                .read_exact(&mut buffer)
                .await
                .map_err(|e| MegaError::Custom(format!("Read error: {}", e)))?;

            // Calculate chunk MAC
            let mut mac_iv = [0u8; 16];
            mac_iv[..8].copy_from_slice(&nonce);
            mac_iv[8..].copy_from_slice(&nonce);
            let chunk_mac = chunk_mac_calculate(&buffer, &file_key, &mac_iv);

            // Encrypt chunk
            let encrypted_chunk = aes128_ctr_encrypt(&buffer, &file_key, &nonce, offset);

            // Upload chunk
            let checksum = upload_checksum(&encrypted_chunk);
            let chunk_url = format!("{}/{}?c={}", upload_url, offset, checksum);

            let client = reqwest::Client::new();
            let response = client
                .post(&chunk_url)
                .body(encrypted_chunk)
                .send()
                .await
                .map_err(MegaError::RequestError)?;

            if !response.status().is_success() {
                return Err(MegaError::Custom(format!(
                    "Chunk upload failed: {}",
                    response.status()
                )));
            }

            let response_text = response.text().await.map_err(MegaError::RequestError)?;
            if !response_text.starts_with("-") && !response_text.is_empty() {
                upload_handle = response_text;
            }

            chunk_macs.push(chunk_mac);
            offset += chunk_size;
            chunk_index += 1;

            // Report progress
            let progress = crate::progress::TransferProgress::new(offset, file_size, &file_name);
            if !self.report_progress(&progress) {
                return Err(MegaError::Custom("Upload cancelled by user".to_string()));
            }
        }

        if upload_handle.is_empty() {
            return Err(MegaError::Custom(
                "Did not receive upload handle".to_string(),
            ));
        }

        // Delegate to shared finalization logic (no preview for stream uploads)
        self.finalize_upload(
            &upload_handle,
            &chunk_macs,
            &file_key,
            &nonce,
            &file_name,
            &parent_handle,
            None,
        )
        .await
    }

    /// Shared upload finalization: creates the file node on MEGA after all chunks are uploaded.
    async fn finalize_upload(
        &mut self,
        upload_handle: &str,
        chunk_macs: &[[u8; 16]],
        file_key: &[u8; 16],
        nonce: &[u8; 8],
        file_name: &str,
        parent_handle: &str,
        file_attr: Option<String>,
    ) -> Result<Node> {
        let meta_mac = meta_mac_calculate(chunk_macs, file_key);

        // Encrypt attributes
        let attrs = json!({ "n": file_name }).to_string();
        let attrs_bytes = format!("MEGA{}", attrs).into_bytes();
        let pad_len = 16 - (attrs_bytes.len() % 16);
        let mut padded_attrs = attrs_bytes;
        padded_attrs.extend(std::iter::repeat(0).take(pad_len));
        let encrypted_attrs = aes128_cbc_encrypt(&padded_attrs, file_key);
        let attrs_b64 = base64url_encode(&encrypted_attrs);

        // Pack and encrypt node key
        let node_key = pack_node_key(file_key, nonce, &meta_mac);
        let encrypted_node_key =
            crate::crypto::aes::aes128_ecb_encrypt(&node_key, &self.master_key);
        let key_b64 = base64url_encode(&encrypted_node_key);

        // Create file node
        let mut node_data = json!({
            "h": upload_handle,
            "t": 0,
            "a": attrs_b64,
            "k": key_b64
        });

        if let Some(fa) = &file_attr {
            node_data["fa"] = json!(fa);
        }

        // If uploading into a shared/exported folder, include CR mapping so sharees can decrypt.
        let mut request = json!({
            "a": "p",
            "t": parent_handle,
            "n": [node_data]
        });

        if let Some((share_handle, share_key)) = self.find_share_for_handle(parent_handle) {
            let targets: Vec<(String, Vec<u8>)> =
                vec![(upload_handle.to_string(), node_key.to_vec())];
            if let Some(cr_value) = self.build_cr_for_nodes(&share_handle, &share_key, &targets) {
                request["cr"] = cr_value;
            }
            // Also persist the parent share key into ^!keys if available (best effort).
            if self.key_manager.is_ready() {
                self.key_manager
                    .add_share_key_from_str(&share_handle, &share_key);
                let _ = self.persist_keys_attribute().await;
            }
        }

        let response = self.api_mut().request(request).await?;

        // Parse result
        let nodes_array = response
            .get("f")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                MegaError::Custom("Invalid API response for upload completion".to_string())
            })?;

        if let Some(node_obj) = nodes_array.get(0) {
            let node = self
                .parse_node(node_obj)
                .ok_or_else(|| MegaError::Custom("Failed to parse new node".to_string()))?;

            // Find parent path
            let parent_path_str = {
                let parent_path = self
                    .nodes
                    .iter()
                    .find(|n| n.handle == parent_handle)
                    .and_then(|n| n.path.as_ref())
                    .map(|p| p.as_str())
                    .unwrap_or("");

                if !parent_path.is_empty() {
                    format!("{}/{}", parent_path.trim_end_matches('/'), node.name)
                } else {
                    format!("/{}", node.name)
                }
            };

            self.nodes.push(node.clone());
            if let Some(last_node) = self.nodes.last_mut() {
                last_node.path = Some(parent_path_str);
            }

            return Ok(node);
        }

        Err(MegaError::Custom("Failed to complete upload".to_string()))
    }
}
