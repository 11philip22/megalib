//! Filesystem operations for Session.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;

use serde_json::{json, Value};

use crate::base64::{base64url_decode, base64url_encode};
use crate::crypto::aes::{
    aes128_cbc_decrypt, aes128_cbc_encrypt, aes128_ctr_decrypt, aes128_ctr_encrypt,
    aes128_ecb_decrypt, chunk_mac_calculate, meta_mac_calculate,
};
use crate::crypto::keys::pack_node_key;
use crate::error::{MegaError, Result};
use crate::fs::node::{Node, NodeType, Quota};
use crate::session::Session;

impl Session {
    /// Refresh the filesystem tree from the server.
    ///
    /// This fetches all nodes and decrypts their attributes.
    /// Must be called before using `list()`, `stat()`, etc.
    ///
    /// # Example
    /// ```no_run
    /// # use mega_rs::Session;
    /// # async fn example() -> mega_rs::error::Result<()> {
    /// let mut session = Session::login("user@example.com", "password").await?;
    /// session.refresh().await?;
    /// let nodes = session.list("/", false)?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn refresh(&mut self) -> Result<()> {
        // Fetch filesystem data
        let response = self.api_mut().request(json!({"a": "f", "c": 1})).await?;

        // Parse share keys from "ok" array
        if let Some(ok_array) = response.get("ok").and_then(|v| v.as_array()) {
            self.parse_share_keys(ok_array);
        }

        // Parse nodes from "f" array
        let nodes_array = response
            .get("f")
            .and_then(|v| v.as_array())
            .ok_or(MegaError::InvalidResponse)?;

        let mut nodes = Vec::new();
        for node_json in nodes_array {
            if let Some(node) = self.parse_node(node_json) {
                nodes.push(node);
            }
        }

        // Build node paths
        self.build_node_paths(&mut nodes);

        // Store nodes
        self.nodes = nodes;

        Ok(())
    }

    /// List files in a directory.
    ///
    /// # Arguments
    /// * `path` - The path to list (e.g., "/", "/Documents")
    /// * `recursive` - If true, list all descendants recursively
    ///
    /// # Returns
    /// Vector of nodes matching the path
    pub fn list(&self, path: &str, recursive: bool) -> Result<Vec<&Node>> {
        let normalized_path = normalize_path(path);
        let search_prefix = if normalized_path == "/" {
            "/".to_string()
        } else {
            format!("{}/", normalized_path)
        };

        let mut results = Vec::new();

        for node in &self.nodes {
            if let Some(node_path) = &node.path {
                if recursive {
                    // Include all nodes under this path
                    if node_path.starts_with(&search_prefix) || node_path == &normalized_path {
                        if node_path != &normalized_path {
                            results.push(node);
                        }
                    }
                } else {
                    // Include only direct children
                    if let Some(stripped) = node_path.strip_prefix(&search_prefix) {
                        if !stripped.contains('/') && !stripped.is_empty() {
                            results.push(node);
                        }
                    }
                }
            }
        }

        Ok(results)
    }

    /// List all contacts.
    ///
    /// Returns all nodes of type Contact. Contacts are users who have
    /// interacted with your shared files or folders.
    ///
    /// # Example
    /// ```no_run
    /// # use megalib::Session;
    /// # async fn example() -> megalib::error::Result<()> {
    /// let mut session = Session::login("user@example.com", "password").await?;
    /// session.refresh().await?;
    /// for contact in session.list_contacts() {
    ///     println!("Contact: {}", contact.name);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn list_contacts(&self) -> Vec<&Node> {
        self.nodes.iter().filter(|n| n.is_contact()).collect()
    }

    /// Get information about a file or folder.
    ///
    /// # Arguments
    /// * `path` - The path to stat
    ///
    /// # Returns
    /// Node information if found
    pub fn stat(&self, path: &str) -> Option<&Node> {
        let normalized_path = normalize_path(path);

        self.nodes
            .iter()
            .find(|n| n.path.as_deref() == Some(&normalized_path))
    }

    /// Get user storage quota.
    pub async fn quota(&mut self) -> Result<Quota> {
        let response = self
            .api_mut()
            .request(json!({"a": "uq", "xfer": 1, "strg": 1}))
            .await?;

        let total = response.get("mstrg").and_then(|v| v.as_u64()).unwrap_or(0);
        let used = response.get("cstrg").and_then(|v| v.as_u64()).unwrap_or(0);

        Ok(Quota { total, used })
    }

    /// Export a file to create a public download link.
    ///
    /// After calling this, use `node.get_link(true)` to get the full URL.
    ///
    /// # Arguments
    /// * `path` - Path to the file to export
    ///
    /// # Returns
    /// The public link URL with decryption key
    ///
    /// # Example
    /// ```no_run
    /// # use mega_rs::Session;
    /// # async fn example() -> mega_rs::error::Result<()> {
    /// let mut session = Session::login("user@example.com", "password").await?;
    /// session.refresh().await?;
    /// let url = session.export("/Root/myfile.txt").await?;
    /// println!("Public link: {}", url);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn export(&mut self, path: &str) -> Result<String> {
        // Find the node
        let normalized_path = normalize_path(path);
        let node_idx = self
            .nodes
            .iter()
            .position(|n| n.path.as_deref() == Some(&normalized_path))
            .ok_or_else(|| MegaError::Custom(format!("Node not found: {}", path)))?;

        let node = &self.nodes[node_idx];
        let handle = node.handle.clone();
        let key = node.key.clone();
        let is_folder = node.node_type.is_container();

        if is_folder {
            // Folder export uses "s" (share) API
            // First set the share: {a: "s2", n: handle, s: [{u: "EXP", r: 0}]}
            // Then get the link handle: {a: "l", n: handle}

            // Step 1: Create share with EXP (export) pseudo-user
            self.api_mut()
                .request(json!({
                    "a": "s2",
                    "n": handle,
                    "s": [{"u": "EXP", "r": 0}],
                    "ok": ""
                }))
                .await?;

            // Step 2: Get the public link handle
            let response = self
                .api_mut()
                .request(json!({
                    "a": "l",
                    "n": handle
                }))
                .await?;

            let link_handle = response
                .as_str()
                .ok_or_else(|| MegaError::Custom("Invalid export response".to_string()))?
                .to_string();

            // Update the node with the link
            self.nodes[node_idx].link = Some(link_handle.clone());

            // Build folder URL
            let key_b64 = base64url_encode(&key);
            Ok(format!(
                "https://mega.nz/folder/{}#{}",
                link_handle, key_b64
            ))
        } else {
            // File export uses "l" (link) API directly
            let response = self
                .api_mut()
                .request(json!({
                    "a": "l",
                    "n": handle
                }))
                .await?;

            // Response is the public link handle as a string
            let link_handle = response
                .as_str()
                .ok_or_else(|| MegaError::Custom("Invalid export response".to_string()))?
                .to_string();

            // Update the node with the link
            self.nodes[node_idx].link = Some(link_handle.clone());

            // Build file URL
            let key_b64 = base64url_encode(&key);
            Ok(format!("https://mega.nz/file/{}#{}", link_handle, key_b64))
        }
    }

    /// Export multiple files to create public download links.
    ///
    /// More efficient than calling `export()` multiple times as it batches the API calls.
    ///
    /// # Arguments
    /// * `paths` - Paths to the files to export
    ///
    /// # Returns
    /// Vector of (path, url) tuples
    pub async fn export_many(&mut self, paths: &[&str]) -> Result<Vec<(String, String)>> {
        // Find all nodes and filter to files only
        let mut node_indices = Vec::new();
        let mut handles = Vec::new();

        for &path in paths {
            let normalized_path = normalize_path(path);
            if let Some(idx) = self
                .nodes
                .iter()
                .position(|n| n.path.as_deref() == Some(&normalized_path))
            {
                let node = &self.nodes[idx];
                if node.node_type == NodeType::File {
                    node_indices.push(idx);
                    handles.push(node.handle.clone());
                }
            }
        }

        if handles.is_empty() {
            return Ok(Vec::new());
        }

        // Build batch request
        let requests: Vec<Value> = handles.iter().map(|h| json!({"a": "l", "n": h})).collect();

        // Make batch API call
        let response = self.api_mut().request_batch(requests).await?;

        // Parse responses
        let responses = response
            .as_array()
            .ok_or_else(|| MegaError::Custom("Invalid batch response".to_string()))?;

        let mut results = Vec::new();

        for (i, resp) in responses.iter().enumerate() {
            if let Some(link_handle) = resp.as_str() {
                let idx = node_indices[i];
                self.nodes[idx].link = Some(link_handle.to_string());

                let node = &self.nodes[idx];
                let key_b64 = base64url_encode(&node.key);
                let url = format!("https://mega.nz/file/{}#{}", link_handle, key_b64);

                if let Some(path) = &node.path {
                    results.push((path.clone(), url));
                }
            }
        }

        Ok(results)
    }

    /// Parse share keys from the "ok" array response.
    ///
    /// Share keys can be encrypted with:
    /// - AES (master key) - for your own shares (key length <= 22 base64 chars)
    /// - RSA (private key) - for shares from other users (key length > 22 base64 chars)
    fn parse_share_keys(&mut self, ok_array: &[Value]) {
        for ok in ok_array {
            if let (Some(h), Some(k)) = (
                ok.get("h").and_then(|v| v.as_str()),
                ok.get("k").and_then(|v| v.as_str()),
            ) {
                // Determine if RSA or AES based on key length (megatools heuristic)
                if k.len() > 22 {
                    // RSA-encrypted share key (from another user)
                    if let Ok(encrypted) = base64url_decode(k) {
                        if let Some(decrypted) = self.rsa_key().decrypt(&encrypted) {
                            if decrypted.len() >= 16 {
                                let mut key = [0u8; 16];
                                key.copy_from_slice(&decrypted[..16]);
                                self.share_keys.insert(h.to_string(), key);
                            }
                        }
                    }
                } else {
                    // AES-encrypted share key (your own share)
                    if let Ok(encrypted) = base64url_decode(k) {
                        let decrypted = aes128_ecb_decrypt(&encrypted, self.master_key());
                        if decrypted.len() >= 16 {
                            let mut key = [0u8; 16];
                            key.copy_from_slice(&decrypted[..16]);
                            self.share_keys.insert(h.to_string(), key);
                        }
                    }
                }
            }
        }
    }

    /// Parse a single node from JSON.
    fn parse_node(&self, json: &Value) -> Option<Node> {
        let handle = json.get("h")?.as_str()?.to_string();
        let parent_handle = json
            .get("p")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let node_type_int = json.get("t")?.as_i64()?;
        let node_type = NodeType::from_i64(node_type_int)?;
        let size = json.get("s").and_then(|v| v.as_u64()).unwrap_or(0);
        let timestamp = json.get("ts").and_then(|v| v.as_i64()).unwrap_or(0);

        let (name, node_key) = match node_type {
            NodeType::Root => ("Root".to_string(), Vec::new()),
            NodeType::Inbox => ("Inbox".to_string(), Vec::new()),
            NodeType::Trash => ("Trash".to_string(), Vec::new()),
            _ => {
                // Decrypt attributes and node key
                let attrs_b64 = json.get("a")?.as_str()?;
                let key_str = json.get("k")?.as_str()?;
                let node_key = self.decrypt_node_key(key_str)?;
                match self.decrypt_node_attrs(attrs_b64, &node_key) {
                    Some(name) => (name, node_key),
                    None => return None,
                }
            }
        };

        Some(Node {
            name,
            handle,
            parent_handle,
            node_type,
            size,
            timestamp,
            key: node_key,
            path: None,
            link: None,
        })
    }

    /// Decrypt a node key from the "k" field.
    fn decrypt_node_key(&self, key_str: &str) -> Option<Vec<u8>> {
        // Key format: "handle:encrypted_key" or "handle:encrypted_key/handle2:key2"
        for part in key_str.split('/') {
            if let Some((key_handle, encrypted_key)) = part.split_once(':') {
                // Try master key first (if key_handle matches user_handle)
                let decrypt_key = if key_handle == self.user_handle {
                    Some(self.master_key())
                } else {
                    self.share_keys.get(key_handle).map(|k| k as &[u8; 16])
                };

                if let Some(key) = decrypt_key {
                    if let Ok(encrypted) = base64url_decode(encrypted_key) {
                        let decrypted = aes128_ecb_decrypt(&encrypted, key);
                        return Some(decrypted);
                    }
                }
            }
        }
        None
    }

    /// Create a new directory.
    pub async fn mkdir(&mut self, path: &str) -> Result<Node> {
        let (parent_path, name) = if let Some(idx) = path.rfind('/') {
            if idx == 0 {
                ("/", &path[1..])
            } else {
                (&path[..idx], &path[idx + 1..])
            }
        } else {
            return Err(crate::error::MegaError::Custom("Invalid path".to_string()));
        };

        let parent_handle = self
            .stat(parent_path)
            .map(|n| n.handle.clone())
            .ok_or_else(|| {
                crate::error::MegaError::Custom(format!(
                    "Parent directory not found: {}",
                    parent_path
                ))
            })?;

        // 1. Generate random 128-bit node key
        let node_key = {
            let mut rng = rand::thread_rng();
            let mut key_bytes = [0u8; 16];
            use rand::RngCore;
            rng.fill_bytes(&mut key_bytes);
            key_bytes
        };

        // 2. Encrypt attributes
        let attrs = json!({ "n": name }).to_string();
        let attrs_bytes = format!("MEGA{}", attrs).into_bytes();
        // Pad to 16 bytes
        let pad_len = 16 - (attrs_bytes.len() % 16);
        let mut padded_attrs = attrs_bytes;
        padded_attrs.extend(std::iter::repeat(0).take(pad_len));

        let encrypted_attrs = crate::crypto::aes::aes128_cbc_encrypt(&padded_attrs, &node_key);
        let attrs_b64 = crate::base64::base64url_encode(&encrypted_attrs);

        // 3. Encrypt node key with master key
        let encrypted_key =
            crate::crypto::aes::aes128_ecb_encrypt_block(&node_key, &self.master_key);
        let key_b64 = crate::base64::base64url_encode(&encrypted_key);

        // 4. Call API
        let response = self
            .api_mut()
            .request(json!({
                "a": "p",
                "t": parent_handle,
                "n": [{
                    "h": "xxxxxxxx", // Placeholder handle
                    "t": 1, // Folder
                    "a": attrs_b64,
                    "k": key_b64
                }]
            }))
            .await?;

        // 5. Parse response
        // Response format: {"f":[{"h":"...","t":1,...}]}
        // The API returns the response object which contains "f" array
        let nodes_array = response
            .get("f") // "f" field
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                crate::error::MegaError::Custom("Invalid API response for mkdir".to_string())
            })?;

        if let Some(node_obj) = nodes_array.get(0) {
            let mut node = self.parse_node(node_obj).ok_or_else(|| {
                crate::error::MegaError::Custom("Failed to parse node".to_string())
            })?;
            node.name = name.to_string(); // Name isn't returned in 'f', set it manually

            // Add to local cache manually
            self.nodes.push(node.clone());
            let parent_path_str = if parent_path == "/" {
                format!("/{}", name)
            } else {
                format!("{}/{}", parent_path.trim_end_matches('/'), name)
            };
            if let Some(last_node) = self.nodes.last_mut() {
                last_node.path = Some(parent_path_str);
            }

            return Ok(node);
        }

        Err(crate::error::MegaError::Custom(
            "Failed to create directory".to_string(),
        ))
    }

    /// Download a file node to a writer.
    ///
    /// # Arguments
    /// * `node` - The file node to download
    /// * `writer` - The writer to write decrypted data to
    pub async fn download<W: std::io::Write>(&mut self, node: &Node, writer: &mut W) -> Result<()> {
        self.download_with_offset(node, writer, 0).await
    }

    /// Download a file node to a writer, starting from a specific offset.
    ///
    /// This is used for resuming interrupted downloads. The offset should be
    /// the number of bytes already downloaded (i.e., the current file size).
    ///
    /// When resume is enabled via `set_resume(true)`, you can check existing
    /// file size and pass it as offset to continue from where you left off.
    ///
    /// # Arguments
    /// * `node` - The file node to download
    /// * `writer` - The writer to write decrypted data to (should be opened in append mode for resume)
    /// * `offset` - Byte offset to resume from (0 for fresh download)
    ///
    /// # Example
    /// ```no_run
    /// # use megalib::Session;
    /// # use std::fs::OpenOptions;
    /// # async fn example() -> megalib::error::Result<()> {
    /// let mut session = Session::login("user@example.com", "password").await?;
    /// session.refresh().await?;
    ///
    /// let node = session.stat("/Root/largefile.zip").unwrap().clone();
    ///
    /// // Check if partial file exists
    /// let offset = std::fs::metadata("largefile.zip")
    ///     .map(|m| m.len())
    ///     .unwrap_or(0);
    ///
    /// let mut file = OpenOptions::new()
    ///     .write(true)
    ///     .create(true)
    ///     .append(true)  // Important: append mode for resume
    ///     .open("largefile.zip")?;
    ///
    /// session.download_with_offset(&node, &mut file, offset).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn download_with_offset<W: std::io::Write>(
        &mut self,
        node: &Node,
        writer: &mut W,
        offset: u64,
    ) -> Result<()> {
        if node.node_type != NodeType::File {
            return Err(MegaError::Custom("Node is not a file".to_string()));
        }

        // Check if we're already done
        if offset >= node.size {
            return Ok(());
        }

        // 1. Get download URL
        let response = self
            .api_mut()
            .request(json!({
                "a": "g",
                "g": 1,
                "n": node.handle
            }))
            .await?;

        let url = response
            .get("g")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MegaError::Custom("Failed to get download URL".to_string()))?;

        // 2. Download content (with Range header if resuming)
        let client = reqwest::Client::new();
        let mut request = client.get(url);

        if offset > 0 {
            // Use HTTP Range header for resume
            request = request.header("Range", format!("bytes={}-", offset));
        }

        let mut response = request.send().await.map_err(MegaError::RequestError)?;

        // Check for valid response
        // 200 OK = full content, 206 Partial Content = range request honored
        let status = response.status();
        if !status.is_success() && status != reqwest::StatusCode::PARTIAL_CONTENT {
            return Err(MegaError::Custom(format!(
                "Download failed with status: {}",
                status
            )));
        }

        // If we requested a range but got 200 (full content), server doesn't support Range
        // We should abort and warn the user
        if offset > 0 && status == reqwest::StatusCode::OK {
            return Err(MegaError::Custom(
                "Server does not support resume (Range header not honored)".to_string(),
            ));
        }

        // 3. Prepare decryption
        let k = &node.key;
        if k.len() != 32 {
            return Err(MegaError::Custom(format!(
                "Invalid node key length: {}",
                k.len()
            )));
        }

        let mut aes_key = [0u8; 16];
        let mut nonce = [0u8; 8];

        for i in 0..16 {
            aes_key[i] = k[i] ^ k[i + 16];
        }

        for i in 0..8 {
            nonce[i] = k[i + 16];
        }

        // 4. Stream and decrypt (starting from the correct offset for CTR mode)
        let filename = node.name.clone();
        let mut current_offset = offset;
        while let Some(chunk) = response.chunk().await.map_err(MegaError::RequestError)? {
            // Decrypt chunk - AES-CTR correctly handles offset for keystream
            let decrypted = aes128_ctr_decrypt(&chunk, &aes_key, &nonce, current_offset);
            writer
                .write_all(&decrypted)
                .map_err(|e| MegaError::Custom(format!("Write error: {}", e)))?;
            current_offset += chunk.len() as u64;

            // Report progress (optional - only fires if callback is set)
            let progress =
                crate::progress::TransferProgress::new(current_offset, node.size, &filename);
            if !self.report_progress(&progress) {
                return Err(MegaError::Custom("Download cancelled by user".to_string()));
            }
        }

        Ok(())
    }

    /// Download a file to a local path with automatic resume support.
    ///
    /// This is the recommended method for downloading files. When `set_resume(true)`
    /// has been called, it will:
    /// - Create a temporary file `.megatmp.<handle>` in the same directory
    /// - If interrupted and restarted, detect the partial download and resume
    /// - On successful completion, rename the temp file to the target path
    ///
    /// # Arguments
    /// * `node` - The file node to download
    /// * `local_path` - Target file path
    ///
    /// # Example
    /// ```no_run
    /// # use megalib::Session;
    /// # async fn example() -> megalib::error::Result<()> {
    /// let mut session = Session::login("user@example.com", "password").await?;
    /// session.set_resume(true);  // Enable resume support
    /// session.refresh().await?;
    ///
    /// let node = session.stat("/Root/largefile.zip").unwrap().clone();
    /// session.download_to_file(&node, "largefile.zip").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn download_to_file<P: AsRef<std::path::Path>>(
        &mut self,
        node: &Node,
        local_path: P,
    ) -> Result<()> {
        if node.node_type != NodeType::File {
            return Err(MegaError::Custom("Node is not a file".to_string()));
        }

        let target_path = local_path.as_ref();

        // Determine parent directory for temp file
        let parent_dir = target_path.parent().unwrap_or(Path::new("."));
        let temp_filename = format!(".megatmp.{}", node.handle);
        let temp_path = parent_dir.join(&temp_filename);

        // Check if we should resume
        let resume_offset = if self.is_resume_enabled() && temp_path.exists() {
            match fs::metadata(&temp_path) {
                Ok(meta) => {
                    let size = meta.len();
                    if size >= node.size {
                        // Already complete, just rename
                        fs::rename(&temp_path, target_path)
                            .map_err(|e| MegaError::Custom(format!("Rename failed: {}", e)))?;
                        return Ok(());
                    }
                    size
                }
                Err(_) => 0,
            }
        } else {
            // Not resuming - delete any existing temp file
            let _ = fs::remove_file(&temp_path);
            0
        };

        // Open temp file for writing (append if resuming)
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .append(resume_offset > 0)
            .truncate(resume_offset == 0)
            .open(&temp_path)
            .map_err(|e| MegaError::Custom(format!("Failed to open temp file: {}", e)))?;

        let mut writer = BufWriter::new(file);

        // Delegate to download_with_offset (reuses all the download logic)
        self.download_with_offset(node, &mut writer, resume_offset)
            .await?;

        // Flush and close
        writer
            .flush()
            .map_err(|e| MegaError::Custom(format!("Flush error: {}", e)))?;
        drop(writer);

        // Rename temp file to target
        fs::rename(&temp_path, target_path)
            .map_err(|e| MegaError::Custom(format!("Rename failed: {}", e)))?;

        Ok(())
    }

    /// Remove a file or directory.
    pub async fn rm(&mut self, path: &str) -> Result<()> {
        let node_handle = self
            .stat(path)
            .map(|n| n.handle.clone())
            .ok_or_else(|| crate::error::MegaError::Custom(format!("Node not found: {}", path)))?;

        self.api_mut()
            .request(json!({
                "a": "d",
                "n": node_handle
            }))
            .await?;

        Ok(())
    }

    /// Move a file or directory to a new location.
    ///
    /// # Arguments
    /// * `source_path` - Path to the file/folder to move
    /// * `dest_parent_path` - Path to the new parent directory
    ///
    /// # Example
    /// ```no_run
    /// # use mega_rs::Session;
    /// # async fn example() -> mega_rs::error::Result<()> {
    /// let mut session = Session::login("user@example.com", "password").await?;
    /// session.refresh().await?;
    /// session.mv("/Root/file.txt", "/Root/Documents").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn mv(&mut self, source_path: &str, dest_parent_path: &str) -> Result<()> {
        // Get source node
        let source_node = self
            .stat(source_path)
            .ok_or_else(|| MegaError::Custom(format!("Source not found: {}", source_path)))?;
        let source_handle = source_node.handle.clone();

        // Get destination parent
        let dest_parent = self.stat(dest_parent_path).ok_or_else(|| {
            MegaError::Custom(format!("Destination not found: {}", dest_parent_path))
        })?;

        if !dest_parent.node_type.is_container() {
            return Err(MegaError::Custom(
                "Destination must be a folder".to_string(),
            ));
        }

        let dest_handle = dest_parent.handle.clone();

        // Call move API: {a: "m", n: source_handle, t: dest_parent_handle}
        self.api_mut()
            .request(json!({
                "a": "m",
                "n": source_handle,
                "t": dest_handle
            }))
            .await?;

        Ok(())
    }

    /// Rename a file or directory.
    ///
    /// # Arguments
    /// * `path` - Path to the file/folder to rename
    /// * `new_name` - The new name (not a path, just the filename)
    ///
    /// # Example
    /// ```no_run
    /// # use mega_rs::Session;
    /// # async fn example() -> mega_rs::error::Result<()> {
    /// let mut session = Session::login("user@example.com", "password").await?;
    /// session.refresh().await?;
    /// session.rename("/Root/old_name.txt", "new_name.txt").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn rename(&mut self, path: &str, new_name: &str) -> Result<()> {
        // Get source node
        let normalized_path = normalize_path(path);
        let node_idx = self
            .nodes
            .iter()
            .position(|n| n.path.as_deref() == Some(&normalized_path))
            .ok_or_else(|| MegaError::Custom(format!("Node not found: {}", path)))?;

        let node = &self.nodes[node_idx];
        let handle = node.handle.clone();
        let key = node.key.clone();

        if key.is_empty() {
            return Err(MegaError::Custom("Cannot rename system nodes".to_string()));
        }

        // Encode new attributes
        let attrs = json!({ "n": new_name }).to_string();
        let attrs_bytes = format!("MEGA{}", attrs).into_bytes();
        let pad_len = (16 - (attrs_bytes.len() % 16)) % 16;
        let mut padded_attrs = attrs_bytes;
        if pad_len > 0 {
            padded_attrs.extend(std::iter::repeat(0).take(pad_len));
        }

        // Get the AES key for attributes
        let aes_key: [u8; 16] = if key.len() >= 32 {
            // File: XOR first and second halves
            let mut k = [0u8; 16];
            for i in 0..16 {
                k[i] = key[i] ^ key[i + 16];
            }
            k
        } else if key.len() >= 16 {
            // Folder: first 16 bytes
            key[..16]
                .try_into()
                .map_err(|_| MegaError::Custom("Invalid key".to_string()))?
        } else {
            return Err(MegaError::Custom("Invalid key length".to_string()));
        };

        // Encrypt attributes
        let encrypted_attrs = aes128_cbc_encrypt(&padded_attrs, &aes_key);
        let attrs_b64 = base64url_encode(&encrypted_attrs);

        // Call setattr API: {a: "a", n: handle, attr: encrypted_attrs}
        self.api_mut()
            .request(json!({
                "a": "a",
                "n": handle,
                "attr": attrs_b64
            }))
            .await?;

        // Update local cache
        self.nodes[node_idx].name = new_name.to_string();

        Ok(())
    }

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
    /// # Arguments
    /// * `local_path` - Path to the local file to upload
    /// * `remote_parent_path` - Path to the remote parent directory
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
            .ok_or_else(|| MegaError::Custom("Failed to get upload URL".to_string()))?;

        // 2. Prepare encryption
        let (file_key, nonce) = {
            let mut rng = rand::thread_rng();
            let mut file_key = [0u8; 16];
            let mut nonce = [0u8; 8];
            use rand::RngCore;
            rng.fill_bytes(&mut file_key);
            rng.fill_bytes(&mut nonce); // Random nonce
            (file_key, nonce)
        };

        let mut file = tokio::fs::File::open(path)
            .await
            .map_err(|e| MegaError::Custom(format!("Failed to open file: {}", e)))?;
        let mut offset = 0u64;
        let mut chunk_index = 0;
        let mut chunk_macs = Vec::new();
        let client = reqwest::Client::new();

        let mut upload_handle = String::new();

        // 3. Upload chunks
        use tokio::io::AsyncReadExt;

        while offset < file_size {
            let chunk_size = get_chunk_size(chunk_index, offset, file_size);
            let mut buffer = vec![0u8; chunk_size as usize];
            file.read_exact(&mut buffer)
                .await
                .map_err(|e| MegaError::Custom(format!("Read error: {}", e)))?;

            // Calculate chunk MAC
            // The IV for MAC is nonce (8 bytes) + 8 bytes of zeros?
            // Megan uses specific IV for chunk MAC:
            // "guchar mac_iv[16]; memcpy(mac_iv, iv, 8); memcpy(mac_iv + 8, iv, 8);"
            // where iv is 8-byte nonce.
            let mut mac_iv = [0u8; 16];
            mac_iv[..8].copy_from_slice(&nonce);
            mac_iv[8..].copy_from_slice(&nonce);

            let chunk_mac = chunk_mac_calculate(&buffer, &file_key, &mac_iv);
            chunk_macs.push(chunk_mac);

            // Encrypt chunk (AES-CTR)
            // IV for CTR: nonce (8 bytes) + counter (8 bytes BE)
            // counter starts at offset / 16.
            // Since we process chunk by chunk, we can pass offset to aes128_ctr_encrypt.
            let encrypted_chunk = aes128_ctr_encrypt(&buffer, &file_key, &nonce, offset);

            // Upload chunk
            // URL: upload_url + "/" + offset + "?c=" + checksum
            let checksum = upload_checksum(&encrypted_chunk); // Note: Mega calculates checksum on ENCRYPTED data?
                                                              // "chksum = upload_checksum(buf, c->size); ... response = http_post(h, url, buf, ...)"
                                                              // In megatools, buf is encrypted in place before upload_checksum!
                                                              // "if (!encrypt_aes128_ctr(buf, buf, ...)) ... chksum = upload_checksum(buf, c->size);"
                                                              // Yes, checksum of encrypted data.

            let chunk_url = format!("{}/{}?c={}", upload_url, offset, checksum);

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

            // Check for completion handle (base64 string)
            // Megatools checks len == 36 ? No, handle is shorter.
            // "if (response->len < 10 && ... numeric error ...)"
            // "if (response->len == 36) ... upload_handle = ..." probably 27 chars base64?
            // Base64 of 27 chars?
            // Let's just assume if it's not empty and not an error code, it's the handle.
            // Or if it's the last chunk.
            if chunk_index == 0 && file_size == 0 {
                // Special case empty file?
            }

            // If response looks like a handle (alphanumeric), save it.
            // In C++ SDK it returns handle on completion.
            // For now, save the last non-empty response that isn't an error.
            if !response_text.starts_with("-") && !response_text.is_empty() {
                upload_handle = response_text;
            }

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

        // 4. Finalize upload
        let meta_mac = meta_mac_calculate(&chunk_macs, &file_key);

        // Encrypt attributes
        // "attrs = encode_node_attrs(remote_name);" -> {"n": name}
        // "attrs_enc = b64_aes128_cbc_encrypt_str(attrs, aes_key);"
        // aes_key for attrs is file_key (randomly generated).
        let attrs = json!({ "n": file_name }).to_string();
        let attrs_bytes = format!("MEGA{}", attrs).into_bytes();
        let pad_len = 16 - (attrs_bytes.len() % 16);
        let mut padded_attrs = attrs_bytes;
        padded_attrs.extend(std::iter::repeat(0).take(pad_len));
        let encrypted_attrs = aes128_cbc_encrypt(&padded_attrs, &file_key);
        let attrs_b64 = base64url_encode(&encrypted_attrs);

        // Pack node key
        let node_key = pack_node_key(&file_key, &nonce, &meta_mac);

        // Encrypt node key with master key
        let encrypted_node_key =
            crate::crypto::aes::aes128_ecb_encrypt(&node_key, &self.master_key);
        let key_b64 = base64url_encode(&encrypted_node_key);

        // Generate preview if enabled
        let file_attr = if self.previews_enabled() {
            if let Some(thumbnail_result) = crate::preview::generate_thumbnail(&path) {
                match thumbnail_result {
                    Ok(thumbnail_data) => {
                        // Upload thumbnail as node attribute type "0"
                        match self
                            .upload_node_attribute(&thumbnail_data, "0", &file_key)
                            .await
                        {
                            Ok(handle) => Some(handle),
                            Err(_) => None, // Silently skip thumbnail on error
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

        // a:p - Create file node
        let mut node_data = json!({
            "h": upload_handle,
            "t": 0, // File
            "a": attrs_b64,
            "k": key_b64
        });

        // Add file attributes (thumbnail) if present
        if let Some(fa) = &file_attr {
            node_data["fa"] = json!(fa);
        }

        let response = self
            .api_mut()
            .request(json!({
                "a": "p",
                "t": parent_handle,
                "n": [node_data]
            }))
            .await?;

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

            // Add to local cache manually
            // Calculate path
            // parent_handle corresponds to a path
            // We can find the parent node to get its path

            // Note: node.parent_handle should be set by parse_node if available,
            // but if not we can assume it matches what we sent.

            let parent_path_str = {
                // Find parent path
                let parent_path = self
                    .nodes
                    .iter()
                    .find(|n| n.handle == parent_handle)
                    .and_then(|n| n.path.as_ref())
                    .map(|p| p.as_str())
                    .unwrap_or(""); // If not found, empty (shouldn't happen if we uploaded)

                if !parent_path.is_empty() {
                    format!("{}/{}", parent_path.trim_end_matches('/'), node.name)
                } else {
                    // Fallback, maybe parent is root but we didn't find it easily?
                    // Or refresh required.
                    format!("/{}", node.name) // Best effort
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

    fn decrypt_node_attrs(&self, attrs_b64: &str, node_key: &[u8]) -> Option<String> {
        let encrypted = base64url_decode(attrs_b64).ok()?;

        // Use first 16 bytes of node key for attribute decryption
        let aes_key: [u8; 16] = if node_key.len() >= 32 {
            // File key: XOR first and second 16-byte halves
            let mut key = [0u8; 16];
            for i in 0..16 {
                key[i] = node_key[i] ^ node_key[i + 16];
            }
            key
        } else if node_key.len() >= 16 {
            node_key[..16].try_into().ok()?
        } else {
            return None;
        };

        let decrypted = aes128_cbc_decrypt(&encrypted, &aes_key);

        // Attributes are JSON prefixed with "MEGA"
        let text = String::from_utf8_lossy(&decrypted);
        if !text.starts_with("MEGA") {
            return None;
        }

        // Parse JSON after "MEGA" prefix
        let json_str = text.trim_start_matches("MEGA").trim_end_matches('\0');
        let attrs: Value = serde_json::from_str(json_str).ok()?;

        attrs
            .get("n")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    /// Build full paths for all nodes.
    fn build_node_paths(&self, nodes: &mut [Node]) {
        // Create handle -> node index map
        let handle_map: HashMap<&str, usize> = nodes
            .iter()
            .enumerate()
            .map(|(i, n)| (n.handle.as_str(), i))
            .collect();

        // First, compute all paths
        let paths: Vec<String> = (0..nodes.len())
            .map(|i| self.build_node_path(nodes, i, &handle_map, 0))
            .collect();

        // Then assign them
        for (i, path) in paths.into_iter().enumerate() {
            nodes[i].path = Some(path);
        }
    }

    /// Recursively build a node's path.
    fn build_node_path(
        &self,
        nodes: &[Node],
        idx: usize,
        handle_map: &HashMap<&str, usize>,
        depth: usize,
    ) -> String {
        // Prevent infinite loops
        if depth > 100 {
            return format!("/{}", nodes[idx].name);
        }

        let node = &nodes[idx];

        // Root nodes have path "/"
        if matches!(
            node.node_type,
            NodeType::Root | NodeType::Inbox | NodeType::Trash | NodeType::Network
        ) {
            return format!("/{}", node.name);
        }

        // Find parent and prepend its path
        if let Some(parent_handle) = &node.parent_handle {
            if let Some(&parent_idx) = handle_map.get(parent_handle.as_str()) {
                let parent_path = self.build_node_path(nodes, parent_idx, handle_map, depth + 1);
                return format!("{}/{}", parent_path.trim_end_matches('/'), node.name);
            }
        }

        format!("/{}", node.name)
    }
}

/// Normalize a path (remove trailing slashes, handle //).
fn normalize_path(path: &str) -> String {
    let mut result = path.replace("//", "/");
    while result.ends_with('/') && result.len() > 1 {
        result.pop();
    }
    if !result.starts_with('/') {
        result = format!("/{}", result);
    }
    result
}

fn get_chunk_size(chunk_index: usize, offset: u64, total_size: u64) -> u64 {
    // Mega chunk sizes:
    // Chunks 1-8: idx * 128KB (128, 256, 384, 512, 640, 768, 896, 1024 KB)
    // After that: 1MB fixed.

    let size = if chunk_index < 8 {
        (chunk_index as u64 + 1) * 128 * 1024
    } else {
        1024 * 1024
    };

    if offset + size > total_size {
        total_size - offset
    } else {
        size
    }
}

fn upload_checksum(data: &[u8]) -> String {
    let mut crc = [0u8; 12];

    // Rolling XOR checksum
    for (i, &byte) in data.iter().enumerate() {
        crc[i % 12] ^= byte;
    }

    base64url_encode(&crc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_path() {
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path("/foo"), "/foo");
        assert_eq!(normalize_path("/foo/"), "/foo");
        assert_eq!(normalize_path("/foo//bar"), "/foo/bar");
        assert_eq!(normalize_path("foo"), "/foo");
    }
}
