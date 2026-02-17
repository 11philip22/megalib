//! Download operations.

use futures::stream::{self, StreamExt};
use serde_json::json;

use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;

use crate::crypto::aes::aes128_ctr_decrypt;
use crate::error::{MegaError, Result};
use crate::fs::node::{Node, NodeType};
use crate::session::Session;

impl Session {
    /// Download a file node to a writer.
    ///
    /// # Arguments
    /// * `node` - The file node to download
    /// * `writer` - The writer to write decrypted data to
    pub async fn download<W: std::io::Write + ?Sized>(
        &mut self,
        node: &Node,
        writer: &mut W,
    ) -> Result<()> {
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
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
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
    pub async fn download_with_offset<W: std::io::Write + ?Sized>(
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

        // If sequential (workers = 1), just stream the response body as before
        if self.workers() <= 1 {
            let client = reqwest::Client::new();
            let mut request = client.get(url);
            if offset > 0 {
                request = request.header("Range", format!("bytes={}-", offset));
            }
            let response = request.send().await.map_err(MegaError::RequestError)?;

            let status = response.status();
            if !status.is_success() && status != reqwest::StatusCode::PARTIAL_CONTENT {
                return Err(MegaError::Custom(format!(
                    "Download failed with status: {}",
                    status
                )));
            }
            if offset > 0 && status == reqwest::StatusCode::OK {
                return Err(MegaError::Custom(
                    "Server does not support resume".to_string(),
                ));
            }

            let mut current_offset = offset;
            let filename = node.name.clone();

            let mut stream = response.bytes_stream();

            while let Some(chunk_result) = stream.next().await {
                let chunk = chunk_result.map_err(MegaError::RequestError)?;
                let decrypted = aes128_ctr_decrypt(&chunk, &aes_key, &nonce, current_offset);
                writer
                    .write_all(&decrypted)
                    .map_err(|e| MegaError::Custom(format!("Write error: {}", e)))?;
                current_offset += chunk.len() as u64;

                let progress =
                    crate::progress::TransferProgress::new(current_offset, node.size, &filename);
                if !self.report_progress(&progress) {
                    return Err(MegaError::Custom("Download cancelled by user".to_string()));
                }
            }
            return Ok(());
        }

        // Parallel download path
        let file_size = node.size;
        let chunk_size = 1024 * 1024; // 1MB chunks

        // Create work items (chunks)
        let mut chunks = Vec::new();
        let mut iter_offset = offset;

        while iter_offset < file_size {
            let end = std::cmp::min(iter_offset + chunk_size, file_size);
            chunks.push((iter_offset, end));
            iter_offset = end;
        }

        let workers = self.workers();
        let url = url.to_string(); // Take ownership for closure

        let mut stream = stream::iter(chunks)
            .map(|(start, end)| {
                let chunk_url = url.clone();
                let aes_key = aes_key;
                let nonce = nonce;

                async move {
                    let client = reqwest::Client::new();
                    let response = client
                        .get(&chunk_url)
                        // Range is inclusive end-byte
                        .header("Range", format!("bytes={}-{}", start, end - 1))
                        .send()
                        .await
                        .map_err(MegaError::RequestError)?;

                    if !response.status().is_success()
                        && response.status() != reqwest::StatusCode::PARTIAL_CONTENT
                    {
                        return Err(MegaError::Custom(format!(
                            "Chunk download failed: {}",
                            response.status()
                        )));
                    }

                    // Read whole chunk to memory
                    let bytes = response.bytes().await.map_err(MegaError::RequestError)?;

                    // Verify size
                    if bytes.len() as u64 != (end - start) {
                        // Some servers might return full content if Range is ignored, catch that
                        if bytes.len() as u64 > (end - start) {
                            return Err(MegaError::Custom(
                                "Server returned more data than requested".to_string(),
                            ));
                        }
                    }

                    // Decrypt
                    let decrypted = aes128_ctr_decrypt(&bytes, &aes_key, &nonce, start);

                    Ok((decrypted, start, end))
                }
            })
            .buffered(workers); // Ordered parallelism

        let filename = node.name.clone();
        let mut current_pos = offset;

        while let Some(result) = stream.next().await {
            let (data, start, end) = result?;

            // Safety check for ordering
            if start != current_pos {
                return Err(MegaError::Custom(format!(
                    "Chunk ordering mismatch: expected {}, got {}",
                    current_pos, start
                )));
            }

            writer
                .write_all(&data)
                .map_err(|e| MegaError::Custom(format!("Write error: {}", e)))?;
            current_pos = end;

            let progress =
                crate::progress::TransferProgress::new(current_pos, file_size, &filename);
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
}
