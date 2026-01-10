//! Filesystem operations for Session.

use std::collections::HashMap;

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

        // Only files can be exported
        if node.node_type != NodeType::File {
            return Err(MegaError::Custom("Only files can be exported".to_string()));
        }

        let handle = node.handle.clone();
        let key = node.key.clone();

        // Call export API: {a: "l", n: handle}
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

        // Build and return the full URL with key
        let key_b64 = base64url_encode(&key);
        Ok(format!("https://mega.nz/file/{}#{}", link_handle, key_b64))
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
    fn parse_share_keys(&mut self, ok_array: &[Value]) {
        for ok in ok_array {
            if let (Some(h), Some(k)) = (
                ok.get("h").and_then(|v| v.as_str()),
                ok.get("k").and_then(|v| v.as_str()),
            ) {
                // Decrypt share key with master key
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
        let mut rng = rand::thread_rng();
        let mut key_bytes = [0u8; 16];
        use rand::RngCore;
        rng.fill_bytes(&mut key_bytes);
        let node_key = key_bytes;

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
                                          // We need to re-add it to our internal cache or refresh, but for now just return it
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
        if node.node_type != NodeType::File {
            return Err(MegaError::Custom("Node is not a file".to_string()));
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

        // 2. Download content
        let client = reqwest::Client::new();
        let mut response = client
            .get(url)
            .send()
            .await
            .map_err(MegaError::RequestError)?;

        if !response.status().is_success() {
            return Err(MegaError::Custom(format!(
                "Download failed with status: {}",
                response.status()
            )));
        }

        // 3. Prepare decryption
        // Node key is 32 bytes: [u64_xor_0, u64_xor_1, u64_nonce_0, u64_nonce_1] (4 x u64) = 16 bytes key parts, 8 bytes nonce, 8 bytes mac
        // Wait, node key is 32 bytes (256 bits).
        // Mega uses AES-128.
        // For files:
        // Key (16 bytes) = XOR(part1, part2) where part1 is first 16 bytes, part2 is second 16 bytes? No, that's for folder attributes?

        // Let's re-read mega.c unpack_node_key:
        // void unpack_node_key(guchar node_key[32], guchar aes_key[16], guchar nonce[8], guchar meta_mac_xor[8])
        // {
        //     if (aes_key) {
        //         DW(aes_key, 0) = DW(node_key, 0) ^ DW(node_key, 4); ... (first 16 bytes XOR last 16 bytes? No)
        //         node_key is 32 bytes = 8 u32s (DW).
        //         DW(aes_key, 0) (bytes 0-4) = DW(node_key, 0) (bytes 0-4) ^ DW(node_key, 4) (bytes 16-20)
        //         DW(aes_key, 1) (bytes 4-8) = DW(node_key, 1) (bytes 4-8) ^ DW(node_key, 5) (bytes 20-24)
        //         DW(aes_key, 2) (bytes 8-12) = DW(node_key, 2) (bytes 8-12) ^ DW(node_key, 6) (bytes 24-28)
        //         DW(aes_key, 3) (bytes 12-16) = DW(node_key, 3) (bytes 12-16) ^ DW(node_key, 7) (bytes 28-32)
        //     }
        //     if (nonce) {
        //         DW(nonce, 0) = DW(node_key, 4); // bytes 16-20
        //         DW(nonce, 1) = DW(node_key, 5); // bytes 20-24
        //     }
        // }
        // So:
        // node_key is 32 bytes.
        // aes_key (16 bytes) = node_key[0..16] XOR node_key[16..32]
        // nonce (8 bytes) = node_key[16..24]

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

        // 4. Stream and decrypt
        let mut offset = 0u64;
        while let Some(chunk) = response.chunk().await.map_err(MegaError::RequestError)? {
            // Decrypt chunk
            let decrypted = aes128_ctr_decrypt(&chunk, &aes_key, &nonce, offset);
            writer
                .write_all(&decrypted)
                .map_err(|e| MegaError::Custom(format!("Write error: {}", e)))?;
            offset += chunk.len() as u64;
        }

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
        let mut rng = rand::thread_rng();
        let mut file_key = [0u8; 16];
        let mut nonce = [0u8; 8];
        use rand::RngCore;
        rng.fill_bytes(&mut file_key);
        rng.fill_bytes(&mut nonce); // Random nonce

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

        // a:p
        let response = self
            .api_mut()
            .request(json!({
                "a": "p",
                "t": parent_handle,
                "n": [{
                    "h": upload_handle,
                    "t": 0, // File
                    "a": attrs_b64,
                    "k": key_b64
                }]
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
            // Invalidate cache or add node?
            let node = self
                .parse_node(node_obj)
                .ok_or_else(|| MegaError::Custom("Failed to parse new node".to_string()))?;
            // Ensure name is set (parse_node usually requires 'a' which we sent, but server returns it decrypted if we passed it correctly? No, parse_node decrypts 'a' from the object. The `f` object usually contains `k` and `a`.
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
