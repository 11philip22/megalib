//! Filesystem operations for Session.

use std::collections::HashMap;

use serde_json::{json, Value};

use crate::base64::base64url_decode;
use crate::crypto::{aes128_cbc_decrypt, aes128_ctr_decrypt, aes128_ecb_decrypt};
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

    /// Decrypt node attributes.
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
