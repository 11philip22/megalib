//! Filesystem tree refresh and parsing.

use std::collections::HashMap;

use serde_json::{Value, json};

use crate::base64::base64url_decode;
use crate::crypto::aes::{aes128_cbc_decrypt, aes128_ecb_decrypt};
use crate::error::{MegaError, Result};
use crate::fs::node::{Node, NodeType};
use crate::session::Session;

impl Session {
    /// Refresh the filesystem tree from the server.
    ///
    /// This fetches all nodes (SDK-style `f`), share keys, and public links, then decrypts
    /// attributes and rebuilds cached paths.
    /// Must be called before using `list()`, `stat()`, etc.
    ///
    /// # Example
    /// ```no_run
    /// # use megalib::Session;
    /// # async fn example() -> megalib::error::Result<()> {
    /// let mut session = Session::login("user@example.com", "password").await?;
    /// session.refresh().await?;
    /// let nodes = session.list("/", false)?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn refresh(&mut self) -> Result<()> {
        // Match SDK behavior: ensure keys are initialized before fetching nodes.
        self.ensure_keys_attribute().await?;

        // Fetch filesystem data
        let response = self
            .api_mut()
            .request(json!({"a": "f", "c": 1, "r": 1, "ca": 1}))
            .await?;

        if let Some(sn) = response.get("sn").and_then(|v| v.as_str()) {
            self.scsn = Some(sn.to_string());
            self.wsc_url = None;
            self.sc_catchup = true;
            self.current_seqtag = None;
            self.current_seqtag_seen = false;
            self.alerts_catchup_pending = true;
        }

        // Parse share keys from "ok" array
        if let Some(ok_array) = response.get("ok").and_then(|v| v.as_array()) {
            self.parse_share_keys(ok_array);
        }

        // Parse outgoing shares (and pending shares) to seed sharee tracking.
        if let Some(s_array) = response.get("s").and_then(|v| v.as_array()) {
            self.ingest_outshares_from_fetch(s_array);
        }

        // Parse public links from "ph" array (if present)
        let public_links = response
            .get("ph")
            .and_then(|v| v.as_array())
            .map(|arr| Self::parse_public_links(arr))
            .unwrap_or_default();

        // Parse nodes from "f" array
        let nodes_array = response
            .get("f")
            .and_then(|v| v.as_array())
            .ok_or(MegaError::InvalidResponse)?;

        // Preload share keys for our own folders so children can decrypt when no ok entry is usable.
        for node_json in nodes_array {
            if let Some(1) = node_json.get("t").and_then(|v| v.as_i64()) {
                if let (Some(handle), Some(kstr)) = (
                    node_json.get("h").and_then(|v| v.as_str()),
                    node_json.get("k").and_then(|v| v.as_str()),
                ) {
                    for part in kstr.split('/') {
                        if let Some((key_handle, encrypted_key)) = part.split_once(':') {
                            if key_handle == self.user_handle {
                                if let Ok(enc) = base64url_decode(encrypted_key) {
                                    let dec = aes128_ecb_decrypt(&enc, self.master_key());
                                    if dec.len() >= 16 {
                                        let mut key = [0u8; 16];
                                        key.copy_from_slice(&dec[..16]);
                                        self.share_keys.entry(handle.to_string()).or_insert(key);
                                        // Also populate key_manager for upgraded flows.
                                        if self.key_manager.is_ready() {
                                            self.key_manager.add_share_key_from_str(handle, &key);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut nodes = Vec::new();
        for node_json in nodes_array {
            if let Some(mut node) = self.parse_node(node_json) {
                if let Some(link) = public_links.get(&node.handle) {
                    node.link = Some(link.clone());
                }
                nodes.push(node);
            }
        }

        // Build node paths
        Self::build_node_paths(&mut nodes);

        // Store nodes
        self.nodes = nodes;

        // Clear in-use flags for share keys no longer present, persist if changed.
        if self.clear_inuse_flags_for_missing_shares() {
            let _ = self.persist_keys_with_retry().await;
        }

        Ok(())
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
                                self.share_keys.entry(h.to_string()).or_insert(key);
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
                            self.share_keys.entry(h.to_string()).or_insert(key);
                        }
                    }
                }
            }
        }
    }

    /// Parse public link handles from the "ph" array response.
    ///
    /// Returns a map of node handle -> public link handle.
    fn parse_public_links(ph_array: &[Value]) -> HashMap<String, String> {
        let mut links = HashMap::new();
        for ph in ph_array {
            if let (Some(h), Some(ph_handle)) = (
                ph.get("h").and_then(|v| v.as_str()),
                ph.get("ph").and_then(|v| v.as_str()),
            ) {
                links.insert(h.to_string(), ph_handle.to_string());
            }
        }
        links
    }

    /// Parse a single node from JSON.
    pub(crate) fn parse_node(&self, json: &Value) -> Option<Node> {
        let handle = json.get("h")?.as_str()?.to_string();
        let parent_handle = json
            .get("p")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let node_type_int = json.get("t")?.as_i64()?;
        let node_type = NodeType::from_i64(node_type_int)?;
        let size = json.get("s").and_then(|v| v.as_u64()).unwrap_or(0);
        let timestamp = json.get("ts").and_then(|v| v.as_i64()).unwrap_or(0);
        let file_attr = json
            .get("fa")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

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
            file_attr,
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

    pub(crate) fn decrypt_node_attrs(&self, attrs_b64: &str, node_key: &[u8]) -> Option<String> {
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
    pub(crate) fn build_node_paths(nodes: &mut [Node]) {
        // Create handle -> node index map
        let handle_map: HashMap<&str, usize> = nodes
            .iter()
            .enumerate()
            .map(|(i, n)| (n.handle.as_str(), i))
            .collect();

        // First, compute all paths
        let paths: Vec<String> = (0..nodes.len())
            .map(|i| Self::build_node_path(nodes, i, &handle_map, 0))
            .collect();

        // Then assign them
        for (i, path) in paths.into_iter().enumerate() {
            nodes[i].path = Some(path);
        }
    }

    /// Recursively build a node's path.
    fn build_node_path(
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
                let parent_path = Self::build_node_path(nodes, parent_idx, handle_map, depth + 1);
                return format!("{}/{}", parent_path.trim_end_matches('/'), node.name);
            }
        }

        format!("/{}", node.name)
    }
}
