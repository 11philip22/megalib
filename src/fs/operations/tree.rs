//! Filesystem tree refresh and parsing.

use std::collections::HashMap;

use serde_json::{Value, json};

use crate::base64::base64url_decode;
use crate::crypto::aes::{aes128_cbc_decrypt, aes128_ecb_decrypt};
use crate::error::{MegaError, Result};
use crate::fs::node::{Node, NodeType};
use crate::session::Session;

/// Maximum number of nodes in the deferred key queue before oldest entries are dropped.
const MAX_PENDING_NODES: usize = 4096;

impl Session {
    fn finalize_refreshed_tree_cache_state(&mut self) -> Result<()> {
        self.nodes_state_ready = true;
        self.recompute_state_current();
        self.action_packets_current =
            self.state_current && (self.current_seqtag.is_none() || self.current_seqtag_seen);
        self.persist_tree_cache_state()
    }

    /// Refresh the filesystem tree from the server.
    ///
    /// This fetches all nodes (SDK-style `f`), share keys, and public links, then decrypts
    /// attributes and rebuilds cached paths.
    /// Must be called before using `list()`, `stat()`, etc.
    /// Cloud Drive paths are rooted at `/Root`.
    ///
    /// # Example
    /// ```no_run
    /// # use megalib::SessionHandle;
    /// # async fn example() -> megalib::error::Result<()> {
    /// let mut session = SessionHandle::login("user@example.com", "password").await?;
    /// session.refresh().await?;
    /// let nodes = session.list("/Root", false).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn refresh(&mut self) -> Result<()> {
        // Match SDK behavior: ensure keys are initialized before fetching nodes.
        self.ensure_keys_attribute().await?;
        self.reset_state_current_tracking();

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
        } else {
            self.sc_catchup = false;
            self.sc_batch_catchup_done = true;
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
            if let Some(1) = node_json.get("t").and_then(|v| v.as_i64())
                && let (Some(handle), Some(kstr)) = (
                    node_json.get("h").and_then(|v| v.as_str()),
                    node_json.get("k").and_then(|v| v.as_str()),
                )
            {
                for part in kstr.split('/') {
                    if let Some((key_handle, encrypted_key)) = part.split_once(':')
                        && key_handle == self.user_handle
                        && let Ok(enc) = base64url_decode(encrypted_key)
                    {
                        let dec = aes128_ecb_decrypt(&enc, self.master_key());
                        if dec.len() >= 16 {
                            let mut key = [0u8; 16];
                            key.copy_from_slice(&dec[..16]);
                            if self.key_manager.get_share_key_from_str(handle).is_none() {
                                self.key_manager.add_share_key_from_str(handle, &key);
                            }
                        }
                    }
                }
            }
        }

        self.pending_nodes.clear();
        let mut nodes = Vec::new();
        for node_json in nodes_array {
            if let Some(mut node) = self.try_parse_or_stash(node_json) {
                if let Some(link) = public_links.get(&node.handle) {
                    node.link = Some(link.clone());
                }
                nodes.push(node);
            }
        }

        // Mark inshare/outshare flags on nodes.
        {
            // Build an owned handle->index map for parent lookups.
            let handle_idx: HashMap<String, usize> = nodes
                .iter()
                .enumerate()
                .map(|(i, n)| (n.handle.clone(), i))
                .collect();

            // Collect parent types so we can read them without borrowing nodes.
            let parent_types: Vec<Option<NodeType>> = nodes
                .iter()
                .map(|n| {
                    n.parent_handle
                        .as_ref()
                        .and_then(|ph| handle_idx.get(ph))
                        .map(|&pidx| nodes[pidx].node_type)
                })
                .collect();

            for i in 0..nodes.len() {
                if self.outshares.contains_key(&nodes[i].handle)
                    || self.pending_outshares.contains_key(&nodes[i].handle)
                {
                    nodes[i].is_outshare = true;
                }

                if nodes[i].share_key.is_some() && nodes[i].node_type == NodeType::Folder {
                    let is_inshare = match parent_types[i] {
                        None => true,
                        Some(pt) => matches!(pt, NodeType::Root | NodeType::Network),
                    };
                    if is_inshare {
                        nodes[i].is_inshare = true;
                    }
                }

                if nodes[i].is_inshare {
                    let handle = nodes[i].handle.clone();
                    if let Some(node_json) = nodes_array
                        .iter()
                        .find(|j| j.get("h").and_then(|v| v.as_str()) == Some(&handle))
                    {
                        nodes[i].share_access = node_json
                            .get("r")
                            .and_then(|v| v.as_i64())
                            .map(|v| v as i32);
                    }
                }
            }
        }

        // Build node paths
        Self::build_node_paths(&mut nodes);

        // Store nodes
        self.nodes = nodes;

        // Drain any nodes that became decryptable after share keys were loaded above.
        self.drain_pending_nodes();

        self.finalize_refreshed_tree_cache_state()?;

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
                if k.len() > 22 {
                    if let Ok(encrypted) = base64url_decode(k)
                        && let Some(decrypted) = self.rsa_key().decrypt(&encrypted)
                        && decrypted.len() >= 16
                    {
                        let mut key = [0u8; 16];
                        key.copy_from_slice(&decrypted[..16]);
                        if self.key_manager.get_share_key_from_str(h).is_none() {
                            self.key_manager.add_share_key_from_str(h, &key);
                        }
                    }
                } else if let Ok(encrypted) = base64url_decode(k) {
                    let decrypted = aes128_ecb_decrypt(&encrypted, self.master_key());
                    if decrypted.len() >= 16 {
                        let mut key = [0u8; 16];
                        key.copy_from_slice(&decrypted[..16]);
                        if self.key_manager.get_share_key_from_str(h).is_none() {
                            self.key_manager.add_share_key_from_str(h, &key);
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

        let (name, node_key, share_key, share_handle) = match node_type {
            NodeType::Root => ("Root".to_string(), Vec::new(), None, None),
            NodeType::Inbox => ("Inbox".to_string(), Vec::new(), None, None),
            NodeType::Trash => ("Trash".to_string(), Vec::new(), None, None),
            _ => {
                let attrs_b64 = json.get("a")?.as_str()?;
                let key_str = json.get("k")?.as_str()?;
                let (node_key, used_share_key) = self.decrypt_node_key(key_str)?;
                let sh = used_share_key.and_then(|_| {
                    key_str.split('/').find_map(|part| {
                        let (kh, _) = part.split_once(':')?;
                        if kh != self.user_handle && self.key_manager.contains_share_key(kh) {
                            Some(kh.to_string())
                        } else {
                            None
                        }
                    })
                });
                match self.decrypt_node_attrs(attrs_b64, &node_key) {
                    Some(name) => (name, node_key, used_share_key, sh),
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
            share_key,
            share_handle,
            is_inshare: false,
            is_outshare: false,
            share_access: None,
        })
    }

    /// Try to parse a node; stash its JSON in the pending queue if the key is unavailable.
    ///
    /// Returns the parsed [`Node`] on success. If parsing fails because the
    /// required share key hasn't arrived yet, the raw JSON is pushed into
    /// `self.pending_nodes` and `None` is returned. Structurally invalid or
    /// corrupt entries are silently dropped (not stashed).
    pub(crate) fn try_parse_or_stash(&mut self, json: &Value) -> Option<Node> {
        // Fast path: if parse succeeds, nothing to decide.
        if let Some(node) = self.parse_node(json) {
            return Some(node);
        }

        // Structural validity: "h" and "t" must exist with valid types.
        let handle = json.get("h").and_then(|v| v.as_str())?;
        let node_type = json
            .get("t")
            .and_then(|v| v.as_i64())
            .and_then(NodeType::from_i64)?;

        // Only file/folder nodes are candidates for deferred key decryption.
        if !matches!(node_type, NodeType::File | NodeType::Folder) {
            return None;
        }

        // A "k" field is required for key decryption.
        let key_str = json.get("k").and_then(|v| v.as_str())?;

        // Check whether any handle in "k" is one we currently recognise.
        let has_recognized_handle = key_str.split('/').any(|part| {
            part.split_once(':')
                .map(|(h, _)| h == self.user_handle || self.key_manager.contains_share_key(h))
                .unwrap_or(false)
        });

        if !has_recognized_handle {
            // No recognised handle — a share key may arrive later.
            self.stash_pending_node(json.clone(), handle);
        } else if self.decrypt_node_key(key_str).is_some() {
            // Key decrypted but attrs could not be parsed — possibly stale share key.
            self.stash_pending_node(json.clone(), handle);
        }
        // Otherwise a recognised handle exists but the key itself couldn't be
        // decrypted (base64 / AES failure) — data is corrupt, don't stash.

        None
    }

    fn stash_pending_node(&mut self, json: Value, handle: &str) {
        if self.pending_nodes.len() >= MAX_PENDING_NODES {
            tracing::warn!(
                pending_count = self.pending_nodes.len(),
                "pending_nodes queue at capacity ({MAX_PENDING_NODES}), dropping oldest entry"
            );
            self.pending_nodes.remove(0);
        }
        tracing::debug!(node_handle = handle, "stashing node with missing key");
        self.pending_nodes.push(json);
    }

    /// Re-attempt parsing for every stashed node now that share keys may have changed.
    ///
    /// Nodes that still cannot be decrypted are put back in the queue.
    /// Returns `true` if at least one node was recovered.
    pub(crate) fn drain_pending_nodes(&mut self) -> bool {
        if self.pending_nodes.is_empty() {
            return false;
        }
        let pending = std::mem::take(&mut self.pending_nodes);
        let count = pending.len();
        let mut recovered = 0usize;
        for json in pending {
            if let Some(node) = self.parse_node(&json) {
                tracing::debug!(node_handle = %node.handle, "recovered node from pending queue");
                self.upsert_node(node);
                recovered += 1;
            } else {
                self.pending_nodes.push(json);
            }
        }
        if recovered > 0 {
            Self::build_node_paths(&mut self.nodes);
        }
        tracing::debug!(
            recovered,
            remaining = self.pending_nodes.len(),
            total = count,
            "drain_pending_nodes complete"
        );
        recovered > 0
    }

    /// Decrypt a node key from the "k" field.
    ///
    /// Returns `(decrypted_node_key, share_key_used)`. The second element is
    /// `Some(key)` when a share key (not the master key) performed the decryption,
    /// matching C++ SDK's `Node::applykey` + `getSharekey`.
    fn decrypt_node_key(&self, key_str: &str) -> Option<(Vec<u8>, Option<[u8; 16]>)> {
        for part in key_str.split('/') {
            if let Some((key_handle, encrypted_key)) = part.split_once(':') {
                let (decrypt_key_arr, used_share_key) = if key_handle == self.user_handle {
                    (Some(*self.master_key()), None)
                } else if let Some(k) = self.key_manager.get_share_key_from_str(key_handle) {
                    (Some(k), Some(k))
                } else {
                    (None, None)
                };

                if let Some(key) = decrypt_key_arr.as_ref()
                    && let Ok(encrypted) = base64url_decode(encrypted_key)
                {
                    let decrypted = aes128_ecb_decrypt(&encrypted, key);
                    return Some((decrypted, used_share_key));
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
        if let Some(parent_handle) = &node.parent_handle
            && let Some(&parent_idx) = handle_map.get(parent_handle.as_str())
        {
            let parent_path = Self::build_node_path(nodes, parent_idx, handle_map, depth + 1);
            return format!("{}/{}", parent_path.trim_end_matches('/'), node.name);
        }

        format!("/{}", node.name)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;

    use serde_json::json;

    use crate::base64::base64url_encode;
    use crate::crypto::aes::{aes128_cbc_encrypt, aes128_ecb_encrypt};
    use crate::fs::{Node, NodeType};
    use crate::session::Session;
    use crate::session::runtime::persistence::{MemoryPersistenceBackend, PersistenceRuntime};

    use super::MAX_PENDING_NODES;

    /// Build a folder-node JSON blob whose key is encrypted under `encrypt_key`
    /// and whose `"k"` handle is `key_handle`.
    fn make_folder_node_json(
        handle: &str,
        name: &str,
        key_handle: &str,
        encrypt_key: &[u8; 16],
    ) -> serde_json::Value {
        let node_key = [0xAA; 16];
        let enc_key = aes128_ecb_encrypt(&node_key, encrypt_key);
        let k_field = format!("{}:{}", key_handle, base64url_encode(&enc_key));

        // Attrs: "MEGA{\"n\":\"<name>\"}" zero-padded to 16-byte boundary.
        let attrs_plain = format!("MEGA{{\"n\":\"{name}\"}}");
        let mut padded = attrs_plain.into_bytes();
        let rem = padded.len() % 16;
        if rem != 0 {
            padded.resize(padded.len() + (16 - rem), 0);
        }
        let attrs_enc = aes128_cbc_encrypt(&padded, &node_key);
        let a_field = base64url_encode(&attrs_enc);

        json!({
            "h": handle,
            "p": "root",
            "t": 1,
            "ts": 12345,
            "k": k_field,
            "a": a_field,
        })
    }

    #[test]
    fn drain_recovers_stashed_node_after_share_key_added() {
        let mut session = Session::test_dummy();
        let share_key: [u8; 16] = [0x02; 16];
        let node_json = make_folder_node_json("nodeA", "shared_folder", "shareXYZ", &share_key);

        // Share key not present — try_parse_or_stash should stash.
        let result = session.try_parse_or_stash(&node_json);
        assert!(result.is_none());
        assert_eq!(session.pending_nodes.len(), 1);
        assert!(session.nodes.is_empty());

        // Add the share key.
        session
            .key_manager
            .add_share_key_from_str("shareXYZ", &share_key);

        // Drain should recover the node.
        assert!(session.drain_pending_nodes());
        assert!(session.pending_nodes.is_empty());
        assert_eq!(session.nodes.len(), 1);
        assert_eq!(session.nodes[0].handle, "nodeA");
        assert_eq!(session.nodes[0].name, "shared_folder");
    }

    #[test]
    fn structurally_invalid_json_is_not_stashed() {
        let mut session = Session::test_dummy();

        // Missing "h"
        let no_handle = json!({"t": 1, "k": "x:y", "a": "z"});
        assert!(session.try_parse_or_stash(&no_handle).is_none());
        assert!(session.pending_nodes.is_empty());

        // Missing "t"
        let no_type = json!({"h": "abc", "k": "x:y", "a": "z"});
        assert!(session.try_parse_or_stash(&no_type).is_none());
        assert!(session.pending_nodes.is_empty());

        // Invalid type value
        let bad_type = json!({"h": "abc", "t": 999, "k": "x:y", "a": "z"});
        assert!(session.try_parse_or_stash(&bad_type).is_none());
        assert!(session.pending_nodes.is_empty());

        // Missing "k" field for a file
        let no_key = json!({"h": "abc", "t": 0, "a": "z"});
        assert!(session.try_parse_or_stash(&no_key).is_none());
        assert!(session.pending_nodes.is_empty());
    }

    #[test]
    fn corrupt_data_with_recognised_handle_is_not_stashed() {
        let mut session = Session::test_dummy();

        // Key handle matches user but encrypted key is garbage base64.
        let corrupt = json!({
            "h": "badnode",
            "t": 0,
            "p": "root",
            "k": "myhandle:!!!invalid-base64!!!",
            "a": "also-garbage",
        });
        assert!(session.try_parse_or_stash(&corrupt).is_none());
        assert!(session.pending_nodes.is_empty());
    }

    #[test]
    fn queue_cap_is_enforced() {
        let mut session = Session::test_dummy();

        // Fill beyond capacity.
        for i in 0..MAX_PENDING_NODES + 10 {
            let node = json!({
                "h": format!("node{i}"),
                "t": 1,
                "p": "root",
                "k": format!("unknown_handle{}:AAAA", i),
                "a": "AAAA",
            });
            session.try_parse_or_stash(&node);
        }

        assert_eq!(session.pending_nodes.len(), MAX_PENDING_NODES);

        // The oldest entries should have been dropped — the last one should be present.
        let last_h = session
            .pending_nodes
            .last()
            .and_then(|v| v.get("h"))
            .and_then(|v| v.as_str())
            .unwrap();
        let expected = format!("node{}", MAX_PENDING_NODES + 9);
        assert_eq!(last_h, expected);
    }

    #[test]
    fn drain_with_no_pending_is_noop() {
        let mut session = Session::test_dummy();
        assert!(!session.drain_pending_nodes());
    }

    #[test]
    fn root_nodes_parse_directly_without_stashing() {
        let mut session = Session::test_dummy();
        let root_json = json!({"h": "rootH", "t": 2, "ts": 0});
        let node = session.try_parse_or_stash(&root_json);
        assert!(node.is_some());
        assert!(session.pending_nodes.is_empty());
        assert_eq!(node.unwrap().name, "Root");
    }

    #[test]
    fn finalize_refreshed_tree_cache_state_persists_coherent_snapshot() {
        let persistence = PersistenceRuntime::new(Arc::new(MemoryPersistenceBackend::default()));
        let mut session = Session::test_dummy().with_persistence_for_tests(persistence.clone());
        session.scsn = Some("refresh-scsn".to_string());
        session.nodes = vec![
            Node {
                name: "Root".to_string(),
                handle: "root".to_string(),
                parent_handle: None,
                node_type: NodeType::Root,
                size: 0,
                timestamp: 0,
                key: Vec::new(),
                path: Some("/Root".to_string()),
                link: None,
                file_attr: None,
                share_key: None,
                share_handle: None,
                is_inshare: false,
                is_outshare: false,
                share_access: None,
            },
            Node {
                name: "docs".to_string(),
                handle: "docs".to_string(),
                parent_handle: Some("root".to_string()),
                node_type: NodeType::Folder,
                size: 0,
                timestamp: 1,
                key: vec![0x11; 16],
                path: Some("/Root/docs".to_string()),
                link: None,
                file_attr: None,
                share_key: None,
                share_handle: None,
                is_inshare: false,
                is_outshare: true,
                share_access: None,
            },
        ];
        session.pending_nodes = vec![json!({"h": "pending", "p": "docs", "t": 0})];
        session.outshares =
            HashMap::from([("docs".to_string(), HashSet::from(["EXP".to_string()]))]);

        session
            .finalize_refreshed_tree_cache_state()
            .expect("refresh finalization should persist");

        let stored = persistence
            .load_engine_state(&session.persistence_scope())
            .expect("load should succeed")
            .expect("tree/cache snapshot should exist");
        let tree = stored.tree.expect("refresh should persist tree snapshot");

        assert_eq!(stored.sc.scsn.as_deref(), Some("refresh-scsn"));
        assert!(session.nodes_state_ready);
        assert_eq!(tree.nodes.len(), 2);
        assert_eq!(tree.pending_nodes.len(), 1);
        assert_eq!(
            tree.outshares.get("docs"),
            Some(&HashSet::from(["EXP".to_string()]))
        );
    }

    #[test]
    fn finalized_refresh_snapshot_restores_after_restart() {
        let persistence = PersistenceRuntime::new(Arc::new(MemoryPersistenceBackend::default()));
        let mut session = Session::test_dummy().with_persistence_for_tests(persistence.clone());
        session.scsn = Some("refresh-scsn".to_string());
        session.nodes = vec![
            Node {
                name: "Root".to_string(),
                handle: "root".to_string(),
                parent_handle: None,
                node_type: NodeType::Root,
                size: 0,
                timestamp: 0,
                key: Vec::new(),
                path: Some("/Root".to_string()),
                link: None,
                file_attr: None,
                share_key: None,
                share_handle: None,
                is_inshare: false,
                is_outshare: false,
                share_access: None,
            },
            Node {
                name: "docs".to_string(),
                handle: "docs".to_string(),
                parent_handle: Some("root".to_string()),
                node_type: NodeType::Folder,
                size: 0,
                timestamp: 1,
                key: vec![0x11; 16],
                path: Some("/Root/docs".to_string()),
                link: None,
                file_attr: None,
                share_key: None,
                share_handle: None,
                is_inshare: false,
                is_outshare: true,
                share_access: None,
            },
        ];
        session.pending_nodes = vec![json!({"h": "pending", "p": "docs", "t": 0})];
        session.outshares =
            HashMap::from([("docs".to_string(), HashSet::from(["EXP".to_string()]))]);
        session.pending_outshares = HashMap::from([(
            "docs".to_string(),
            HashSet::from(["pending-user".to_string()]),
        )]);

        session
            .finalize_refreshed_tree_cache_state()
            .expect("refresh finalization should persist");

        let mut restored = Session::test_dummy().with_persistence_for_tests(persistence);
        let loaded = restored
            .restore_tree_cache_state()
            .expect("restored refresh snapshot should load");

        assert!(loaded);
        assert_eq!(restored.scsn.as_deref(), Some("refresh-scsn"));
        assert_eq!(restored.nodes.len(), 2);
        assert_eq!(
            restored
                .nodes
                .iter()
                .find(|node| node.handle == "docs")
                .and_then(Node::path),
            Some("/Root/docs")
        );
        assert_eq!(restored.pending_nodes.len(), 1);
        assert_eq!(
            restored.outshares.get("docs"),
            Some(&HashSet::from(["EXP".to_string()]))
        );
        assert_eq!(
            restored.pending_outshares.get("docs"),
            Some(&HashSet::from(["pending-user".to_string()]))
        );
    }
}
