//! Export and public link operations.

use rand::RngCore;
use serde_json::{Value, json};
use std::collections::HashMap;

use super::utils::normalize_path;
use crate::base64::base64url_encode;
use crate::error::{MegaError, Result};
use crate::fs::node::NodeType;
use crate::session::Session;

impl Session {
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
    /// # use megalib::Session;
    /// # async fn example() -> megalib::error::Result<()> {
    /// let mut session = Session::login("user@example.com", "password").await?;
    /// session.refresh().await?;
    /// let url = session.export("/Root/myfile.txt").await?;
    /// println!("Public link: {}", url);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn export(&mut self, path: &str) -> Result<String> {
        // Ensure upgraded keys are present before sharing/exporting.
        self.ensure_keys_attribute().await?;

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

            // Collect this folder and all descendants so we can include their keys in `cr`.
            let mut share_nodes: Vec<(String, Vec<u8>)> = Vec::new();
            share_nodes.push((handle.clone(), key.clone()));
            let mut stack = vec![handle.clone()];
            while let Some(parent) = stack.pop() {
                for n in &self.nodes {
                    if let Some(p) = &n.parent_handle {
                        if p == &parent {
                            stack.push(n.handle.clone());
                            share_nodes.push((n.handle.clone(), n.key.clone()));
                        }
                    }
                }
            }
            // Reuse existing share key if we already have one; otherwise generate new.
            let share_key = if let Some((_, k)) = self.find_share_for_handle(&handle) {
                k
            } else {
                let mut sk = [0u8; 16];
                rand::thread_rng().fill_bytes(&mut sk);
                sk
            };

            // Build a minimal share: ok/ha, cr covering root + descendants.
            // SDK sends dummy zero values for ok/ha (even for upgraded accounts).
            let zero = base64url_encode(&[0u8; 16]);
            let (ok, ha) = (zero.clone(), zero);

            // Build cr similar to webclient:
            // cr[0] = [root handle]
            // cr[1] = [root handle, child1, child2, ...]
            // cr[2] = [0, idx, enc_key_for_handle] per entry (idx into cr[1])
            let cr = self.build_cr_for_nodes(&handle, &share_key, &share_nodes);

            let mut request = json!({
                "a": "s2",
                "n": handle,
                "s": [{"u": "EXP", "r": 0}],
                "ok": ok,
                "ha": ha,
                "i": self.session_id()
            });
            if let Some(cr_value) = cr {
                request["cr"] = cr_value;
            }

            // s2 can return -3 transiently or -8 if share already exists.
            let mut share_resp = self.api_mut().request(request.clone()).await;
            if matches!(share_resp, Err(MegaError::ApiError { code: -3, .. })) {
                // Backoff once and retry after refresh.
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                let _ = self.refresh().await;
                share_resp = self.api_mut().request(request.clone()).await;
            }
            let share_resp = match share_resp {
                Err(MegaError::ApiError { code: -8, .. }) => json!(0),
                Err(e) => return Err(e),
                Ok(v) => v,
            };

            if let Some(err) = share_resp.as_i64().filter(|v| *v < 0) {
                return Err(MegaError::ApiError {
                    code: err as i32,
                    message: crate::api::ApiErrorCode::from(err)
                        .description()
                        .to_string(),
                });
            }
            if let Some(tag) = self.track_seqtag_from_response(&share_resp) {
                if !self.defer_seqtag_wait {
                    self.wait_for_seqtag(&tag).await?;
                }
            }

            // Persist share key into ^!keys only for upgraded accounts, once per export.
            self.share_keys.insert(handle.clone(), share_key);
            if self.key_manager.is_ready() {
                let mut keys_changed = false;
                let existing = self.key_manager.get_share_key_from_str(&handle);
                if existing.map(|k| k != share_key).unwrap_or(true) {
                    self.key_manager
                        .add_share_key_with_flags(&handle, &share_key, true, true); // trusted + in_use
                    keys_changed = true;
                }
                keys_changed |= self.key_manager.set_share_key_in_use(&handle, true);
                keys_changed |= self.key_manager.set_share_key_trusted(&handle, true);
                if keys_changed {
                    let _ = self.persist_keys_attribute().await;
                }
            }

            // eprintln!(
            //     "debug: export folder ok for {} (share_key={})",
            //     path,
            //     base64url_encode(&share_key)
            // );

            // Step 2: Get the public link handle
            let session_id = self.session_id().to_string();
            let response = self
                .api_mut()
                .request(json!({
                    "a": "l",
                    "n": handle,
                    "i": session_id
                }))
                .await?;

            if let Some(err) = response.as_i64().filter(|v| *v < 0) {
                return Err(MegaError::ApiError {
                    code: err as i32,
                    message: crate::api::ApiErrorCode::from(err)
                        .description()
                        .to_string(),
                });
            }

            let link_handle = parse_public_link_handle(&response)
                .ok_or_else(|| MegaError::Custom("Invalid export response".to_string()))?;

            // Update the node with the link
            self.nodes[node_idx].link = Some(link_handle.clone());

            // Build folder URL
            let key_b64 = base64url_encode(&share_key);
            Ok(format!(
                "https://mega.nz/folder/{}#{}",
                link_handle, key_b64
            ))
        } else {
            // File export uses "l" (link) API directly
            let session_id = self.session_id().to_string();
            let response = self
                .api_mut()
                .request(json!({
                    "a": "l",
                    "n": handle,
                    "i": session_id
                }))
                .await?;

            // Response is the public link handle as a string
            let link_handle = parse_public_link_handle(&response)
                .ok_or_else(|| MegaError::Custom("Invalid export response".to_string()))?;

            // Update the node with the link
            self.nodes[node_idx].link = Some(link_handle.clone());

            // Optionally persist file key into ^!keys when upgraded (avoid redundant writes).
            if self.key_manager.is_ready() {
                let mut keys_changed = false;
                let existing = self.key_manager.get_share_key_from_str(&handle);
                if existing
                    .map(|k| key.as_slice() != k.as_ref())
                    .unwrap_or(true)
                {
                    self.key_manager.add_share_key_from_str(&handle, &key);
                    keys_changed = true;
                }
                if keys_changed {
                    let _ = self.persist_keys_attribute().await;
                }
            }

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
        let requests: Vec<Value> = handles
            .iter()
            .map(|h| json!({"a": "l", "n": h, "i": self.session_id()}))
            .collect();

        // Make batch API call
        let response = self.api_mut().request_batch(requests).await?;

        // Parse responses
        let responses = response
            .as_array()
            .ok_or_else(|| MegaError::Custom("Invalid batch response".to_string()))?;

        let mut parsed_links = HashMap::new();
        for (i, resp) in responses.iter().enumerate() {
            if let Some(link_handle) = parse_public_link_handle(resp) {
                let idx = node_indices[i];
                self.nodes[idx].link = Some(link_handle.clone());
                parsed_links.insert(handles[i].clone(), link_handle);
            }
        }

        // Allow SC action packets to update public links (SDK parity).
        if self.scsn.is_some() {
            let _ = self.poll_action_packets_once().await;
        }

        let mut results = Vec::new();
        for handle in &handles {
            let Some(node) = self.get_node_by_handle(handle) else {
                continue;
            };
            let link_handle = node
                .link
                .clone()
                .or_else(|| parsed_links.get(handle).cloned());
            if let Some(link_handle) = link_handle {
                let key_b64 = base64url_encode(&node.key);
                let url = format!("https://mega.nz/file/{}#{}", link_handle, key_b64);
                if let Some(path) = &node.path {
                    results.push((path.clone(), url));
                }
            }
        }

        Ok(results)
    }
}

fn parse_public_link_handle(response: &Value) -> Option<String> {
    if let Some(link) = response.as_str() {
        return Some(link.to_string());
    }
    let arr = response.as_array()?;
    if arr.len() >= 2 {
        arr[1].as_str().map(|s| s.to_string())
    } else {
        arr.first().and_then(|v| v.as_str()).map(|s| s.to_string())
    }
}
