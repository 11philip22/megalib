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
    /// Export a cached node to create a public link.
    pub async fn export_node(&mut self, node: &crate::fs::Node) -> Result<String> {
        // SDK parity: refuse share/export until account key material is fully initialized.
        self.ensure_share_keys_ready().await?;

        let node_idx = self
            .nodes
            .iter()
            .position(|cached| cached.handle == node.handle)
            .ok_or_else(|| MegaError::Custom(format!("Node not found: {}", node.handle)))?;

        let node = &self.nodes[node_idx];
        let handle = node.handle.clone();
        let key = node.key.clone();
        let is_folder = node.node_type.is_container();

        if is_folder {
            let mut share_nodes = self.collect_share_nodes_bottom_up(&handle);
            if share_nodes.is_empty() {
                share_nodes.push((handle.clone(), key.clone()));
            }
            let share_key = if let Some((_, k)) = self.find_share_for_handle(&handle) {
                k
            } else {
                let mut sk = [0u8; 16];
                rand::thread_rng().fill_bytes(&mut sk);
                sk
            };

            let zero = base64url_encode(&[0u8; 16]);
            let (ok, ha) = (zero.clone(), zero);
            let cr = self.build_cr_for_nodes(&handle, &share_key, &share_nodes);

            let mut request = json!({
                "a": "s2",
                "n": handle,
                "s": [{"u": "EXP", "r": 0}],
                "ok": ok,
                "ha": ha
            });
            if let Some(cr_value) = cr {
                request["cr"] = cr_value;
            }

            let mut share_resp = self.api_mut().request(request.clone()).await;
            if matches!(share_resp, Err(MegaError::ApiError { code: -11, .. })) {
                self.ensure_share_keys_ready().await?;
                let _ = self.refresh().await;
                share_resp = self.api_mut().request(request.clone()).await;
            }
            if matches!(share_resp, Err(MegaError::ApiError { code: -3, .. })) {
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
            let _ = self.track_seqtag_from_response(&share_resp);

            {
                let mut keys_changed = false;
                let existing = self.key_manager.get_share_key_from_str(&handle);
                if existing.map(|k| k != share_key).unwrap_or(true) {
                    self.key_manager
                        .add_share_key_with_flags(&handle, &share_key, true, true);
                    keys_changed = true;
                }
                keys_changed |= self.key_manager.set_share_key_in_use(&handle, true);
                keys_changed |= self.key_manager.set_share_key_trusted(&handle, true);
                if keys_changed {
                    let _ = self.persist_keys_attribute().await;
                }
            }

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
            self.nodes[node_idx].link = Some(link_handle.clone());

            let key_b64 = base64url_encode(&share_key);
            Ok(format!(
                "https://mega.nz/folder/{}#{}",
                link_handle, key_b64
            ))
        } else {
            let session_id = self.session_id().to_string();
            let response = self
                .api_mut()
                .request(json!({
                    "a": "l",
                    "n": handle,
                    "i": session_id
                }))
                .await?;

            let link_handle = parse_public_link_handle(&response)
                .ok_or_else(|| MegaError::Custom("Invalid export response".to_string()))?;

            self.nodes[node_idx].link = Some(link_handle.clone());

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

            let key_b64 = base64url_encode(&key);
            Ok(format!("https://mega.nz/file/{}#{}", link_handle, key_b64))
        }
    }

    /// Export multiple cached nodes and return `(node, url)` pairs.
    ///
    /// File nodes are batched through the public-link API. Folder nodes fall back
    /// to single-node export flow because they require share setup.
    pub async fn export_many_nodes(
        &mut self,
        nodes: &[crate::fs::Node],
    ) -> Result<Vec<(crate::fs::Node, String)>> {
        let mut results: Vec<Option<(crate::fs::Node, String)>> = vec![None; nodes.len()];
        let mut file_inputs = Vec::new();
        let mut file_node_indices = Vec::new();
        let mut file_handles = Vec::new();

        for (input_idx, node) in nodes.iter().enumerate() {
            let idx = self
                .nodes
                .iter()
                .position(|cached| cached.handle == node.handle)
                .ok_or_else(|| MegaError::Custom(format!("Node not found: {}", node.handle)))?;

            if self.nodes[idx].node_type == NodeType::File {
                file_inputs.push(input_idx);
                file_node_indices.push(idx);
                file_handles.push(self.nodes[idx].handle.clone());
            } else {
                let url = self.export_node(node).await?;
                results[input_idx] = Some((node.clone(), url));
            }
        }

        if file_handles.is_empty() {
            return Ok(results.into_iter().flatten().collect());
        }

        let requests: Vec<Value> = file_handles
            .iter()
            .map(|h| json!({"a": "l", "n": h, "i": self.session_id()}))
            .collect();

        let response = self.api_mut().request_batch(requests).await?;
        let responses = response
            .as_array()
            .ok_or_else(|| MegaError::Custom("Invalid batch response".to_string()))?;

        let mut parsed_links = HashMap::new();
        for (i, resp) in responses.iter().enumerate() {
            if let Some(link_handle) = parse_public_link_handle(resp) {
                let idx = file_node_indices[i];
                self.nodes[idx].link = Some(link_handle.clone());
                parsed_links.insert(file_handles[i].clone(), link_handle);
            }
        }

        for (result_idx, handle) in file_inputs.iter().zip(file_handles.iter()) {
            let node = &nodes[*result_idx];
            let cached = self
                .get_node_by_handle(handle)
                .ok_or_else(|| MegaError::Custom(format!("Node not found: {}", node.handle)))?;
            let link_handle = cached
                .link
                .clone()
                .or_else(|| parsed_links.get(handle).cloned());
            if let Some(link_handle) = link_handle {
                let key_b64 = base64url_encode(&cached.key);
                let url = format!("https://mega.nz/file/{}#{}", link_handle, key_b64);
                results[*result_idx] = Some((cached.clone(), url));
            }
        }

        Ok(results.into_iter().flatten().collect())
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
    /// # use megalib::SessionHandle;
    /// # async fn example() -> megalib::error::Result<()> {
    /// let mut session = SessionHandle::login("user@example.com", "password").await?;
    /// session.refresh().await?;
    /// let url = session.export("/Root/myfile.txt").await?;
    /// println!("Public link: {}", url);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn export(&mut self, path: &str) -> Result<String> {
        let normalized_path = normalize_path(path);
        let node = self
            .nodes
            .iter()
            .find(|n| n.path.as_deref() == Some(&normalized_path))
            .cloned()
            .ok_or_else(|| MegaError::Custom(format!("Node not found: {}", path)))?;
        self.export_node(&node).await
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
        let nodes: Vec<crate::fs::Node> = paths
            .iter()
            .filter_map(|path| {
                let normalized_path = normalize_path(path);
                self.nodes
                    .iter()
                    .find(|n| n.path.as_deref() == Some(&normalized_path))
                    .cloned()
            })
            .collect();

        let exported = self.export_many_nodes(&nodes).await?;
        Ok(exported
            .into_iter()
            .filter_map(|(node, url)| node.path.map(|path| (path, url)))
            .collect())
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
