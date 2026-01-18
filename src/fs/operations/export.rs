//! Export and public link operations.

use serde_json::{json, Value};

use crate::base64::base64url_encode;
use crate::crypto::aes::aes128_ecb_encrypt_block;
use crate::error::{MegaError, Result};
use crate::fs::node::NodeType;
use crate::session::Session;
use super::utils::normalize_path;

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

            // Step 1: Create share with EXP (export) pseudo-user, include ok/ha
            if key.len() != 16 {
                return Err(MegaError::Custom("Invalid folder key length".to_string()));
            }
            let folder_key: [u8; 16] = key
                .as_slice()
                .try_into()
                .map_err(|_| MegaError::Custom("Invalid folder key length".to_string()))?;
            // Try to mimic webclient flow:
            // 1) upv with ^!keys to avoid -3 on s2 (best-effort; ignore errors).
            let _ = self
                .api_mut()
                .request(json!({
                    "a": "upv",
                    "^!keys": ["", ""]
                }))
                .await;

            // 2) Use zeroed ok/ha; cr carries folder key encrypted with share key.
            let share_key = crate::crypto::make_random_key();
            let ok = "AAAAAAAAAAAAAAAAAAAAAA";
            let ha = "AAAAAAAAAAAAAAAAAAAAAA";
            let enc_node_key = base64url_encode(&aes128_ecb_encrypt_block(&folder_key, &share_key));
            let cr = json!([
                [handle],
                [handle],
                [0, 0, enc_node_key] // privilege 0 (read-only), padding 0, node key encrypted with share key
            ]);

            let share_resp = self
                .api_mut()
                .request(json!({
                    "a": "s2",
                    "n": handle,
                    "s": [{"u": "EXP", "r": 0}],
                    "ok": ok,
                    "ha": ha,
                "cr": cr
            }))
                .await?;
            eprintln!(
                "debug: export folder ok (enc share key) for {} -> {}",
                path, enc_node_key
            );

            if let Some(err) = share_resp.as_i64().filter(|v| *v < 0) {
                return Err(MegaError::ApiError {
                    code: err as i32,
                    message: crate::api::client::ApiErrorCode::from(err).description().to_string(),
                });
            }

            // Step 2: Get the public link handle
            let response = self
                .api_mut()
                .request(json!({
                    "a": "l",
                    "n": handle
                }))
                .await?;

            if let Some(err) = response.as_i64().filter(|v| *v < 0) {
                return Err(MegaError::ApiError {
                    code: err as i32,
                    message: crate::api::client::ApiErrorCode::from(err).description().to_string(),
                });
            }

            let link_handle = response
                .as_str()
                .ok_or_else(|| MegaError::Custom("Invalid export response".to_string()))?
                .to_string();

            // Update the node with the link and remember share key for children
            self.nodes[node_idx].link = Some(link_handle.clone());
            // Exported link key is the share key.
            self.share_keys.insert(handle.clone(), share_key);

            // Build folder URL
            let key_b64 = base64url_encode(&share_key);
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

}
