//! Export and public link operations.

use serde_json::{json, Value};
use rand::RngCore;

use crate::base64::base64url_encode;
use crate::crypto::aes::aes128_ecb_encrypt;
use crate::error::{MegaError, Result};
use crate::fs::node::NodeType;
use crate::session::Session;
use super::utils::normalize_path;

impl Session {
    /// Best-effort refresh of ^!keys attribute to avoid server -3 on s2.
    async fn refresh_keys_attribute(&mut self) -> Option<(String, String)> {
        let user = self.user_handle.clone();
        // Fetch current ^!keys user attribute
        let resp = self
            .api_mut()
            .request(json!({
                "a": "uga",
                "u": user,
                "ua": "^!keys"
            }))
            .await;

        let Ok(resp) = resp else {
            eprintln!("debug: uga (^!keys) failed: {:?}", resp.err());
            return None;
        };
        // Response may be object or nested in an array; try both.
        let (av, v) = if let Some(av) = resp.get("av").and_then(|v| v.as_str()) {
            let ver = resp.get("v").and_then(|v| v.as_str()).unwrap_or("");
            (av.to_string(), ver.to_string())
        } else if let Some(arr) = resp.as_array() {
            if let Some(obj) = arr.iter().find_map(|v| v.as_object()) {
                let av = obj.get("av").and_then(|v| v.as_str()).unwrap_or("");
                let ver = obj.get("v").and_then(|v| v.as_str()).unwrap_or("");
                (av.to_string(), ver.to_string())
            } else {
                ("".to_string(), "".to_string())
            }
        } else {
            ("".to_string(), "".to_string())
        };

        eprintln!("debug: uga (^!keys) av len={} v={}", av.len(), v);
        if av.is_empty() {
            return None;
        }

        // Post back via upv; ignore errors.
        let upv_res = self
            .api_mut()
            .request(json!({
                "a": "upv",
                "^!keys": [av, v]
            }))
            .await;
        if let Err(err) = upv_res {
            eprintln!("debug: upv (^!keys) failed: {}", err);
        } else {
            eprintln!("debug: upv (^!keys) ok");
        }
        Some((av, v))
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
            // Step 1: Create share with EXP (export) pseudo-user, include ok/ha and cr for all nodes
            if key.len() != 16 {
                return Err(MegaError::Custom("Invalid folder key length".to_string()));
            }
            // Try to mimic webclient flow: refresh ^!keys then share.
            let _ = self.refresh_keys_attribute().await;

            // Build a minimal share: zero ok/ha, random share key, cr covering root + descendants.
            let mut share_key = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut share_key);
            let ok = "AAAAAAAAAAAAAAAAAAAAAA".to_string();
            let ha = "AAAAAAAAAAAAAAAAAAAAAA".to_string();

            // Build cr similar to webclient:
            // cr[0] = [root handle]
            // cr[1] = [root handle, child1, child2, ...]
            // cr[2] = [0, idx, enc_key_for_handle] per entry (idx into cr[1])
            let cr_nodes = vec![handle.clone()];
            let mut cr_users: Vec<String> = Vec::new();
            let mut cr_triplets: Vec<Value> = Vec::new();
            for (idx, (h, kbytes)) in share_nodes.iter().enumerate() {
                if kbytes.is_empty() || kbytes.len() % 16 != 0 {
                    // skip malformed key
                    continue;
                }
                let enc = aes128_ecb_encrypt(kbytes, &share_key);
                let enc_b64 = base64url_encode(&enc);
                cr_users.push(h.clone());
                cr_triplets.push(json!(0));
                cr_triplets.push(json!(idx as i64));
                cr_triplets.push(json!(enc_b64));
            }
            let cr = json!([cr_nodes, cr_users, cr_triplets]);

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

            if let Some(err) = share_resp.as_i64().filter(|v| *v < 0) {
                return Err(MegaError::ApiError {
                    code: err as i32,
                    message: crate::api::client::ApiErrorCode::from(err).description().to_string(),
                });
            }

            eprintln!(
                "debug: export folder ok for {} (share_key={})",
                path,
                base64url_encode(&share_key)
            );

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
