//! Directory and node mutation operations.

use rand::RngCore;
use serde_json::json;

use super::utils::normalize_path;
use crate::api::ApiErrorCode;
use crate::base64::base64url_encode;
use crate::crypto::aes::aes128_cbc_encrypt;
use crate::error::{MegaError, Result};
use crate::fs::node::Node;
use crate::session::Session;
use crate::session::runtime::request::RequestClass;

impl Session {
    /// Create a new directory inside a cached parent node.
    pub async fn create_folder_in(&mut self, name: &str, parent: &Node) -> Result<Node> {
        let parent_handle = parent.handle.clone();

        // 1. Generate random 128-bit node key
        let node_key = {
            let mut rng = rand::thread_rng();
            let mut key_bytes = [0u8; 16];
            rng.fill_bytes(&mut key_bytes);
            key_bytes
        };

        // 2. Encrypt attributes
        let attrs = json!({ "n": name }).to_string();
        let attrs_bytes = format!("MEGA{}", attrs).into_bytes();
        let pad_len = 16 - (attrs_bytes.len() % 16);
        let mut padded_attrs = attrs_bytes;
        padded_attrs.extend(std::iter::repeat_n(0, pad_len));

        let encrypted_attrs = crate::crypto::aes::aes128_cbc_encrypt(&padded_attrs, &node_key);
        let attrs_b64 = crate::base64::base64url_encode(&encrypted_attrs);

        // 3. Encrypt node key with master key
        let encrypted_key =
            crate::crypto::aes::aes128_ecb_encrypt_block(&node_key, &self.master_key);
        let key_b64 = crate::base64::base64url_encode(&encrypted_key);

        // 4. Call API
        let session_id = self.session_id().to_string();
        let outcome = self
            .submit_request_single(
                RequestClass::Mutating,
                json!({
                    "a": "p",
                    "t": parent_handle,
                    "n": [{
                        "h": "xxxxxxxx",
                        "t": 1,
                        "a": attrs_b64,
                        "k": key_b64
                    }],
                    "v": 4,
                    "sm": 1,
                    "i": session_id
                }),
            )
            .await?;
        let seqtag = outcome.seqtag;
        let response = outcome.response;
        let _ = self.apply_request_seqtag(seqtag);

        let mut created_node: Option<Node> = None;
        if let Some(nodes_array) = response.get("f").and_then(|v| v.as_array())
            && let Some(node_obj) = nodes_array.first()
        {
            let mut node = self.parse_node(node_obj).ok_or_else(|| {
                crate::error::MegaError::Custom("Failed to parse node".to_string())
            })?;
            node.name = name.to_string();

            self.nodes.push(node.clone());
            let parent_path_str = parent.path().unwrap_or("");
            let created_path = if !parent_path_str.is_empty() {
                format!("{}/{}", parent_path_str.trim_end_matches('/'), name)
            } else {
                format!("/{}", name)
            };
            if let Some(last_node) = self.nodes.last_mut() {
                last_node.path = Some(created_path);
            }

            created_node = Some(node);
        }

        if let Some(arr) = response.as_array()
            && let Some(errors) = arr.get(1)
            && let Some(code) = first_error_code(errors)
        {
            let api = ApiErrorCode::from(code);
            return Err(MegaError::ApiError {
                code: code as i32,
                message: api.description().to_string(),
            });
        }

        if let Some(node) = created_node {
            return Ok(node);
        }

        Err(MegaError::Custom(
            "Folder creation pending action packets".to_string(),
        ))
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

        let parent_handle = self.stat_by_path(parent_path).cloned().ok_or_else(|| {
            crate::error::MegaError::Custom(format!("Parent directory not found: {}", parent_path))
        })?;
        self.create_folder_in(name, &parent_handle).await
    }

    /// Remove a cached node by handle.
    pub async fn remove_node(&mut self, node: &Node) -> Result<()> {
        let session_id = self.session_id().to_string();
        let response = self
            .api_mut()
            .request(json!({
                "a": "d",
                "n": node.handle,
                "i": session_id
            }))
            .await?;
        let _ = self.track_seqtag_from_response(&response);

        Ok(())
    }

    /// Remove a file or directory.
    pub async fn rm(&mut self, path: &str) -> Result<()> {
        let node = self
            .stat_by_path(path)
            .cloned()
            .ok_or_else(|| crate::error::MegaError::Custom(format!("Node not found: {}", path)))?;
        self.remove_node(&node).await
    }

    /// Move a file or directory to a new location.
    ///
    /// # Arguments
    /// * `source_path` - Path to the file/folder to move
    /// * `dest_parent_path` - Path to the new parent directory
    ///
    /// # Example
    /// ```no_run
    /// # use megalib::SessionHandle;
    /// # async fn example() -> megalib::error::Result<()> {
    /// let mut session = SessionHandle::login("user@example.com", "password").await?;
    /// session.refresh().await?;
    /// session.mv("/Root/file.txt", "/Root/Documents").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn move_node(&mut self, node: &Node, new_parent: &Node) -> Result<()> {
        if !new_parent.node_type.is_container() {
            return Err(MegaError::Custom(
                "Destination must be a folder".to_string(),
            ));
        }

        let session_id = self.session_id().to_string();
        let response = self
            .api_mut()
            .request(json!({
                "a": "m",
                "n": node.handle,
                "t": new_parent.handle,
                "i": session_id
            }))
            .await?;
        let _ = self.track_seqtag_from_response(&response);

        Ok(())
    }

    pub async fn mv(&mut self, source_path: &str, dest_parent_path: &str) -> Result<()> {
        let source_node = self
            .stat_by_path(source_path)
            .cloned()
            .ok_or_else(|| MegaError::Custom(format!("Source not found: {}", source_path)))?;
        let dest_parent = self
            .stat_by_path(dest_parent_path)
            .cloned()
            .ok_or_else(|| {
                MegaError::Custom(format!("Destination not found: {}", dest_parent_path))
            })?;

        self.move_node(&source_node, &dest_parent).await
    }

    /// Rename a file or directory.
    ///
    /// # Arguments
    /// * `path` - Path to the file/folder to rename
    /// * `new_name` - The new name (not a path, just the filename)
    ///
    /// # Example
    /// ```no_run
    /// # use megalib::SessionHandle;
    /// # async fn example() -> megalib::error::Result<()> {
    /// let mut session = SessionHandle::login("user@example.com", "password").await?;
    /// session.refresh().await?;
    /// session.rename("/Root/old_name.txt", "new_name.txt").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn rename_node(&mut self, node: &Node, new_name: &str) -> Result<()> {
        let node_idx = self
            .nodes
            .iter()
            .position(|n| n.handle == node.handle)
            .ok_or_else(|| MegaError::Custom(format!("Node not found: {}", node.handle)))?;

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
            padded_attrs.extend(std::iter::repeat_n(0, pad_len));
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
        let session_id = self.session_id().to_string();
        let response = self
            .api_mut()
            .request(json!({
                "a": "a",
                "n": node.handle,
                "attr": attrs_b64,
                "i": session_id
            }))
            .await?;
        let _ = self.track_seqtag_from_response(&response);

        // Update local cache
        self.nodes[node_idx].name = new_name.to_string();

        Ok(())
    }

    pub async fn rename(&mut self, path: &str, new_name: &str) -> Result<()> {
        let normalized_path = normalize_path(path);
        let node = self
            .nodes
            .iter()
            .find(|n| n.path.as_deref() == Some(&normalized_path))
            .cloned()
            .ok_or_else(|| MegaError::Custom(format!("Node not found: {}", path)))?;

        self.rename_node(&node, new_name).await
    }
}

fn first_error_code(errors: &serde_json::Value) -> Option<i64> {
    if let Some(code) = errors.as_i64() {
        return if code != 0 { Some(code) } else { None };
    }

    if let Some(arr) = errors.as_array() {
        for v in arr {
            if let Some(code) = v.as_i64()
                && code != 0
            {
                return Some(code);
            }
        }
        return None;
    }

    if let Some(obj) = errors.as_object() {
        for v in obj.values() {
            if let Some(code) = v.as_i64()
                && code != 0
            {
                return Some(code);
            }
        }
    }

    None
}
