//! Sharing helpers for Session.

use serde_json::json;

use crate::base64::base64url_encode;
use crate::crypto::MegaRsaKey;
use crate::crypto::aes::aes128_ecb_encrypt;
use crate::error::{MegaError, Result};
use crate::fs::NodeType;
use crate::session::Session;

impl Session {
    /// Get a user's public key (for sharing).
    pub async fn get_public_key(&mut self, email: &str) -> Result<MegaRsaKey> {
        let response = self
            .api
            .request(json!({
                "a": "uk",
                "u": email
            }))
            .await?;

        let pubk_b64 = response["pubk"]
            .as_str()
            .ok_or_else(|| MegaError::Custom("Public key not found for user".to_string()))?;

        MegaRsaKey::from_encoded_public_key(pubk_b64)
            .map_err(|e| MegaError::CryptoError(format!("Invalid public key: {}", e)))
    }

    /// Share a folder with another user.
    ///
    /// # Arguments
    /// * `node_handle` - Handle of the folder to share
    /// * `email` - Email of the user to share with
    /// * `level` - Access level (0=Read-only, 1=Read/Write, 2=Full Access)
    pub async fn share_folder(&mut self, node_handle: &str, email: &str, level: i32) -> Result<()> {
        self.ensure_share_keys_ready().await?;

        // 1. Find the node to get its key - clone it to release borrow
        let node_key = {
            let node = self
                .nodes
                .iter()
                .find(|n| n.handle == node_handle)
                .ok_or_else(|| MegaError::Custom("Node not found".to_string()))?;

            if node.node_type != NodeType::Folder {
                return Err(MegaError::Custom("Can only share folders".to_string()));
            }

            if node.key.is_empty() {
                return Err(MegaError::Custom("Node key not available".to_string()));
            }
            node.key.clone()
        };

        // 2. Fetch recipient's public key
        let pub_key = self.get_public_key(email).await?;

        // 3. Encrypt the node key with recipient's public key
        let encrypted_key = pub_key.encrypt(&node_key);
        let key_b64 = base64url_encode(&encrypted_key);

        // Build CR (share mapping) so descendants are decryptable by the recipient.
        // Keep SDK ordering: children first, root last.
        let mut share_nodes = self.collect_share_nodes_bottom_up(node_handle);
        if share_nodes.is_empty() {
            share_nodes.push((node_handle.to_string(), node_key.clone()));
        }

        let share_key: [u8; 16] = if node_key.len() >= 16 {
            let mut sk = [0u8; 16];
            sk.copy_from_slice(&node_key[..16]);
            sk
        } else {
            return Err(MegaError::Custom("Invalid folder key length".to_string()));
        };

        if self.key_manager.is_ready() {
            self.key_manager
                .add_share_key_with_flags(node_handle, &share_key, true, false);
            self.key_manager.add_pending_out_email(node_handle, email);
            self.persist_keys_attribute().await?;
        }

        let cr = self.build_cr_for_nodes(node_handle, &share_key, &share_nodes);

        // 4. Send share command ('s2')
        // 'ok': Output Key (encrypted share key)
        let mut request = json!({
            "a": "s2",
            "n": node_handle,
            "s": [{
                "u": email,
                "l": level
            }],
            "ok": key_b64
        });

        if let Some(cr_value) = cr {
            request["cr"] = cr_value;
        }

        let mut response = self.api.request(request.clone()).await;
        if matches!(response, Err(MegaError::ApiError { code: -11, .. })) {
            self.ensure_share_keys_ready().await?;
            let _ = self.refresh().await;
            response = self.api.request(request).await;
        }
        let response = response?;

        // Check for error code
        if let Some(err_code) = response.as_i64() {
            if err_code < 0 {
                // Fix: Fully qualified path to ApiErrorCode
                let error_code = crate::api::ApiErrorCode::from(err_code);
                return Err(MegaError::ApiError {
                    code: err_code as i32,
                    message: error_code.description().to_string(),
                });
            }
        }
        if let Some(tag) = self.track_seqtag_from_response(&response) {
            if !self.defer_seqtag_wait {
                self.wait_for_seqtag(&tag).await?;
            }
        }

        // Remember the share key locally so children uploaded later can reuse it.
        self.share_keys
            .entry(node_handle.to_string())
            .or_insert(share_key);
        if self.key_manager.is_ready() {
            let _ = self.key_manager.set_share_key_trusted(node_handle, true);
            let _ = self.key_manager.set_share_key_in_use(node_handle, true);
            let _ = self.persist_keys_attribute().await;
        }

        Ok(())
    }

    /// Find the nearest share key for a node handle by walking ancestors.
    pub(crate) fn find_share_for_handle(&self, start_handle: &str) -> Option<(String, [u8; 16])> {
        let mut current = Some(start_handle.to_string());

        while let Some(handle) = current {
            if let Some(key) = self.share_keys.get(&handle) {
                return Some((handle, *key));
            }
            if let Some(k) = self.share_key_from_manager(&handle) {
                return Some((handle, k));
            }

            current = self
                .nodes
                .iter()
                .find(|n| n.handle == handle)
                .and_then(|n| n.parent_handle.clone());
        }

        None
    }

    /// Collect a subtree's nodes in SDK-compatible CR order:
    /// descendants first, root last (post-order traversal).
    pub(crate) fn collect_share_nodes_bottom_up(
        &self,
        root_handle: &str,
    ) -> Vec<(String, Vec<u8>)> {
        fn walk(session: &Session, handle: &str, out: &mut Vec<(String, Vec<u8>)>) {
            let children: Vec<String> = session
                .nodes
                .iter()
                .filter_map(|n| {
                    (n.parent_handle.as_deref() == Some(handle)).then(|| n.handle.clone())
                })
                .collect();

            for child in children {
                walk(session, &child, out);
            }

            if let Some(node) = session.nodes.iter().find(|n| n.handle == handle) {
                out.push((node.handle.clone(), node.key.clone()));
            }
        }

        let mut out = Vec::new();
        walk(self, root_handle, &mut out);
        out
    }

    /// Build a CR payload mapping a share to node keys for new nodes.
    pub(crate) fn build_cr_for_nodes(
        &self,
        share_handle: &str,
        share_key: &[u8; 16],
        targets: &[(String, Vec<u8>)],
    ) -> Option<serde_json::Value> {
        use serde_json::json;

        let cr_nodes = vec![share_handle.to_string()];
        let mut cr_items: Vec<String> = Vec::new();
        let mut cr_triplets: Vec<serde_json::Value> = Vec::new();

        for (idx, (node_handle, key_bytes)) in targets.iter().enumerate() {
            if key_bytes.is_empty() || key_bytes.len() % 16 != 0 {
                continue;
            }

            cr_items.push(node_handle.clone());

            let enc = aes128_ecb_encrypt(key_bytes, share_key);
            let enc_b64 = base64url_encode(&enc);

            cr_triplets.push(json!(0));
            cr_triplets.push(json!(idx as i64));
            cr_triplets.push(json!(enc_b64));
        }

        if cr_items.is_empty() {
            return None;
        }

        Some(json!([cr_nodes, cr_items, cr_triplets]))
    }
}
