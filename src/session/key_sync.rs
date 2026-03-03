//! Helpers for share-key lifecycle, pending promotions, and ^!keys synchronization.
//!
//! The MEGA SDK keeps most share-key logic inside the session layer and uses the
//! KeyManager (^!keys) as the single source of truth. This module mirrors that
//! approach while keeping network I/O inside `Session`.

use std::collections::HashSet;

use serde_json::{Value, json};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::api::ApiErrorCode;
use crate::base64::{base64url_decode, base64url_encode};
use crate::crypto::aes::{aes128_ecb_decrypt, aes128_ecb_encrypt};
use crate::crypto::key_manager::{KeyManager, PendingUid};
use crate::crypto::{AuthRing, AuthState};
use crate::error::{MegaError, Result};
use crate::session::Session;
use crate::session::core::Contact;

/// Contact public keys and verification status (subset of SDK contact info).
#[derive(Debug, Clone)]
pub struct ContactPublicKeys {
    pub ed25519: Vec<u8>,
    pub cu25519: Vec<u8>,
    pub verified: bool,
    pub user_handle: Option<String>,
}

pub(crate) type ActionPacketContactUpdate = (
    String,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    bool,
    Option<Contact>,
);

#[derive(Debug, Clone)]
pub(crate) struct ActionPacketKeyWork {
    pub(crate) share_changed: bool,
    pub(crate) share_packets: Vec<Value>,
    pub(crate) changed_handles: Vec<String>,
    pub(crate) stale_key_attrs: Vec<String>,
    pub(crate) contact_updates: Vec<ActionPacketContactUpdate>,
}

impl ActionPacketKeyWork {
    pub(crate) fn is_empty(&self) -> bool {
        !self.share_changed
            && self.share_packets.is_empty()
            && self.changed_handles.is_empty()
            && self.stale_key_attrs.is_empty()
            && self.contact_updates.is_empty()
    }

    pub(crate) fn merge_from(&mut self, mut other: ActionPacketKeyWork) {
        self.share_changed |= other.share_changed;
        self.share_packets.append(&mut other.share_packets);
        self.changed_handles.append(&mut other.changed_handles);
        self.stale_key_attrs.append(&mut other.stale_key_attrs);
        self.contact_updates.append(&mut other.contact_updates);

        self.changed_handles.sort_unstable();
        self.changed_handles.dedup();
        self.stale_key_attrs.sort_unstable();
        self.stale_key_attrs.dedup();
    }
}

fn derive_pairwise_key(priv_cu: &[u8], peer_pub: &[u8]) -> Result<[u8; 16]> {
    if priv_cu.len() != 32 || peer_pub.len() != 32 {
        return Err(MegaError::Custom(
            "Curve25519 key length must be 32 bytes".to_string(),
        ));
    }
    let mut priv_arr = [0u8; 32];
    priv_arr.copy_from_slice(priv_cu);
    let mut pub_arr = [0u8; 32];
    pub_arr.copy_from_slice(peer_pub);

    let secret = StaticSecret::from(priv_arr);
    let public = PublicKey::from(pub_arr);
    let shared = secret.diffie_hellman(&public);
    let mut out = [0u8; 16];
    out.copy_from_slice(&shared.as_bytes()[..16]);
    Ok(out)
}

impl Session {
    /// Fetch a contact's Curve25519/Ed25519 public keys and verification flag.
    ///
    /// This is a best-effort wrapper around the `uk` command. The MEGA API
    /// returns slightly different shapes; we normalize the fields we need.
    pub async fn fetch_contact_public_keys(&mut self, user: &str) -> Result<ContactPublicKeys> {
        // Accept either user handle (b64) or email.
        let resp = self
            .api_mut()
            .request(json!({"a": "uk", "u": user, "v": 2}))
            .await?;

        // Response may be an object or array[0]
        let obj = if let Some(arr) = resp.as_array() {
            arr.first()
                .and_then(|v| v.as_object())
                .cloned()
                .ok_or(MegaError::InvalidResponse)?
        } else {
            resp.as_object()
                .cloned()
                .ok_or(MegaError::InvalidResponse)?
        };

        // MEGA names vary: prefer prCu255/prEd255 (SDK), fall back to cu25519/ed25519 or "k" map.
        let cu_b64 = obj
            .get("prCu255")
            .or_else(|| obj.get("cu25519"))
            .or_else(|| obj.get("k"))
            .and_then(|v| v.as_str());
        let ed_b64 = obj
            .get("prEd255")
            .or_else(|| obj.get("ed25519"))
            .and_then(|v| v.as_str());

        let cu25519 = cu_b64
            .map(base64url_decode)
            .transpose()?
            .unwrap_or_default();
        let ed25519 = ed_b64
            .map(base64url_decode)
            .transpose()?
            .unwrap_or_default();

        if cu25519.is_empty() {
            return Err(MegaError::Custom(
                "Contact Cu25519 key not available".to_string(),
            ));
        }

        // Simple verification indicator: SDK stores contact-verified flag in `c`
        let verified = obj.get("c").and_then(|v| v.as_i64()).unwrap_or(0) > 0;
        let user_handle = obj
            .get("u")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            // if not present and input looked like a handle, reuse it
            .or_else(|| {
                if user.len() == 11 {
                    Some(user.to_string())
                } else {
                    None
                }
            });

        Ok(ContactPublicKeys {
            ed25519,
            cu25519,
            verified,
            user_handle,
        })
    }

    /// Send promotion command for a pending share key (SDK: CommandPendingKeys).
    pub async fn send_pending_key_promotion(
        &mut self,
        node_handle: &str,
        recipient_handle_b64: &str,
        encrypted_share_key_b64: &str,
    ) -> Result<()> {
        let resp = self
            .api_mut()
            .request(json!({
                "a": "pk",
                "u": recipient_handle_b64,
                "h": node_handle,
                "k": encrypted_share_key_b64
            }))
            .await?;

        if let Some(code) = resp.as_i64()
            && code < 0
        {
            let err = ApiErrorCode::from(code);
            return Err(MegaError::ApiError {
                code: code as i32,
                message: err.description().to_string(),
            });
        }
        Ok(())
    }

    /// Fetch pending keys from the server (read variant of 'pk'). Returns lastcompleted token.
    pub async fn fetch_pending_keys(
        &mut self,
        last_completed: Option<&str>,
    ) -> Result<(String, Vec<(String, String, Vec<u8>)>)> {
        let mut req = json!({"a": "pk"});
        if let Some(tok) = last_completed {
            req["d"] = json!(tok);
        }
        let resp = self.api_mut().request_with_allowed(req, &[-9]).await?;
        if resp.as_i64() == Some(-9) {
            return Ok((String::new(), Vec::new()));
        }

        // Response is object: { "d": "<token>", "<userHandle>": { "<shareHandle>": "<b64key>", ... }, ... }
        let mut token = String::new();
        let mut items: Vec<(String, String, Vec<u8>)> = Vec::new();

        if let Some(obj) = resp.as_object() {
            for (k, v) in obj {
                if k == "d" {
                    if let Some(tok) = v.as_str() {
                        token = tok.to_string();
                    }
                    continue;
                }
                // k is user handle b64
                if let Some(inner) = v.as_object() {
                    for (share_b64, key_val) in inner {
                        if let Some(key_str) = key_val.as_str()
                            && let Ok(key_bin) = base64url_decode(key_str)
                        {
                            items.push((k.clone(), share_b64.clone(), key_bin));
                        }
                    }
                }
            }
        }

        Ok((token, items))
    }

    /// Rebuild the in-memory share key cache from the KeyManager share table.
    fn rebuild_share_key_cache(&mut self) {
        self.share_keys.clear();
        for sk in &self.key_manager.share_keys {
            let mut k = [0u8; 16];
            k.copy_from_slice(&sk.key);
            let handle_b64 = base64url_encode(&sk.handle);
            self.share_keys.entry(handle_b64).or_insert(k);
        }
    }

    async fn promote_pending_shares_internal(&mut self, persist_immediately: bool) -> Result<bool> {
        if !self.key_manager.is_ready() {
            return Ok(false);
        }
        let mut changed = false;
        // Process remote pending keys feed first (pull then update KM).
        // avoid simultaneous mutable/immutable borrow by taking token first
        let token_in = self.pending_keys_token.clone();
        let (token, remote_items) = self
            .fetch_pending_keys(token_in.as_deref())
            .await
            .unwrap_or_default();
        if !token.is_empty() {
            self.pending_keys_token = Some(token);
        }
        if !remote_items.is_empty() {
            for (user_b64, share_b64, enc_key) in remote_items {
                let mut uh = [0u8; 8];
                if let Ok(u) = base64url_decode(&user_b64)
                    && u.len() == 8
                {
                    uh.copy_from_slice(&u);
                    self.key_manager.add_pending_in(&share_b64, &uh, enc_key);
                }
            }
            changed = true;
        }

        // Pending outshares: encrypt share key to recipient and send promotion command.
        let pending_out = self.key_manager.pending_out.clone();
        for entry in pending_out {
            let handle_b64 = base64url_encode(&entry.node_handle);
            let Some(share_key) = self
                .key_manager
                .get_share_key_from_str(&handle_b64)
                .or_else(|| self.share_keys.get(&handle_b64).copied())
            else {
                continue;
            };

            // We need the recipient user handle (8 bytes -> b64). Prefer stored user handle; if email only, try to obtain handle from contact info.
            let recipient_handle_b64 = match &entry.uid {
                PendingUid::UserHandle(h) => base64url_encode(h),
                PendingUid::Email(email) => {
                    let contact = match self.fetch_contact_public_keys(email).await {
                        Ok(c) => c,
                        Err(_) => continue,
                    };
                    if let Some(h) = contact.user_handle {
                        h
                    } else {
                        continue; // cannot promote without handle
                    }
                }
            };

            let contact = match self.fetch_contact_public_keys(&recipient_handle_b64).await {
                Ok(c) => c,
                Err(_) => continue, // keep pending; will retry later
            };

            // Update authrings with latest pubkeys
            if !contact.cu25519.is_empty() {
                self.authring_cu
                    .update(&recipient_handle_b64, &contact.cu25519, contact.verified);
            }
            if !contact.ed25519.is_empty() {
                self.authring_ed
                    .update(&recipient_handle_b64, &contact.ed25519, contact.verified);
            }

            if self.manual_verification {
                // Require authring Cu AND Ed entries to be Verified
                let cu_ok = self
                    .authring_cu
                    .get_state(&recipient_handle_b64)
                    .filter(|s| *s == AuthState::Verified)
                    .is_some();
                let ed_ok = self
                    .authring_ed
                    .get_state(&recipient_handle_b64)
                    .filter(|s| *s == AuthState::Verified)
                    .is_some();
                if !(cu_ok && ed_ok) {
                    // mark warning flag 'cv'
                    self.warnings.set_cv(true);
                    continue;
                }
            }

            if self.manual_verification && !contact.verified {
                // Manual verification required; leave pending.
                continue;
            }

            let pairwise = derive_pairwise_key(&self.key_manager.priv_cu25519, &contact.cu25519)?;
            let enc_share = aes128_ecb_encrypt(&share_key, &pairwise);
            let enc_b64 = base64url_encode(&enc_share);

            if self
                .send_pending_key_promotion(&handle_b64, &recipient_handle_b64, &enc_b64)
                .await
                .is_ok()
            {
                let _ = self.key_manager.set_share_key_trusted(&handle_b64, true);
                let _ = self.key_manager.set_share_key_in_use(&handle_b64, true);
                let _ = self.key_manager.remove_pending_out(&handle_b64, &entry.uid);
                changed = true;
            }
        }

        // Pending inshares: decrypt using pairwise key and store share key.
        let pending_in = self.key_manager.pending_in.clone();
        for entry in pending_in {
            let contact_handle_b64 = base64url_encode(&entry.user_handle);
            let contact = match self.fetch_contact_public_keys(&contact_handle_b64).await {
                Ok(c) => c,
                Err(_) => continue,
            };

            let pairwise = derive_pairwise_key(&self.key_manager.priv_cu25519, &contact.cu25519)?;
            if entry.share_key.len() % 16 != 0 {
                continue;
            }
            let dec = aes128_ecb_decrypt(&entry.share_key, &pairwise);
            if dec.len() < 16 {
                continue;
            }
            let mut share_key = [0u8; 16];
            share_key.copy_from_slice(&dec[..16]);

            self.key_manager.add_share_key_with_flags(
                &entry.node_handle_b64,
                &share_key,
                true,
                true,
            );
            let _ = self
                .key_manager
                .remove_pending_in(&entry.node_handle_b64, &entry.user_handle);
            self.share_keys
                .insert(entry.node_handle_b64.clone(), share_key);
            changed = true;
        }

        if changed {
            self.drain_pending_nodes();
            // clear cv warning if everyone verified
            self.maybe_clear_cv_warning();
            if persist_immediately {
                self.persist_keys_with_retry().await?;
            }
        }

        Ok(changed)
    }

    /// Promote pending out/in shares by performing pairwise ECDH and encrypting/decrypting share keys.
    ///
    /// Returns true if any state changed (pending entries cleared or flags updated).
    pub async fn promote_pending_shares(&mut self) -> Result<bool> {
        self.promote_pending_shares_internal(true).await
    }

    /// Clear IN_USE bits for share keys whose folders are no longer present in the node graph.
    pub fn clear_inuse_flags_for_missing_shares(&mut self) -> bool {
        if !self.key_manager.is_ready() {
            return false;
        }
        let handles: HashSet<String> = self.nodes.iter().map(|n| n.handle.clone()).collect();
        let changed = self.key_manager.clear_in_use_not_in(&handles);
        if changed {
            self.rebuild_share_key_cache();
        }
        changed
    }

    /// Remove share keys whose roots are missing from the current node graph.
    pub fn drop_share_keys_for_removed_roots(&mut self) -> bool {
        let node_handles: HashSet<String> = self.nodes.iter().map(|n| n.handle.clone()).collect();
        let removals: Vec<String> = self
            .key_manager
            .share_keys
            .iter()
            .filter_map(|sk| {
                let h = base64url_encode(&sk.handle);
                if !node_handles.contains(&h) {
                    Some(h)
                } else {
                    None
                }
            })
            .collect();

        let mut changed = false;
        for h in removals {
            if self.key_manager.remove_share_key(&h) {
                self.share_keys.remove(&h);
                changed = true;
            }
        }
        changed
    }

    /// Clear trusted flags for share keys whose roots are no longer present.
    pub fn clear_trusted_for_missing_shares(&mut self) -> bool {
        if !self.key_manager.is_ready() {
            return false;
        }
        let handles: HashSet<String> = self.nodes.iter().map(|n| n.handle.clone()).collect();
        self.key_manager.clear_trusted_not_in(&handles)
    }

    /// Handle contact key updates (action packet). Updates authrings, warning flags, clears trusted flags on fingerprint change.
    /// Returns true if local key state changed.
    async fn handle_contact_key_update_internal(
        &mut self,
        contact_handle_b64: &str,
        ed_pub: Option<&[u8]>,
        cu_pub: Option<&[u8]>,
        verified: bool,
        persist_immediately: bool,
    ) -> Result<bool> {
        let mut changed = false;
        let mut fingerprint_changed = false;

        if let Some(cu) = cu_pub {
            let prev = self.authring_cu.get_state(contact_handle_b64);
            let st = self.authring_cu.update(contact_handle_b64, cu, verified);
            fingerprint_changed |= prev.is_some() && st == AuthState::Changed;
        }
        if let Some(ed) = ed_pub {
            let prev = self.authring_ed.get_state(contact_handle_b64);
            let st = self.authring_ed.update(contact_handle_b64, ed, verified);
            fingerprint_changed |= prev.is_some() && st == AuthState::Changed;
        }

        if self.manual_verification {
            let cu_verified = self
                .authring_cu
                .get_state(contact_handle_b64)
                .filter(|s| *s == AuthState::Verified)
                .is_some();
            let ed_verified = self
                .authring_ed
                .get_state(contact_handle_b64)
                .filter(|s| *s == AuthState::Verified)
                .is_some();
            if !(cu_verified && ed_verified) {
                if let Some(entry) = self.warnings.0.iter_mut().find(|(k, _)| k == "cv") {
                    entry.1 = b"1".to_vec();
                } else {
                    self.warnings.0.push(("cv".to_string(), b"1".to_vec()));
                }
            }
        }

        // Clear trusted flags globally if a fingerprint changed (conservative).
        if fingerprint_changed && self.key_manager.clear_trusted_all() {
            self.rebuild_share_key_cache();
            changed = true;
        }

        if changed && persist_immediately {
            self.persist_keys_with_retry().await?;
        }
        Ok(changed)
    }

    /// Handle multiple contact updates from an action packet batch.
    pub async fn handle_contact_updates(
        &mut self,
        updates: &[ActionPacketContactUpdate],
    ) -> Result<bool> {
        let mut changed = false;
        for (h, ed, cu, verified, _contact) in updates {
            let ed_ref = ed.as_deref();
            let cu_ref = cu.as_deref();
            if self
                .handle_contact_key_update_internal(h, ed_ref, cu_ref, *verified, false)
                .await?
            {
                changed = true;
            }
        }
        Ok(changed)
    }

    pub(crate) async fn execute_actionpacket_key_work(
        &mut self,
        work: ActionPacketKeyWork,
    ) -> Result<bool> {
        if work.is_empty() {
            return Ok(false);
        }

        let mut changed = false;

        if !work.share_packets.is_empty()
            && self.apply_deferred_share_packets(&work.share_packets)?
        {
            changed = true;
        }

        if !work.contact_updates.is_empty()
            && self.handle_contact_updates(&work.contact_updates).await?
        {
            changed = true;
        }

        if !work.contact_updates.is_empty() {
            if self.cleanup_pending_outshares_for_deleted_contacts() {
                changed = true;
            }
            self.maybe_clear_cv_warning();
        }

        if !work.stale_key_attrs.is_empty() {
            let stale: HashSet<String> = work.stale_key_attrs.iter().cloned().collect();
            if self.refetch_key_user_attrs(&stale).await? {
                changed = true;
            }
        }

        let needs_key_maintenance = work.share_changed
            || !work.changed_handles.is_empty()
            || !work.stale_key_attrs.is_empty();

        if needs_key_maintenance
            && self
                .handle_actionpacket_keys(&work.changed_handles, work.share_changed)
                .await?
        {
            changed = true;
        }

        Ok(changed)
    }

    /// SDK-style pending keys handling for AP `a:"pk"`: trigger pending keys retrieval asynchronously.
    pub(crate) async fn handle_actionpacket_pending_keys_fetch(&mut self) -> Result<bool> {
        if self.key_manager.generation == 0 {
            return Ok(false);
        }
        self.promote_pending_shares_internal(false).await
    }

    /// SDK-style startup/post-upgrade reconciliation pass.
    ///
    /// This mirrors the intent of fetching latest key material and then running one
    /// pending-key promotion pass without requiring a new `a:"pk"` action packet.
    pub(crate) async fn run_startup_key_reconciliation(&mut self) -> Result<bool> {
        if self.key_manager.generation == 0 {
            return Ok(false);
        }
        let mut changed = false;
        if self.sync_keys_attribute_internal(false, false).await? {
            changed = true;
        }
        if self.handle_actionpacket_pending_keys_fetch().await? {
            changed = true;
        }
        Ok(changed)
    }

    /// Convenience wrapper for action-packet processing to clear cv flag when all contacts verified.
    pub fn maybe_clear_cv_warning(&mut self) {
        if self.warnings.cv_enabled() {
            let any_unverified = self
                .authring_cu
                .entries
                .iter()
                .any(|(_, e)| e.state != AuthState::Verified)
                || self
                    .authring_ed
                    .entries
                    .iter()
                    .any(|(_, e)| e.state != AuthState::Verified);
            if !any_unverified {
                self.warnings.set_cv(false);
            }
        }
    }

    /// List handles that currently have share keys (roots).
    pub fn share_roots(&self) -> Vec<String> {
        self.key_manager
            .share_keys
            .iter()
            .map(|sk| base64url_encode(&sk.handle))
            .collect()
    }

    // /// Return descendant node handles for a given share root by walking the cached node tree.
    // pub fn share_descendants(&self, share_handle: &str) -> Vec<String> {
    //     let mut out = Vec::new();
    //     let mut stack = vec![share_handle.to_string()];
    //     while let Some(parent) = stack.pop() {
    //         for n in &self.nodes {
    //             if let Some(p) = &n.parent_handle {
    //                 if p == &parent {
    //                     out.push(n.handle.clone());
    //                     stack.push(n.handle.clone());
    //                 }
    //             }
    //         }
    //     }
    //     out
    // }

    /// Handles of share keys whose nodes are no longer present (potential removals).
    pub fn share_removals(&self) -> Vec<String> {
        let node_handles: HashSet<String> = self.nodes.iter().map(|n| n.handle.clone()).collect();
        self.key_manager
            .share_keys
            .iter()
            .filter_map(|sk| {
                let h = base64url_encode(&sk.handle);
                if !node_handles.contains(&h) {
                    Some(h)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Handle action-packet events that may affect keys. Best-effort:
    /// - Sync remote ^!keys if any key-bearing handles changed
    /// - Promote pending shares
    /// - Clear in-use flags for removed shares
    ///
    /// Returns true if local key state changed.
    pub async fn handle_actionpacket_keys(
        &mut self,
        changed_handles: &[String],
        share_changed: bool,
    ) -> Result<bool> {
        if !self.key_manager.is_ready() {
            return Ok(false);
        }

        let mut changed = false;
        if share_changed {
            changed = true;
        }

        // If any changed handle matches share roots or removals, clear in-use flags.
        let changed_set: HashSet<String> = changed_handles.iter().cloned().collect();
        let mut needs_clear =
            !changed_set.is_empty() && self.share_roots().iter().any(|h| changed_set.contains(h));

        if !needs_clear {
            // also check for removed shares
            needs_clear = self
                .share_removals()
                .iter()
                .any(|h| changed_set.contains(h));
        }

        if needs_clear && self.clear_inuse_flags_for_missing_shares() {
            changed = true;
        }

        // Drop share keys whose roots disappeared.
        if self.drop_share_keys_for_removed_roots() {
            changed = true;
        }

        // Clear trusted flags for missing shares.
        if self.clear_trusted_for_missing_shares() {
            changed = true;
        }

        // Try to sync remote ^!keys and then promote pending shares.
        if self
            .sync_keys_attribute_internal(true, false)
            .await
            .unwrap_or(false)
            || self.promote_pending_shares_internal(false).await?
        {
            changed = true;
        }

        Ok(changed)
    }

    async fn sync_keys_attribute_internal(
        &mut self,
        include_pending_promotions: bool,
        persist_immediately: bool,
    ) -> Result<bool> {
        let Some(remote_blob) = self.get_user_attribute_raw("^!keys").await? else {
            return Ok(false);
        };

        let mut remote = KeyManager::new();
        remote.decode_container(&remote_blob, &self.master_key)?;
        self.last_keys_blob_b64 = Some(base64url_encode(&remote_blob));

        // Reject downgrade explicitly
        if remote.generation < self.key_manager.generation {
            self.keys_downgrade_detected = true;
            return Err(MegaError::DowngradeDetected);
        }

        let mut merged = remote.clone();
        merged.merge_from(&self.key_manager);
        self.key_manager = merged;
        self.rebuild_share_key_cache();
        self.drain_pending_nodes();

        // propagate cached blobs
        self.authring_ed = AuthRing::deserialize_ltlv(&self.key_manager.auth_ed25519);
        self.authring_cu = AuthRing::deserialize_ltlv(&self.key_manager.auth_cu25519);
        self.backups = self.key_manager.backups.clone();
        self.warnings = self.key_manager.warnings.clone();
        self.manual_verification = self.key_manager.manual_verification;

        let mut changed = false;
        if include_pending_promotions {
            changed |= self
                .promote_pending_shares_internal(persist_immediately)
                .await?;
        }
        changed |= self.clear_inuse_flags_for_missing_shares();
        if changed && persist_immediately {
            self.persist_keys_with_retry().await?;
        }
        Ok(changed)
    }

    pub(crate) async fn refetch_key_user_attrs(&mut self, stale: &HashSet<String>) -> Result<bool> {
        let priority = [
            "^!keys",
            "*keyring",
            "*~usk",
            "*~jscd",
            "+puCu255",
            "+puEd255",
            "+sigCu255",
            "+sigPubk",
        ];

        let mut changed = false;
        for attr in priority {
            if !stale.contains(attr) {
                continue;
            }
            let existing = self.user_attr_cache.get(attr).cloned();
            let fetched = self.get_user_attribute_raw(attr).await?;
            if fetched.is_some() {
                changed = true;
            } else if existing.is_some() {
                self.user_attr_cache.remove(attr);
                self.user_attr_versions.remove(attr);
                changed = true;
            }
        }
        Ok(changed)
    }

    /// Persist ^!keys with one merge-retry on version/busy errors (-8/-3/-11).
    pub async fn persist_keys_with_retry(&mut self) -> Result<()> {
        if !self.key_manager.is_ready() {
            return Err(MegaError::Custom(
                "KeyManager not initialized; cannot persist ^!keys".to_string(),
            ));
        }
        if self.keys_persist_inflight {
            return Ok(());
        }
        self.keys_persist_inflight = true;

        let result = async {
            // Sync cached auth/backups/warnings before encoding
            self.key_manager.auth_ed25519 = self.authring_ed.serialize_ltlv();
            self.key_manager.auth_cu25519 = self.authring_cu.serialize_ltlv();
            self.key_manager.backups = self.backups.clone();
            self.key_manager.warnings = self.warnings.clone();
            self.key_manager.manual_verification = self.manual_verification;
            // ensure priv_rsa is in the container if session has one and km lacks it
            if self.key_manager.priv_rsa.is_empty() && self.has_valid_rsa_key() {
                let encoded = self.rsa_key().encode_private_key(&self.master_key);
                self.key_manager.priv_rsa = encoded.into_bytes();
            }

            let desired = self.key_manager.clone();

            let mut attempts = 0;
            loop {
                let blob = self.key_manager.encode_container(&self.master_key)?;
                let blob_b64 = base64url_encode(&blob);
                if self.last_keys_blob_b64.as_deref() == Some(&blob_b64) {
                    return Ok(());
                }
                let version = self.user_attr_versions.get("^!keys").cloned();

                match self
                    .set_private_attribute("^!keys", &blob_b64, version)
                    .await
                {
                    Ok(_) => {
                        self.key_manager.generation = self.key_manager.generation.saturating_add(1);
                        self.rebuild_share_key_cache();
                        self.last_keys_blob_b64 = Some(blob_b64);
                        return Ok(());
                    }
                    Err(MegaError::ApiError { code, .. })
                        if attempts < 3 && (code == -8 || code == -3 || code == -11) =>
                    {
                        attempts += 1;
                        // fetch remote and merge
                        if let Some(remote_blob) = self.get_user_attribute_raw("^!keys").await? {
                            let mut remote = KeyManager::new();
                            if remote
                                .decode_container(&remote_blob, &self.master_key)
                                .is_ok()
                            {
                                remote.merge_from(&desired);
                                self.key_manager = remote;
                                self.rebuild_share_key_cache();
                                continue;
                            }
                        }
                        continue;
                    }
                    Err(MegaError::DowngradeDetected) => {
                        self.keys_downgrade_detected = true;
                        return Err(MegaError::DowngradeDetected);
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        .await;

        self.keys_persist_inflight = false;
        if result.is_ok() {
            self.keys_persist_dirty = false;
        }
        result
    }
}
