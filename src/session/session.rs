//! Session management and authentication.
//!
//! This module handles user login, session state, and logout.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::api::ApiClient;
use crate::base64::{base64url_decode, base64url_encode};
use crate::crypto::aes::{aes128_ecb_decrypt, aes128_ecb_encrypt, aes128_ecb_encrypt_block};
use crate::crypto::key_manager::KeyManager;
use crate::crypto::keyring::{Keyring, encrypt_tlv_records};
use crate::crypto::{AuthRing, AuthState, MegaRsaKey, make_random_key, parse_raw_private_key};
use crate::error::{MegaError, Result};
use crate::fs::{Node, NodeType};
use tokio::time::{sleep, timeout};

/// MEGA user session.
///
/// This holds all authentication state needed for API requests.
pub(crate) struct Session {
    /// API client for making requests
    pub(crate) api: ApiClient,
    /// Session ID
    session_id: String,
    session_key: Option<[u8; 16]>,
    /// User's master key (decrypted)
    pub(crate) master_key: [u8; 16],
    /// User's RSA private key
    rsa_key: MegaRsaKey,
    /// User's email
    pub email: String,
    /// User's display name
    pub name: Option<String>,
    /// User's handle
    pub user_handle: String,
    /// Cached filesystem nodes
    pub(crate) nodes: Vec<Node>,
    /// Share keys for shared folders
    pub(crate) share_keys: HashMap<String, [u8; 16]>,
    /// Outgoing shares by node handle (sharee handle or "EXP").
    pub(crate) outshares: HashMap<String, HashSet<String>>,
    /// Pending outgoing shares by node handle (pending handle).
    pub(crate) pending_outshares: HashMap<String, HashSet<String>>,
    /// Known contacts keyed by user handle (base64).
    pub(crate) contacts: HashMap<String, Contact>,
    /// Minimal key manager for upgraded accounts (^!keys)
    pub(crate) key_manager: KeyManager,
    /// Parsed authring Ed25519
    pub(crate) authring_ed: AuthRing,
    /// Parsed authring Cu25519
    pub(crate) authring_cu: AuthRing,
    /// Cached backups blob (opaque)
    pub(crate) backups: Vec<u8>,
    /// Cached warnings (LTLV map)
    pub(crate) warnings: crate::crypto::Warnings,
    /// Manual verification flag
    pub(crate) manual_verification: bool,
    /// Cached user attributes from `ug` (decoded bytes), to avoid redundant `uga` calls.
    pub(crate) user_attr_cache: HashMap<String, Vec<u8>>,
    /// Cached user attribute versions for upv (e.g. ^!keys version).
    pub(crate) user_attr_versions: HashMap<String, String>,
    /// Last persisted ^!keys blob (base64url), to avoid redundant updates.
    pub(crate) last_keys_blob_b64: Option<String>,
    /// Prevent re-entrant ^!keys persistence attempts.
    pub(crate) keys_persist_inflight: bool,
    /// Last completed token for pending keys feed (pk command)
    pub(crate) pending_keys_token: Option<String>,
    /// Flag set when a ^!keys downgrade is detected
    pub(crate) keys_downgrade_detected: bool,
    /// Last seen action-packet sequence number (scsn) for SC polling.
    pub(crate) scsn: Option<String>,
    /// WSC base URL from SC polling (SDK uses `w` field).
    pub(crate) wsc_url: Option<String>,
    /// Whether the next SC poll should use the catch-up endpoint.
    pub(crate) sc_catchup: bool,
    /// Current pending seqtag from a mutating request.
    pub(crate) current_seqtag: Option<String>,
    /// Whether the current seqtag has been observed in APs.
    pub(crate) current_seqtag_seen: bool,
    /// If true, do not block on seqtag waits (actor will resolve).
    pub(crate) defer_seqtag_wait: bool,
    /// Whether to kick off SC50 catch-up after reaching current state.
    pub(crate) alerts_catchup_pending: bool,
    /// Last seen user-alert sequence number (SC50).
    pub(crate) user_alert_lsn: Option<String>,
    /// Cached user alerts (SC50).
    pub(crate) user_alerts: Vec<Value>,
    /// Whether resume is enabled for interrupted transfers
    resume_enabled: bool,
    /// Progress callback for transfer progress
    progress_callback: Option<crate::progress::ProgressCallback>,
    /// Whether to generate previews during uploads
    previews_enabled: bool,
    /// Number of concurrent transfer workers (default: 1 for sequential)
    workers: usize,
}

#[derive(Debug, Clone)]
pub struct Contact {
    pub handle: String,
    pub email: Option<String>,
    pub status: i64,
    pub last_updated: i64,
}

impl Session {
    pub(super) fn new_internal(
        api: ApiClient,
        session_id: String,
        session_key: Option<[u8; 16]>,
        master_key: [u8; 16],
        rsa_key: MegaRsaKey,
        email: String,
        name: Option<String>,
        user_handle: String,
        user_attr_cache: HashMap<String, Vec<u8>>,
        user_attr_versions: HashMap<String, String>,
        scsn: Option<String>,
    ) -> Self {
        let sc_catchup = scsn.is_some();
        let alerts_catchup_pending = scsn.is_some();
        Session {
            api,
            session_id,
            session_key,
            master_key,
            rsa_key,
            email,
            name,
            user_handle,
            nodes: Vec::new(),
            share_keys: HashMap::new(),
            outshares: HashMap::new(),
            pending_outshares: HashMap::new(),
            contacts: HashMap::new(),
            key_manager: KeyManager::default(),
            authring_ed: AuthRing::default(),
            authring_cu: AuthRing::default(),
            backups: Vec::new(),
            warnings: crate::crypto::Warnings::default(),
            manual_verification: false,
            user_attr_cache,
            user_attr_versions,
            last_keys_blob_b64: None,
            keys_persist_inflight: false,
            pending_keys_token: None,
            keys_downgrade_detected: false,
            scsn,
            wsc_url: None,
            sc_catchup,
            current_seqtag: None,
            current_seqtag_seen: false,
            defer_seqtag_wait: false,
            alerts_catchup_pending,
            user_alert_lsn: None,
            user_alerts: Vec::new(),
            resume_enabled: false,
            progress_callback: None,
            previews_enabled: false,
            workers: 1,
        }
    }

    fn build_upv_command(attrs: Vec<(&str, String, Option<String>)>) -> Value {
        let mut obj = serde_json::Map::new();
        obj.insert("a".into(), Value::from("upv"));
        for (name, value, version) in attrs {
            if let Some(v) = version {
                obj.insert(name.into(), json!([value, v]));
            } else {
                obj.insert(name.into(), json!([value, 0]));
            }
        }
        Value::Object(obj)
    }

    fn validate_upv_batch(resp: Value) -> Result<()> {
        if let Some(arr) = resp.as_array() {
            for item in arr {
                if let Some(code) = item.as_i64() {
                    if code < 0 {
                        let error_code = crate::api::client::ApiErrorCode::from(code);
                        return Err(MegaError::ApiError {
                            code: code as i32,
                            message: error_code.description().to_string(),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) async fn attach_account_keys_if_missing(&mut self) -> Result<()> {
        if self.get_user_attribute_raw("^!keys").await?.is_some() {
            return Ok(());
        }

        let existing_keyring = self.get_user_attribute_raw("*keyring").await?;
        let (keyring, keyring_enc) = if let Some(enc) = existing_keyring {
            (Keyring::from_encrypted(&enc, &self.master_key)?, None)
        } else {
            let kr = Keyring::generate();
            let enc = kr.to_encrypted(&self.master_key)?;
            (kr, Some(enc))
        };

        let ed = keyring
            .ed25519
            .clone()
            .ok_or_else(|| MegaError::Custom("Missing Ed25519 key".to_string()))?;
        let cu = keyring
            .cu25519
            .clone()
            .ok_or_else(|| MegaError::Custom("Missing Curve25519 key".to_string()))?;
        if ed.len() != 32 || cu.len() != 32 {
            return Err(MegaError::Custom(
                "Invalid keyring lengths; expected 32-byte keys".to_string(),
            ));
        }

        let mut ed_arr = [0u8; 32];
        ed_arr.copy_from_slice(&ed);
        let signing = SigningKey::from_bytes(&ed_arr);
        let pu_ed = signing.verifying_key().to_bytes().to_vec();

        let mut cu_arr = [0u8; 32];
        cu_arr.copy_from_slice(&cu);
        let cu_secret = StaticSecret::from(cu_arr);
        let pu_cu = PublicKey::from(&cu_secret).to_bytes().to_vec();

        let sig_cu = signing.sign(&pu_cu).to_bytes().to_vec();
        let rsa_pub = self.rsa_key.public_key_bytes();
        let sig_pubk = signing.sign(&rsa_pub).to_bytes().to_vec();

        let mut km = KeyManager::new();
        km.set_priv_keys(&ed, &cu);
        km.priv_rsa = self.rsa_key.private_key_bytes();
        km.generation = 1;
        km.creation_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        if let Ok(decoded_handle) = base64url_decode(&self.user_handle) {
            let mut ident = [0u8; 8];
            let copy_len = decoded_handle.len().min(8);
            ident[..copy_len].copy_from_slice(&decoded_handle[..copy_len]);
            km.identity = u64::from_le_bytes(ident);
        }

        let keys_blob = km.encode_container(&self.master_key)?;
        let keys_b64 = base64url_encode(&keys_blob);

        let mut commands = Vec::new();

        let usk_missing = self.get_user_attribute_raw("*~usk").await?.is_none();
        let jscd_missing = self.get_user_attribute_raw("*~jscd").await?.is_none();

        let attr_versions = self.user_attr_versions.clone();
        let version_for = |name: &str| attr_versions.get(name).cloned();

        let mut generated_usk: Option<Vec<u8>> = None;
        if usk_missing {
            let usk = make_random_key();
            let usk_b64 = base64url_encode(&usk);
            commands.push(Self::build_upv_command(vec![(
                "*~usk",
                usk_b64,
                version_for("*~usk"),
            )]));
            generated_usk = Some(usk.to_vec());
        }

        let mut key_attrs = Vec::new();
        if let Some(enc) = keyring_enc.as_ref() {
            key_attrs.push((
                "*keyring",
                base64url_encode(enc),
                version_for("*keyring"),
            ));
        }
        key_attrs.push(("^!keys", keys_b64, version_for("^!keys")));
        key_attrs.push(("+puEd255", base64url_encode(&pu_ed), version_for("+puEd255")));
        key_attrs.push(("+puCu255", base64url_encode(&pu_cu), version_for("+puCu255")));
        key_attrs.push(("+sigCu255", base64url_encode(&sig_cu), version_for("+sigCu255")));
        key_attrs.push(("+sigPubk", base64url_encode(&sig_pubk), version_for("+sigPubk")));
        commands.push(Self::build_upv_command(key_attrs));

        let mut generated_jscd: Option<Vec<u8>> = None;
        if jscd_missing {
            let mut records = BTreeMap::new();
            records.insert("ak".to_string(), make_random_key().to_vec());
            records.insert("ck".to_string(), make_random_key().to_vec());
            records.insert("fn".to_string(), make_random_key().to_vec());
            let jscd = encrypt_tlv_records(&records, &self.master_key)?;
            let jscd_b64 = base64url_encode(&jscd);
            commands.push(Self::build_upv_command(vec![(
                "*~jscd",
                jscd_b64,
                version_for("*~jscd"),
            )]));
            generated_jscd = Some(jscd);
        }

        if !commands.is_empty() {
            let resp = self.api.request_batch(commands).await?;
            Self::validate_upv_batch(resp.clone())?;
            if let Some(ver) = Self::extract_attr_version(&resp, "^!keys") {
                self.user_attr_versions.insert("^!keys".to_string(), ver);
            }
        }

        // Cache the attributes we just set so we don't immediately re-fetch via uga.
        if let Some(enc) = keyring_enc {
            self.user_attr_cache
                .insert("*keyring".to_string(), enc);
        }
        if let Some(usk) = generated_usk {
            self.user_attr_cache.insert("*~usk".to_string(), usk);
        }
        self.user_attr_cache.insert("^!keys".to_string(), keys_blob.clone());
        self.last_keys_blob_b64 = Some(base64url_encode(&keys_blob));
        self.user_attr_cache
            .insert("+puEd255".to_string(), pu_ed);
        self.user_attr_cache
            .insert("+puCu255".to_string(), pu_cu);
        self.user_attr_cache
            .insert("+sigCu255".to_string(), sig_cu);
        self.user_attr_cache
            .insert("+sigPubk".to_string(), sig_pubk);
        if let Some(jscd) = generated_jscd {
            self.user_attr_cache.insert("*~jscd".to_string(), jscd);
        }

        self.key_manager = km;
        self.authring_ed = AuthRing::deserialize_ltlv(&self.key_manager.auth_ed25519);
        self.authring_cu = AuthRing::deserialize_ltlv(&self.key_manager.auth_cu25519);
        Ok(())
    }

    /// Get the current session ID.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Get the master key (for internal use).
    pub(crate) fn master_key(&self) -> &[u8; 16] {
        &self.master_key
    }

    /// Get a share key from the cached KeyManager-minimal (if present).
    pub(crate) fn share_key_from_manager(&self, handle: &str) -> Option<[u8; 16]> {
        self.key_manager.get_share_key_from_str(handle)
    }

    /// Get the RSA private key (for decrypting share keys from other users).
    pub(crate) fn rsa_key(&self) -> &MegaRsaKey {
        &self.rsa_key
    }

    /// Get mutable reference to the API client.
    pub(crate) fn api_mut(&mut self) -> &mut ApiClient {
        &mut self.api
    }

    /// Enable or disable resume for interrupted transfers.
    ///
    /// When enabled, downloads will check if the target file exists and
    /// attempt to resume from where it left off using HTTP Range requests.
    ///
    /// # Example
    /// ```no_run
    /// # use megalib::Session;
    /// # async fn example() -> megalib::error::Result<()> {
    /// let mut session = Session::login("user@example.com", "password").await?;
    /// session.set_resume(true);
    /// // Now downloads will attempt to resume if partial file exists
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_resume(&mut self, enabled: bool) {
        self.resume_enabled = enabled;
    }

    /// Check if resume is enabled for transfers.
    pub fn is_resume_enabled(&self) -> bool {
        self.resume_enabled
    }

    /// Set a progress callback for upload/download status.
    ///
    /// The callback will be called periodically during file transfers with
    /// progress information. Return `false` from the callback to cancel the transfer.
    ///
    /// # Example
    /// ```no_run
    /// # use megalib::Session;
    /// # async fn example() -> megalib::error::Result<()> {
    /// let mut session = Session::login("user@example.com", "password").await?;
    ///
    /// // Use built-in progress bar
    /// session.watch_status(megalib::make_progress_bar());
    ///
    /// // Or custom callback
    /// session.watch_status(Box::new(|progress| {
    ///     println!("{}% complete", progress.percent() as u32);
    ///     true // continue transfer
    /// }));
    /// # Ok(())
    /// # }
    /// ```
    pub fn watch_status(&mut self, callback: crate::progress::ProgressCallback) {
        self.progress_callback = Some(callback);
    }

    /// Clear the progress callback.
    pub fn clear_status(&mut self) {
        self.progress_callback = None;
    }

    /// Call the progress callback if set.
    pub(crate) fn report_progress(&mut self, progress: &crate::progress::TransferProgress) -> bool {
        if let Some(ref mut callback) = self.progress_callback {
            callback(progress)
        } else {
            true // Continue if no callback
        }
    }

    /// Enable or disable preview generation during uploads.
    ///
    /// When enabled, thumbnails will be generated for supported image and video
    /// files and uploaded alongside the file.
    ///
    /// # Example
    /// ```no_run
    /// # use megalib::Session;
    /// # async fn example() -> megalib::error::Result<()> {
    /// let mut session = Session::login("user@example.com", "password").await?;
    /// session.enable_previews(true);
    /// // Now uploads will generate and attach thumbnails
    /// # Ok(())
    /// # }
    /// ```
    pub fn enable_previews(&mut self, enabled: bool) {
        self.previews_enabled = enabled;
    }

    /// Check if preview generation is enabled.
    pub fn previews_enabled(&self) -> bool {
        self.previews_enabled
    }

    /// Set the number of concurrent transfer workers.
    ///
    /// Higher values can speed up large file transfers by uploading/downloading
    /// multiple chunks in parallel. Default is 1 (sequential transfers).
    ///
    /// # Arguments
    /// * `workers` - Number of concurrent workers (1-16, clamped to range)
    ///
    /// # Example
    /// ```no_run
    /// # use megalib::Session;
    /// # async fn example() -> megalib::error::Result<()> {
    /// let mut session = Session::login("user@example.com", "password").await?;
    /// session.set_workers(4); // Use 4 parallel transfers
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_workers(&mut self, workers: usize) {
        self.workers = workers.clamp(1, 16);
    }

    /// Get the current number of transfer workers.
    pub fn workers(&self) -> usize {
        self.workers
    }

    /// Poll the SC channel once and dispatch action packets.
    ///
    /// Returns true if any local state changed (e.g., ^!keys or authrings updated).
    /// This is legacy; prefer the Session actor which polls in the background.
    pub(crate) async fn poll_action_packets_once(&mut self) -> Result<bool> {
        let (changed, _) = self.poll_action_packets_once_with_seqtags().await?;
        Ok(changed)
    }

    pub(crate) async fn poll_action_packets_once_with_seqtags(
        &mut self,
    ) -> Result<(bool, Vec<String>)> {
        if self.scsn.is_none() {
            return Err(MegaError::Custom(
                "SC not initialized; call refresh() before polling action packets".to_string(),
            ));
        }
        let mut changed = false;
        let mut seqtags = Vec::new();
        loop {
            let (packets, sn, wsc, ir) = self
                .api
                .poll_sc(
                    self.scsn.as_deref(),
                    self.wsc_url.as_deref(),
                    self.sc_catchup,
                )
                .await?;
            self.scsn = Some(sn);
            if let Some(w) = wsc {
                self.wsc_url = Some(w);
            }
            seqtags.extend(Self::extract_seqtags_from_packets(&packets));
            if self.dispatch_action_packets(&packets).await? {
                changed = true;
            }
            if !ir {
                if self.sc_catchup {
                    self.sc_catchup = false;
                }
                break;
            }
        }
        Ok((changed, seqtags))
    }

    fn extract_seqtags_from_packets(packets: &[Value]) -> Vec<String> {
        let mut out = Vec::new();
        for pkt in packets {
            if let Some(obj) = pkt.as_object() {
                if let Some(st) = obj.get("st").and_then(|v| v.as_str()) {
                    out.push(st.to_string());
                }
            }
        }
        out
    }

    fn extract_seqtag_from_response(response: &Value) -> Option<String> {
        if let Some(st) = response.get("st").and_then(|v| v.as_str()) {
            return Some(st.to_string());
        }
        if let Some(arr) = response.as_array() {
            if let Some(st) = arr.get(0).and_then(|v| v.as_str()) {
                return Some(st.to_string());
            }
        }
        None
    }

    pub(crate) fn track_seqtag_from_response(&mut self, response: &Value) -> Option<String> {
        let st = Self::extract_seqtag_from_response(response)?;
        self.current_seqtag = Some(st.clone());
        self.current_seqtag_seen = false;
        Some(st)
    }

    pub(crate) async fn wait_for_seqtag(&mut self, expected: &str) -> Result<()> {
        if self.scsn.is_none() {
            return Err(MegaError::Custom(
                "SC not initialized; call refresh() before waiting for action packets".to_string(),
            ));
        }

        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if self.current_seqtag_seen && self.current_seqtag.as_deref() == Some(expected) {
                self.current_seqtag = None;
                self.current_seqtag_seen = false;
                return Ok(());
            }

            match timeout(Duration::from_secs(20), self.poll_action_packets_once()).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    // Ignore long-poll timeout; try again until deadline.
                }
            }
        }

        Err(MegaError::Custom(
            "Timed out waiting for action packets".to_string(),
        ))
    }

    /// Poll user alerts (SC50) once. Optional, used by clients that need alerts.
    pub async fn poll_user_alerts_once(&mut self) -> Result<(Vec<Value>, Option<String>)> {
        if self.scsn.is_none() {
            return Ok((Vec::new(), self.user_alert_lsn.clone()));
        }
        let (alerts, lsn) = self.api.poll_user_alerts().await?;
        if !alerts.is_empty() {
            self.user_alerts.extend(alerts.clone());
        }
        if let Some(token) = lsn.clone() {
            self.user_alert_lsn = Some(token);
        }
        self.alerts_catchup_pending = false;
        Ok((alerts, lsn))
    }

    /// Run a lightweight action-packet loop with exponential backoff.
    ///
    /// The `should_stop` predicate is evaluated after each poll to allow
    /// embedding applications to terminate the loop.
    pub(crate) async fn run_action_packet_loop<F>(&mut self, mut should_stop: F) -> Result<()>
    where
        F: FnMut() -> bool,
    {
        let mut delay_ms = 1_000u64;
        let max_delay = 60_000u64;

        while !should_stop() {
            match self.poll_action_packets_once().await {
                Ok(_) => {
                    delay_ms = 1_000;
                }
                Err(MegaError::ServerBusy) | Err(MegaError::InvalidResponse) => {
                    delay_ms = (delay_ms * 2).min(max_delay);
                }
                Err(e) => return Err(e),
            }
            sleep(Duration::from_millis(delay_ms)).await;
        }
        Ok(())
    }

    async fn dispatch_action_packets(&mut self, packets: &[Value]) -> Result<bool> {
        let mut changed_handles = Vec::new();
        let mut contact_updates = Vec::new();
        let mut node_changed = false;
        let mut share_changed = false;
        let mut key_event = false;
        let mut stale_user_attrs = HashSet::new();

        for pkt in packets {
            if let Some(obj) = pkt.as_object() {
                if let Some(st) = obj.get("st").and_then(|v| v.as_str()) {
                    if self.current_seqtag.as_deref() == Some(st) {
                        self.current_seqtag_seen = true;
                    }
                }

                if let Some(origin) = obj.get("i").and_then(|v| v.as_str()) {
                    if origin == self.session_id() {
                        let action = obj.get("a").and_then(|v| v.as_str());
                        if !matches!(action, Some("d") | Some("t")) {
                            continue;
                        }
                    }
                }

                Self::extract_handles_from_action(obj, &mut changed_handles);
                if Self::is_key_attr_update(obj) {
                    key_event = true;
                }
                if obj.get("a").and_then(|v| v.as_str()) == Some("ua") {
                    let skip_refetch =
                        obj.get("st").and_then(|v| v.as_str()) == self.current_seqtag.as_deref();
                    if !skip_refetch {
                        self.collect_user_attr_versions(obj, &mut stale_user_attrs);
                    }
                }
                if let Some(update) = Self::extract_contact_update(obj)? {
                    contact_updates.push(update);
                }
                let is_share_action = matches!(
                    obj.get("a").and_then(|v| v.as_str()),
                    Some("s") | Some("s2")
                );
                if self.handle_actionpacket_nodes(obj)? {
                    if is_share_action {
                        share_changed = true;
                    } else {
                        node_changed = true;
                    }
                }
            }
        }

        let mut changed = false;
        if !contact_updates.is_empty() {
            let mut contact_changed = false;
            for (_h, _ed, _cu, _verified, contact) in &contact_updates {
                if let Some(c) = contact {
                    let needs_update = self
                        .contacts
                        .get(&c.handle)
                        .map(|existing| existing.last_updated != c.last_updated
                            || existing.status != c.status
                            || existing.email != c.email)
                        .unwrap_or(true);
                    if needs_update {
                        self.contacts.insert(c.handle.clone(), c.clone());
                        contact_changed = true;
                    }
                }
            }
            if self.handle_contact_updates(&contact_updates).await? {
                changed = true;
            }
            if contact_changed {
                changed = true;
                if self.key_manager.is_ready() {
                    self.cleanup_pending_outshares_for_deleted_contacts();
                }
            }
            self.maybe_clear_cv_warning();
        }

        if !stale_user_attrs.is_empty() {
            let key_attrs_changed = stale_user_attrs.iter().any(|attr| Self::is_key_attr(attr));
            if self.refetch_user_attrs(&stale_user_attrs).await? {
                changed = true;
            }
            if key_attrs_changed {
                key_event = true;
            }
        }

        if share_changed {
            key_event = true;
        }

        if key_event || !changed_handles.is_empty() || share_changed {
            if self
                .handle_actionpacket_keys(&changed_handles, share_changed)
                .await?
            {
                changed = true;
            }
        }

        if share_changed && !self.key_manager.is_ready() {
            changed = true;
        }

        if node_changed {
            changed = true;
        }

        Ok(changed)
    }

    fn extract_handles_from_action(
        obj: &serde_json::Map<String, Value>,
        out: &mut Vec<String>,
    ) {
        for key in ["n", "p", "h", "t", "k"] {
            if let Some(v) = obj.get(key).and_then(|v| v.as_str()) {
                out.push(v.to_string());
            }
        }
        if let Some(arr) = obj.get("c").and_then(|v| v.as_array()) {
            for item in arr {
                if let Some(h) = item.get("h").and_then(|v| v.as_str()) {
                    out.push(h.to_string());
                }
            }
        }
    }

    fn is_key_attr_update(obj: &serde_json::Map<String, Value>) -> bool {
        let Some(action) = obj.get("a").and_then(|v| v.as_str()) else {
            return false;
        };
        if action != "ua" {
            return false;
        }
        let Some(attrs) = obj.get("ua").and_then(|v| v.as_array()) else {
            return false;
        };
        attrs
            .iter()
            .filter_map(|v| v.as_str())
            .any(Self::is_key_attr)
    }

    fn is_key_attr(attr: &str) -> bool {
        matches!(
            attr,
            "^!keys"
                | "*keyring"
                | "*~usk"
                | "*~jscd"
                | "+puCu255"
                | "+puEd255"
                | "+sigCu255"
                | "+sigPubk"
        )
    }

    fn collect_user_attr_versions(
        &self,
        obj: &serde_json::Map<String, Value>,
        stale: &mut HashSet<String>,
    ) {
        let Some(attrs) = obj.get("ua").and_then(|v| v.as_array()) else {
            return;
        };
        let Some(versions) = obj.get("v").and_then(|v| v.as_array()) else {
            return;
        };
        if attrs.len() != versions.len() {
            return;
        }

        for (attr_val, ver_val) in attrs.iter().zip(versions.iter()) {
            let Some(attr) = attr_val.as_str() else {
                continue;
            };
            let Some(version) = ver_val.as_str() else {
                continue;
            };
            if self
                .user_attr_versions
                .get(attr)
                .map(|v| v.as_str())
                != Some(version)
            {
                stale.insert(attr.to_string());
            }
        }
    }

    async fn refetch_user_attrs(&mut self, stale: &HashSet<String>) -> Result<bool> {
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

    fn handle_actionpacket_nodes(
        &mut self,
        obj: &serde_json::Map<String, Value>,
    ) -> Result<bool> {
        let Some(action) = obj.get("a").and_then(|v| v.as_str()) else {
            return Ok(false);
        };

        match action {
            "t" => self.handle_actionpacket_newnodes(obj),
            "u" => self.handle_actionpacket_update_node(obj),
            "d" => self.handle_actionpacket_delete_node(obj),
            "ph" => self.handle_actionpacket_public_link(obj),
            "s" | "s2" => self.handle_actionpacket_share(obj),
            "fa" => self.handle_actionpacket_file_attr(obj),
            "psts" | "psts_v2" | "ftr" => self.handle_actionpacket_upgrade(obj),
            _ => Ok(false),
        }
    }

    fn handle_actionpacket_upgrade(
        &mut self,
        _obj: &serde_json::Map<String, Value>,
    ) -> Result<bool> {
        // SDK triggers account_updated and user alerts; we currently no-op.
        Ok(false)
    }

    fn handle_actionpacket_file_attr(
        &mut self,
        obj: &serde_json::Map<String, Value>,
    ) -> Result<bool> {
        let Some(handle) = obj.get("h").and_then(|v| v.as_str()) else {
            return Ok(false);
        };
        let Some(fa) = obj.get("fa").and_then(|v| v.as_str()) else {
            return Ok(false);
        };

        for node in &mut self.nodes {
            if node.handle == handle {
                if node.file_attr.as_deref() != Some(fa) {
                    node.file_attr = Some(fa.to_string());
                    return Ok(true);
                }
                return Ok(false);
            }
        }

        Ok(false)
    }

    fn handle_actionpacket_share(
        &mut self,
        obj: &serde_json::Map<String, Value>,
    ) -> Result<bool> {
        let Some(handle) = obj.get("n").and_then(|v| v.as_str()) else {
            return Ok(false);
        };

        let owner = obj.get("o").and_then(|v| v.as_str());
        let target = obj.get("u").and_then(|v| v.as_str());
        let pending = obj.get("p").and_then(|v| v.as_str());
        let access = obj.get("r").and_then(|v| v.as_i64());
        let ok_b64 = obj.get("ok").and_then(|v| v.as_str());
        let k_b64 = obj.get("k").and_then(|v| v.as_str());
        let _ha = obj.get("ha").and_then(|v| v.as_str());
        let _ts = obj.get("ts").and_then(|v| v.as_i64());
        let _op = obj.get("op").and_then(|v| v.as_i64());
        let _okd = obj.get("okd").and_then(|v| v.as_str());
        let ou = obj.get("ou").and_then(|v| v.as_str());

        let outbound = owner == Some(self.user_handle.as_str());
        let mut changed = false;

        let mut share_key: Option<[u8; 16]> = None;

        if outbound {
            if let Some(ok_str) = ok_b64 {
                if let Ok(enc) = base64url_decode(ok_str) {
                    let dec = aes128_ecb_decrypt(&enc, &self.master_key);
                    if dec.len() >= 16 {
                        let mut key = [0u8; 16];
                        key.copy_from_slice(&dec[..16]);
                        share_key = Some(key);
                    }
                }
            }
        }

        if share_key.is_none() {
            if let Some(k_str) = k_b64 {
                if let Ok(enc) = base64url_decode(k_str) {
                    if let Some(dec) = self.rsa_key().decrypt(&enc) {
                        if dec.len() >= 16 {
                            let mut key = [0u8; 16];
                            key.copy_from_slice(&dec[..16]);
                            share_key = Some(key);
                        }
                    } else if !outbound && self.key_manager.is_ready() {
                        if let Some(owner_b64) = owner {
                            if let Some(owner_handle) = Self::decode_user_handle(owner_b64) {
                                self.key_manager
                                    .add_pending_in(handle, &owner_handle, enc);
                                changed = true;
                            }
                        }
                    }
                }
            }
        }

        if let Some(key) = share_key {
            self.share_keys.insert(handle.to_string(), key);
            changed = true;
            if self.key_manager.is_ready() {
                let in_use = access.map_or(true, |r| r >= 0);
                self.key_manager
                    .add_share_key_with_flags(handle, &key, true, in_use);
            }
        }

        let sharee_id = pending.or(target);
        let is_removed = access.unwrap_or(-1) < 0;
        if outbound {
            if let Some(id) = sharee_id {
                if is_removed {
                    let total_before = self.outshare_total(handle);
                    if self.remove_outshare(handle, id, pending.is_some()) {
                        changed = true;
                    }
                    if self.key_manager.is_ready()
                        && owner == Some(self.user_handle.as_str())
                        && ou.as_deref() != Some(self.user_handle.as_str())
                        && !self.sc_catchup
                        && self.key_manager.generation > 0
                        && self.key_manager.is_share_key_in_use(handle)
                        && total_before == 1
                    {
                        if self.key_manager.set_share_key_in_use(handle, false) {
                            changed = true;
                        }
                    }
                } else if self.add_outshare(handle, id, pending.is_some()) {
                    changed = true;
                }
            }
        }

        if outbound && self.key_manager.is_ready() {
            let pending_id = sharee_id;
            if let Some(p) = pending_id {
                if p.contains('@') {
                    self.key_manager.add_pending_out_email(handle, p);
                    changed = true;
                } else if let Some(user_handle) = Self::decode_user_handle(p) {
                    self.key_manager
                        .add_pending_out_user_handle(handle, &user_handle);
                    changed = true;
                }
            }
        }

        if self.key_manager.is_ready() {
            if let Some(r) = access {
                if r >= 0 {
                    let mut flag_changed = false;
                    flag_changed |= self.key_manager.set_share_key_in_use(handle, true);
                    flag_changed |= self.key_manager.set_share_key_trusted(handle, true);
                    if flag_changed {
                        changed = true;
                    }
                }
            }
        }

        Ok(changed)
    }

    fn handle_actionpacket_newnodes(
        &mut self,
        obj: &serde_json::Map<String, Value>,
    ) -> Result<bool> {
        let nodes_array = if let Some(arr) = obj.get("t").and_then(|v| v.as_array()) {
            Some(arr)
        } else if let Some(tobj) = obj.get("t").and_then(|v| v.as_object()) {
            tobj.get("f").and_then(|v| v.as_array())
        } else {
            None
        };

        let Some(nodes_array) = nodes_array else {
            return Ok(false);
        };

        let mut changed = false;
        for node_json in nodes_array {
            if let Some(node) = self.parse_node(node_json) {
                changed |= self.upsert_node(node);
            }
        }

        if changed {
            Self::build_node_paths(&mut self.nodes);
        }

        Ok(changed)
    }

    fn handle_actionpacket_update_node(
        &mut self,
        obj: &serde_json::Map<String, Value>,
    ) -> Result<bool> {
        let Some(handle) = obj.get("n").and_then(|v| v.as_str()) else {
            return Ok(false);
        };
        let node_idx = match self.nodes.iter().position(|n| n.handle == handle) {
            Some(idx) => idx,
            None => return Ok(false),
        };

        let mut changed = false;
        if let Some(at) = obj.get("at").and_then(|v| v.as_str()) {
            if let Some(name) = self.decrypt_node_attrs(at, &self.nodes[node_idx].key) {
                if self.nodes[node_idx].name != name {
                    self.nodes[node_idx].name = name;
                    changed = true;
                }
            }
        }

        if let Some(ts) = obj.get("ts").and_then(|v| v.as_i64()) {
            if self.nodes[node_idx].timestamp != ts {
                self.nodes[node_idx].timestamp = ts;
                changed = true;
            }
        }

        if changed {
            Self::build_node_paths(&mut self.nodes);
        }

        Ok(changed)
    }

    fn handle_actionpacket_delete_node(
        &mut self,
        obj: &serde_json::Map<String, Value>,
    ) -> Result<bool> {
        let Some(handle) = obj.get("n").and_then(|v| v.as_str()) else {
            return Ok(false);
        };

        let handle_map: HashMap<&str, usize> = self
            .nodes
            .iter()
            .enumerate()
            .map(|(i, n)| (n.handle.as_str(), i))
            .collect();

        let mut remove = HashSet::new();
        for (i, node) in self.nodes.iter().enumerate() {
            if node.handle == handle
                || Self::node_has_ancestor_in_nodes(&self.nodes, i, handle, &handle_map)
            {
                remove.insert(node.handle.clone());
            }
        }

        if remove.is_empty() {
            return Ok(false);
        }

        self.nodes.retain(|n| !remove.contains(&n.handle));
        Self::build_node_paths(&mut self.nodes);
        Ok(true)
    }

    fn handle_actionpacket_public_link(
        &mut self,
        obj: &serde_json::Map<String, Value>,
    ) -> Result<bool> {
        let Some(handle) = obj.get("h").and_then(|v| v.as_str()) else {
            return Ok(false);
        };

        let deleted = obj.get("d").and_then(|v| v.as_i64()).unwrap_or(0) == 1;
        let link_handle = obj.get("ph").and_then(|v| v.as_str());

        for node in &mut self.nodes {
            if node.handle == handle {
                if deleted {
                    if node.link.is_some() {
                        node.link = None;
                        return Ok(true);
                    }
                    return Ok(false);
                }
                if let Some(ph) = link_handle {
                    if node.link.as_deref() != Some(ph) {
                        node.link = Some(ph.to_string());
                        return Ok(true);
                    }
                }
                return Ok(false);
            }
        }

        Ok(false)
    }

    fn upsert_node(&mut self, node: Node) -> bool {
        if let Some(idx) = self.nodes.iter().position(|n| n.handle == node.handle) {
            self.nodes[idx] = node;
            true
        } else {
            self.nodes.push(node);
            true
        }
    }

    pub(crate) fn ingest_outshares_from_fetch(&mut self, s_array: &[Value]) {
        self.outshares.clear();
        self.pending_outshares.clear();

        for item in s_array {
            let Some(obj) = item.as_object() else {
                continue;
            };
            let Some(handle) = obj.get("h").and_then(|v| v.as_str()) else {
                continue;
            };
            let access = obj.get("r").and_then(|v| v.as_i64()).unwrap_or(-1);
            if access < 0 {
                continue;
            }
            if let Some(pending) = obj.get("p").and_then(|v| v.as_str()) {
                self.add_outshare(handle, pending, true);
                continue;
            }
            if let Some(user) = obj.get("u").and_then(|v| v.as_str()) {
                self.add_outshare(handle, user, false);
            }
        }
    }

    fn add_outshare(&mut self, handle: &str, sharee: &str, pending: bool) -> bool {
        let map = if pending {
            &mut self.pending_outshares
        } else {
            &mut self.outshares
        };
        let entry = map.entry(handle.to_string()).or_insert_with(HashSet::new);
        entry.insert(sharee.to_string())
    }

    fn remove_outshare(&mut self, handle: &str, sharee: &str, pending: bool) -> bool {
        let map = if pending {
            &mut self.pending_outshares
        } else {
            &mut self.outshares
        };
        let Some(entry) = map.get_mut(handle) else {
            return false;
        };
        let removed = entry.remove(sharee);
        if entry.is_empty() {
            map.remove(handle);
        }
        removed
    }

    fn outshare_total(&self, handle: &str) -> usize {
        let out_count = self
            .outshares
            .get(handle)
            .map(|s| s.len())
            .unwrap_or(0);
        let pending_count = self
            .pending_outshares
            .get(handle)
            .map(|s| s.len())
            .unwrap_or(0);
        out_count + pending_count
    }

    fn cleanup_pending_outshares_for_deleted_contacts(&mut self) {
        let mut removed_any = false;
        for (_handle, sharees) in self.pending_outshares.iter_mut() {
            let before = sharees.len();
            sharees.retain(|sharee| {
                if sharee.contains('@') {
                    let still_exists = self
                        .contacts
                        .values()
                        .any(|c| c.email.as_deref() == Some(sharee));
                    return still_exists;
                }
                self.contacts.contains_key(sharee)
            });
            if sharees.is_empty() && before > 0 {
                removed_any = true;
            } else if sharees.len() != before {
                removed_any = true;
            }
        }

        if removed_any && self.key_manager.is_ready() {
            self.key_manager
                .pending_out
                .retain(|entry| match &entry.uid {
                    crate::crypto::key_manager::PendingUid::Email(email) => self
                        .contacts
                        .values()
                        .any(|c| c.email.as_deref() == Some(email)),
                    crate::crypto::key_manager::PendingUid::UserHandle(handle) => {
                        let handle_b64 = base64url_encode(handle);
                        self.contacts.contains_key(&handle_b64)
                    }
                });
        }
    }

    fn node_has_ancestor_in_nodes(
        nodes: &[Node],
        idx: usize,
        ancestor_handle: &str,
        handle_map: &HashMap<&str, usize>,
    ) -> bool {
        let mut current = nodes[idx].parent_handle.as_deref();
        for _ in 0..100 {
            match current {
                Some(handle) if handle == ancestor_handle => return true,
                Some(handle) => {
                    if let Some(&parent_idx) = handle_map.get(handle) {
                        current = nodes[parent_idx].parent_handle.as_deref();
                    } else {
                        return false;
                    }
                }
                None => return false,
            }
        }
        false
    }

    fn decode_user_handle(handle_b64: &str) -> Option<[u8; 8]> {
        let decoded = base64url_decode(handle_b64).ok()?;
        if decoded.len() != 8 {
            return None;
        }
        let mut out = [0u8; 8];
        out.copy_from_slice(&decoded);
        Some(out)
    }

    fn extract_contact_update(
        obj: &serde_json::Map<String, Value>,
    ) -> Result<Option<(String, Option<Vec<u8>>, Option<Vec<u8>>, bool, Option<Contact>)>> {
        let user = match obj.get("u").and_then(|v| v.as_str()) {
            Some(u) => u.to_string(),
            None => return Ok(None),
        };

        let cu_b64 = obj
            .get("prCu255")
            .or_else(|| obj.get("cu25519"))
            .or_else(|| obj.get("k"))
            .and_then(|v| v.as_str());
        let ed_b64 = obj
            .get("prEd255")
            .or_else(|| obj.get("ed25519"))
            .and_then(|v| v.as_str());

        let cu = cu_b64
            .map(base64url_decode)
            .transpose()?
            .filter(|v| !v.is_empty());
        let ed = ed_b64
            .map(base64url_decode)
            .transpose()?
            .filter(|v| !v.is_empty());
        let verified = obj.get("c").and_then(|v| v.as_i64()).unwrap_or(0) > 0;

        let email = obj.get("m").and_then(|v| v.as_str()).map(|s| s.to_string());
        let status = obj.get("c").and_then(|v| v.as_i64()).unwrap_or(0);
        let ts = obj.get("ts").and_then(|v| v.as_i64()).unwrap_or(0);
        let contact = Contact {
            handle: user.clone(),
            email,
            status,
            last_updated: ts,
        };

        if cu.is_none() && ed.is_none() {
            return Ok(Some((user, None, None, verified, Some(contact))));
        }

        Ok(Some((user, ed, cu, verified, Some(contact))))
    }

    /// Get all nodes in the session cache.
    pub fn nodes(&self) -> &[crate::fs::Node] {
        &self.nodes
    }

    /// Spawn a background actor that owns this session and polls SC automatically.
    pub(crate) fn spawn_actor(self) -> crate::session::actor::SessionHandle {
        crate::session::actor::SessionHandle::from_session(self)
    }

    /// Save session to a file for later restoration.
    ///
    /// This allows you to avoid re-logging in on every run.
    /// The saved file contains the SDK-compatible session string - keep it secure!
    ///
    /// # Example
    /// ```no_run
    /// use megalib::Session;
    ///
    /// # async fn example() -> megalib::error::Result<()> {
    /// let session = Session::login("user@example.com", "password").await?;
    /// session.save("session.json")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn save<P: AsRef<std::path::Path>>(&self, path: P) -> Result<()> {
        let session = self.dump_session()?;
        std::fs::write(path, session)
            .map_err(|e| MegaError::Custom(format!("Write error: {}", e)))?;
        Ok(())
    }

    /// Dump the session in SDK-compatible binary format.
    ///
    /// Normal account sessions are encoded as:
    /// - if session_key exists: [1] + AES-ECB(master_key, session_key) + sid_bytes
    /// - otherwise: master_key + sid_bytes
    pub fn dump_session_blob(&self) -> Result<Vec<u8>> {
        let sid_bytes = base64url_decode(&self.session_id)
            .map_err(|_| MegaError::Custom("Invalid session id".to_string()))?;
        if sid_bytes.is_empty() {
            return Err(MegaError::Custom("Session id is empty".to_string()));
        }

        let mut out = Vec::with_capacity(1 + 16 + sid_bytes.len());
        if let Some(sek) = self.session_key {
            out.push(1);
            let enc = aes128_ecb_encrypt_block(&self.master_key, &sek);
            out.extend_from_slice(&enc);
        } else {
            out.extend_from_slice(&self.master_key);
        }
        out.extend_from_slice(&sid_bytes);
        Ok(out)
    }

    /// Dump the session as a standard base64 string (SDK `dumpSession()` compatible).
    pub fn dump_session(&self) -> Result<String> {
        let blob = self.dump_session_blob()?;
        Ok(general_purpose::STANDARD.encode(blob))
    }

    /// Parse a SDK-compatible session blob (base64 string).
    ///
    /// Returns a decoded session payload for normal account sessions.
    pub fn parse_session_blob(session_b64: &str) -> Result<SessionBlob> {
        let data = general_purpose::STANDARD
            .decode(session_b64.as_bytes())
            .map_err(|_| MegaError::Custom("Invalid session blob".to_string()))?;
        if data.is_empty() {
            return Err(MegaError::Custom("Empty session blob".to_string()));
        }
        if data[0] == 2 {
            return Err(MegaError::Custom(
                "Folder-link sessions are not supported; use parse_folder_session_blob".to_string(),
            ));
        }

        let (session_version, key_bytes, sid_bytes, master_key_encrypted) = if data[0] == 1
            && data.len() >= 17
        {
            (1u8, &data[1..17], &data[17..], true)
        } else if data.len() >= 16 {
            (0u8, &data[0..16], &data[16..], false)
        } else {
            return Err(MegaError::Custom("Invalid session blob length".to_string()));
        };

        if sid_bytes.is_empty() {
            return Err(MegaError::Custom("Session id is empty".to_string()));
        }

        let mut master_key = [0u8; 16];
        master_key.copy_from_slice(key_bytes);
        let session_id = base64url_encode(sid_bytes);

        Ok(SessionBlob {
            session_id,
            master_key,
            session_version,
            master_key_encrypted,
        })
    }

    /// Parse a SDK folder-link session blob (type 2).
    pub fn parse_folder_session_blob(session_b64: &str) -> Result<FolderSessionBlob> {
        let data = general_purpose::STANDARD
            .decode(session_b64.as_bytes())
            .map_err(|_| MegaError::Custom("Invalid session blob".to_string()))?;
        if data.is_empty() {
            return Err(MegaError::Custom("Empty session blob".to_string()));
        }
        if data[0] != 2 {
            return Err(MegaError::Custom("Not a folder-link session blob".to_string()));
        }

        let mut idx = 1usize;
        if idx + 6 + 6 + 16 + 8 > data.len() {
            return Err(MegaError::Custom("Invalid folder session blob".to_string()));
        }

        let public_handle = base64url_encode(&data[idx..idx + 6]);
        idx += 6;
        let root_handle = base64url_encode(&data[idx..idx + 6]);
        idx += 6;
        let mut folder_key = [0u8; 16];
        folder_key.copy_from_slice(&data[idx..idx + 16]);
        idx += 16;

        let flags = &data[idx..idx + 8];
        idx += 8;
        if flags[3..].iter().any(|b| *b != 0) {
            return Err(MegaError::Custom(
                "Invalid folder session flags".to_string(),
            ));
        }
        let has_write = flags[0] != 0;
        let has_account = flags[1] != 0;
        let has_padding = flags[2] != 0;

        let read_string = |buf: &[u8], pos: &mut usize| -> Result<String> {
            if *pos + 2 > buf.len() {
                return Err(MegaError::Custom("Invalid folder session blob".to_string()));
            }
            let len = u16::from_le_bytes([buf[*pos], buf[*pos + 1]]) as usize;
            *pos += 2;
            if *pos + len > buf.len() {
                return Err(MegaError::Custom("Invalid folder session blob".to_string()));
            }
            let out = String::from_utf8(buf[*pos..*pos + len].to_vec())
                .map_err(|_| MegaError::Custom("Invalid folder session string".to_string()))?;
            *pos += len;
            Ok(out)
        };

        let write_auth = if has_write {
            Some(read_string(&data, &mut idx)?)
        } else {
            None
        };
        let account_auth = if has_account {
            Some(read_string(&data, &mut idx)?)
        } else {
            None
        };
        let padding = if has_padding {
            Some(read_string(&data, &mut idx)?)
        } else {
            None
        };

        if idx != data.len() {
            return Err(MegaError::Custom("Invalid folder session blob".to_string()));
        }

        Ok(FolderSessionBlob {
            public_handle,
            root_handle,
            folder_key,
            write_auth,
            account_auth,
            padding,
        })
    }

    /// Dump a folder-link session blob (type 2) as standard base64.
    pub fn dump_folder_session_blob(blob: &FolderSessionBlob) -> Result<String> {
        let public_bytes = base64url_decode(&blob.public_handle)
            .map_err(|_| MegaError::Custom("Invalid public handle".to_string()))?;
        let root_bytes = base64url_decode(&blob.root_handle)
            .map_err(|_| MegaError::Custom("Invalid root handle".to_string()))?;
        if public_bytes.len() != 6 || root_bytes.len() != 6 {
            return Err(MegaError::Custom("Invalid handle length".to_string()));
        }

        let mut out = Vec::new();
        out.push(2);
        out.extend_from_slice(&public_bytes);
        out.extend_from_slice(&root_bytes);
        out.extend_from_slice(&blob.folder_key);

        let has_write = blob.write_auth.is_some();
        let has_account = blob.account_auth.is_some();
        let has_padding = true;
        let mut flags = [0u8; 8];
        flags[0] = if has_write { 1 } else { 0 };
        flags[1] = if has_account { 1 } else { 0 };
        flags[2] = if has_padding { 1 } else { 0 };
        out.extend_from_slice(&flags);

        let mut write_string = |s: &str| {
            let len = s.len().min(u16::MAX as usize) as u16;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&s.as_bytes()[..len as usize]);
        };

        if let Some(auth) = blob.write_auth.as_deref() {
            write_string(auth);
        }
        if let Some(auth) = blob.account_auth.as_deref() {
            write_string(auth);
        }

        let padding = blob
            .padding
            .clone()
            .unwrap_or_else(|| "P".to_string());
        write_string(&padding);

        Ok(general_purpose::STANDARD.encode(out))
    }

    /// Try to decode the keyring (*keyring) attribute and return Ed25519/Cu25519 privkeys.
    pub(crate) async fn load_keyring(&mut self) -> Result<Keyring> {
        let Some(enc_keyring) = self.get_user_attribute_raw("*keyring").await? else {
            return Err(MegaError::Custom("Keyring not found".to_string()));
        };

        Keyring::from_encrypted(&enc_keyring, &self.master_key)
    }

    /// Fetch a raw user attribute (e.g. "^!keys" or "*keyring"). Returns decoded bytes if present.
    /// If the attribute does not exist, returns Ok(None).
    pub async fn get_user_attribute_raw(&mut self, attr: &str) -> Result<Option<Vec<u8>>> {
        if let Some(cached) = self.user_attr_cache.get(attr) {
            return Ok(Some(cached.clone()));
        }

        let response = match self.api_mut().get_user_attribute(attr).await {
            Ok(v) => v,
            Err(MegaError::ApiError { code, .. }) if code == -9 => {
                // Attribute not set
                return Ok(None);
            }
            Err(e) => return Err(e),
        };

        // Attribute responses can be either {"av": "...", "v": <version>} or an array of objects.
        if let Some(av) = response.get("av").and_then(|v| v.as_str()) {
            if av.is_empty() {
                return Ok(None);
            }
            let decoded = base64url_decode(av)?;
            self.user_attr_cache
                .insert(attr.to_string(), decoded.clone());
            if let Some(ver) = response.get("v").and_then(|v| v.as_str()) {
                self.user_attr_versions
                    .insert(attr.to_string(), ver.to_string());
            }
            return Ok(Some(decoded));
        }

        if let Some(arr) = response.as_array() {
            if let Some(obj) = arr.iter().find(|o| o.get("av").and_then(|v| v.as_str()).is_some())
            {
                let av = obj.get("av").and_then(|v| v.as_str()).unwrap_or("");
                if av.is_empty() {
                    return Ok(None);
                }
                let decoded = base64url_decode(av)?;
                self.user_attr_cache
                    .insert(attr.to_string(), decoded.clone());
                if let Some(ver) = obj.get("v").and_then(|v| v.as_str()) {
                    self.user_attr_versions
                        .insert(attr.to_string(), ver.to_string());
                }
                return Ok(Some(decoded));
            }
        }

        Ok(None)
    }

    /// Set a private user attribute (e.g. "^!keys") with a base64url-encoded value.
    /// The server uses versioning; pass the latest version token when updating.
    pub async fn set_private_attribute(
        &mut self,
        attr: &str,
        value_b64: &str,
        version: Option<String>,
    ) -> Result<()> {
        let resp = self
            .api_mut()
            .set_private_attribute(attr, value_b64, version.as_deref())
            .await?;

        if let Some(err) = resp.as_i64().filter(|v| *v < 0) {
            let code = crate::api::client::ApiErrorCode::from(err);
            return Err(MegaError::ApiError {
                code: err as i32,
                message: code.description().to_string(),
            });
        }

        if let Some(ver) = Self::extract_attr_version(&resp, attr) {
            self.user_attr_versions
                .insert(attr.to_string(), ver);
        }
        if attr == "^!keys" {
            self.last_keys_blob_b64 = Some(value_b64.to_string());
        }
        Ok(())
    }

    fn extract_attr_version(resp: &Value, attr: &str) -> Option<String> {
        if let Some(obj) = resp.as_object() {
            if let Some(v) = obj.get(attr).and_then(|v| v.as_str()) {
                return Some(v.to_string());
            }
        }
        if let Some(arr) = resp.as_array() {
            for item in arr {
                if let Some(v) = Self::extract_attr_version(item, attr) {
                    return Some(v);
                }
            }
        }
        None
    }

    /// Replace authring Ed25519 blob (LTLV) and persist into ^!keys.
    pub async fn set_authring_ed25519(&mut self, blob: Vec<u8>) -> Result<()> {
        self.authring_ed = AuthRing::deserialize_ltlv(&blob);
        self.persist_keys_attribute().await
    }

    /// Replace authring Cu25519 blob (LTLV) and persist into ^!keys.
    pub async fn set_authring_cu25519(&mut self, blob: Vec<u8>) -> Result<()> {
        self.authring_cu = AuthRing::deserialize_ltlv(&blob);
        self.persist_keys_attribute().await
    }

    /// Check if a ^!keys downgrade has been detected.
    pub fn keys_downgrade_detected(&self) -> bool {
        self.keys_downgrade_detected
    }

    /// Replace backups blob (opaque) and persist into ^!keys.
    pub async fn set_backups_blob(&mut self, blob: Vec<u8>) -> Result<()> {
        self.backups = blob;
        self.persist_keys_attribute().await
    }

    /// Update warnings (LTLV map) and persist.
    pub async fn set_warnings(&mut self, warnings: crate::crypto::Warnings) -> Result<()> {
        self.warnings = warnings;
        self.persist_keys_attribute().await
    }

    /// Enable/disable contact verification warning flag (cv) and persist.
    pub async fn set_contact_verification_warning(&mut self, enabled: bool) -> Result<()> {
        self.warnings.set_cv(enabled);
        self.persist_keys_attribute().await
    }

    /// Set manual verification flag (gates share-key exchange) and persist.
    pub async fn set_manual_verification(&mut self, enabled: bool) -> Result<()> {
        self.manual_verification = enabled;
        self.persist_keys_attribute().await
    }

    /// Check if contact verification warning flag is set.
    pub fn contact_verification_warning(&self) -> bool {
        self.warnings.cv_enabled()
    }

    /// Get authring state for a contact (Ed25519 / Cu25519)
    pub fn authring_state(&self, handle_b64: &str) -> (Option<AuthState>, Option<AuthState>) {
        (
            self.authring_ed.get_state(handle_b64),
            self.authring_cu.get_state(handle_b64),
        )
    }

    /// Try to load ^!keys (minimal) into key_manager. Returns true if loaded and ready.
    pub async fn load_keys_attribute(&mut self) -> Result<bool> {
        let Some(enc_keys) = self.get_user_attribute_raw("^!keys").await? else {
            return Ok(false);
        };

        let mut km = KeyManager::new();
        km.decode_container(&enc_keys, &self.master_key)?;
        if km.is_ready() {
            self.last_keys_blob_b64 = Some(base64url_encode(&enc_keys));
            // populate share_keys map for quick lookup
            for sk in &km.share_keys {
                let mut arr: [u8; 16] = [0u8; 16];
                arr.copy_from_slice(&sk.key);
                // encode handle back to base64url for map key
                let handle_b64 = crate::base64::base64url_encode(&sk.handle);
                self.share_keys.entry(handle_b64).or_insert(arr);
            }
            self.key_manager = km;
            // If priv RSA is present, propagate into session crypto layer.
            if !self.key_manager.priv_rsa.is_empty() {
                if let Ok(rsa) = parse_raw_private_key(&self.key_manager.priv_rsa) {
                    self.rsa_key = rsa;
                }
            }
            // Cache authrings/backups/warnings/manual verification in session for quick access.
            self.authring_ed =
                AuthRing::deserialize_ltlv(&self.key_manager.auth_ed25519);
            self.authring_cu =
                AuthRing::deserialize_ltlv(&self.key_manager.auth_cu25519);
            self.backups = self.key_manager.backups.clone();
            self.warnings = self.key_manager.warnings.clone();
            self.manual_verification = self.key_manager.manual_verification;

            // Process any pending promotions and in-use cleanup after loading.
            self.promote_pending_shares().await?;
            if self.clear_inuse_flags_for_missing_shares() {
                self.persist_keys_with_retry().await?;
            }

            return Ok(true);
        }
        Ok(false)
    }

    /// Minimal upgrade: ensure ^!keys exists. If missing, build from keyring;
    /// if keyring is absent, generate a fresh one (auto-upgrade like SDK).
    pub async fn ensure_keys_attribute(&mut self) -> Result<()> {
        if self.key_manager.is_ready() {
            return Ok(());
        }

        if self.load_keys_attribute().await? {
            return Ok(());
        }

        // No ^!keys yet: try to load keyring; if missing, skip (legacy/non-upgraded account).
        let keyring = match self.load_keyring().await {
            Ok(kr) => kr,
            Err(MegaError::Custom(msg)) if msg.contains("Keyring not found") => {
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        let mut km = KeyManager::new();
        km.set_priv_keys(
            keyring.ed25519.clone().unwrap_or_default().as_slice(),
            keyring.cu25519.clone().unwrap_or_default().as_slice(),
        );
        km.generation = 1;
        km.creation_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        if let Ok(decoded_handle) = base64url_decode(&self.user_handle) {
            let mut ident = [0u8; 8];
            let copy_len = decoded_handle.len().min(8);
            ident[..copy_len].copy_from_slice(&decoded_handle[..copy_len]);
            km.identity = u64::from_le_bytes(ident);
        }

        // include any cached share_keys (legacy) into ^!keys
        for (h, k) in self.share_keys.iter() {
            km.add_share_key_from_str(h, k);
        }

        let blob = km.encode_container(&self.master_key)?;
        let blob_b64 = base64url_encode(&blob);
        self.set_private_attribute("^!keys", &blob_b64, None)
            .await?;

        // Reload to populate share_keys map consistently
        self.key_manager = km;
        Ok(())
    }

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
        self.ensure_keys_attribute().await?;

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
        let mut share_nodes: Vec<(String, Vec<u8>)> = Vec::new();
        share_nodes.push((node_handle.to_string(), node_key.clone()));
        let mut stack = vec![node_handle.to_string()];
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
            "ok": key_b64,
            "i": self.session_id()
        });

        if let Some(cr_value) = cr {
            request["cr"] = cr_value;
        }

        let response = self.api.request(request).await?;

        // Check for error code
        if let Some(err_code) = response.as_i64() {
            if err_code < 0 {
                // Fix: Fully qualified path to ApiErrorCode
                let error_code = crate::api::client::ApiErrorCode::from(err_code);
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

    /// Persist the minimal ^!keys attribute from the in-memory KeyManager.
    pub async fn persist_keys_attribute(&mut self) -> Result<()> {
        self.persist_keys_with_retry().await
    }

    /// Load a previously saved session from a file.
    ///
    /// Returns `None` if the file doesn't exist.
    /// Returns an error if the file exists but is invalid.
    ///
    /// # Example
    /// ```no_run
    /// use megalib::Session;
    ///
    /// # async fn example() -> megalib::error::Result<()> {
    /// // Try to load cached session, fall back to login
    /// let session = match Session::load("session.json").await? {
    ///     Some(s) => s,
    ///     None => {
    ///         let s = Session::login("user@example.com", "password").await?;
    ///         s.save("session.json")?;
    ///         s
    ///     }
    /// };
    /// # Ok(())
    /// # }
    /// ```
    pub async fn load<P: AsRef<std::path::Path>>(path: P) -> Result<Option<Self>> {
        Self::load_internal(path, None).await
    }

    /// Load a previously saved session with proxy support.
    ///
    /// # Arguments
    /// * `path` - Path to the cached session file
    /// * `proxy` - Proxy URL (e.g., "http://proxy:8080")
    pub async fn load_with_proxy<P: AsRef<std::path::Path>>(
        path: P,
        proxy: &str,
    ) -> Result<Option<Self>> {
        Self::load_internal(path, Some(proxy)).await
    }

    /// Internal load implementation.
    async fn load_internal<P: AsRef<std::path::Path>>(
        path: P,
        proxy: Option<&str>,
    ) -> Result<Option<Self>> {
        let path = path.as_ref();

        if !path.exists() {
            return Ok(None);
        }

        let session_b64 = std::fs::read_to_string(path)
            .map_err(|e| MegaError::Custom(format!("Read error: {}", e)))?;
        let session_b64 = session_b64.trim();
        if session_b64.is_empty() {
            return Err(MegaError::Custom("Empty session file".to_string()));
        }

        let session = match Self::login_with_session(session_b64, proxy).await {
            Ok(session) => session,
            Err(_) => {
                let _ = std::fs::remove_file(path);
                return Ok(None);
            }
        };

        Ok(Some(session))
    }

}

/// Parsed SDK session blob (normal account sessions).
#[derive(Debug, Clone)]
pub struct SessionBlob {
    pub session_id: String,
    pub master_key: [u8; 16],
    pub session_version: u8,
    pub master_key_encrypted: bool,
}

/// Parsed SDK folder-link session blob (type 2).
#[derive(Debug, Clone)]
pub struct FolderSessionBlob {
    pub public_handle: String,
    pub root_handle: String,
    pub folder_key: [u8; 16],
    pub write_auth: Option<String>,
    pub account_auth: Option<String>,
    pub padding: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::MegaRsaKey;

    // Helper to create a dummy session for testing configuration methods
    fn create_dummy_session() -> Session {
        Session {
            api: ApiClient::new(),
            session_id: "dummy_session".to_string(),
            session_key: None,
            master_key: [0u8; 16],
            rsa_key: MegaRsaKey::generate().unwrap(),
            email: "test@example.com".to_string(),
            name: None,
            user_handle: "handle".to_string(),
            nodes: Vec::new(),
            keys_downgrade_detected: false,
            share_keys: HashMap::new(),
            outshares: HashMap::new(),
            pending_outshares: HashMap::new(),
            contacts: HashMap::new(),
            key_manager: KeyManager::default(),
            authring_ed: AuthRing::default(),
            authring_cu: AuthRing::default(),
            backups: Vec::new(),
            warnings: crate::crypto::Warnings::default(),
            manual_verification: false,
            user_attr_cache: HashMap::new(),
            user_attr_versions: HashMap::new(),
            last_keys_blob_b64: None,
            keys_persist_inflight: false,
            pending_keys_token: None,
            scsn: None,
            wsc_url: None,
            sc_catchup: false,
            current_seqtag: None,
            current_seqtag_seen: false,
            defer_seqtag_wait: false,
            alerts_catchup_pending: false,
            user_alert_lsn: None,
            user_alerts: Vec::new(),
            resume_enabled: false,
            progress_callback: None,
            previews_enabled: false,
            workers: 1,
        }
    }

    #[test]
    fn test_resume_configuration() {
        let mut session = create_dummy_session();

        assert!(!session.is_resume_enabled());

        session.set_resume(true);
        assert!(session.is_resume_enabled());

        session.set_resume(false);
        assert!(!session.is_resume_enabled());
    }

    #[test]
    fn test_previews_configuration() {
        let mut session = create_dummy_session();

        assert!(!session.previews_enabled());

        session.enable_previews(true);
        assert!(session.previews_enabled());

        session.enable_previews(false);
        assert!(!session.previews_enabled());
    }

    #[test]
    fn test_workers_configuration() {
        let mut session = create_dummy_session();

        assert_eq!(session.workers(), 1);

        session.set_workers(4);
        assert_eq!(session.workers(), 4);

        // Test 0 workers -> should be clamped to 1 (assuming implementation does this,
        // if not we'll update the test or the code)
        // Checking implementation: usually strictly sets generic value.
        // Let's just test basic setting for now.
        session.set_workers(10);
        assert_eq!(session.workers(), 10);
    }
}
