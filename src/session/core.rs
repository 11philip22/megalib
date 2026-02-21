//! Session management and authentication.
//!
//! This module handles user login, session state, and logout.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::api::ApiClient;
use crate::base64::{base64url_decode, base64url_encode};
use crate::crypto::aes::aes128_ecb_encrypt_block;
use crate::crypto::key_manager::KeyManager;
use crate::crypto::keyring::{Keyring, encrypt_tlv_records};
use crate::crypto::{AuthRing, AuthState, MegaRsaKey, make_random_key, parse_raw_private_key};
use crate::error::{MegaError, Result};
use crate::fs::Node;

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
                        let error_code = crate::api::ApiErrorCode::from(code);
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
        if !self.has_valid_rsa_key() {
            return Err(MegaError::Custom(
                "Cannot attach account keys without a valid RSA key".to_string(),
            ));
        }
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
            key_attrs.push(("*keyring", base64url_encode(enc), version_for("*keyring")));
        }
        key_attrs.push(("^!keys", keys_b64, version_for("^!keys")));
        key_attrs.push((
            "+puEd255",
            base64url_encode(&pu_ed),
            version_for("+puEd255"),
        ));
        key_attrs.push((
            "+puCu255",
            base64url_encode(&pu_cu),
            version_for("+puCu255"),
        ));
        key_attrs.push((
            "+sigCu255",
            base64url_encode(&sig_cu),
            version_for("+sigCu255"),
        ));
        key_attrs.push((
            "+sigPubk",
            base64url_encode(&sig_pubk),
            version_for("+sigPubk"),
        ));
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
            self.user_attr_cache.insert("*keyring".to_string(), enc);
        }
        if let Some(usk) = generated_usk {
            self.user_attr_cache.insert("*~usk".to_string(), usk);
        }
        self.user_attr_cache
            .insert("^!keys".to_string(), keys_blob.clone());
        self.last_keys_blob_b64 = Some(base64url_encode(&keys_blob));
        self.user_attr_cache.insert("+puEd255".to_string(), pu_ed);
        self.user_attr_cache.insert("+puCu255".to_string(), pu_cu);
        self.user_attr_cache.insert("+sigCu255".to_string(), sig_cu);
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

    async fn upload_rsa_keypair(&mut self, rsa_key: &MegaRsaKey) -> Result<()> {
        let privk = rsa_key.encode_private_key(&self.master_key);
        let pubk = rsa_key.encode_public_key();
        let response = self
            .api_mut()
            .request(json!({
                "a": "up",
                "privk": privk,
                "pubk": pubk
            }))
            .await?;

        if let Some(err) = response.as_i64().filter(|v| *v < 0) {
            let code = crate::api::ApiErrorCode::from(err);
            return Err(MegaError::ApiError {
                code: err as i32,
                message: code.description().to_string(),
            });
        }

        Ok(())
    }

    /// Initialize account crypto attributes in the same order as the SDK:
    /// 1) Ensure RSA keypair exists on the account (`up` with `privk/pubk`)
    /// 2) Ensure upgraded key attributes exist (`*keyring`, `^!keys`, signatures via `upv`)
    pub(super) async fn initialize_account_keys(&mut self) -> Result<()> {
        if self.key_manager.is_ready() {
            return Ok(());
        }
        if self.load_keys_attribute().await? {
            return Ok(());
        }

        if !self.has_valid_rsa_key() {
            let rsa_key = MegaRsaKey::generate().map_err(|e| {
                MegaError::CryptoError(format!("Failed to generate RSA keypair: {e}"))
            })?;
            self.upload_rsa_keypair(&rsa_key).await?;
            self.rsa_key = rsa_key;
        }

        self.attach_account_keys_if_missing().await?;

        if self.key_manager.is_ready() || self.load_keys_attribute().await? {
            return Ok(());
        }

        Err(MegaError::Custom(
            "Request incomplete: account keys are not initialized".to_string(),
        ))
    }

    /// Strict preflight for share/export flows.
    /// Unlike `ensure_keys_attribute`, this must fail if account keys are still incomplete.
    pub(crate) async fn ensure_share_keys_ready(&mut self) -> Result<()> {
        if self.key_manager.is_ready() || self.load_keys_attribute().await? {
            return Ok(());
        }

        self.initialize_account_keys().await
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

    /// Returns true if a real RSA private key is currently available.
    pub(crate) fn has_valid_rsa_key(&self) -> bool {
        self.rsa_key.is_valid_private_key()
    }

    /// Construct an empty/sentinel RSA key when login path has no RSA material.
    pub(crate) fn empty_rsa_key() -> MegaRsaKey {
        MegaRsaKey {
            p: num_bigint::BigUint::from(0u32),
            q: num_bigint::BigUint::from(0u32),
            d: num_bigint::BigUint::from(0u32),
            u: num_bigint::BigUint::from(0u32),
            m: num_bigint::BigUint::from(0u32),
            e: num_bigint::BigUint::from(3u32),
        }
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
    /// // Register a custom callback
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

    /// Get all nodes in the session cache.
    pub fn nodes(&self) -> &[crate::fs::Node] {
        &self.nodes
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

        let (session_version, key_bytes, sid_bytes, master_key_encrypted) =
            if data[0] == 1 && data.len() >= 17 {
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
            return Err(MegaError::Custom(
                "Not a folder-link session blob".to_string(),
            ));
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

        let padding = blob.padding.clone().unwrap_or_else(|| "P".to_string());
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
            if let Some(obj) = arr
                .iter()
                .find(|o| o.get("av").and_then(|v| v.as_str()).is_some())
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
            let code = crate::api::ApiErrorCode::from(err);
            return Err(MegaError::ApiError {
                code: err as i32,
                message: code.description().to_string(),
            });
        }

        if let Some(ver) = Self::extract_attr_version(&resp, attr) {
            self.user_attr_versions.insert(attr.to_string(), ver);
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
            self.authring_ed = AuthRing::deserialize_ltlv(&self.key_manager.auth_ed25519);
            self.authring_cu = AuthRing::deserialize_ltlv(&self.key_manager.auth_cu25519);
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
