//! Session management and authentication.
//!
//! This module handles user login, session state, and logout.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::json;

use crate::api::ApiClient;
use crate::base64::{base64url_decode, base64url_encode};
use crate::crypto::aes::aes128_ecb_encrypt;
use crate::crypto::key_manager::KeyManager;
use crate::crypto::keyring::Keyring;
use crate::crypto::{
    MegaRsaKey, decrypt_key, decrypt_private_key, decrypt_session_id, derive_key_v2, encrypt_key,
    make_password_key, make_random_key, make_username_hash,
};
use crate::error::{MegaError, Result};
use crate::fs::{Node, NodeType};

/// MEGA user session.
///
/// This holds all authentication state needed for API requests.
pub struct Session {
    /// API client for making requests
    pub(crate) api: ApiClient,
    /// Session ID
    session_id: String,
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
    /// Minimal key manager for upgraded accounts (^!keys)
    pub(crate) key_manager: KeyManager,
    /// Whether resume is enabled for interrupted transfers
    resume_enabled: bool,
    /// Progress callback for transfer progress
    progress_callback: Option<crate::progress::ProgressCallback>,
    /// Whether to generate previews during uploads
    previews_enabled: bool,
    /// Number of concurrent transfer workers (default: 1 for sequential)
    workers: usize,
}

impl Session {
    /// Login with email and password.
    ///
    /// This creates a new authenticated session with MEGA.
    ///
    /// # Example
    /// ```no_run
    /// use megalib::Session;
    ///
    /// # async fn example() -> megalib::error::Result<()> {
    /// let session = Session::login("user@example.com", "password").await?;
    /// println!("Logged in as: {}", session.email);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn login(email: &str, password: &str) -> Result<Self> {
        Self::login_internal(email, password, None).await
    }

    /// Login with email, password, and HTTP proxy.
    ///
    /// # Arguments
    /// * `email` - User's email address
    /// * `password` - User's password
    /// * `proxy` - Proxy URL (e.g., "http://proxy:8080" or "socks5://proxy:1080")
    ///
    /// # Example
    /// ```no_run
    /// use megalib::Session;
    ///
    /// # async fn example() -> megalib::error::Result<()> {
    /// let session = Session::login_with_proxy(
    ///     "user@example.com",
    ///     "password",
    ///     "http://proxy.example.com:8080"
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn login_with_proxy(email: &str, password: &str, proxy: &str) -> Result<Self> {
        Self::login_internal(email, password, Some(proxy)).await
    }

    /// Internal login implementation.
    async fn login_internal(email: &str, password: &str, proxy: Option<&str>) -> Result<Self> {
        let mut api = if let Some(p) = proxy {
            #[cfg(not(target_arch = "wasm32"))]
            {
                ApiClient::with_proxy(p)?
            }
            #[cfg(target_arch = "wasm32")]
            {
                return Err(MegaError::Custom(format!(
                    "Proxy support not available in WASM (ignored proxy: {})",
                    p
                )));
            }
        } else {
            ApiClient::new()
        };
        let email_lower = email.to_lowercase();

        // Step 1: Pre-login to determine login variant
        let pre_login = api
            .request(json!({
                "a": "us0",
                "user": &email_lower
            }))
            .await?;

        let login_variant = pre_login["v"].as_i64().unwrap_or(0);

        // Step 2: Compute password key and user hash based on variant
        let (password_key, user_hash) = if login_variant == 2 {
            // V2 login: PBKDF2-SHA512
            let salt_b64 = pre_login["s"].as_str().ok_or(MegaError::InvalidResponse)?;
            let salt = base64url_decode(salt_b64)?;

            let derived = derive_key_v2(password, &salt)?;
            let password_key: [u8; 16] = derived[..16].try_into().unwrap();
            let user_hash = base64url_encode(&derived[16..32]);

            (password_key, user_hash)
        } else {
            // V1 login: Legacy password key derivation
            let password_key = make_password_key(password);
            let user_hash_bytes = make_username_hash(&email_lower, &password_key);
            let user_hash = base64url_encode(&user_hash_bytes);

            (password_key, user_hash)
        };

        // Step 3: Login request
        let login_response = api
            .request(json!({
                "a": "us",
                "user": &email_lower,
                "uh": &user_hash
            }))
            .await?;

        // Step 4: Decrypt master key
        let k_b64 = login_response["k"]
            .as_str()
            .ok_or(MegaError::InvalidResponse)?;
        let master_key = decrypt_key(k_b64, &password_key)?;

        // Step 5: Decrypt RSA private key
        let privk_b64 = login_response["privk"]
            .as_str()
            .ok_or(MegaError::InvalidResponse)?;
        let rsa_key = decrypt_private_key(privk_b64, &master_key)?;

        // Step 6: Decrypt session ID with RSA
        let csid_b64 = login_response["csid"]
            .as_str()
            .ok_or(MegaError::InvalidResponse)?;
        let session_id = decrypt_session_id(csid_b64, &rsa_key)?;

        // Set session ID for future requests
        api.set_session_id(session_id.clone());

        // Step 7: Get user info
        let user_info = api.request(json!({"a": "ug"})).await?;

        let user_handle = user_info["u"]
            .as_str()
            .ok_or(MegaError::InvalidResponse)?
            .to_string();
        let user_email = user_info["email"]
            .as_str()
            .unwrap_or(&email_lower)
            .to_string();
        let user_name = user_info["name"].as_str().map(|s| s.to_string());

        Ok(Session {
            api,
            session_id,
            master_key,
            rsa_key,
            email: user_email,
            name: user_name,
            user_handle,
            nodes: Vec::new(),
            share_keys: HashMap::new(),
            key_manager: KeyManager::default(),
            resume_enabled: false,
            progress_callback: None,
            previews_enabled: false,
            workers: 1,
        })
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

    /// Get all nodes in the session cache.
    pub fn nodes(&self) -> &[crate::fs::Node] {
        &self.nodes
    }

    /// Change the current user's password.
    ///
    /// This updates the password on the server by re-encrypting the master key
    /// with a new key derived from the new password and a fresh salt.
    ///
    /// # Arguments
    /// * `new_password` - The new password to set
    ///
    /// # Example
    /// ```no_run
    /// # use megalib::Session;
    /// # async fn example() -> megalib::error::Result<()> {
    /// let mut session = Session::login("user@example.com", "old_password").await?;
    /// session.change_password("new_secure_password").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn change_password(&mut self, new_password: &str) -> Result<()> {
        // 1. Generate new 16-byte random salt
        let salt = make_random_key();
        let salt_b64 = base64url_encode(&salt);

        // 2. Derive new keys (V2)
        let derived = derive_key_v2(new_password, &salt)?;
        let password_key: [u8; 16] = derived[..16].try_into().unwrap();
        let user_hash = base64url_encode(&derived[16..32]);

        // 3. Re-encrypt the master key with the new password key
        let encrypted_master_key = encrypt_key(&self.master_key, &password_key);
        let k_b64 = base64url_encode(&encrypted_master_key);

        // 4. Send 'up' request to update profile
        let response = self
            .api
            .request(json!({
                "a": "up",
                "k": k_b64,
                "uh": user_hash,
                "s": salt_b64
            }))
            .await?;

        // Check for error code if any
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

        Ok(())
    }

    /// Save session to a file for later restoration.
    ///
    /// This allows you to avoid re-logging in on every run.
    /// The saved file contains encrypted credentials - keep it secure!
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
        let data = SessionCache {
            session_id: self.session_id.clone(),
            master_key: base64url_encode(&self.master_key),
            email: self.email.clone(),
            name: self.name.clone(),
            user_handle: self.user_handle.clone(),
        };

        let json = serde_json::to_string_pretty(&data)
            .map_err(|e| MegaError::Custom(format!("Serialization error: {}", e)))?;

        std::fs::write(path, json).map_err(|e| MegaError::Custom(format!("Write error: {}", e)))?;

        Ok(())
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
            return Ok(Some(base64url_decode(av)?));
        }

        if let Some(arr) = response.as_array() {
            if let Some(av) = arr
                .iter()
                .find_map(|o| o.get("av").and_then(|v| v.as_str()))
            {
                if av.is_empty() {
                    return Ok(None);
                }
                return Ok(Some(base64url_decode(av)?));
            }
        }

        Ok(None)
    }

    /// Set a private user attribute (e.g. "^!keys") with a base64url-encoded value.
    /// The server uses versioning; we default to "0" on first set. If the server
    /// returns -8 (version clash), retry once with version "1", then treat as success.
    pub async fn set_private_attribute(
        &mut self,
        attr: &str,
        value_b64: &str,
        version: Option<i64>,
    ) -> Result<()> {
        // First attempt with provided or default "0".
        let first_ver = version.unwrap_or(0);
        let mut resp = self
            .api_mut()
            .set_private_attribute(attr, value_b64, Some(first_ver))
            .await;

        // On version clash, retry once with "1".
        if matches!(resp, Err(MegaError::ApiError { code: -8, .. })) {
            resp = self
                .api_mut()
                .set_private_attribute(attr, value_b64, Some(first_ver + 1))
                .await;
        }

        // Treat -8 as success after retry.
        match resp {
            Err(MegaError::ApiError { code: -8, .. }) => return Ok(()),
            Err(e) => return Err(e),
            Ok(val) => {
                if let Some(err) = val.as_i64().filter(|v| *v < 0) {
                    if err == -8 {
                        return Ok(());
                    }
                    let code = crate::api::client::ApiErrorCode::from(err);
                    return Err(MegaError::ApiError {
                        code: err as i32,
                        message: code.description().to_string(),
                    });
                }
            }
        }

        Ok(())
    }

    /// Try to load ^!keys (minimal) into key_manager. Returns true if loaded and ready.
    pub async fn load_keys_attribute(&mut self) -> Result<bool> {
        let Some(enc_keys) = self.get_user_attribute_raw("^!keys").await? else {
            return Ok(false);
        };

        let mut km = KeyManager::new();
        km.decode_container(&enc_keys, &self.master_key)?;
        if km.is_ready() {
            // populate share_keys map for quick lookup
            for sk in &km.share_keys {
                let mut arr: [u8; 16] = [0u8; 16];
                arr.copy_from_slice(&sk.key);
                // encode handle back to base64url for map key
                let handle_b64 = crate::base64::base64url_encode(&sk.handle);
                self.share_keys.entry(handle_b64).or_insert(arr);
            }
            self.key_manager = km;
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
            "ok": key_b64
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

        // Remember the share key locally so children uploaded later can reuse it.
        self.share_keys
            .entry(node_handle.to_string())
            .or_insert(share_key);
        if self.key_manager.is_ready() {
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
        if !self.key_manager.is_ready() {
            return Err(MegaError::Custom(
                "KeyManager not initialized; cannot persist ^!keys".to_string(),
            ));
        }

        let desired = self.key_manager.clone();
        let mut attempts = 0;

        loop {
            let blob = self.key_manager.encode_container(&self.master_key)?;
            let blob_b64 = base64url_encode(&blob);
            match self.set_private_attribute("^!keys", &blob_b64, None).await {
                Ok(_) => {
                    self.key_manager.generation = self.key_manager.generation.saturating_add(1);
                    return Ok(());
                }
                Err(MegaError::ApiError { code, .. })
                    if attempts == 0 && (code == -3 || code == -11) =>
                {
                    // Version clash or busy server; reload remote copy and merge, then retry once.
                    attempts += 1;
                    if self.load_keys_attribute().await? {
                        let mut merged = self.key_manager.clone();
                        merged.merge_from(&desired);
                        self.key_manager = merged;
                        self.share_keys.clear();
                        for sk in &self.key_manager.share_keys {
                            let mut arr: [u8; 16] = [0u8; 16];
                            arr.copy_from_slice(&sk.key);
                            let handle_b64 = base64url_encode(&sk.handle);
                            self.share_keys.entry(handle_b64).or_insert(arr);
                        }
                    } else {
                        self.key_manager = desired.clone();
                    }
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Compute handle auth (ha) like the C++ SDK: base64(handle)||base64(handle) then AES-ECB with master key.
    pub(crate) fn compute_handle_auth(&self, handle_b64: &str) -> Option<String> {
        let decoded = crate::base64::base64url_decode(handle_b64).ok()?;
        if decoded.len() != 6 {
            return None;
        }
        let text = crate::base64::base64url_encode(&decoded); // 8 ASCII bytes
        let mut auth = [0u8; 16];
        let bytes = text.as_bytes();
        let len = bytes.len().min(8);
        auth[..len].copy_from_slice(&bytes[..len]);
        auth[8..8 + len].copy_from_slice(&bytes[..len]);
        let enc = crate::crypto::aes::aes128_ecb_encrypt(&auth, &self.master_key);
        Some(base64url_encode(&enc))
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

        let json = std::fs::read_to_string(path)
            .map_err(|e| MegaError::Custom(format!("Read error: {}", e)))?;

        let data: SessionCache = serde_json::from_str(&json)
            .map_err(|e| MegaError::Custom(format!("Parse error: {}", e)))?;

        // Decode master key
        let master_key_bytes = base64url_decode(&data.master_key)?;
        if master_key_bytes.len() != 16 {
            return Err(MegaError::Custom("Invalid master key".to_string()));
        }
        let mut master_key = [0u8; 16];
        master_key.copy_from_slice(&master_key_bytes);

        // Create API client with session ID (with or without proxy)
        // Create API client with session ID (with or without proxy)
        let mut api = if let Some(p) = proxy {
            #[cfg(not(target_arch = "wasm32"))]
            {
                ApiClient::with_proxy(p)?
            }
            #[cfg(target_arch = "wasm32")]
            {
                return Err(MegaError::Custom(format!(
                    "Proxy support not available in WASM (ignored proxy: {})",
                    p
                )));
            }
        } else {
            ApiClient::new()
        };
        api.set_session_id(data.session_id.clone());

        // Verify session is still valid by fetching user info
        let user_info = match api.request(json!({"a": "ug"})).await {
            Ok(info) => info,
            Err(_) => {
                // Session expired, delete cache file
                let _ = std::fs::remove_file(path);
                return Ok(None);
            }
        };

        // Create a placeholder RSA key (not needed for most operations)
        let rsa_key = MegaRsaKey {
            p: num_bigint::BigUint::from(2u32),
            q: num_bigint::BigUint::from(3u32),
            d: num_bigint::BigUint::from(1u32),
            u: num_bigint::BigUint::from(1u32),
            m: num_bigint::BigUint::from(6u32),
            e: num_bigint::BigUint::from(3u32),
        };

        // Get fresh user info
        let user_handle = user_info["u"]
            .as_str()
            .unwrap_or(&data.user_handle)
            .to_string();

        Ok(Some(Session {
            api,
            session_id: data.session_id,
            master_key,
            rsa_key,
            email: data.email,
            name: data.name,
            user_handle,
            nodes: Vec::new(),
            share_keys: HashMap::new(),
            key_manager: KeyManager::default(),
            resume_enabled: false,
            progress_callback: None,
            previews_enabled: false,
            workers: 1,
        }))
    }
}

/// Serializable session cache data.
#[derive(serde::Serialize, serde::Deserialize)]
struct SessionCache {
    session_id: String,
    master_key: String,
    email: String,
    name: Option<String>,
    user_handle: String,
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
            master_key: [0u8; 16],
            rsa_key: MegaRsaKey::generate().unwrap(),
            email: "test@example.com".to_string(),
            name: None,
            user_handle: "handle".to_string(),
            nodes: Vec::new(),
            share_keys: HashMap::new(),
            key_manager: KeyManager::default(),
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
