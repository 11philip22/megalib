use std::collections::HashMap;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::api::ApiClient;
use crate::base64::{base64url_decode, base64url_encode};
use crate::crypto::aes::aes128_ecb_decrypt_block;
use crate::crypto::{
    MegaRsaKey, decrypt_key, decrypt_private_key, decrypt_session_id, derive_key_v2, encrypt_key,
    make_password_key, make_random_key, make_username_hash,
};
use crate::error::{MegaError, Result};

use super::device_id::device_id_hash;
use super::session::Session;

#[derive(Debug, Clone, Copy)]
enum UpgradeOutcome {
    NotNeeded,
    Upgraded,
    AlreadyUpgraded,
    Failed,
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
        let mut api = match proxy {
            Some(p) => ApiClient::with_proxy(p)?,
            None => ApiClient::new(),
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

        let sek = make_random_key();
        let sek_b64 = base64url_encode(&sek);
        let si = device_id_hash();
        let mut login_payload = json!({
            "a": "us",
            "user": &email_lower,
            "uh": &user_hash,
            "sek": &sek_b64
        });
        if let Some(si) = si {
            login_payload["si"] = Value::String(si);
        }

        // Step 3: Login request
        let login_response = api.request(login_payload).await?;

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

        let session_key = match login_response.get("sek").and_then(|v| v.as_str()) {
            Some(sek_b64) => {
                let decoded = base64url_decode(sek_b64)?;
                if decoded.len() != 16 {
                    return Err(MegaError::InvalidResponse);
                }
                let mut key = [0u8; 16];
                key.copy_from_slice(&decoded);
                Some(key)
            }
            None => None,
        };

        // Step 6: Decrypt session ID with RSA
        let csid_b64 = login_response["csid"]
            .as_str()
            .ok_or(MegaError::InvalidResponse)?;
        let session_id = decrypt_session_id(csid_b64, &rsa_key)?;

        // Set session ID for future requests
        api.set_session_id(session_id.clone());

        let mut upgrade_outcome = UpgradeOutcome::NotNeeded;
        if login_variant == 1 {
            upgrade_outcome =
                Self::attempt_account_upgrade(&mut api, password, &master_key)
                    .await
                    .unwrap_or(UpgradeOutcome::Failed);

            let mut batch = Vec::new();
            if matches!(upgrade_outcome, UpgradeOutcome::Upgraded) {
                batch.push(json!({
                    "a": "log",
                    "e": 99473,
                    "m": "Account successfully upgraded to v2"
                }));
            }
            batch.push(json!({"a": "uq", "pro": 1, "src": -1, "v": 2}));
            let _ = api.request_batch(batch).await;
        } else {
            api.request_batch(vec![
                json!({"a": "stp"}),
                json!({"a": "uq", "pro": 1, "src": -1, "v": 2})
            ])
            .await?;
        }

        // Step 7: Get user info
        let user_info = api.request(json!({"a": "ug", "v": 1})).await?;

        let user_handle = user_info["u"]
            .as_str()
            .ok_or(MegaError::InvalidResponse)?
            .to_string();
        let user_email = user_info["email"]
            .as_str()
            .unwrap_or(&email_lower)
            .to_string();
        let user_name = user_info["name"].as_str().map(|s| s.to_string());
        let scsn = user_info
            .get("sn")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let user_attr_cache = Self::collect_user_attrs_from_ug(&user_info);
        let user_attr_versions = Self::collect_user_attr_versions_from_ug(&user_info);

        let mut session = Session::new_internal(
            api,
            session_id,
            session_key,
            master_key,
            rsa_key,
            user_email,
            user_name,
            user_handle,
            user_attr_cache,
            user_attr_versions,
            scsn,
        );

        let account_is_v2 = login_variant == 2
            || matches!(
                upgrade_outcome,
                UpgradeOutcome::Upgraded | UpgradeOutcome::AlreadyUpgraded
            );

        if account_is_v2 && !session.user_attr_cache.contains_key("^!keys") {
            let _ = session.attach_account_keys_if_missing().await;
        }

        // On login, attempt to load ^!keys and process pending promotions.
        let _ = session.load_keys_attribute().await;
        let _ = session.promote_pending_shares().await;
        if session.clear_inuse_flags_for_missing_shares() {
            let _ = session.persist_keys_with_retry().await;
        }

        Ok(session)
    }

    fn collect_user_attrs_from_ug(user_info: &Value) -> HashMap<String, Vec<u8>> {
        let mut cache = HashMap::new();
        let Some(obj) = user_info.as_object() else {
            return cache;
        };

        let attrs = [
            "^!keys",
            "*keyring",
            "*~usk",
            "*~jscd",
            "+puCu255",
            "+puEd255",
            "+sigCu255",
            "+sigPubk",
        ];

        for attr in attrs {
            if let Some(av) = obj
                .get(attr)
                .and_then(|v| v.get("av"))
                .and_then(|v| v.as_str())
            {
                if av.is_empty() {
                    continue;
                }
                if let Ok(decoded) = base64url_decode(av) {
                    cache.insert(attr.to_string(), decoded);
                }
            }
        }

        cache
    }

    fn collect_user_attr_versions_from_ug(user_info: &Value) -> HashMap<String, String> {
        let mut versions = HashMap::new();
        let Some(obj) = user_info.as_object() else {
            return versions;
        };

        let attrs = [
            "^!keys",
            "*keyring",
            "*~usk",
            "*~jscd",
            "+puCu255",
            "+puEd255",
            "+sigCu255",
            "+sigPubk",
        ];

        for attr in attrs {
            if let Some(v) = obj
                .get(attr)
                .and_then(|v| v.get("v"))
                .and_then(|v| v.as_str())
            {
                versions.insert(attr.to_string(), v.to_string());
            }
        }

        versions
    }

    fn build_upgrade_payload(
        password: &str,
        master_key: &[u8; 16],
    ) -> Result<(String, String, String)> {
        let client_random = make_random_key();
        let mut buffer = b"mega.nz".to_vec();
        buffer.resize(200, b'P');
        buffer.extend_from_slice(&client_random);
        let salt = Sha256::digest(&buffer);

        let derived = derive_key_v2(password, salt.as_slice())?;
        let password_key: [u8; 16] = derived[..16].try_into().unwrap();
        let auth_key = &derived[16..32];

        let encrypted_master_key = encrypt_key(master_key, &password_key);

        let mut hasher = Sha256::new();
        hasher.update(auth_key);
        let hashed = hasher.finalize();
        let hak = &hashed[..16];

        Ok((
            base64url_encode(&client_random),
            base64url_encode(&encrypted_master_key),
            base64url_encode(hak),
        ))
    }

    async fn attempt_account_upgrade(
        api: &mut ApiClient,
        password: &str,
        master_key: &[u8; 16],
    ) -> Result<UpgradeOutcome> {
        let (crv, emk, hak) = Self::build_upgrade_payload(password, master_key)?;
        let resp = api
            .request_batch(vec![
                json!({"a": "stp"}),
                json!({"a": "avu", "crv": crv, "emk": emk, "hak": hak}),
            ])
            .await?;

        let arr = resp.as_array().ok_or(MegaError::InvalidResponse)?;
        let avu = arr.get(1).ok_or(MegaError::InvalidResponse)?;
        if let Some(code) = avu.as_i64() {
            if code == 0 {
                return Ok(UpgradeOutcome::Upgraded);
            }
            if code == -8 {
                return Ok(UpgradeOutcome::AlreadyUpgraded);
            }
            if code < 0 {
                return Ok(UpgradeOutcome::Failed);
            }
        }

        Ok(UpgradeOutcome::Upgraded)
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
                let error_code = crate::api::ApiErrorCode::from(err_code);
                return Err(MegaError::ApiError {
                    code: err_code as i32,
                    message: error_code.description().to_string(),
                });
            }
        }

        Ok(())
    }

    pub(super) async fn login_with_session(
        session_b64: &str,
        proxy: Option<&str>,
    ) -> Result<Self> {
        let blob = Session::parse_session_blob(session_b64)?;

        let mut api = match proxy {
            Some(p) => ApiClient::with_proxy(p)?,
            None => ApiClient::new(),
        };

        // Use existing session id to validate the session on the server.
        let mut session_id = blob.session_id.clone();
        api.set_session_id(session_id.clone());

        let sek = make_random_key();
        let sek_b64 = base64url_encode(&sek);
        let mut login_payload = json!({
            "a": "us",
            "sek": &sek_b64
        });
        if let Some(si) = device_id_hash() {
            login_payload["si"] = Value::String(si);
        }

        let login_response = api.request(login_payload).await?;

        let session_key = match login_response.get("sek").and_then(|v| v.as_str()) {
            Some(sek_b64) => {
                let decoded = base64url_decode(sek_b64)?;
                if decoded.len() != 16 {
                    return Err(MegaError::InvalidResponse);
                }
                let mut key = [0u8; 16];
                key.copy_from_slice(&decoded);
                Some(key)
            }
            None => None,
        };

        let mut master_key = blob.master_key;
        if blob.master_key_encrypted {
            let sek = session_key.ok_or(MegaError::InvalidResponse)?;
            master_key = aes128_ecb_decrypt_block(&blob.master_key, &sek);
        }

        let rsa_key = if let Some(privk_b64) = login_response.get("privk").and_then(|v| v.as_str()) {
            decrypt_private_key(privk_b64, &master_key)?
        } else {
            MegaRsaKey {
                p: num_bigint::BigUint::from(2u32),
                q: num_bigint::BigUint::from(3u32),
                d: num_bigint::BigUint::from(1u32),
                u: num_bigint::BigUint::from(1u32),
                m: num_bigint::BigUint::from(6u32),
                e: num_bigint::BigUint::from(3u32),
            }
        };

        if let Some(tsid) = login_response.get("tsid").and_then(|v| v.as_str()) {
            session_id = tsid.to_string();
            api.set_session_id(session_id.clone());
        }

        let user_info = api.request(json!({"a": "ug", "v": 1})).await?;

        let user_handle = user_info["u"]
            .as_str()
            .ok_or(MegaError::InvalidResponse)?
            .to_string();
        let user_email = user_info["email"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let user_name = user_info["name"].as_str().map(|s| s.to_string());
        let scsn = user_info
            .get("sn")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let user_attr_cache = Self::collect_user_attrs_from_ug(&user_info);
        let user_attr_versions = Self::collect_user_attr_versions_from_ug(&user_info);

        let mut session = Session::new_internal(
            api,
            session_id,
            session_key,
            master_key,
            rsa_key,
            user_email,
            user_name,
            user_handle,
            user_attr_cache,
            user_attr_versions,
            scsn,
        );

        let account_is_v2 = user_info.get("aav").and_then(|v| v.as_i64()) == Some(2);
        if account_is_v2 && !session.user_attr_cache.contains_key("^!keys") {
            let _ = session.attach_account_keys_if_missing().await;
        }

        let _ = session.load_keys_attribute().await;
        let _ = session.promote_pending_shares().await;
        if session.clear_inuse_flags_for_missing_shares() {
            let _ = session.persist_keys_with_retry().await;
        }

        Ok(session)
    }
}
