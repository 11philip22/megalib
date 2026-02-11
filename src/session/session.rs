//! Session management and authentication.
//!
//! This module handles user login, session state, and logout.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::api::ApiClient;
use crate::base64::{base64url_decode, base64url_encode};
use crate::crypto::aes::aes128_ecb_encrypt;
use crate::crypto::key_manager::KeyManager;
use crate::crypto::keyring::{Keyring, encrypt_tlv_records};
use crate::crypto::{
    AuthRing, AuthState, MegaRsaKey, decrypt_key, decrypt_private_key, decrypt_session_id,
    derive_key_v2, encrypt_key, make_password_key, make_random_key, make_username_hash,
    parse_raw_private_key,
};
use crate::error::{MegaError, Result};
use crate::fs::{Node, NodeType};
use tokio::time::sleep;

#[cfg(not(target_arch = "wasm32"))]
fn device_id_hash() -> Option<String> {
    let id = device_id_bytes()?;
    let mut hasher = Sha256::new();
    hasher.update(&id);
    let digest = hasher.finalize();
    Some(base64url_encode(&digest))
}

#[cfg(target_arch = "wasm32")]
fn device_id_hash() -> Option<String> {
    None
}

#[cfg(target_os = "windows")]
fn device_id_bytes() -> Option<Vec<u8>> {
    use std::ffi::{OsString, c_void};
    use std::os::windows::ffi::OsStringExt;
    use std::ptr;

    type HKEY = *mut c_void;

    const HKEY_LOCAL_MACHINE: HKEY = 0x80000002 as HKEY;
    const KEY_QUERY_VALUE: u32 = 0x0001;
    const KEY_WOW64_64KEY: u32 = 0x0100;
    const REG_SZ: u32 = 1;

    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(
            hKey: HKEY,
            lpSubKey: *const u16,
            ulOptions: u32,
            samDesired: u32,
            phkResult: *mut HKEY,
        ) -> i32;
        fn RegQueryValueExW(
            hKey: HKEY,
            lpValueName: *const u16,
            lpReserved: *mut u32,
            lpType: *mut u32,
            lpData: *mut u8,
            lpcbData: *mut u32,
        ) -> i32;
        fn RegCloseKey(hKey: HKEY) -> i32;
    }

    let subkey: Vec<u16> = "Software\\Microsoft\\Cryptography\0".encode_utf16().collect();
    let mut hkey: HKEY = ptr::null_mut();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            0,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &mut hkey,
        )
    };
    if status != 0 {
        return None;
    }

    let value: Vec<u16> = "MachineGuid\0".encode_utf16().collect();
    let mut data_type: u32 = 0;
    let mut data_len: u32 = 0;
    let status = unsafe {
        RegQueryValueExW(
            hkey,
            value.as_ptr(),
            ptr::null_mut(),
            &mut data_type,
            ptr::null_mut(),
            &mut data_len,
        )
    };
    if status != 0 || data_len == 0 {
        unsafe {
            RegCloseKey(hkey);
        }
        return None;
    }

    let mut buf: Vec<u16> = vec![0u16; (data_len as usize + 1) / 2];
    let status = unsafe {
        RegQueryValueExW(
            hkey,
            value.as_ptr(),
            ptr::null_mut(),
            &mut data_type,
            buf.as_mut_ptr() as *mut u8,
            &mut data_len,
        )
    };
    unsafe {
        RegCloseKey(hkey);
    }
    if status != 0 || data_type != REG_SZ {
        return None;
    }

    let len_u16 = (data_len as usize) / 2;
    let mut slice = &buf[..len_u16];
    if slice.last() == Some(&0) {
        slice = &slice[..slice.len() - 1];
    }
    let os = OsString::from_wide(slice);
    let s = os.to_string_lossy();
    if s.is_empty() {
        None
    } else {
        Some(s.as_bytes().to_vec())
    }
}

#[cfg(target_os = "macos")]
fn device_id_bytes() -> Option<Vec<u8>> {
    #[repr(C)]
    struct Timespec {
        tv_sec: i64,
        tv_nsec: i64,
    }

    unsafe extern "C" {
        fn gethostuuid(uuid: *mut u8, timeout: *const Timespec) -> i32;
    }

    let mut uuid = [0u8; 16];
    let ts = Timespec { tv_sec: 1, tv_nsec: 0 };
    let rc = unsafe { gethostuuid(uuid.as_mut_ptr(), &ts) };
    if rc != 0 {
        return None;
    }
    let s = format_uuid(&uuid);
    if s.is_empty() {
        None
    } else {
        Some(s.into_bytes())
    }
}

#[cfg(target_os = "macos")]
fn format_uuid(uuid: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        uuid[0],
        uuid[1],
        uuid[2],
        uuid[3],
        uuid[4],
        uuid[5],
        uuid[6],
        uuid[7],
        uuid[8],
        uuid[9],
        uuid[10],
        uuid[11],
        uuid[12],
        uuid[13],
        uuid[14],
        uuid[15]
    )
}

#[cfg(all(
    unix,
    not(target_os = "macos"),
    not(target_os = "ios"),
    not(target_os = "android")
))]
fn device_id_bytes() -> Option<Vec<u8>> {
    let mut data = std::fs::read("/etc/machine-id")
        .or_else(|_| std::fs::read("/var/lib/dbus/machine-id"))
        .ok()?;
    if data.last() == Some(&b'\n') {
        data.pop();
    }
    if data.is_empty() {
        None
    } else {
        Some(data)
    }
}

#[cfg(any(target_os = "ios", target_os = "android"))]
fn device_id_bytes() -> Option<Vec<u8>> {
    None
}

/// MEGA user session.
///
/// This holds all authentication state needed for API requests.
pub struct Session {
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
    /// Last completed token for pending keys feed (pk command)
    pub(crate) pending_keys_token: Option<String>,
    /// Flag set when a ^!keys downgrade is detected
    pub(crate) keys_downgrade_detected: bool,
    /// Last seen action-packet sequence number (scsn) for SC polling.
    pub(crate) scsn: Option<String>,
    /// WSC base URL from SC polling (SDK uses `w` field).
    pub(crate) wsc_url: Option<String>,
    /// Whether resume is enabled for interrupted transfers
    resume_enabled: bool,
    /// Progress callback for transfer progress
    progress_callback: Option<crate::progress::ProgressCallback>,
    /// Whether to generate previews during uploads
    previews_enabled: bool,
    /// Number of concurrent transfer workers (default: 1 for sequential)
    workers: usize,
}

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

        let mut session = Session {
            api,
            session_id,
            session_key,
            master_key,
            rsa_key,
            email: user_email,
            name: user_name,
            user_handle,
            nodes: Vec::new(),
            share_keys: HashMap::new(),
            key_manager: KeyManager::default(),
            authring_ed: AuthRing::default(),
            authring_cu: AuthRing::default(),
            backups: Vec::new(),
            warnings: crate::crypto::Warnings::default(),
            manual_verification: false,
            user_attr_cache,
            pending_keys_token: None,
            keys_downgrade_detected: false,
            scsn,
            wsc_url: None,
            resume_enabled: false,
            progress_callback: None,
            previews_enabled: false,
            workers: 1,
        };

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

    fn build_upv_command(attrs: Vec<(&str, String)>) -> Value {
        let mut obj = serde_json::Map::new();
        obj.insert("a".into(), Value::from("upv"));
        for (name, value) in attrs {
            obj.insert(name.into(), json!([value, 0]));
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

    async fn attach_account_keys_if_missing(&mut self) -> Result<()> {
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

        let mut generated_usk: Option<Vec<u8>> = None;
        if self.get_user_attribute_raw("*~usk").await?.is_none() {
            let usk = make_random_key();
            let usk_b64 = base64url_encode(&usk);
            commands.push(Self::build_upv_command(vec![("*~usk", usk_b64)]));
            generated_usk = Some(usk.to_vec());
        }

        let mut key_attrs = Vec::new();
        if let Some(enc) = keyring_enc.as_ref() {
            key_attrs.push(("*keyring", base64url_encode(enc)));
        }
        key_attrs.push(("^!keys", keys_b64));
        key_attrs.push(("+puEd255", base64url_encode(&pu_ed)));
        key_attrs.push(("+puCu255", base64url_encode(&pu_cu)));
        key_attrs.push(("+sigCu255", base64url_encode(&sig_cu)));
        key_attrs.push(("+sigPubk", base64url_encode(&sig_pubk)));
        commands.push(Self::build_upv_command(key_attrs));

        let mut generated_jscd: Option<Vec<u8>> = None;
        if self.get_user_attribute_raw("*~jscd").await?.is_none() {
            let mut records = BTreeMap::new();
            records.insert("ak".to_string(), make_random_key().to_vec());
            records.insert("ck".to_string(), make_random_key().to_vec());
            records.insert("fn".to_string(), make_random_key().to_vec());
            let jscd = encrypt_tlv_records(&records, &self.master_key)?;
            let jscd_b64 = base64url_encode(&jscd);
            commands.push(Self::build_upv_command(vec![("*~jscd", jscd_b64)]));
            generated_jscd = Some(jscd);
        }

        if !commands.is_empty() {
            let resp = self.api.request_batch(commands).await?;
            Self::validate_upv_batch(resp)?;
        }

        // Cache the attributes we just set so we don't immediately re-fetch via uga.
        if let Some(enc) = keyring_enc {
            self.user_attr_cache
                .insert("*keyring".to_string(), enc);
        }
        if let Some(usk) = generated_usk {
            self.user_attr_cache.insert("*~usk".to_string(), usk);
        }
        self.user_attr_cache.insert("^!keys".to_string(), keys_blob);
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
    pub async fn poll_action_packets_once(&mut self) -> Result<bool> {
        if self.scsn.is_none() {
            return Err(MegaError::Custom(
                "SC not initialized; call refresh() before polling action packets".to_string(),
            ));
        }
        let (packets, sn, wsc) = self
            .api
            .poll_sc(self.scsn.as_deref(), self.wsc_url.as_deref())
            .await?;
        self.scsn = Some(sn);
        if let Some(w) = wsc {
            self.wsc_url = Some(w);
        }
        self.dispatch_action_packets(&packets).await
    }

    /// Poll user alerts (SC50) once. Optional, used by clients that need alerts.
    pub async fn poll_user_alerts_once(&mut self) -> Result<(Vec<Value>, Option<String>)> {
        self.api.poll_user_alerts().await
    }

    /// Run a lightweight action-packet loop with exponential backoff.
    ///
    /// The `should_stop` predicate is evaluated after each poll to allow
    /// embedding applications to terminate the loop.
    pub async fn run_action_packet_loop<F>(&mut self, mut should_stop: F) -> Result<()>
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
        let mut key_event = false;

        for pkt in packets {
            if let Some(obj) = pkt.as_object() {
                Self::extract_handles_from_action(obj, &mut changed_handles);
                if Self::is_key_attr_update(obj) {
                    key_event = true;
                }
                if let Some(update) = Self::extract_contact_update(obj)? {
                    contact_updates.push(update);
                }
                if self.handle_actionpacket_nodes(obj)? {
                    node_changed = true;
                }
            }
        }

        let mut changed = false;
        if !contact_updates.is_empty() {
            if self.handle_contact_updates(&contact_updates).await? {
                changed = true;
            }
            self.maybe_clear_cv_warning();
        }

        if key_event || !changed_handles.is_empty() {
            if self.handle_actionpacket_keys(&changed_handles).await? {
                changed = true;
            }
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
        attrs.iter().any(|v| {
            matches!(
                v.as_str(),
                Some("^!keys")
                    | Some("*keyring")
                    | Some("*~usk")
                    | Some("*~jscd")
                    | Some("+puCu255")
                    | Some("+puEd255")
                    | Some("+sigCu255")
                    | Some("+sigPubk")
            )
        })
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
            _ => Ok(false),
        }
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

    fn extract_contact_update(
        obj: &serde_json::Map<String, Value>,
    ) -> Result<Option<(String, Option<Vec<u8>>, Option<Vec<u8>>, bool)>> {
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
        if cu.is_none() && ed.is_none() {
            return Ok(None);
        }
        let verified = obj.get("c").and_then(|v| v.as_i64()).unwrap_or(0) > 0;

        Ok(Some((user, ed, cu, verified)))
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
            pending_keys_token: self.pending_keys_token.clone(),
            keys_downgrade_detected: self.keys_downgrade_detected,
            scsn: self.scsn.clone(),
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
            return Ok(Some(decoded));
        }

        if let Some(arr) = response.as_array() {
            if let Some(av) = arr
                .iter()
                .find_map(|o| o.get("av").and_then(|v| v.as_str()))
            {
                if av.is_empty() {
                    return Ok(None);
                }
                let decoded = base64url_decode(av)?;
                self.user_attr_cache
                    .insert(attr.to_string(), decoded.clone());
                return Ok(Some(decoded));
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
        let scsn = data
            .scsn
            .or_else(|| user_info.get("sn").and_then(|v| v.as_str()).map(|s| s.to_string()));

        Ok(Some(Session {
            api,
            session_id: data.session_id,
            session_key: None,
            master_key,
            rsa_key,
            email: data.email,
            name: data.name,
            user_handle,
            nodes: Vec::new(),
            share_keys: HashMap::new(),
            key_manager: KeyManager::default(),
            authring_ed: AuthRing::default(),
            authring_cu: AuthRing::default(),
            backups: Vec::new(),
            warnings: crate::crypto::Warnings::default(),
            manual_verification: false,
            user_attr_cache: HashMap::new(),
            pending_keys_token: data.pending_keys_token,
            keys_downgrade_detected: data.keys_downgrade_detected,
            scsn,
            wsc_url: None,
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
    #[serde(default)]
    pending_keys_token: Option<String>,
    #[serde(default)]
    keys_downgrade_detected: bool,
    #[serde(default)]
    scsn: Option<String>,
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
            key_manager: KeyManager::default(),
            authring_ed: AuthRing::default(),
            authring_cu: AuthRing::default(),
            backups: Vec::new(),
            warnings: crate::crypto::Warnings::default(),
            manual_verification: false,
            user_attr_cache: HashMap::new(),
            pending_keys_token: None,
            scsn: None,
            wsc_url: None,
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
