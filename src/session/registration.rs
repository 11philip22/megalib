//! Account registration for MEGA.
//!
//! Registration is a two-step process:
//! 1. Call `register()` with email, password, and name - this sends a verification email
//! 2. Call `verify_registration()` with the state from step 1 and the signup key from the email

use serde_json::json;
use sha2::{Digest, Sha256};

use crate::api::ApiClient;
use crate::base64::{base64url_decode, base64url_encode};
use crate::crypto::{aes128_ecb_encrypt, aes128_ecb_encrypt_block, derive_key_v2, make_random_key};
use crate::error::{MegaError, Result};

/// State preserved between registration steps.
///
/// This must be saved after `register()` and passed to `verify_registration()`.
#[derive(Debug, Clone)]
pub struct RegistrationState {
    /// Session key for resuming the signup process.
    ///
    /// Format: `base64(user_handle)#base64(derived_key[0..16])`
    pub session_key: String,
}

impl RegistrationState {
    /// Serialize state for storage between steps.
    ///
    /// Format: `base64(user_handle)#base64(key)`
    pub fn serialize(&self) -> String {
        self.session_key.clone()
    }

    /// Deserialize state from string.
    pub fn deserialize(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split('#').collect();
        if parts.len() != 2 {
            return Err(MegaError::InvalidState(
                "Expected format: handle#key".to_string(),
            ));
        }

        let handle_bytes = base64url_decode(parts[0])?;
        if handle_bytes.len() != 8 {
            return Err(MegaError::InvalidState(
                "User handle must be 8 bytes".to_string(),
            ));
        }

        let key_bytes = base64url_decode(parts[1])?;
        if key_bytes.len() != 16 {
            return Err(MegaError::InvalidState(
                "Resume key must be 16 bytes".to_string(),
            ));
        }

        Ok(Self {
            session_key: s.to_string(),
        })
    }
}

fn build_signup_payload_v2(
    password: &str,
    master_key: &[u8; 16],
) -> Result<(String, String, String, [u8; 32])> {
    let client_random = make_random_key();
    let mut buffer = b"mega.nz".to_vec();
    buffer.resize(200, b'P');
    buffer.extend_from_slice(&client_random);
    let salt = Sha256::digest(&buffer);

    let derived = derive_key_v2(password, salt.as_slice())?;
    let password_key: [u8; 16] = derived[..16].try_into().unwrap();
    let auth_key = &derived[16..32];

    let encrypted_master_key = aes128_ecb_encrypt(master_key, &password_key);

    let mut hasher = Sha256::new();
    hasher.update(auth_key);
    let hashed = hasher.finalize();
    let hak = &hashed[..16];

    Ok((
        base64url_encode(&client_random),
        base64url_encode(&encrypted_master_key),
        base64url_encode(hak),
        derived,
    ))
}

fn extract_confirm_code(signup_key: &str) -> Result<Vec<u8>> {
    let fragment = if let Some(pos) = signup_key.find("confirm") {
        &signup_key[pos + "confirm".len()..]
    } else {
        signup_key
    };

    let decoded = base64url_decode(fragment)?;
    if !decoded
        .windows(b"ConfirmCodeV2".len())
        .any(|window| window == b"ConfirmCodeV2")
    {
        return Err(MegaError::Custom("Invalid confirmation link".to_string()));
    }

    Ok(decoded)
}

/// Step 1: Initiate account registration.
///
/// This creates an anonymous user account and sends a verification email using
/// the v2 signup flow (`uc2`).
/// The returned `RegistrationState` contains the session key required to resume
/// the signup process if needed.
///
/// # Arguments
/// * `email` - Email address for the new account
/// * `password` - Password for the new account
/// * `name` - Display name for the user
///
/// * `proxy` - Optional proxy URL
///
/// # Returns
/// `RegistrationState` that can be used to resume the process if needed
///
/// # Example
/// ```no_run
/// use megalib::session::register;
///
/// # async fn example() -> megalib::error::Result<()> {
/// let state = register("user@example.com", "SecurePassword123", "John Doe", None).await?;
/// println!("Check your email and run verify_registration with the link");
/// println!("State to save (session key): {}", state.serialize());
/// # Ok(())
/// # }
/// ```
pub async fn register(
    email: &str,
    password: &str,
    name: &str,
    proxy: Option<&str>,
) -> Result<RegistrationState> {
    let mut api = match proxy {
        Some(url) => ApiClient::with_proxy(url)?,
        None => ApiClient::new(),
    };

    // 1. Generate cryptographic keys (ephemeral account)
    let master_key = make_random_key();
    let ephemeral_key = make_random_key();

    // ts = ssc || AES(ssc, master_key)
    let ssc = make_random_key();
    let encrypted_ssc = aes128_ecb_encrypt_block(&ssc, &master_key);
    let mut ts_data = [0u8; 32];
    ts_data[..16].copy_from_slice(&ssc);
    ts_data[16..].copy_from_slice(&encrypted_ssc);

    // 2. Create anonymous user: up(k=encrypted_master_key, ts=ts_data)
    let encrypted_master_key = aes128_ecb_encrypt(&master_key, &ephemeral_key);
    let response = api
        .request(json!({
            "a": "up",
            "k": base64url_encode(&encrypted_master_key),
            "ts": base64url_encode(&ts_data)
        }))
        .await?;

    let arr = response.as_array().ok_or(MegaError::InvalidResponse)?;
    if arr.len() < 2 {
        return Err(MegaError::InvalidResponse);
    }
    let user_handle = arr[1]
        .as_str()
        .ok_or(MegaError::InvalidResponse)?
        .to_string();

    // 3. Login as anonymous user: us(user=user_handle)
    let response = api
        .request(json!({
            "a": "us",
            "user": &user_handle
        }))
        .await?;

    let tsid = response["tsid"]
        .as_str()
        .ok_or(MegaError::InvalidResponse)?;
    api.set_session_id(tsid.to_string());

    // 4. Get user info (required by some clients)
    api.request(json!({"a": "ug"})).await?;

    // 5. Request signup link: uc2(n=name, m=email, crv, hak, k, v=2)
    let (crv, emk, hak, derived_key) = build_signup_payload_v2(password, &master_key)?;
    api.request(json!({
        "a": "uc2",
        "n": base64url_encode(name.as_bytes()),
        "m": base64url_encode(email.as_bytes()),
        "crv": crv,
        "hak": hak,
        "k": emk,
        "v": 2
    }))
    .await?;

    let session_key = format!("{}#{}", user_handle, base64url_encode(&derived_key[..16]));

    Ok(RegistrationState { session_key })
}

/// Step 2: Complete registration with verification link.
///
/// This verifies the email address using the v2 signup flow (`ud2`).
/// The session key in `RegistrationState` is kept for compatibility but is not
/// required for confirmation.
///
/// # Arguments
/// * `state` - The `RegistrationState` from `register()`
/// * `signup_key` - Confirmation link (full URL) or base64 fragment from the email
/// * `proxy` - Optional proxy URL
///
/// # Example
/// ```no_run
/// use megalib::session::{verify_registration, RegistrationState};
///
/// # async fn example() -> megalib::error::Result<()> {
/// let state = RegistrationState::deserialize("...")?;
/// let signup_key = "https://mega.app/#confirm..."; // From email link
/// verify_registration(&state, signup_key, None).await?;
/// println!("Account registered successfully!");
/// # Ok(())
/// # }
/// ```
pub async fn verify_registration(
    _state: &RegistrationState,
    signup_key: &str,
    proxy: Option<&str>,
) -> Result<()> {
    let mut api = match proxy {
        Some(url) => ApiClient::with_proxy(url)?,
        None => ApiClient::new(),
    };

    // 1. Normalize and decode the confirmation code
    let code = extract_confirm_code(signup_key)?;

    // 2. Verify signup: ud2(c=code)
    // Returns: [email, name, handle, version]
    let response = api
        .request(json!({
            "a": "ud2",
            "c": base64url_encode(&code)
        }))
        .await?;

    let wrapper = response.as_array().ok_or(MegaError::InvalidResponse)?;
    if wrapper.len() != 2 || !wrapper[0].is_string() {
        return Err(MegaError::InvalidResponse);
    }
    let payload = wrapper[1].as_array().ok_or(MegaError::InvalidResponse)?;
    if payload.len() != 4 {
        return Err(MegaError::InvalidResponse);
    }

    let _b64_email = payload[0].as_str().ok_or(MegaError::InvalidResponse)?;
    let _b64_name = payload[1].as_str().ok_or(MegaError::InvalidResponse)?;
    let _handle = payload[2].as_str().ok_or(MegaError::InvalidResponse)?;
    let version = payload[3].as_i64().ok_or(MegaError::InvalidResponse)?;
    if version != 2 {
        return Err(MegaError::InvalidResponse);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_serialization_roundtrip() {
        let handle = [1u8; 8];
        let key = [2u8; 16];
        let session_key = format!("{}#{}", base64url_encode(&handle), base64url_encode(&key));
        let state = RegistrationState { session_key };

        let serialized = state.serialize();
        let deserialized = RegistrationState::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.session_key, state.session_key);
    }

    #[test]
    fn test_state_deserialization_invalid() {
        assert!(RegistrationState::deserialize("").is_err());
        assert!(RegistrationState::deserialize("invalid").is_err());
        assert!(RegistrationState::deserialize("a:b").is_err());
        assert!(RegistrationState::deserialize("a:b:c:d").is_err());
        assert!(RegistrationState::deserialize("abcd#efgh").is_err());
    }
}
