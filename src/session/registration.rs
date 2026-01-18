//! Account registration for MEGA.
//!
//! Registration is a two-step process:
//! 1. Call `register()` with email, password, and name - this sends a verification email
//! 2. Call `verify_registration()` with the state from step 1 and the signup key from the email

use rand::RngCore;
use serde_json::json;

use crate::api::ApiClient;
use crate::base64::{base64url_decode, base64url_encode};
use crate::crypto::{
    aes128_ecb_decrypt, aes128_ecb_encrypt, aes128_ecb_encrypt_block, make_password_key,
    make_random_key, make_username_hash, MegaRsaKey,
};
use crate::error::{MegaError, Result};

/// State preserved between registration steps.
///
/// This must be saved after `register()` and passed to `verify_registration()`.
#[derive(Debug, Clone)]
pub struct RegistrationState {
    /// Temporary user handle assigned by MEGA
    pub user_handle: String,
    /// Password-derived key (16 bytes)
    pub password_key: [u8; 16],
    /// Challenge for email verification (16 bytes)
    pub challenge: [u8; 16],
}

impl RegistrationState {
    /// Serialize state for storage between steps.
    ///
    /// Format: `base64(password_key):base64(challenge):user_handle`
    pub fn serialize(&self) -> String {
        format!(
            "{}:{}:{}",
            base64url_encode(&self.password_key),
            base64url_encode(&self.challenge),
            self.user_handle
        )
    }

    /// Deserialize state from string.
    pub fn deserialize(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 3 {
            return Err(MegaError::InvalidState(
                "Expected format: pk:challenge:handle".to_string(),
            ));
        }

        let password_key_bytes = base64url_decode(parts[0])?;
        let challenge_bytes = base64url_decode(parts[1])?;

        if password_key_bytes.len() != 16 {
            return Err(MegaError::InvalidState(
                "Password key must be 16 bytes".to_string(),
            ));
        }
        if challenge_bytes.len() != 16 {
            return Err(MegaError::InvalidState(
                "Challenge must be 16 bytes".to_string(),
            ));
        }

        let mut password_key = [0u8; 16];
        let mut challenge = [0u8; 16];
        password_key.copy_from_slice(&password_key_bytes);
        challenge.copy_from_slice(&challenge_bytes);

        Ok(Self {
            user_handle: parts[2].to_string(),
            password_key,
            challenge,
        })
    }
}

/// Step 1: Initiate account registration.
///
/// This creates an anonymous user account and sends a verification email.
/// The returned `RegistrationState` must be preserved and used in `verify_registration()`.
///
/// # Arguments
/// * `email` - Email address for the new account
/// * `password` - Password for the new account
/// * `name` - Display name for the user
///
/// * `proxy` - Optional proxy URL
///
/// # Returns
/// `RegistrationState` that must be passed to `verify_registration()`
///
/// # Example
/// ```no_run
/// use megalib::session::register;
///
/// # async fn example() -> megalib::error::Result<()> {
/// let state = register("user@example.com", "SecurePassword123", "John Doe", None).await?;
/// println!("Check your email and run verify_registration with the link");
/// println!("State to save: {}", state.serialize());
/// # Ok(())
/// # }
/// ```
pub async fn register(
    email: &str,
    password: &str,
    name: &str,
    proxy: Option<&str>,
) -> Result<RegistrationState> {
    #[cfg(not(target_arch = "wasm32"))]
    let mut api = match proxy {
        Some(url) => ApiClient::with_proxy(url)?,
        None => ApiClient::new(),
    };

    #[cfg(target_arch = "wasm32")]
    let mut api = ApiClient::new();

    // 1. Generate cryptographic keys
    let master_key = make_random_key();
    let password_key = make_password_key(password);
    let ssc = make_random_key(); // Session self-challenge

    // 2. Create ts = ssc || AES(ssc, master_key)
    let encrypted_ssc = aes128_ecb_encrypt_block(&ssc, &master_key);
    let mut ts_data = [0u8; 32];
    ts_data[..16].copy_from_slice(&ssc);
    ts_data[16..].copy_from_slice(&encrypted_ssc);

    // 3. Create anonymous user: up(k=encrypted_master_key, ts=ts_data)
    let encrypted_master_key = aes128_ecb_encrypt(&master_key, &password_key);
    let response = api
        .request(json!({
            "a": "up",
            "k": base64url_encode(&encrypted_master_key),
            "ts": base64url_encode(&ts_data)
        }))
        .await?;

    let user_handle = response
        .as_str()
        .ok_or(MegaError::InvalidResponse)?
        .to_string();

    // 4. Login as anonymous user: us(user=user_handle)
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

    // 5. Get user info (required step)
    api.request(json!({"a": "ug"})).await?;

    // 6. Set user name: up(name=name)
    api.request(json!({
        "a": "up",
        "name": name
    }))
    .await?;

    // 7. Request signup link: uc(c=encrypted_challenge, n=name, m=email)
    // c_data = master_key || challenge
    let mut challenge = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut challenge[..4]);
    rand::thread_rng().fill_bytes(&mut challenge[12..]);

    let mut c_data = [0u8; 32];
    c_data[..16].copy_from_slice(&master_key);
    c_data[16..].copy_from_slice(&challenge);

    let encrypted_c = aes128_ecb_encrypt(&c_data, &password_key);

    api.request(json!({
        "a": "uc",
        "c": base64url_encode(&encrypted_c),
        "n": base64url_encode(name.as_bytes()),
        "m": base64url_encode(email.as_bytes())
    }))
    .await?;

    Ok(RegistrationState {
        user_handle,
        password_key,
        challenge,
    })
}

/// Step 2: Complete registration with verification link.
///
/// This verifies the email address and sets up the RSA keys for the account.
///
/// # Arguments
/// * `state` - The `RegistrationState` from `register()`
/// * `signup_key` - The signup key from the verification email link
/// * `proxy` - Optional proxy URL
///
/// # Example
/// ```no_run
/// use megalib::session::{verify_registration, RegistrationState};
///
/// # async fn example() -> megalib::error::Result<()> {
/// let state = RegistrationState::deserialize("...")?;
/// let signup_key = "..."; // From email link
/// verify_registration(&state, signup_key, None).await?;
/// println!("Account registered successfully!");
/// # Ok(())
/// # }
/// ```
pub async fn verify_registration(
    state: &RegistrationState,
    signup_key: &str,
    proxy: Option<&str>,
) -> Result<()> {
    #[cfg(not(target_arch = "wasm32"))]
    let mut api = match proxy {
        Some(url) => ApiClient::with_proxy(url)?,
        None => ApiClient::new(),
    };

    #[cfg(target_arch = "wasm32")]
    let mut api = ApiClient::new();

    // 1. Generate RSA keypair
    let rsa_key = MegaRsaKey::generate()
        .map_err(|e| MegaError::CryptoError(format!("RSA generation: {}", e)))?;

    // 2. Login as anonymous user: us(user=user_handle)
    let response = api
        .request(json!({
            "a": "us",
            "user": &state.user_handle
        }))
        .await?;

    let tsid = response["tsid"]
        .as_str()
        .ok_or(MegaError::InvalidResponse)?;
    api.set_session_id(tsid.to_string());

    // 3. Verify signup: ud(c=signup_key)
    // Returns: [email, name, handle, encrypted_master_key, encrypted_challenge]
    let response = api
        .request(json!({
            "a": "ud",
            "c": signup_key
        }))
        .await?;

    let arr = response.as_array().ok_or(MegaError::InvalidResponse)?;
    if arr.len() != 5 {
        return Err(MegaError::InvalidResponse);
    }

    let b64_email = arr[0].as_str().ok_or(MegaError::InvalidResponse)?;
    let _b64_name = arr[1].as_str().ok_or(MegaError::InvalidResponse)?;
    let _handle = arr[2].as_str().ok_or(MegaError::InvalidResponse)?;
    let b64_master_key = arr[3].as_str().ok_or(MegaError::InvalidResponse)?;
    let b64_challenge = arr[4].as_str().ok_or(MegaError::InvalidResponse)?;

    // 4. Decrypt and verify
    let email_bytes = base64url_decode(b64_email)?;
    let email = String::from_utf8(email_bytes).map_err(|_| MegaError::InvalidResponse)?;

    let encrypted_master_key = base64url_decode(b64_master_key)?;
    let encrypted_challenge = base64url_decode(b64_challenge)?;

    let master_key = aes128_ecb_decrypt(&encrypted_master_key, &state.password_key);
    let challenge = aes128_ecb_decrypt(&encrypted_challenge, &state.password_key);

    // Verify challenge matches
    if challenge != state.challenge {
        return Err(MegaError::InvalidChallenge);
    }

    // 5. Create username hash
    let email_lower = email.to_lowercase();
    let uh = make_username_hash(&email_lower, &state.password_key);
    let uh_b64 = base64url_encode(&uh);

    // 6. Save credentials: up(c=signup_key, uh=username_hash)
    api.request(json!({
        "a": "up",
        "c": signup_key,
        "uh": uh_b64
    }))
    .await?;

    // 7. Re-login with email: us(user=email, uh=username_hash)
    let response = api
        .request(json!({
            "a": "us",
            "user": email_lower,
            "uh": uh_b64
        }))
        .await?;

    let tsid = response["tsid"]
        .as_str()
        .ok_or(MegaError::InvalidResponse)?;
    api.set_session_id(tsid.to_string());

    // 8. Set RSA keypair: up(pubk=public_key, privk=encrypted_private_key)
    let master_key_arr: [u8; 16] = master_key
        .try_into()
        .map_err(|_| MegaError::InvalidResponse)?;

    api.request(json!({
        "a": "up",
        "pubk": rsa_key.encode_public_key(),
        "privk": rsa_key.encode_private_key(&master_key_arr)
    }))
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_serialization_roundtrip() {
        let state = RegistrationState {
            user_handle: "test_handle_123".to_string(),
            password_key: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            challenge: [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1],
        };

        let serialized = state.serialize();
        let deserialized = RegistrationState::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.user_handle, state.user_handle);
        assert_eq!(deserialized.password_key, state.password_key);
        assert_eq!(deserialized.challenge, state.challenge);
    }

    #[test]
    fn test_state_deserialization_invalid() {
        assert!(RegistrationState::deserialize("invalid").is_err());
        assert!(RegistrationState::deserialize("a:b").is_err());
        assert!(RegistrationState::deserialize("a:b:c:d").is_err());
    }
}
