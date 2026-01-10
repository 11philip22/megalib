//! Session management and authentication.
//!
//! This module handles user login, session state, and logout.

use std::collections::HashMap;

use serde_json::json;

use crate::api::ApiClient;
use crate::base64::{base64url_decode, base64url_encode};
use crate::crypto::{aes128_ecb_decrypt, make_password_key, make_username_hash, MegaRsaKey};
use crate::error::{MegaError, Result};
use crate::fs::Node;

/// MEGA user session.
///
/// This holds all authentication state needed for API requests.
#[derive(Debug)]
pub struct Session {
    /// API client for making requests
    pub(crate) api: ApiClient,
    /// Session ID
    session_id: String,
    /// User's master key (decrypted)
    pub(crate) master_key: [u8; 16],
    /// User's RSA private key
    #[allow(dead_code)]
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
}

impl Session {
    /// Login with email and password.
    ///
    /// This creates a new authenticated session with MEGA.
    ///
    /// # Example
    /// ```no_run
    /// use mega_rs::Session;
    ///
    /// # async fn example() -> mega_rs::error::Result<()> {
    /// let session = Session::login("user@example.com", "password").await?;
    /// println!("Logged in as: {}", session.email);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn login(email: &str, password: &str) -> Result<Self> {
        let mut api = ApiClient::new();
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

    /// Get mutable reference to the API client.
    pub(crate) fn api_mut(&mut self) -> &mut ApiClient {
        &mut self.api
    }

    #[allow(dead_code)]
    /// Get reference to the API client.
    pub(crate) fn api(&self) -> &ApiClient {
        &self.api
    }
}

/// Derive key using PBKDF2-SHA512 (login variant 2).
fn derive_key_v2(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    use hmac::Hmac;
    use pbkdf2::pbkdf2;
    use sha2::Sha512;

    let mut key = [0u8; 32];
    pbkdf2::<Hmac<Sha512>>(password.as_bytes(), salt, 100_000, &mut key)
        .map_err(|_| MegaError::CryptoError("PBKDF2 failed".to_string()))?;

    Ok(key)
}

/// Decrypt a key from base64 using AES-128-ECB.
fn decrypt_key(b64: &str, password_key: &[u8; 16]) -> Result<[u8; 16]> {
    let data = base64url_decode(b64)?;
    if data.len() != 16 {
        return Err(MegaError::CryptoError("Invalid key length".to_string()));
    }

    let decrypted = aes128_ecb_decrypt(&data, password_key);
    let mut key = [0u8; 16];
    key.copy_from_slice(&decrypted);
    Ok(key)
}

/// Decrypt RSA private key from base64.
fn decrypt_private_key(b64: &str, master_key: &[u8; 16]) -> Result<MegaRsaKey> {
    let encrypted = base64url_decode(b64)?;
    let decrypted = aes128_ecb_decrypt(&encrypted, master_key);

    // Parse MPI format: p, q, d, u
    let mut pos = 0;

    let p = read_mpi(&decrypted, &mut pos)?;
    let q = read_mpi(&decrypted, &mut pos)?;
    let d = read_mpi(&decrypted, &mut pos)?;
    let u = read_mpi(&decrypted, &mut pos)?;

    // Compute m = p * q and e = 3 (MEGA always uses e=3)
    let m = &p * &q;
    let e = num_bigint::BigUint::from(3u32);

    Ok(MegaRsaKey { p, q, d, u, m, e })
}

/// Read an MPI (Multi-Precision Integer) from a byte slice.
fn read_mpi(data: &[u8], pos: &mut usize) -> Result<num_bigint::BigUint> {
    use num_bigint::BigUint;

    if *pos + 2 > data.len() {
        return Err(MegaError::CryptoError("MPI truncated".to_string()));
    }

    let bit_len = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
    let byte_len = (bit_len + 7) / 8;
    *pos += 2;

    if *pos + byte_len > data.len() {
        return Err(MegaError::CryptoError("MPI data truncated".to_string()));
    }

    let bytes = &data[*pos..*pos + byte_len];
    *pos += byte_len;

    Ok(BigUint::from_bytes_be(bytes))
}

/// Decrypt session ID using RSA.
fn decrypt_session_id(csid_b64: &str, rsa_key: &MegaRsaKey) -> Result<String> {
    let data = base64url_decode(csid_b64)?;

    // Read MPI
    let mut pos = 0;
    let ciphertext = read_mpi(&data, &mut pos)?;

    // RSA decrypt using CRT
    let plaintext = rsa_decrypt_crt(&ciphertext, &rsa_key.d, &rsa_key.p, &rsa_key.q, &rsa_key.u);

    // Convert to bytes and take first 43 bytes
    let plaintext_bytes = plaintext.to_bytes_be();
    if plaintext_bytes.len() < 43 {
        return Err(MegaError::CryptoError("Session ID too short".to_string()));
    }

    Ok(base64url_encode(&plaintext_bytes[..43]))
}

/// RSA decryption using Chinese Remainder Theorem optimization.
fn rsa_decrypt_crt(
    m: &num_bigint::BigUint,
    d: &num_bigint::BigUint,
    p: &num_bigint::BigUint,
    q: &num_bigint::BigUint,
    u: &num_bigint::BigUint, // p^-1 mod q
) -> num_bigint::BigUint {
    use num_bigint::BigUint;
    use num_traits::One;

    // xp = m^(d mod (p-1)) mod p
    let p1 = p - BigUint::one();
    let dp1 = d % &p1;
    let mp = m % p;
    let xp = mp.modpow(&dp1, p);

    // xq = m^(d mod (q-1)) mod q
    let q1 = q - BigUint::one();
    let dq1 = d % &q1;
    let mq = m % q;
    let xq = mq.modpow(&dq1, q);

    // CRT combination
    let t = if xq >= xp {
        let diff = &xq - &xp;
        (&diff * u) % q
    } else {
        let diff = &xp - &xq;
        let tmp = (&diff * u) % q;
        q - tmp
    };

    &t * p + &xp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_mpi() {
        // MPI with 16 bits (2 bytes) of data: 0x1234
        let data = vec![0x00, 0x10, 0x12, 0x34]; // 16 bits, then 0x1234
        let mut pos = 0;
        let result = read_mpi(&data, &mut pos).unwrap();
        assert_eq!(result, num_bigint::BigUint::from(0x1234u32));
        assert_eq!(pos, 4);
    }
}
