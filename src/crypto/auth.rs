//! Authentication-related cryptographic operations.

use hmac::Hmac;
use num_bigint::BigUint;
use num_traits::One;
use pbkdf2::pbkdf2;
use sha2::Sha512;

use crate::base64::{base64url_decode, base64url_encode};
use crate::crypto::rsa::read_mpi;
use crate::crypto::{MegaRsaKey, aes128_ecb_decrypt, aes128_ecb_encrypt, aes128_ecb_encrypt_block};
use crate::error::{MegaError, Result};

/// Derive the login key using PBKDF2-SHA512 (variant 2).
///
/// This follows MEGA's v2 login flow and returns the 32-byte derived key.
///
/// # Errors
/// Returns [`crate::MegaError::CryptoError`] if PBKDF2 fails.
///
/// # Examples
/// ```
/// use megalib::crypto::derive_key_v2;
///
/// # fn example() -> megalib::Result<()> {
/// let key = derive_key_v2("password", b"salt")?;
/// assert_eq!(key.len(), 32);
/// # Ok(())
/// # }
/// ```
pub fn derive_key_v2(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    pbkdf2::<Hmac<Sha512>>(password.as_bytes(), salt, 100_000, &mut key)
        .map_err(|_| MegaError::CryptoError("PBKDF2 failed".to_string()))?;

    Ok(key)
}

/// Encrypt a 16-byte key using AES-128-ECB.
///
/// The returned bytes are raw ciphertext and are typically encoded with
/// MEGA's URL-safe base64 before transmission or storage.
///
/// # Examples
/// ```
/// use megalib::base64::base64url_encode;
/// use megalib::crypto::{decrypt_key, encrypt_key};
///
/// # fn example() -> megalib::Result<()> {
/// let key = [1u8; 16];
/// let password_key = [2u8; 16];
/// let encrypted = encrypt_key(&key, &password_key);
/// let b64 = base64url_encode(&encrypted);
/// let decrypted = decrypt_key(&b64, &password_key)?;
/// assert_eq!(decrypted, key);
/// # Ok(())
/// # }
/// ```
pub fn encrypt_key(key_to_encrypt: &[u8; 16], password_key: &[u8; 16]) -> Vec<u8> {
    aes128_ecb_encrypt(key_to_encrypt, password_key)
}

/// Decrypt a 16-byte key from MEGA's base64 encoding.
///
/// # Errors
/// Returns an error if the input is not valid base64 or does not decode to
/// exactly 16 bytes.
///
/// # Examples
/// ```
/// use megalib::base64::base64url_encode;
/// use megalib::crypto::{decrypt_key, encrypt_key};
///
/// # fn example() -> megalib::Result<()> {
/// let key = [3u8; 16];
/// let password_key = [4u8; 16];
/// let encrypted = encrypt_key(&key, &password_key);
/// let b64 = base64url_encode(&encrypted);
/// let decrypted = decrypt_key(&b64, &password_key)?;
/// assert_eq!(decrypted, key);
/// # Ok(())
/// # }
/// ```
pub fn decrypt_key(b64: &str, password_key: &[u8; 16]) -> Result<[u8; 16]> {
    let data = base64url_decode(b64)?;
    if data.len() != 16 {
        return Err(MegaError::CryptoError("Invalid key length".to_string()));
    }

    let decrypted = aes128_ecb_decrypt(&data, password_key);
    let mut key = [0u8; 16];
    key.copy_from_slice(&decrypted);
    Ok(key)
}

/// Decrypt an RSA private key from MEGA's base64 format.
///
/// The input is expected to be the AES-ECB encrypted MPI blob stored in user
/// attributes.
///
/// # Errors
/// Returns an error if decoding or MPI parsing fails.
///
/// # Examples
/// ```no_run
/// use megalib::crypto::decrypt_private_key;
///
/// # fn example() -> megalib::Result<()> {
/// let encrypted_b64 = "BASE64_PRIVATE_KEY";
/// let master_key = [0u8; 16];
/// let _key = decrypt_private_key(encrypted_b64, &master_key)?;
/// # Ok(())
/// # }
/// ```
pub fn decrypt_private_key(b64: &str, master_key: &[u8; 16]) -> Result<MegaRsaKey> {
    let encrypted = base64url_decode(b64)?;
    let decrypted = aes128_ecb_decrypt(&encrypted, master_key);

    // Parse MPI format: p, q, d, u
    let mut pos = 0;

    let p = read_mpi(&decrypted, &mut pos).map_err(MegaError::CryptoError)?;
    let q = read_mpi(&decrypted, &mut pos).map_err(MegaError::CryptoError)?;
    let d = read_mpi(&decrypted, &mut pos).map_err(MegaError::CryptoError)?;
    let u = read_mpi(&decrypted, &mut pos).map_err(MegaError::CryptoError)?;

    // Compute m = p * q and e = 3 (MEGA always uses e=3)
    let m = &p * &q;
    let e = num_bigint::BigUint::from(3u32);

    Ok(MegaRsaKey { p, q, d, u, m, e })
}

/// Parse an unencrypted RSA private key blob stored inside ^!keys.
///
/// The blob must contain MPI-encoded `p`, `q`, `d`, and `u` in order.
///
/// # Errors
/// Returns an error if the blob is truncated or MPI parsing fails.
///
/// # Examples
/// ```no_run
/// use megalib::crypto::parse_raw_private_key;
///
/// # fn example() -> megalib::Result<()> {
/// let blob = vec![0u8; 512];
/// let _key = parse_raw_private_key(&blob)?;
/// # Ok(())
/// # }
/// ```
pub fn parse_raw_private_key(blob: &[u8]) -> Result<MegaRsaKey> {
    let mut pos = 0;
    let p = read_mpi(blob, &mut pos).map_err(MegaError::CryptoError)?;
    let q = read_mpi(blob, &mut pos).map_err(MegaError::CryptoError)?;
    let d = read_mpi(blob, &mut pos).map_err(MegaError::CryptoError)?;
    let u = read_mpi(blob, &mut pos).map_err(MegaError::CryptoError)?;
    let m = &p * &q;
    let e = num_bigint::BigUint::from(3u32);
    Ok(MegaRsaKey { p, q, d, u, m, e })
}

/// Validate a `tsid` challenge exactly like SDK `checktsid`.
///
/// The decoded session id must be 43 bytes. The first 16 bytes are encrypted
/// with the master key; the result must equal the last 16 bytes.
pub fn verify_tsid(tsid_b64: &str, master_key: &[u8; 16]) -> Result<bool> {
    const SID_LEN: usize = 43;
    const CHALLENGE_LEN: usize = 16;

    let sid = base64url_decode(tsid_b64)?;
    if sid.len() != SID_LEN {
        return Ok(false);
    }

    let mut challenge = [0u8; CHALLENGE_LEN];
    challenge.copy_from_slice(&sid[..CHALLENGE_LEN]);
    let encrypted = aes128_ecb_encrypt_block(&challenge, master_key);
    Ok(encrypted.as_slice() == &sid[SID_LEN - CHALLENGE_LEN..])
}

/// Decrypt a session ID using an RSA private key.
///
/// # Errors
/// Returns an error if the session blob is malformed or RSA decryption fails.
///
/// # Examples
/// ```no_run
/// use megalib::crypto::{decrypt_session_id, MegaRsaKey};
///
/// # fn example(rsa_key: &MegaRsaKey) -> megalib::Result<()> {
/// let encrypted = "BASE64_SESSION_ID";
/// let _sid = decrypt_session_id(encrypted, rsa_key)?;
/// # Ok(())
/// # }
/// ```
pub fn decrypt_session_id(csid_b64: &str, rsa_key: &MegaRsaKey) -> Result<String> {
    let data = base64url_decode(csid_b64)?;

    // Read MPI
    let mut pos = 0;
    let ciphertext = read_mpi(&data, &mut pos).map_err(MegaError::CryptoError)?;

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
    fn test_derive_key_v2() {
        let password = "password";
        let salt = b"salt";
        // PBKDF2-HMAC-SHA512 with 100,000 iterations
        // We just check it runs and produces 32 bytes
        let key = derive_key_v2(password, salt).expect("Derivation failed");
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_encrypt_decrypt_key() {
        let key_to_encrypt = [1u8; 16];
        let password_key = [2u8; 16];

        let encrypted = encrypt_key(&key_to_encrypt, &password_key);
        let b64 = base64url_encode(&encrypted);

        let decrypted = decrypt_key(&b64, &password_key).expect("Decryption failed");
        assert_eq!(decrypted, key_to_encrypt);
    }

    #[test]
    fn test_verify_tsid() {
        let master_key = [7u8; 16];
        let mut sid = [0u8; 43];
        sid[..16].copy_from_slice(&[9u8; 16]);
        sid[16..27].copy_from_slice(&[1u8; 11]);
        let tail = aes128_ecb_encrypt_block(&[9u8; 16], &master_key);
        sid[27..].copy_from_slice(&tail);

        let tsid = base64url_encode(&sid);
        assert!(verify_tsid(&tsid, &master_key).expect("verify tsid"));

        sid[42] ^= 1;
        let bad_tsid = base64url_encode(&sid);
        assert!(!verify_tsid(&bad_tsid, &master_key).expect("verify bad tsid"));
    }
}
