//! Authentication-related cryptographic operations.

use hmac::Hmac;
use num_bigint::BigUint;
use num_traits::One;
use pbkdf2::pbkdf2;
use sha2::Sha512;

use crate::base64::{base64url_decode, base64url_encode};
use crate::crypto::rsa::read_mpi;
use crate::crypto::{aes128_ecb_decrypt, aes128_ecb_encrypt, MegaRsaKey};
use crate::error::{MegaError, Result};

/// Derive key using PBKDF2-SHA512 (login variant 2).
pub fn derive_key_v2(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    pbkdf2::<Hmac<Sha512>>(password.as_bytes(), salt, 100_000, &mut key)
        .map_err(|_| MegaError::CryptoError("PBKDF2 failed".to_string()))?;

    Ok(key)
}

/// Encrypt a key to base64 using AES-128-ECB.
pub fn encrypt_key(key_to_encrypt: &[u8; 16], password_key: &[u8; 16]) -> Vec<u8> {
    aes128_ecb_encrypt(key_to_encrypt, password_key)
}

/// Decrypt a key from base64 using AES-128-ECB.
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

/// Decrypt RSA private key from base64.
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

/// Decrypt session ID using RSA.
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
}
