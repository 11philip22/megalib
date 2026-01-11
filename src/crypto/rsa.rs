//! RSA key operations for MEGA protocol.
//!
//! MEGA uses RSA-2048 with a non-standard public exponent e=3.

use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::Rng;

use crate::base64::base64url_encode;
use crate::crypto::aes::aes128_ecb_encrypt;

/// MEGA RSA key structure.
///
/// Contains both public and private key components in MEGA's format.
#[derive(Debug, Clone)]
pub struct MegaRsaKey {
    /// Prime factor p
    pub p: BigUint,
    /// Prime factor q
    pub q: BigUint,
    /// Private exponent d
    pub d: BigUint,
    /// CRT coefficient: p^-1 mod q
    pub u: BigUint,
    /// Modulus n = p * q
    pub m: BigUint,
    /// Public exponent (always 3 for MEGA)
    pub e: BigUint,
}

impl MegaRsaKey {
    /// Generate a new 2048-bit RSA key with e=3.
    ///
    /// MEGA uses the non-standard public exponent e=3 (RSA_3).
    pub fn generate() -> Result<Self, String> {
        let mut rng = rand::thread_rng();
        let e = BigUint::from(3u32);

        // Generate two 1024-bit primes p and q such that:
        // - p ≡ 2 (mod 3) to ensure gcd(e, p-1) = 1
        // - q ≡ 2 (mod 3) to ensure gcd(e, q-1) = 1
        let p = generate_prime_for_e3(&mut rng, 1024)?;
        let q = generate_prime_for_e3(&mut rng, 1024)?;

        // Compute modulus
        let m = &p * &q;

        // Compute phi(n) = (p-1)(q-1)
        let p_minus_1 = &p - 1u32;
        let q_minus_1 = &q - 1u32;
        let phi = &p_minus_1 * &q_minus_1;

        // Compute private exponent d = e^-1 mod phi(n)
        let d = mod_inverse(&e, &phi).ok_or("Failed to compute private exponent")?;

        // Compute CRT coefficient u = p^-1 mod q
        let u = mod_inverse(&p, &q).ok_or("Failed to compute CRT coefficient")?;

        Ok(Self { p, q, d, u, m, e })
    }

    /// Encode public key in MEGA's MPI format (base64).
    ///
    /// Format: MPI(m) + MPI(e) where MPI is:
    /// - 2 bytes big-endian bit length
    /// - Followed by the number bytes
    pub fn encode_public_key(&self) -> String {
        let mut data = Vec::new();
        append_mpi(&mut data, &self.m);
        append_mpi(&mut data, &self.e);
        base64url_encode(&data)
    }

    /// Decode public key from MEGA's MPI format (base64).
    pub fn from_encoded_public_key(b64: &str) -> Result<Self, String> {
        let data =
            crate::base64::base64url_decode(b64).map_err(|_| "Invalid base64".to_string())?;

        // Helper to read MPI locally since it's private in auth.rs/session.rs
        // Re-implementing simplified read_mpi here or making it public in auth?
        // Let's implement a private helper here since it's needed.

        let mut pos = 0;
        let m = read_mpi(&data, &mut pos).map_err(|e| e)?;
        let e = read_mpi(&data, &mut pos).map_err(|e| e)?;

        // For public key, we don't have p, q, d, u.
        // We can fill them with zero or make them Option in struct?
        // Struct defines them as BigUint, so we set them to 0.

        Ok(Self {
            m,
            e,
            p: BigUint::zero(),
            q: BigUint::zero(),
            d: BigUint::zero(),
            u: BigUint::zero(),
        })
    }

    /// Encode private key encrypted with master key in MEGA's format.
    ///
    /// Format: MPI(p) + MPI(q) + MPI(d) + MPI(u), all AES-encrypted
    pub fn encode_private_key(&self, master_key: &[u8; 16]) -> String {
        let mut data = Vec::new();
        append_mpi(&mut data, &self.p);
        append_mpi(&mut data, &self.q);
        append_mpi(&mut data, &self.d);
        append_mpi(&mut data, &self.u);

        // Pad to multiple of 16 bytes
        let padding = (16 - (data.len() % 16)) % 16;
        data.extend(vec![0u8; padding]);

        // Encrypt with AES-128-ECB
        let encrypted = aes128_ecb_encrypt(&data, master_key);
        base64url_encode(&encrypted)
    }

    /// Decrypt data using RSA private key.
    ///
    /// Used for decrypting share keys from other users.
    /// The ciphertext is interpreted as a big-endian integer and
    /// decrypted using m = c^d mod n.
    ///
    /// # Arguments
    /// * `ciphertext` - Encrypted data (raw bytes, big-endian integer)
    ///
    /// # Returns
    /// Decrypted data as bytes, or None if decryption fails.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        if ciphertext.is_empty() {
            return None;
        }

        // Interpret ciphertext as big-endian integer
        let c = BigUint::from_bytes_be(ciphertext);

        // RSA decryption: m = c^d mod n
        let m = mod_pow(&c, &self.d, &self.m);

        // Convert back to bytes
        let result = m.to_bytes_be();

        // Result should be at least 16 bytes for a share key
        if result.is_empty() {
            return None;
        }

        Some(result)
    }

    /// Encrypt data using RSA public key.
    ///
    /// Used for encrypting share keys for other users.
    /// c = m^e mod n
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    ///
    /// # Returns
    /// Encrypted data as bytes
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let m = BigUint::from_bytes_be(plaintext);
        let c = mod_pow(&m, &self.e, &self.m);
        c.to_bytes_be()
    }
}

/// Append a number in MPI (Multi-Precision Integer) format.
///
/// MPI format:
/// - 2 bytes: bit length (big-endian)
/// - N bytes: the number itself (big-endian)
fn append_mpi(buf: &mut Vec<u8>, n: &BigUint) {
    let bytes = n.to_bytes_be();
    let bit_len = if bytes.is_empty() {
        0u16
    } else {
        ((bytes.len() - 1) * 8 + (8 - bytes[0].leading_zeros() as usize)) as u16
    };

    buf.extend_from_slice(&bit_len.to_be_bytes());
    buf.extend_from_slice(&bytes);
}

/// Read an MPI (Multi-Precision Integer) from a byte slice.
pub fn read_mpi(data: &[u8], pos: &mut usize) -> Result<BigUint, String> {
    if *pos + 2 > data.len() {
        return Err("MPI truncated".to_string());
    }

    let bit_len = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
    let byte_len = (bit_len + 7) / 8;
    *pos += 2;

    if *pos + byte_len > data.len() {
        return Err("MPI data truncated".to_string());
    }

    let bytes = &data[*pos..*pos + byte_len];
    *pos += byte_len;

    Ok(BigUint::from_bytes_be(bytes))
}

/// Generate a random prime p such that p ≡ 2 (mod 3).
///
/// This ensures gcd(3, p-1) = 1, which is required for e=3.
fn generate_prime_for_e3(rng: &mut impl Rng, bits: usize) -> Result<BigUint, String> {
    for _ in 0..10000 {
        // Generate random odd number of specified bit length
        let mut bytes = vec![0u8; bits / 8];
        rng.fill(&mut bytes[..]);

        // Ensure high bit is set (correct bit length)
        bytes[0] |= 0x80;
        // Ensure it's odd
        let last_idx = bytes.len() - 1;
        bytes[last_idx] |= 0x01;

        let candidate = BigUint::from_bytes_be(&bytes);

        // Adjust to p ≡ 2 (mod 3)
        let remainder = &candidate % 3u32;
        let p = if remainder == BigUint::from(0u32) {
            &candidate + 2u32
        } else if remainder == BigUint::from(1u32) {
            &candidate + 1u32
        } else {
            candidate
        };

        // Simple primality test (Miller-Rabin would be better)
        if is_probably_prime(&p, 20) {
            return Ok(p);
        }
    }

    Err("Failed to generate prime after 10000 attempts".to_string())
}

/// Simple Miller-Rabin primality test.
fn is_probably_prime(n: &BigUint, rounds: usize) -> bool {
    if n <= &BigUint::from(1u32) {
        return false;
    }
    if n == &BigUint::from(2u32) {
        return true;
    }
    if n.is_even() {
        return false;
    }

    // Write n-1 as 2^r * d
    let n_minus_1 = n - 1u32;
    let mut d = n_minus_1.clone();
    let mut r = 0u32;
    while d.is_even() {
        d >>= 1;
        r += 1;
    }

    let mut rng = rand::thread_rng();

    'witness: for _ in 0..rounds {
        // Pick random a in [2, n-2]
        let a = loop {
            let bytes: Vec<u8> = (0..n.to_bytes_be().len()).map(|_| rng.gen()).collect();
            let candidate = BigUint::from_bytes_be(&bytes) % n;
            if candidate >= BigUint::from(2u32) && candidate <= &n_minus_1 - 1u32 {
                break candidate;
            }
        };

        let mut x = mod_pow(&a, &d, n);

        if x == BigUint::one() || x == n_minus_1 {
            continue 'witness;
        }

        for _ in 0..r - 1 {
            x = mod_pow(&x, &BigUint::from(2u32), n);
            if x == n_minus_1 {
                continue 'witness;
            }
        }

        return false;
    }

    true
}

/// Modular exponentiation: base^exp mod modulus
fn mod_pow(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    if modulus.is_one() {
        return BigUint::zero();
    }

    let mut result = BigUint::one();
    let mut base = base % modulus;
    let mut exp = exp.clone();

    while !exp.is_zero() {
        if exp.is_odd() {
            result = (&result * &base) % modulus;
        }
        exp >>= 1;
        base = (&base * &base) % modulus;
    }

    result
}

/// Extended Euclidean algorithm for modular inverse.
/// Returns a^-1 mod m, or None if not invertible.
fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    use num_bigint::BigInt;
    use num_traits::Signed;

    let a = BigInt::from(a.clone());
    let m = BigInt::from(m.clone());

    let mut old_r = a;
    let mut r = m.clone();
    let mut old_s = BigInt::one();
    let mut s = BigInt::zero();

    while !r.is_zero() {
        let quotient = &old_r / &r;
        let temp_r = r.clone();
        r = &old_r - &quotient * &r;
        old_r = temp_r;

        let temp_s = s.clone();
        s = &old_s - &quotient * &s;
        old_s = temp_s;
    }

    if old_r > BigInt::one() {
        return None; // Not invertible
    }

    if old_s.is_negative() {
        old_s = old_s + &m;
    }

    Some(old_s.to_biguint().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_rsa_key() {
        let key = MegaRsaKey::generate();
        assert!(key.is_ok());

        let key = key.unwrap();
        assert_eq!(key.e, BigUint::from(3u32));

        // Verify n = p * q
        assert_eq!(key.m, &key.p * &key.q);

        // Verify key is roughly 2048 bits
        assert!(key.m.bits() >= 2040 && key.m.bits() <= 2056);
    }

    #[test]
    fn test_encode_public_key() {
        let key = MegaRsaKey::generate().unwrap();
        let encoded = key.encode_public_key();

        // Should be non-empty base64
        assert!(!encoded.is_empty());
        assert!(!encoded.contains('='));
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
    }

    #[test]
    fn test_encode_private_key() {
        let key = MegaRsaKey::generate().unwrap();
        let master_key = [0u8; 16];
        let encoded = key.encode_private_key(&master_key);

        // Should be non-empty base64
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_mod_inverse() {
        let a = BigUint::from(3u32);
        let m = BigUint::from(11u32);
        let inv = mod_inverse(&a, &m);

        assert!(inv.is_some());
        let inv = inv.unwrap();

        // Verify: a * inv ≡ 1 (mod m)
        assert_eq!((&a * &inv) % &m, BigUint::one());
    }
}
