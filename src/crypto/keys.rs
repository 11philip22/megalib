//! MEGA-specific key derivation functions.
//!
//! These are proprietary algorithms used by MEGA, NOT industry-standard KDFs.
//! Do not use these for other purposes.

use super::aes::aes128_ecb_encrypt_block;

/// Convert a UTF-8 password into the JavaScript-style a32 layout used by MEGA's
/// legacy KDF. This mirrors the web client's `str_to_a32`/C++
/// `utf8_to_a32forjs` function: UTF-16 code units are packed into 32-bit words
/// with shifts of 24,16,8,0 and the result is stored in big-endian byte order.
/// The returned tuple contains the packed bytes and the original code-unit
/// length (needed for block sizing in the KDF).
fn password_to_a32_bytes(password: &str) -> (Vec<u8>, usize) {
    let code_units: Vec<u16> = password.encode_utf16().collect();
    let len_units = code_units.len();

    // The webclient packs UTF-16 code units into bytes, dropping leading zero
    // bytes for BMP ASCII (so "test" becomes 0x74 0x65 0x73 0x74) but keeping
    // both bytes for non-ASCII (so 😀 -> D8 3D DE 00). Pad to 4-byte boundary.
    let mut bytes = Vec::with_capacity(len_units * 2);
    for cu in &code_units {
        if *cu <= 0x00FF {
            bytes.push(*cu as u8);
        } else {
            let be = cu.to_be_bytes();
            bytes.extend_from_slice(&be);
        }
    }

    while bytes.len() % 4 != 0 {
        bytes.push(0);
    }

    (bytes, len_units)
}

/// MEGA's password key derivation function.
///
/// This is NOT a standard KDF like PBKDF2 or Argon2. It's MEGA's proprietary
/// algorithm that uses 65,536 rounds of AES encryption.
///
/// # Algorithm
/// 1. Start with a fixed 16-byte initialization vector
/// 2. For 65,536 iterations:
///    - Split password into 16-byte chunks
///    - Use each chunk as an AES key to encrypt the running hash
/// 3. Return the final 16-byte result
///
/// # Arguments
/// * `password` - User's password
///
/// # Returns
/// 16-byte derived key
pub fn make_password_key(password: &str) -> [u8; 16] {
    let (password_bytes, len_units) = password_to_a32_bytes(password);
    // Fixed initialization vector used by MEGA
    let mut pkey: [u8; 16] = [
        0x93, 0xC4, 0x67, 0xE3, 0x7D, 0xB0, 0xC7, 0xA4, 0xD1, 0xBE, 0x3F, 0x81, 0x01, 0x52, 0xCB,
        0x56,
    ];

    if len_units == 0 {
        return pkey;
    }

    let total_len = password_bytes.len();

    // 65536 iterations
    for _ in 0..65536 {
        let mut i = 0;
        while i < total_len {
            // Create a 16-byte key from the password chunk (zero-padded)
            let mut key = [0u8; 16];
            let chunk_len = std::cmp::min(16, total_len - i);
            key[..chunk_len].copy_from_slice(&password_bytes[i..i + chunk_len]);

            // Encrypt pkey with this chunk as the key
            pkey = aes128_ecb_encrypt_block(&pkey, &key);
            i += 16;
        }
    }

    pkey
}

/// MEGA's username hash for authentication.
///
/// This is used during login to prove knowledge of the password without
/// sending the password itself.
///
/// # Algorithm
/// 1. XOR username bytes into a 16-byte buffer (cycling through positions)
/// 2. Encrypt this buffer 16,384 times using the password key
/// 3. Return bytes [0..4] + [8..12] (8 bytes total)
///
/// # Arguments
/// * `username` - User's email (lowercase)
/// * `key` - 16-byte password key from `make_password_key`
///
/// # Returns
/// 8-byte username hash
pub fn make_username_hash(username: &str, key: &[u8; 16]) -> [u8; 8] {
    let username_bytes = username.as_bytes();
    let mut hash = [0u8; 16];

    // XOR username bytes into hash buffer (cycling through 16 positions)
    for (i, &byte) in username_bytes.iter().enumerate() {
        hash[i % 16] ^= byte;
    }

    // Encrypt 16384 times
    for _ in 0..16384 {
        hash = aes128_ecb_encrypt_block(&hash, key);
    }

    // Return first 4 bytes + bytes 8-11
    let mut result = [0u8; 8];
    result[..4].copy_from_slice(&hash[..4]);
    result[4..].copy_from_slice(&hash[8..12]);
    result
}

/// Pack the node key components into the 32-byte format used by Mega for upload.
///
/// This essentially obfuscates the file key and nonce using the calculated MAC.
///
/// # Arguments
/// * `file_key` - Randomly generated 16-byte file key
/// * `nonce` - Randomly generated 8-byte nonce
/// * `meta_mac` - 16-byte MAC calculated from file chunks
///
/// # Returns
/// 32-byte packed node key
pub fn pack_node_key(file_key: &[u8; 16], nonce: &[u8; 8], meta_mac: &[u8; 16]) -> [u8; 32] {
    let mut node_key = [0u8; 32];

    // Helper to convert u8 slice to u32 array (native endian is fine for XOR if consistent)
    // Mega uses 32-bit word operations.
    // To match strict C logic, we can just iterate 4 bytes at a time.

    // Logic:
    // 0-4:   fk[0..4] ^ n[0..4]
    // 4-8:   fk[4..8] ^ n[4..8]
    // 8-12:  fk[8..12] ^ mm[0..4] ^ mm[4..8]
    // 12-16: fk[12..16] ^ mm[8..12] ^ mm[12..16]
    // 16-20: n[0..4]
    // 20-24: n[4..8]
    // 24-28: mm[0..4] ^ mm[4..8]
    // 28-32: mm[8..12] ^ mm[12..16]

    for i in 0..4 {
        node_key[i] = file_key[i] ^ nonce[i];
        node_key[4 + i] = file_key[4 + i] ^ nonce[4 + i];
        node_key[8 + i] = file_key[8 + i] ^ meta_mac[i] ^ meta_mac[4 + i];
        node_key[12 + i] = file_key[12 + i] ^ meta_mac[8 + i] ^ meta_mac[12 + i];
        node_key[16 + i] = nonce[i];
        node_key[20 + i] = nonce[4 + i];
        node_key[24 + i] = meta_mac[i] ^ meta_mac[4 + i];
        node_key[28 + i] = meta_mac[8 + i] ^ meta_mac[12 + i];
    }

    node_key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_key_deterministic() {
        let key1 = make_password_key("testpassword");
        let key2 = make_password_key("testpassword");
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_password_key_different_passwords() {
        let key1 = make_password_key("password1");
        let key2 = make_password_key("password2");
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_password_to_a32_ascii() {
        let (bytes, len_units) = password_to_a32_bytes("test");
        assert_eq!(len_units, 4);
        assert_eq!(bytes, vec![0x74, 0x65, 0x73, 0x74]);
    }

    #[test]
    fn test_password_to_a32_surrogate_pair() {
        let (bytes, len_units) = password_to_a32_bytes("😀");
        // U+1F600 becomes two UTF-16 code units
        assert_eq!(len_units, 2);
        assert_eq!(bytes, vec![0xD8, 0x3D, 0xDE, 0x00]);
    }

    #[test]
    fn test_username_hash_deterministic() {
        let password_key = make_password_key("testpassword");
        let hash1 = make_username_hash("test@example.com", &password_key);
        let hash2 = make_username_hash("test@example.com", &password_key);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_username_hash_different_usernames() {
        let password_key = make_password_key("testpassword");
        let hash1 = make_username_hash("user1@example.com", &password_key);
        let hash2 = make_username_hash("user2@example.com", &password_key);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_empty_password() {
        // Empty password should return the initial vector unchanged
        let key = make_password_key("");
        let expected: [u8; 16] = [
            0x93, 0xC4, 0x67, 0xE3, 0x7D, 0xB0, 0xC7, 0xA4, 0xD1, 0xBE, 0x3F, 0x81, 0x01, 0x52,
            0xCB, 0x56,
        ];
        assert_eq!(key, expected);
    }
}
