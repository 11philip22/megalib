//! AES-128 encryption operations.
//!
//! MEGA uses AES-128 in multiple modes:
//! - ECB: For key encryption and password key derivation
//! - CTR: For file content encryption (not yet implemented)

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;

/// AES-128-ECB encrypt a single 16-byte block.
///
/// # Arguments
/// * `data` - 16-byte block to encrypt
/// * `key` - 16-byte AES key
///
/// # Returns
/// Encrypted 16-byte block
pub fn aes128_ecb_encrypt_block(data: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut block = GenericArray::clone_from_slice(data);
    cipher.encrypt_block(&mut block);
    block.into()
}

/// AES-128-ECB decrypt a single 16-byte block.
///
/// # Arguments
/// * `data` - 16-byte block to decrypt
/// * `key` - 16-byte AES key
///
/// # Returns
/// Decrypted 16-byte block
pub fn aes128_ecb_decrypt_block(data: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut block = GenericArray::clone_from_slice(data);
    cipher.decrypt_block(&mut block);
    block.into()
}

/// AES-128-ECB encrypt multiple blocks.
///
/// # Arguments
/// * `data` - Data to encrypt (length must be multiple of 16)
/// * `key` - 16-byte AES key
///
/// # Panics
/// Panics if data length is not a multiple of 16.
pub fn aes128_ecb_encrypt(data: &[u8], key: &[u8; 16]) -> Vec<u8> {
    assert!(
        data.len() % 16 == 0,
        "Data length must be multiple of 16, got {}",
        data.len()
    );

    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut result = data.to_vec();

    for chunk in result.chunks_mut(16) {
        let block = GenericArray::from_mut_slice(chunk);
        cipher.encrypt_block(block);
    }

    result
}

/// AES-128-ECB decrypt multiple blocks.
///
/// # Arguments
/// * `data` - Data to decrypt (length must be multiple of 16)
/// * `key` - 16-byte AES key
///
/// # Panics
/// Panics if data length is not a multiple of 16.
pub fn aes128_ecb_decrypt(data: &[u8], key: &[u8; 16]) -> Vec<u8> {
    assert!(
        data.len() % 16 == 0,
        "Data length must be multiple of 16, got {}",
        data.len()
    );

    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut result = data.to_vec();

    for chunk in result.chunks_mut(16) {
        let block = GenericArray::from_mut_slice(chunk);
        cipher.decrypt_block(block);
    }

    result
}

/// AES-128-CBC decrypt multiple blocks with zero IV.
///
/// # Arguments
/// * `data` - Data to decrypt (length must be multiple of 16)
/// * `key` - 16-byte AES key
///
/// # Panics
/// Panics if data length is not a multiple of 16.
pub fn aes128_cbc_decrypt(data: &[u8], key: &[u8; 16]) -> Vec<u8> {
    assert!(
        data.len() % 16 == 0,
        "Data length must be multiple of 16, got {}",
        data.len()
    );

    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut result = Vec::with_capacity(data.len());
    let mut iv = GenericArray::from([0u8; 16]);

    for chunk in data.chunks(16) {
        let mut block = GenericArray::clone_from_slice(chunk);

        // Decrypt block
        cipher.decrypt_block(&mut block);

        // XOR with previous ciphertext block (or IV for first block)
        for i in 0..16 {
            block[i] ^= iv[i];
        }

        result.extend_from_slice(&block);

        // Update IV to current ciphertext block for next iteration
        iv.copy_from_slice(chunk);
    }

    result
}

/// AES-128-CBC encrypt multiple blocks with zero IV.
///
/// # Arguments
/// * `data` - Data to encrypt (length must be multiple of 16)
/// * `key` - 16-byte AES key
///
/// # Panics
/// Panics if data length is not a multiple of 16.
pub fn aes128_cbc_encrypt(data: &[u8], key: &[u8; 16]) -> Vec<u8> {
    assert!(
        data.len() % 16 == 0,
        "Data length must be multiple of 16, got {}",
        data.len()
    );

    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut result = Vec::with_capacity(data.len());
    let mut iv = GenericArray::from([0u8; 16]);

    for chunk in data.chunks(16) {
        let mut block = GenericArray::clone_from_slice(chunk);

        // XOR with IV (or previous ciphertext block)
        for i in 0..16 {
            block[i] ^= iv[i];
        }

        // Encrypt block
        cipher.encrypt_block(&mut block);

        result.extend_from_slice(&block);

        // Update IV to current ciphertext block for next iteration
        iv.copy_from_slice(&block);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_block() {
        let key = [0u8; 16];
        let plaintext = [1u8; 16];

        let ciphertext = aes128_ecb_encrypt_block(&plaintext, &key);
        let decrypted = aes128_ecb_decrypt_block(&ciphertext, &key);

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_multiple_blocks() {
        let key = [0x42u8; 16];
        let plaintext = vec![0xABu8; 32]; // Two blocks

        let ciphertext = aes128_ecb_encrypt(&plaintext, &key);
        let decrypted = aes128_ecb_decrypt(&ciphertext, &key);

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    #[should_panic(expected = "Data length must be multiple of 16")]
    fn test_encrypt_invalid_length() {
        let key = [0u8; 16];
        let plaintext = vec![0u8; 15]; // Invalid length
        aes128_ecb_encrypt(&plaintext, &key);
    }

    #[test]
    fn test_known_vector() {
        // NIST test vector for AES-128
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plaintext: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let expected: [u8; 16] = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ];

        let ciphertext = aes128_ecb_encrypt_block(&plaintext, &key);
        assert_eq!(ciphertext, expected);
    }

    #[test]
    fn test_cbc_decrypt() {
        // Test vector from megatools (zero IV) check or standard CBC logic
        // Let's create a synthetic test case:
        // Key: all zeros
        // Plaintext: two blocks of all ones
        // IV: all zeros

        let key = [0u8; 16];
        let p1 = [1u8; 16];
        let p2 = [1u8; 16];

        // Encrypt manually to generate expected ciphertext
        // C1 = E(P1 ^ IV) = E(P1 ^ 0) = E(P1)
        // C2 = E(P2 ^ C1)

        let c1 = aes128_ecb_encrypt_block(&p1, &key);

        let mut p2_xor_c1 = [0u8; 16];
        for i in 0..16 {
            p2_xor_c1[i] = p2[i] ^ c1[i];
        }
        let c2 = aes128_ecb_encrypt_block(&p2_xor_c1, &key);

        let mut ciphertext = Vec::new();
        ciphertext.extend_from_slice(&c1);
        ciphertext.extend_from_slice(&c2);

        // Decrypt
        let decrypted = aes128_cbc_decrypt(&ciphertext, &key);

        assert_eq!(decrypted[..16], p1);
        assert_eq!(decrypted[16..], p2);
    }

    #[test]
    fn test_cbc_encrypt_decrypt() {
        let key = [0x12u8; 16];
        let plaintext = vec![0xABu8; 32]; // Two blocks

        let ciphertext = aes128_cbc_encrypt(&plaintext, &key);
        let decrypted = aes128_cbc_decrypt(&ciphertext, &key);

        assert_eq!(decrypted, plaintext);
    }
}
