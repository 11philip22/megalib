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
}
