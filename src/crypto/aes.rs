//! AES-128 encryption operations.
//!
//! MEGA uses AES-128 in multiple modes:
//! - ECB: For key encryption and password key derivation
//! - CTR: For file content encryption (not yet implemented)

use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};

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

/// AES-128-CTR decrypt/encrypt (symmetric).
///
/// Mega uses a specific CTR mode where the 16-byte counter block is formed by:
/// - 8 bytes: Nonce (from bits 32-96 of the node key)
/// - 8 bytes: Counter (64-bit Big Endian, starting from offset/16)
///
/// # Arguments
/// * `data` - Data to decrypt/encrypt
/// * `key` - 16-byte AES key
/// * `nonce` - 8-byte nonce
/// * `offset` - Byte offset in the file (used to calculate initial counter)
pub fn aes128_ctr_decrypt(data: &[u8], key: &[u8; 16], nonce: &[u8; 8], offset: u64) -> Vec<u8> {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut result = Vec::with_capacity(data.len());

    // Initial counter value based on offset
    let mut counter_val = offset / 16;
    let mut block_offset = (offset % 16) as usize;

    let mut input_block = [0u8; 16];
    input_block[0..8].copy_from_slice(nonce);

    // Process data byte by byte (or chunk by chunk)
    // For efficiency, we'll process 16-byte chunks of data, but we need to handle the initial unaligned offset

    let mut data_idx = 0;
    while data_idx < data.len() {
        // Construct counter block
        input_block[8..16].copy_from_slice(&counter_val.to_be_bytes());

        // Generate keystream block
        let mut keystream = GenericArray::clone_from_slice(&input_block);
        cipher.encrypt_block(&mut keystream);

        // XOR data with keystream
        // Use block_offset for the first block if we started in the middle of a block
        let available_keystream = 16 - block_offset;
        let bytes_to_process = std::cmp::min(available_keystream, data.len() - data_idx);

        for i in 0..bytes_to_process {
            result.push(data[data_idx + i] ^ keystream[block_offset + i]);
        }

        data_idx += bytes_to_process;

        // Advance counter and reset block_offset for subsequent blocks
        if block_offset + bytes_to_process == 16 {
            counter_val += 1;
            block_offset = 0;
        } else {
            // We finished the data before finishing the current block
            block_offset += bytes_to_process;
        }
    }

    result
}

/// AES-128-CTR encrypt (same as decrypt).
pub fn aes128_ctr_encrypt(data: &[u8], key: &[u8; 16], nonce: &[u8; 8], offset: u64) -> Vec<u8> {
    aes128_ctr_decrypt(data, key, nonce, offset)
}

/// Calculate Chunk MAC for Mega upload.
///
/// Mega uses a variant of CBC-MAC for chunk integrity.
/// The IV for the MAC calculation depends on the chunk's offset and the nonce.
///
/// # Arguments
/// * `data` - Chunk data
/// * `key` - 16-byte File Key
/// * `iv` - 16-byte specific IV
///
/// # Returns
/// 16-byte MAC
pub fn chunk_mac_calculate(data: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut mac = GenericArray::clone_from_slice(iv);

    // Process data in 16-byte blocks
    let chunks = data.chunks(16);
    for chunk in chunks {
        // Prepare block (pad with zeros if partial)
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);

        // XOR data into MAC
        for i in 0..16 {
            mac[i] ^= block[i];
        }

        // Encrypt MAC (ECB)
        cipher.encrypt_block(&mut mac);
    }

    mac.into()
}

/// Calculate Meta MAC from list of Chunk MACs.
///
/// The Meta MAC is an AES-CBC-MAC of the XORed chunk MACs.
///
/// # Arguments
/// * `chunk_macs` - List of 16-byte Chunk MACs
/// * `key` - 16-byte File Key
///
/// # Returns
/// 16-byte Meta MAC
pub fn meta_mac_calculate(chunk_macs: &[[u8; 16]], key: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut meta_mac = GenericArray::from([0u8; 16]);

    for chunk_mac in chunk_macs {
        for i in 0..16 {
            meta_mac[i] ^= chunk_mac[i];
        }
        cipher.encrypt_block(&mut meta_mac);
    }

    meta_mac.into()
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

    #[test]
    fn test_ctr_encrypt_decrypt() {
        let key = [0x55u8; 16];
        let nonce = [0xAAu8; 8];
        let plaintext = b"Hello Mega World! This is a test of CTR mode.";
        let offset = 0;

        // CTR is symmetric, so encrypting is the same function as removing encryption
        let ciphertext = aes128_ctr_decrypt(plaintext, &key, &nonce, offset);
        let decrypted = aes128_ctr_decrypt(&ciphertext, &key, &nonce, offset);

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ctr_offset_handling() {
        let key = [0x55u8; 16];
        let nonce = [0xAAu8; 8];
        let plaintext = vec![0x33u8; 100];

        // Encrypt whole buffer
        let ciphertext = aes128_ctr_decrypt(&plaintext, &key, &nonce, 0);

        // Decrypt in two parts to test offset handling
        let split_point = 20;
        let mut decrypted = Vec::new();

        let part1 = aes128_ctr_decrypt(&ciphertext[..split_point], &key, &nonce, 0);
        let part2 =
            aes128_ctr_decrypt(&ciphertext[split_point..], &key, &nonce, split_point as u64);

        decrypted.extend_from_slice(&part1);
        decrypted.extend_from_slice(&part2);

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chunk_mac_calculate() {
        let key = [0x11u8; 16];
        let iv = [0x22u8; 16];
        let data = vec![0x33u8; 32]; // 2 blocks

        // Manually calculate expected MAC
        // Block 1
        let mut mac = iv;
        for i in 0..16 {
            mac[i] ^= data[i];
        }
        let mac = aes128_ecb_encrypt_block(&mac, &key);

        // Block 2
        let mut mac2 = mac;
        for i in 0..16 {
            mac2[i] ^= data[16 + i];
        }
        let mac2 = aes128_ecb_encrypt_block(&mac2, &key);

        let calculated = chunk_mac_calculate(&data, &key, &iv);
        assert_eq!(calculated, mac2);
    }

    #[test]
    fn test_meta_mac_calculate() {
        let key = [0x44u8; 16];
        let chunk_mac1 = [0x55u8; 16];
        let chunk_mac2 = [0x66u8; 16];
        let chunk_macs = vec![chunk_mac1, chunk_mac2];

        // Manual calculation
        let mut mac = [0u8; 16];
        // Chunk 1
        for i in 0..16 {
            mac[i] ^= chunk_mac1[i];
        }
        let mac = aes128_ecb_encrypt_block(&mac, &key);
        // Chunk 2
        let mut mac2 = mac;
        for i in 0..16 {
            mac2[i] ^= chunk_mac2[i];
        }
        let mac2 = aes128_ecb_encrypt_block(&mac2, &key);

        let calculated = meta_mac_calculate(&chunk_macs, &key);
        assert_eq!(calculated, mac2);
    }

    #[test]
    fn test_chunk_mac_pading() {
        let key = [0x11u8; 16];
        let iv = [0x22u8; 16];
        let data = vec![0x33u8; 10]; // 10 bytes (partial block)

        // Manual calculation
        let mut block = [0u8; 16];
        block[..10].copy_from_slice(&data); // Pad with zeros

        let mut mac = iv;
        for i in 0..16 {
            mac[i] ^= block[i];
        }
        let mac = aes128_ecb_encrypt_block(&mac, &key);

        let calculated = chunk_mac_calculate(&data, &key, &iv);
        assert_eq!(calculated, mac);
    }
}
