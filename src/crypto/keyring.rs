//! Decode MEGA's keyring user attribute (`*keyring`).
//!
//! The keyring is a TLV container (tag-length-value) encrypted with the user's
//! master key. It typically contains Ed25519 and Curve25519 private keys.

use crate::crypto::aes::aes128_ecb_decrypt;
use crate::error::{MegaError, Result};

/// Parsed keyring contents.
#[derive(Debug, Clone, Default)]
pub struct Keyring {
    /// Ed25519 private seed (32 bytes)
    pub ed25519: Option<Vec<u8>>,
    /// Curve25519 private key (32 bytes)
    pub cu25519: Option<Vec<u8>>,
}

impl Keyring {
    /// Decrypt and parse a keyring buffer using the master key.
    pub fn from_encrypted(data: &[u8], master_key: &[u8; 16]) -> Result<Self> {
        let decrypted = aes128_ecb_decrypt(data, master_key);
        let mut offset = 0usize;
        let mut keyring = Keyring::default();

        while offset + 2 <= decrypted.len() {
            let tag = decrypted[offset];
            let len = decrypted[offset + 1] as usize;
            offset += 2;

            if offset + len > decrypted.len() {
                break; // malformed, stop parsing
            }

            let value = &decrypted[offset..offset + len];
            offset += len;

            match tag {
                1 => {
                    // Ed25519 private seed
                    if len == 32 {
                        keyring.ed25519 = Some(value.to_vec());
                    }
                }
                2 => {
                    // Curve25519 private key
                    if len == 32 {
                        keyring.cu25519 = Some(value.to_vec());
                    }
                }
                _ => {
                    // ignore other tags
                }
            }
        }

        if keyring.ed25519.is_none() || keyring.cu25519.is_none() {
            return Err(MegaError::Custom(
                "Incomplete keyring: missing Ed25519 or Cu25519 key".to_string(),
            ));
        }

        Ok(keyring)
    }
}
