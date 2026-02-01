//! Decode and encode MEGA's `*keyring` user attribute.
//!
//! The SDK stores the keyring as an encrypted TLV container:
//! - Payload: repeated records `<type>\0<u16 len><value>`, where `type` is an ASCII string.
//!   Keys of interest are `prEd255` (Ed25519 seed) and `prCu255` (Curve25519 private key).
//! - Container: `[encSetting][IV][ciphertext||tag]` where `encSetting` selects AES-GCM/CCM
//!   parameters. The SDK currently writes `0x10` (AES-GCM, 12-byte IV, 16-byte tag).

use std::collections::BTreeMap;

use aes::Aes128;
use aes_gcm::aead::consts::U8;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, AesGcm};
use ccm::aead::{generic_array::GenericArray, Aead as CcmAead, AeadCore as CcmAeadCore};
use ccm::consts::{U10 as CU10, U12 as CU12, U16 as CU16, U8 as CU8};
use ccm::Ccm;
use rand::RngCore;

use crate::error::{MegaError, Result};

const ENC_CCM_12_16: u8 = 0x00;
const ENC_CCM_10_16: u8 = 0x01;
const ENC_CCM_10_08: u8 = 0x02;
const ENC_GCM_12_16_BROKEN: u8 = 0x03; // treated as CCM by SDK
const ENC_GCM_10_08_BROKEN: u8 = 0x04; // treated as CCM by SDK
const ENC_GCM_12_16: u8 = 0x10;
const ENC_GCM_10_08: u8 = 0x11;

const TLV_KEY_ED25519: &str = "prEd255";
const TLV_KEY_CU25519: &str = "prCu255";

#[derive(Debug, Clone, Default)]
pub struct Keyring {
    /// Ed25519 private seed (32 bytes)
    pub ed25519: Option<Vec<u8>>,
    /// Curve25519 private key (32 bytes)
    pub cu25519: Option<Vec<u8>>,
}

enum EncMode {
    Gcm { tag_len: usize },
    Ccm { tag_len: usize },
}

impl Keyring {
    /// Decrypt and parse a keyring buffer using the master key.
    pub fn from_encrypted(data: &[u8], master_key: &[u8; 16]) -> Result<Self> {
        if data.len() < 1 + 10 + 8 {
            return Err(MegaError::InvalidResponse);
        }

        let setting = data[0];
        let (mode, iv_len, tag_len) = enc_params(setting)
            .ok_or_else(|| MegaError::Custom("Unsupported *keyring encSetting".into()))?;

        if data.len() < 1 + iv_len + tag_len {
            return Err(MegaError::InvalidResponse);
        }

        let iv = &data[1..1 + iv_len];
        let ct = &data[1 + iv_len..];
        if ct.len() < tag_len {
            return Err(MegaError::InvalidResponse);
        }

        let plain = match mode {
            EncMode::Gcm { tag_len: 16, .. } => {
                let cipher = Aes128Gcm::new_from_slice(master_key)
                    .map_err(|e| MegaError::CryptoError(e.to_string()))?;
                cipher
                    .decrypt(aes_gcm::Nonce::from_slice(iv), ct)
                    .map_err(|_| MegaError::CryptoError("GCM decrypt failed".into()))?
            }
            EncMode::Gcm { tag_len: 8, .. } => {
                type Aes128Gcm8 = AesGcm<Aes128, U8>;
                let cipher = Aes128Gcm8::new_from_slice(master_key)
                    .map_err(|e| MegaError::CryptoError(e.to_string()))?;
                cipher
                    .decrypt(aes_gcm::Nonce::from_slice(iv), ct)
                    .map_err(|_| MegaError::CryptoError("GCM(8) decrypt failed".into()))?
            }
            EncMode::Ccm { tag_len: 16 } if iv_len == 12 => {
                type Aes128Ccm = Ccm<Aes128, CU16, CU12>;
                let cipher = Aes128Ccm::new_from_slice(master_key)
                    .map_err(|e| MegaError::CryptoError(e.to_string()))?;
                let nonce =
                    GenericArray::<u8, <Aes128Ccm as CcmAeadCore>::NonceSize>::from_slice(iv);
                CcmAead::decrypt(&cipher, nonce, ct)
                    .map_err(|_| MegaError::CryptoError("CCM decrypt failed".into()))?
            }
            EncMode::Ccm { tag_len: 16 } if iv_len == 10 => {
                type Aes128Ccm = Ccm<Aes128, CU16, CU10>;
                let cipher = Aes128Ccm::new_from_slice(master_key)
                    .map_err(|e| MegaError::CryptoError(e.to_string()))?;
                let nonce =
                    GenericArray::<u8, <Aes128Ccm as CcmAeadCore>::NonceSize>::from_slice(iv);
                CcmAead::decrypt(&cipher, nonce, ct)
                    .map_err(|_| MegaError::CryptoError("CCM decrypt failed".into()))?
            }
            EncMode::Ccm { tag_len: 8 } if iv_len == 10 => {
                type Aes128Ccm = Ccm<Aes128, CU8, CU10>;
                let cipher = Aes128Ccm::new_from_slice(master_key)
                    .map_err(|e| MegaError::CryptoError(e.to_string()))?;
                let nonce =
                    GenericArray::<u8, <Aes128Ccm as CcmAeadCore>::NonceSize>::from_slice(iv);
                CcmAead::decrypt(&cipher, nonce, ct)
                    .map_err(|_| MegaError::CryptoError("CCM decrypt failed".into()))?
            }
            _ => return Err(MegaError::InvalidResponse),
        };

        let records = parse_tlv_records(&plain)?;
        let ed = records.get(TLV_KEY_ED25519).cloned();
        let cu = records.get(TLV_KEY_CU25519).cloned();

        if let (Some(ed), Some(cu)) = (ed, cu) {
            if ed.len() == 32 && cu.len() == 32 {
                return Ok(Keyring {
                    ed25519: Some(ed),
                    cu25519: Some(cu),
                });
            }
        }

        Err(MegaError::Custom(
            "Incomplete keyring: missing Ed25519 or Cu25519 key".to_string(),
        ))
    }

    /// Create a fresh keyring with random Ed25519 / Curve25519 keys.
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let mut ed = [0u8; 32];
        let mut cu = [0u8; 32];
        rng.fill_bytes(&mut ed);
        rng.fill_bytes(&mut cu);
        Keyring {
            ed25519: Some(ed.to_vec()),
            cu25519: Some(cu.to_vec()),
        }
    }

    /// Encrypt this keyring into the attribute format using the master key.
    pub fn to_encrypted(&self, master_key: &[u8; 16]) -> Result<Vec<u8>> {
        let ed = self
            .ed25519
            .as_ref()
            .ok_or_else(|| MegaError::Custom("Missing Ed25519 key".to_string()))?;
        let cu = self
            .cu25519
            .as_ref()
            .ok_or_else(|| MegaError::Custom("Missing Curve25519 key".to_string()))?;

        if ed.len() != 32 || cu.len() != 32 {
            return Err(MegaError::Custom(
                "Invalid keyring lengths; expected 32-byte keys".to_string(),
            ));
        }

        let mut records = BTreeMap::new();
        records.insert(TLV_KEY_ED25519.to_string(), ed.to_vec());
        records.insert(TLV_KEY_CU25519.to_string(), cu.to_vec());

        let plain = build_tlv_records(&records)?;

        // SDK writes AES-GCM (12-byte IV, 16-byte tag)
        let iv_len = 12;
        let mut iv = vec![0u8; iv_len];
        rand::thread_rng().fill_bytes(&mut iv);

        let cipher = Aes128Gcm::new_from_slice(master_key)
            .map_err(|e| MegaError::CryptoError(e.to_string()))?;
        let mut ct = cipher
            .encrypt(aes_gcm::Nonce::from_slice(&iv), plain.as_ref())
            .map_err(|_| MegaError::CryptoError("GCM encrypt failed".into()))?;

        let mut out = Vec::with_capacity(1 + iv.len() + ct.len());
        out.push(ENC_GCM_12_16);
        out.extend_from_slice(&iv);
        out.append(&mut ct);
        Ok(out)
    }
}

fn enc_params(setting: u8) -> Option<(EncMode, usize, usize)> {
    match setting {
        ENC_GCM_12_16 => Some((EncMode::Gcm { tag_len: 16 }, 12, 16)),
        ENC_GCM_10_08 => Some((EncMode::Gcm { tag_len: 8 }, 10, 8)),
        ENC_CCM_12_16 | ENC_GCM_12_16_BROKEN => Some((EncMode::Ccm { tag_len: 16 }, 12, 16)),
        ENC_CCM_10_16 => Some((EncMode::Ccm { tag_len: 16 }, 10, 16)),
        ENC_CCM_10_08 | ENC_GCM_10_08_BROKEN => Some((EncMode::Ccm { tag_len: 8 }, 10, 8)),
        _ => None,
    }
}

fn parse_tlv_records(data: &[u8]) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut records = BTreeMap::new();
    let datalen = data.len();

    // Shortcut for oversized empty-tag blobs (mirrors SDK behaviour)
    if datalen >= 1 + 2 + 0xFFFF && data.first() == Some(&0u8) {
        records.insert("".to_string(), data[3..].to_vec());
        return Ok(records);
    }

    let mut offset = 0usize;
    while offset < datalen {
        let Some(pos) = data[offset..].iter().position(|b| *b == 0) else {
            return Err(MegaError::InvalidResponse);
        };
        let typelen = pos;
        let key_start = offset;
        let key_end = offset + typelen;
        let key = String::from_utf8_lossy(&data[key_start..key_end]).to_string();

        offset = key_end + 1; // skip null
        if offset + 2 > datalen {
            return Err(MegaError::InvalidResponse);
        }
        let len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if offset + len > datalen {
            return Err(MegaError::InvalidResponse);
        }
        let value = data[offset..offset + len].to_vec();
        offset += len;
        records.insert(key, value);
    }
    Ok(records)
}

fn build_tlv_records(records: &BTreeMap<String, Vec<u8>>) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for (key, value) in records {
        if value.len() > u16::MAX as usize {
            return Err(MegaError::Custom("TLV value too large".into()));
        }
        out.extend_from_slice(key.as_bytes());
        out.push(0); // null terminator
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_keyring_matches_sdk_layout() {
        let master = [7u8; 16];
        let kr = Keyring {
            ed25519: Some(vec![1u8; 32]),
            cu25519: Some(vec![2u8; 32]),
        };

        let enc = kr.to_encrypted(&master).expect("encrypt");
        assert_eq!(enc[0], ENC_GCM_12_16);

        let decoded = Keyring::from_encrypted(&enc, &master).expect("decrypt");
        assert_eq!(decoded.ed25519.unwrap(), vec![1u8; 32]);
        assert_eq!(decoded.cu25519.unwrap(), vec![2u8; 32]);
    }
}
