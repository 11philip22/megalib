//! Minimal KeyManager for upgraded security (^!keys) handling.
//!
//! This is a reduced version focused on share keys and private key storage.
//! It supports serializing/deserializing ^!keys and tracking generation.

use crate::error::{MegaError, Result};

/// Holds the minimal set of values we need from ^!keys.
#[derive(Debug, Clone, Default)]
pub struct KeyManager {
    pub generation: u32,
    pub priv_ed25519: Option<Vec<u8>>, // 32 bytes
    pub priv_cu25519: Option<Vec<u8>>, // 32 bytes
    pub share_keys: Vec<(String, Vec<u8>)>, // (node handle, 16-byte key)
}

impl KeyManager {
    pub fn is_ready(&self) -> bool {
        self.generation > 0
            && self.priv_ed25519.is_some()
            && self.priv_cu25519.is_some()
    }

    pub fn set_priv_keys(&mut self, ed: Vec<u8>, cu: Vec<u8>) {
        self.priv_ed25519 = Some(ed);
        self.priv_cu25519 = Some(cu);
    }

    pub fn add_share_key(&mut self, handle: String, key: Vec<u8>) {
        self.share_keys.push((handle, key));
    }

    pub fn get_share_key(&self, handle: &str) -> Option<[u8; 16]> {
        self.share_keys
            .iter()
            .find(|(h, _)| h == handle)
            .and_then(|(_, k)| {
                if k.len() == 16 {
                    let mut out = [0u8; 16];
                    out.copy_from_slice(k);
                    Some(out)
                } else {
                    None
                }
            })
    }

    /// Serialize to a very small ad-hoc blob suitable for ^!keys in this minimal implementation.
    /// Format:
    /// [gen(1)][ed_len(1) ed...][cu_len(1) cu...][count(1)][(handle_len(1) handle bytes key16) * count]
    pub fn serialize_minimal(&self, generation: u32) -> Result<Vec<u8>> {
        if self.priv_ed25519.as_ref().map(|v| v.len()) != Some(32)
            || self.priv_cu25519.as_ref().map(|v| v.len()) != Some(32)
        {
            return Err(MegaError::Custom(
                "Missing ed25519/cu25519 private keys for ^!keys".to_string(),
            ));
        }

        let mut buf = Vec::new();
        buf.push((generation & 0xFF) as u8);

        let ed = self.priv_ed25519.as_ref().unwrap();
        buf.push(ed.len() as u8);
        buf.extend_from_slice(ed);

        let cu = self.priv_cu25519.as_ref().unwrap();
        buf.push(cu.len() as u8);
        buf.extend_from_slice(cu);

        let count = self.share_keys.len().min(255) as u8;
        buf.push(count);

        for (handle, key) in self.share_keys.iter().take(count as usize) {
            if key.len() != 16 {
                continue;
            }
            let hl = handle.len().min(255) as u8;
            buf.push(hl);
            buf.extend_from_slice(handle.as_bytes().get(..hl as usize).unwrap_or(&[]));
            buf.extend_from_slice(key);
        }

        Ok(buf)
    }

    /// Deserialize the minimal format produced by `serialize_minimal`.
    pub fn deserialize_minimal(data: &[u8]) -> Result<Self> {
        let mut km = KeyManager::default();

        let mut offset = 0usize;
        if offset >= data.len() {
            return Err(MegaError::Custom("Invalid ^!keys blob".to_string()));
        }
        km.generation = data[offset] as u32;
        offset += 1;

        let ed_len = *data.get(offset).ok_or_else(|| MegaError::InvalidResponse)? as usize;
        offset += 1;
        if ed_len > 0 {
            let end = offset + ed_len;
            if end > data.len() {
                return Err(MegaError::InvalidResponse);
            }
            km.priv_ed25519 = Some(data[offset..end].to_vec());
            offset = end;
        }

        let cu_len = *data.get(offset).ok_or_else(|| MegaError::InvalidResponse)? as usize;
        offset += 1;
        if cu_len > 0 {
            let end = offset + cu_len;
            if end > data.len() {
                return Err(MegaError::InvalidResponse);
            }
            km.priv_cu25519 = Some(data[offset..end].to_vec());
            offset = end;
        }

        let count = *data.get(offset).ok_or_else(|| MegaError::InvalidResponse)? as usize;
        offset += 1;

        for _ in 0..count {
            if offset >= data.len() {
                break;
            }
            let hl = data[offset] as usize;
            offset += 1;
            if offset + hl + 16 > data.len() {
                break;
            }
            let handle_bytes = &data[offset..offset + hl];
            offset += hl;
            let key = &data[offset..offset + 16];
            offset += 16;
            km.share_keys
                .push((String::from_utf8_lossy(handle_bytes).to_string(), key.to_vec()));
        }

        Ok(km)
    }
}

