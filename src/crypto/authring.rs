//! Authring handling: per-contact public key fingerprints and trust state.
//!
//! This is a simplified mirror of the SDK's AuthRing structures. Entries are
//! keyed by user handle (base64url, 11 chars). Values store the SHA-256
//! fingerprint of the contact's public key and a verification state.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::base64::base64url_decode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthState {
    Seen = 0,
    Verified = 1,
    Changed = 2,
}

#[derive(Debug, Clone)]
pub struct AuthEntry {
    pub fingerprint: Vec<u8>,
    pub state: AuthState,
}

#[derive(Debug, Clone, Default)]
pub struct AuthRing {
    pub entries: HashMap<String, AuthEntry>,
}

impl AuthRing {
    pub fn compute_fingerprint(pubkey: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(pubkey);
        hasher.finalize().to_vec()
    }

    /// Update entry for handle with given public key; mark state based on changes and verified flag.
    pub fn update(&mut self, handle_b64: &str, pubkey: &[u8], verified: bool) -> AuthState {
        let fp = Self::compute_fingerprint(pubkey);
        match self.entries.get_mut(handle_b64) {
            Some(entry) => {
                if entry.fingerprint == fp {
                    if verified {
                        entry.state = AuthState::Verified;
                    }
                    entry.state
                } else {
                    entry.fingerprint = fp;
                    entry.state = if verified {
                        AuthState::Verified
                    } else {
                        AuthState::Changed
                    };
                    entry.state
                }
            }
            None => {
                let state = if verified {
                    AuthState::Verified
                } else {
                    AuthState::Seen
                };
                self.entries.insert(
                    handle_b64.to_string(),
                    AuthEntry {
                        fingerprint: fp,
                        state,
                    },
                );
                state
            }
        }
    }

    pub fn get_state(&self, handle_b64: &str) -> Option<AuthState> {
        self.entries.get(handle_b64).map(|e| e.state)
    }

    pub fn merge_union(&mut self, other: &AuthRing) {
        for (h, e) in &other.entries {
            self.entries.entry(h.clone()).or_insert_with(|| e.clone());
        }
    }

    /// Serialize to LTLV map: tag = handle, value = [state_byte || fingerprint]
    pub fn serialize_ltlv(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (tag, entry) in &self.entries {
            if tag.len() > 255 {
                continue;
            }
            let mut value = Vec::with_capacity(1 + entry.fingerprint.len());
            value.push(entry.state as u8);
            value.extend_from_slice(&entry.fingerprint);

            out.push(tag.len() as u8);
            out.extend_from_slice(tag.as_bytes());
            if value.len() < 0xFFFF {
                out.extend_from_slice(&(value.len() as u16).to_be_bytes());
            } else {
                out.extend_from_slice(&0xFFFFu16.to_be_bytes());
                out.extend_from_slice(&(value.len() as u32).to_be_bytes());
            }
            out.extend_from_slice(&value);
        }
        out
    }

    /// Deserialize from LTLV map. Unknown/invalid entries are skipped.
    pub fn deserialize_ltlv(data: &[u8]) -> Self {
        let mut ring = AuthRing::default();
        let mut offset = 0usize;
        while offset < data.len() {
            if offset >= data.len() {
                break;
            }
            let tag_len = data[offset] as usize;
            offset += 1;
            if offset + tag_len > data.len() {
                break;
            }
            let tag = String::from_utf8_lossy(&data[offset..offset + tag_len]).to_string();
            offset += tag_len;
            if offset + 2 > data.len() {
                break;
            }
            let len16 = u16::from_be_bytes([data[offset], data[offset + 1]]);
            offset += 2;
            let mut val_len = len16 as usize;
            if len16 == 0xFFFF {
                if offset + 4 > data.len() {
                    break;
                }
                let len32 = u32::from_be_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]);
                val_len = len32 as usize;
                offset += 4;
            }
            if offset + val_len > data.len() || val_len == 0 {
                break;
            }
            let value = &data[offset..offset + val_len];
            offset += val_len;
            let state = match value[0] {
                1 => AuthState::Verified,
                2 => AuthState::Changed,
                _ => AuthState::Seen,
            };
            let fp = value[1..].to_vec();
            ring.entries.insert(
                tag,
                AuthEntry {
                    fingerprint: fp,
                    state,
                },
            );
        }
        ring
    }
}

/// Convenience: parse handle from email if possible (SDK sometimes uses emails in pending data).
pub fn normalize_handle(input: &str) -> Option<String> {
    // Handle is 11-char base64url; if input decodes to 8 bytes, accept; else None.
    if input.len() == 11
        && base64url_decode(input)
            .map(|v| v.len() == 8)
            .unwrap_or(false)
    {
        Some(input.to_string())
    } else {
        None
    }
}
