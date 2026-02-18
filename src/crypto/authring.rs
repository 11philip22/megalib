//! Authring handling: per-contact public key fingerprints and trust state.
//!
//! This is a simplified mirror of the SDK's AuthRing structures. Entries are
//! keyed by user handle (base64url, 11 chars). Values store the SHA-256
//! fingerprint of the contact's public key and a verification state.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::base64::base64url_decode;

/// Verification state for a contact's public key fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthState {
    /// Fingerprint has been observed but not verified.
    Seen = 0,
    /// Fingerprint has been verified by the user.
    Verified = 1,
    /// Fingerprint changed since last observation.
    Changed = 2,
}

/// Stored fingerprint and verification state for a contact.
#[derive(Debug, Clone)]
pub struct AuthEntry {
    /// SHA-256 fingerprint of the contact's public key.
    pub fingerprint: Vec<u8>,
    /// Verification state associated with the fingerprint.
    pub state: AuthState,
}

/// Authring entries keyed by user handle (base64url).
#[derive(Debug, Clone, Default)]
pub struct AuthRing {
    /// Map of user handle to fingerprint/state entry.
    pub entries: HashMap<String, AuthEntry>,
}

impl AuthRing {
    /// Compute the SHA-256 fingerprint of a public key.
    ///
    /// # Examples
    /// ```
    /// use megalib::crypto::AuthRing;
    ///
    /// let fp = AuthRing::compute_fingerprint(b"public-key-bytes");
    /// assert_eq!(fp.len(), 32);
    /// ```
    pub fn compute_fingerprint(pubkey: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(pubkey);
        hasher.finalize().to_vec()
    }

    /// Update an entry for a handle and return its resulting state.
    ///
    /// The fingerprint is recomputed from `pubkey`. If the fingerprint matches the
    /// existing entry, the state is preserved unless `verified` is `true`, which
    /// upgrades it to [`AuthState::Verified`].
    ///
    /// # Examples
    /// ```
    /// use megalib::base64::base64url_encode;
    /// use megalib::crypto::{AuthRing, AuthState};
    ///
    /// let handle = base64url_encode(&[0u8; 8]);
    /// let mut ring = AuthRing::default();
    /// let state = ring.update(&handle, b"public-key", false);
    /// assert_eq!(state, AuthState::Seen);
    /// ```
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

    /// Get the stored verification state for a handle, if present.
    pub fn get_state(&self, handle_b64: &str) -> Option<AuthState> {
        self.entries.get(handle_b64).map(|e| e.state)
    }

    /// Merge another authring, preserving existing entries on key collisions.
    pub fn merge_union(&mut self, other: &AuthRing) {
        for (h, e) in &other.entries {
            self.entries.entry(h.clone()).or_insert_with(|| e.clone());
        }
    }

    /// Serialize to an LTLV map (`tag = handle`, `value = [state_byte || fingerprint]`).
    ///
    /// Handles longer than 255 bytes are skipped.
    ///
    /// # Examples
    /// ```
    /// use megalib::base64::base64url_encode;
    /// use megalib::crypto::AuthRing;
    ///
    /// let handle = base64url_encode(&[1u8; 8]);
    /// let mut ring = AuthRing::default();
    /// ring.update(&handle, b"key", false);
    ///
    /// let data = ring.serialize_ltlv();
    /// assert!(!data.is_empty());
    /// ```
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

    /// Deserialize from an LTLV map.
    ///
    /// Unknown or invalid entries are skipped.
    ///
    /// # Examples
    /// ```
    /// use megalib::base64::base64url_encode;
    /// use megalib::crypto::{AuthRing, AuthState};
    ///
    /// let handle = base64url_encode(&[2u8; 8]);
    /// let mut ring = AuthRing::default();
    /// ring.update(&handle, b"key", true);
    ///
    /// let data = ring.serialize_ltlv();
    /// let decoded = AuthRing::deserialize_ltlv(&data);
    /// assert_eq!(decoded.get_state(&handle), Some(AuthState::Verified));
    /// ```
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

/// Parse a handle from input if it looks like a base64url user handle.
///
/// This returns `Some(handle)` only when `input` is 11 characters long and
/// decodes to 8 bytes.
///
/// # Examples
/// ```
/// use megalib::base64::base64url_encode;
/// use megalib::crypto::normalize_handle;
///
/// let handle = base64url_encode(&[0u8; 8]);
/// assert_eq!(normalize_handle(&handle), Some(handle));
/// ```
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
