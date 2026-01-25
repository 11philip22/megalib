//! KeyManager implementation for MEGA ^!keys attribute (simplified but format-compatible).
//!
//! This mirrors the SDK's `KeyManager::toKeysContainer/fromKeysContainer` layout enough to keep
//! share/export working on upgraded accounts. It supports the core fields (version/generation,
//! identity, privkeys, authrings, share keys, pending shares) and encrypts the container with
//! AES-128-GCM using the master key.

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes128Gcm, Nonce};
use rand::RngCore;

use crate::base64::base64url_decode;
use crate::error::{MegaError, Result};

// Tag constants (from SDK)
const TAG_VERSION: u8 = 1;
const TAG_CREATION_TIME: u8 = 2;
const TAG_IDENTITY: u8 = 3;
const TAG_GENERATION: u8 = 4;
const TAG_ATTR: u8 = 5;
const TAG_PRIV_ED25519: u8 = 16;
const TAG_PRIV_CU25519: u8 = 17;
const TAG_PRIV_RSA: u8 = 18;
const TAG_AUTHRING_ED25519: u8 = 32;
const TAG_AUTHRING_CU25519: u8 = 33;
const TAG_SHAREKEYS: u8 = 48;
const TAG_PENDING_OUTSHARES: u8 = 64;
const TAG_PENDING_INSHARES: u8 = 65;
const TAG_BACKUPS: u8 = 80;
const TAG_WARNINGS: u8 = 96;

const HEADER_BYTE0: u8 = 20;
const HEADER_BYTE1: u8 = 0;
const GCM_IV_LEN: usize = 12;

/// Share key flags are not used in this simplified implementation (set to 0).
#[derive(Debug, Clone)]
pub struct ShareKeyEntry {
    pub handle: [u8; 6],
    pub key: [u8; 16],
    pub flags: u8,
}

/// Pending outshare entry: folder handle + uid (user handle 8 bytes or email).
#[derive(Debug, Clone)]
pub struct PendingOutEntry {
    pub node_handle: [u8; 6],
    pub uid: PendingUid,
}

#[derive(Debug, Clone)]
pub enum PendingUid {
    UserHandle([u8; 8]),
    Email(String),
}

/// Pending inshare: map key (string handle) to (user handle, encrypted share key).
#[derive(Debug, Clone)]
pub struct PendingInEntry {
    pub node_handle_b64: String,
    pub user_handle: [u8; 8],
    pub share_key: Vec<u8>,
}

/// Minimal warnings/authrings/backups are carried as raw blobs (LTLV for warnings).
#[derive(Debug, Clone, Default)]
pub struct Warnings(pub Vec<(String, Vec<u8>)>);

#[derive(Debug, Clone, Default)]
pub struct KeyManager {
    pub version: u8,
    pub creation_time: u32,
    pub identity: u64,
    pub generation: u32,
    pub attr: Vec<u8>,
    pub priv_ed25519: Vec<u8>,
    pub priv_cu25519: Vec<u8>,
    pub priv_rsa: Vec<u8>,
    pub auth_ed25519: Vec<u8>,
    pub auth_cu25519: Vec<u8>,
    pub share_keys: Vec<ShareKeyEntry>,
    pub pending_out: Vec<PendingOutEntry>,
    pub pending_in: Vec<PendingInEntry>,
    pub backups: Vec<u8>,
    pub warnings: Warnings,
}

impl Default for ShareKeyEntry {
    fn default() -> Self {
        ShareKeyEntry {
            handle: [0u8; 6],
            key: [0u8; 16],
            flags: 0,
        }
    }
}

impl KeyManager {
    pub fn new() -> Self {
        let mut km = KeyManager::default();
        km.version = 1;
        km.generation = 0;
        km
    }

    pub fn is_ready(&self) -> bool {
        !self.priv_ed25519.is_empty() && !self.priv_cu25519.is_empty()
    }

    pub fn set_priv_keys(&mut self, ed: &[u8], cu: &[u8]) {
        self.priv_ed25519 = ed.to_vec();
        self.priv_cu25519 = cu.to_vec();
    }

    pub fn add_share_key_from_str(&mut self, handle_b64: &str, key: &[u8]) {
        if key.len() != 16 {
            return;
        }
        if let Ok(decoded) = base64url_decode(handle_b64) {
            if decoded.len() == 6 {
                let mut h = [0u8; 6];
                h.copy_from_slice(&decoded);
                let mut k = [0u8; 16];
                k.copy_from_slice(key);
                self.share_keys.push(ShareKeyEntry {
                    handle: h,
                    key: k,
                    flags: 0,
                });
            }
        }
    }

    pub fn add_share_key(&mut self, handle_b64: String, key: Vec<u8>) {
        self.add_share_key_from_str(&handle_b64, &key);
    }

    pub fn get_share_key_from_str(&self, handle_b64: &str) -> Option<[u8; 16]> {
        let decoded = base64url_decode(handle_b64).ok()?;
        if decoded.len() != 6 {
            return None;
        }
        for sk in &self.share_keys {
            if sk.handle == decoded.as_slice() {
                return Some(sk.key);
            }
        }
        None
    }
    /// Encode to LTLV then AES-GCM encrypt with master key. Returns final ^!keys blob.
    pub fn encode_container(&self, master_key: &[u8; 16]) -> Result<Vec<u8>> {
        let plain = self.serialize_ltlv()?;
        // GCM encrypt
        let cipher = Aes128Gcm::new_from_slice(master_key)
            .map_err(|e| MegaError::CryptoError(format!("GCM init: {}", e)))?;
        let mut iv = [0u8; GCM_IV_LEN];
        OsRng.fill_bytes(&mut iv);
        let nonce = Nonce::from_slice(&iv);
        let mut ct = cipher
            .encrypt(nonce, plain.as_ref())
            .map_err(|e| MegaError::CryptoError(format!("GCM encrypt: {}", e)))?;

        let mut out = Vec::with_capacity(2 + GCM_IV_LEN + ct.len());
        out.push(HEADER_BYTE0);
        out.push(HEADER_BYTE1);
        out.extend_from_slice(&iv);
        out.append(&mut ct);
        Ok(out)
    }

    /// Decode ^!keys blob: check header, decrypt GCM, parse LTLV.
    pub fn decode_container(&mut self, data: &[u8], master_key: &[u8; 16]) -> Result<()> {
        if data.len() < 2 + GCM_IV_LEN + 16 {
            return Err(MegaError::InvalidResponse);
        }
        if data[0] != HEADER_BYTE0 || data[1] != HEADER_BYTE1 {
            return Err(MegaError::InvalidResponse);
        }
        let iv = &data[2..2 + GCM_IV_LEN];
        let ct = &data[2 + GCM_IV_LEN..];
        let cipher = Aes128Gcm::new_from_slice(master_key)
            .map_err(|e| MegaError::CryptoError(format!("GCM init: {}", e)))?;
        let nonce = Nonce::from_slice(iv);
        let plain = cipher
            .decrypt(nonce, ct)
            .map_err(|e| MegaError::CryptoError(format!("GCM decrypt: {}", e)))?;
        self.deserialize_ltlv(&plain)
    }

    fn tag_header(tag: u8, len: usize) -> [u8; 4] {
        [
            tag,
            ((len >> 16) & 0xFF) as u8,
            ((len >> 8) & 0xFF) as u8,
            (len & 0xFF) as u8,
        ]
    }

    fn serialize_ltlv(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        // version
        out.extend_from_slice(&Self::tag_header(TAG_VERSION, 1));
        out.push(self.version);
        // creation time
        let ct_be = self.creation_time.to_be_bytes();
        out.extend_from_slice(&Self::tag_header(TAG_CREATION_TIME, ct_be.len()));
        out.extend_from_slice(&ct_be);
        // identity
        let id_bytes = self.identity.to_le_bytes(); // SDK stores as little? It appends raw u64.
        out.extend_from_slice(&Self::tag_header(TAG_IDENTITY, id_bytes.len()));
        out.extend_from_slice(&id_bytes);
        // generation (stored as gen+1, BE)
        let gen_be = (self.generation + 1).to_be_bytes();
        out.extend_from_slice(&Self::tag_header(TAG_GENERATION, gen_be.len()));
        out.extend_from_slice(&gen_be);
        // attr
        out.extend_from_slice(&Self::tag_header(TAG_ATTR, self.attr.len()));
        out.extend_from_slice(&self.attr);
        // priv ed
        out.extend_from_slice(&Self::tag_header(TAG_PRIV_ED25519, self.priv_ed25519.len()));
        out.extend_from_slice(&self.priv_ed25519);
        // priv cu
        out.extend_from_slice(&Self::tag_header(TAG_PRIV_CU25519, self.priv_cu25519.len()));
        out.extend_from_slice(&self.priv_cu25519);
        // priv rsa
        out.extend_from_slice(&Self::tag_header(TAG_PRIV_RSA, self.priv_rsa.len()));
        out.extend_from_slice(&self.priv_rsa);
        // authrings
        out.extend_from_slice(&Self::tag_header(TAG_AUTHRING_ED25519, self.auth_ed25519.len()));
        out.extend_from_slice(&self.auth_ed25519);
        out.extend_from_slice(&Self::tag_header(TAG_AUTHRING_CU25519, self.auth_cu25519.len()));
        out.extend_from_slice(&self.auth_cu25519);
        // share keys
        let sk_blob = self.serialize_share_keys();
        out.extend_from_slice(&Self::tag_header(TAG_SHAREKEYS, sk_blob.len()));
        out.extend_from_slice(&sk_blob);
        // pending out/in, backups, warnings (may be empty)
        let po_blob = self.serialize_pending_out();
        out.extend_from_slice(&Self::tag_header(TAG_PENDING_OUTSHARES, po_blob.len()));
        out.extend_from_slice(&po_blob);
        let pi_blob = self.serialize_pending_in();
        out.extend_from_slice(&Self::tag_header(TAG_PENDING_INSHARES, pi_blob.len()));
        out.extend_from_slice(&pi_blob);
        out.extend_from_slice(&Self::tag_header(TAG_BACKUPS, self.backups.len()));
        out.extend_from_slice(&self.backups);
        let warn_blob = self.serialize_warnings();
        out.extend_from_slice(&Self::tag_header(TAG_WARNINGS, warn_blob.len()));
        out.extend_from_slice(&warn_blob);
        // other (omitted)
        Ok(out)
    }

    fn deserialize_ltlv(&mut self, data: &[u8]) -> Result<()> {
        let mut offset = 0usize;
        while offset + 4 <= data.len() {
            let tag = data[offset];
            let len = ((data[offset + 1] as usize) << 16)
                | ((data[offset + 2] as usize) << 8)
                | data[offset + 3] as usize;
            offset += 4;
            if offset + len > data.len() {
                return Err(MegaError::InvalidResponse);
            }
            let slice = &data[offset..offset + len];
            offset += len;
            match tag {
                TAG_VERSION => {
                    if !slice.is_empty() {
                        self.version = slice[0];
                    }
                }
                TAG_CREATION_TIME => {
                    if slice.len() == 4 {
                        self.creation_time = u32::from_be_bytes(slice.try_into().unwrap());
                    }
                }
                TAG_IDENTITY => {
                    if slice.len() == 8 {
                        self.identity = u64::from_le_bytes(slice.try_into().unwrap());
                    }
                }
                TAG_GENERATION => {
                    if slice.len() == 4 {
                        let v = u32::from_be_bytes(slice.try_into().unwrap());
                        self.generation = v.saturating_sub(1);
                    }
                }
                TAG_ATTR => self.attr = slice.to_vec(),
                TAG_PRIV_ED25519 => self.priv_ed25519 = slice.to_vec(),
                TAG_PRIV_CU25519 => self.priv_cu25519 = slice.to_vec(),
                TAG_PRIV_RSA => self.priv_rsa = slice.to_vec(),
                TAG_AUTHRING_ED25519 => self.auth_ed25519 = slice.to_vec(),
                TAG_AUTHRING_CU25519 => self.auth_cu25519 = slice.to_vec(),
                TAG_SHAREKEYS => self.share_keys = Self::parse_share_keys(slice)?,
                TAG_PENDING_OUTSHARES => self.pending_out = Self::parse_pending_out(slice)?,
                TAG_PENDING_INSHARES => self.pending_in = Self::parse_pending_in(slice)?,
                TAG_BACKUPS => self.backups = slice.to_vec(),
                TAG_WARNINGS => self.warnings = Self::parse_warnings(slice)?,
                _ => {
                    // ignore unknown tags
                }
            }
        }
        Ok(())
    }

    fn serialize_share_keys(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for sk in &self.share_keys {
            out.extend_from_slice(&sk.handle);
            out.extend_from_slice(&sk.key);
            out.push(sk.flags);
        }
        out
    }

    fn parse_share_keys(data: &[u8]) -> Result<Vec<ShareKeyEntry>> {
        let mut out = Vec::new();
        let mut offset = 0usize;
        while offset + 6 + 16 + 1 <= data.len() {
            let mut h = [0u8; 6];
            h.copy_from_slice(&data[offset..offset + 6]);
            offset += 6;
            let mut k = [0u8; 16];
            k.copy_from_slice(&data[offset..offset + 16]);
            offset += 16;
            let flags = data[offset];
            offset += 1;
            out.push(ShareKeyEntry { handle: h, key: k, flags });
        }
        Ok(out)
    }

    fn serialize_pending_out(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for entry in &self.pending_out {
            match &entry.uid {
                PendingUid::Email(email) => {
                    if email.len() >= 256 {
                        continue;
                    }
                    out.push(email.len() as u8);
                    out.extend_from_slice(&entry.node_handle);
                    out.extend_from_slice(email.as_bytes());
                }
                PendingUid::UserHandle(uh) => {
                    out.push(0);
                    out.extend_from_slice(&entry.node_handle);
                    out.extend_from_slice(uh);
                }
            }
        }
        out
    }

    fn parse_pending_out(data: &[u8]) -> Result<Vec<PendingOutEntry>> {
        let mut out = Vec::new();
        let mut offset = 0usize;
        while offset + 1 + 6 <= data.len() {
            let len = data[offset] as usize;
            offset += 1;
            if offset + 6 > data.len() {
                break;
            }
            let mut h = [0u8; 6];
            h.copy_from_slice(&data[offset..offset + 6]);
            offset += 6;
            if len == 0 {
                if offset + 8 > data.len() {
                    break;
                }
                let mut uh = [0u8; 8];
                uh.copy_from_slice(&data[offset..offset + 8]);
                offset += 8;
                out.push(PendingOutEntry {
                    node_handle: h,
                    uid: PendingUid::UserHandle(uh),
                });
            } else {
                if offset + len > data.len() {
                    break;
                }
                let email = String::from_utf8_lossy(&data[offset..offset + len]).to_string();
                offset += len;
                out.push(PendingOutEntry {
                    node_handle: h,
                    uid: PendingUid::Email(email),
                });
            }
        }
        Ok(out)
    }

    fn serialize_pending_in(&self) -> Vec<u8> {
        // LTLV: [len(tag) tag len(value) value]*
        let mut entries = Vec::new();
        for entry in &self.pending_in {
            let mut value = Vec::new();
            value.extend_from_slice(&entry.user_handle);
            value.extend_from_slice(&entry.share_key);
            entries.push((entry.node_handle_b64.clone(), value));
        }
        Self::serialize_ltlv_map(entries)
    }

    fn parse_pending_in(data: &[u8]) -> Result<Vec<PendingInEntry>> {
        let map = Self::parse_ltlv_map(data)?;
        let mut out = Vec::new();
        for (tag, value) in map {
            if value.len() < 8 {
                continue;
            }
            let mut uh = [0u8; 8];
            uh.copy_from_slice(&value[..8]);
            let share_key = value[8..].to_vec();
            out.push(PendingInEntry {
                node_handle_b64: tag,
                user_handle: uh,
                share_key,
            });
        }
        Ok(out)
    }

    fn serialize_warnings(&self) -> Vec<u8> {
        let items = self
            .warnings
            .0
            .iter()
            .map(|(t, v)| (t.clone(), v.clone()))
            .collect::<Vec<_>>();
        Self::serialize_ltlv_map(items)
    }

    fn parse_warnings(data: &[u8]) -> Result<Warnings> {
        let map = Self::parse_ltlv_map(data)?;
        Ok(Warnings(map))
    }

    fn serialize_ltlv_map(entries: Vec<(String, Vec<u8>)>) -> Vec<u8> {
        let mut out = Vec::new();
        for (tag, value) in entries {
            if tag.len() > 255 {
                continue;
            }
            out.push(tag.len() as u8);
            out.extend_from_slice(tag.as_bytes());
            if value.len() < 0xFFFF {
                let len_be = (value.len() as u16).to_be_bytes();
                out.extend_from_slice(&len_be);
            } else {
                out.extend_from_slice(&0xFFFFu16.to_be_bytes());
                let len_be = (value.len() as u32).to_be_bytes();
                out.extend_from_slice(&len_be);
            }
            out.extend_from_slice(&value);
        }
        out
    }

    fn parse_ltlv_map(data: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
        let mut out = Vec::new();
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
            let mut val_len: usize = len16 as usize;
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
            if offset + val_len > data.len() {
                break;
            }
            let value = data[offset..offset + val_len].to_vec();
            offset += val_len;
            out.push((tag, value));
        }
        Ok(out)
    }
}
