//! KeyManager implementation for MEGA ^!keys attribute (simplified but format-compatible).
//!
//! This mirrors the SDK's `KeyManager::toKeysContainer/fromKeysContainer` layout enough to keep
//! share/export working on upgraded accounts. It supports the core fields (version/generation,
//! identity, privkeys, authrings, share keys, pending shares) and encrypts the container with
//! AES-128-GCM using the master key.

use std::collections::HashSet;

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes128Gcm, Nonce};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

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
pub const SHAREKEY_FLAG_TRUSTED: u8 = 1 << 0;
pub const SHAREKEY_FLAG_IN_USE: u8 = 1 << 1;

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

impl Warnings {
    pub fn set_cv(&mut self, enabled: bool) {
        let val = if enabled {
            b"1".to_vec()
        } else {
            b"0".to_vec()
        };
        if let Some(entry) = self.0.iter_mut().find(|(k, _)| k == "cv") {
            entry.1 = val;
        } else {
            self.0.push(("cv".to_string(), val));
        }
    }

    pub fn cv_enabled(&self) -> bool {
        self.0
            .iter()
            .find(|(k, _)| k == "cv")
            .map(|(_, v)| v != b"0")
            .unwrap_or(false)
    }
}

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

    /// When true, the user must manually verify contacts before share-key exchange (mirrors SDK flag).
    pub manual_verification: bool,
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

/// Derive the ^!keys AES-128-GCM key from the master key using HKDF-SHA256 (info byte = 1).
fn derive_keys_cipher(master_key: &[u8; 16]) -> [u8; 16] {
    // HKDF-Extract with salt = zeros(hashlen)
    let mut prk_mac = <Hmac<Sha256> as Mac>::new_from_slice(&[0u8; 32]).expect("HMAC key len");
    prk_mac.update(master_key);
    let prk = prk_mac.finalize().into_bytes();

    // HKDF-Expand with info = {1}, single block needed for 16 bytes
    let mut okm_mac = <Hmac<Sha256> as Mac>::new_from_slice(&prk).expect("HMAC key len");
    okm_mac.update(&[1u8]); // info
    okm_mac.update(&[1u8]); // counter
    let t1 = okm_mac.finalize().into_bytes();

    let mut out = [0u8; 16];
    out.copy_from_slice(&t1[..16]);
    out
}

impl KeyManager {
    fn validate_authring(blob: &[u8]) -> Result<()> {
        if blob.len() > 64 * 1024 {
            return Err(MegaError::InvalidResponse);
        }
        // Must be decodable as LTLV map
        let _ = Self::parse_ltlv_map(blob)?;
        Ok(())
    }

    fn union_authring(current: &[u8], incoming: &[u8]) -> Vec<u8> {
        // merge maps, preferring existing entries
        let mut map = Self::parse_ltlv_map(current).unwrap_or_default();
        if let Ok(new_entries) = Self::parse_ltlv_map(incoming) {
            for (k, v) in new_entries {
                if !map.iter().any(|(ek, _)| ek == &k) {
                    map.push((k, v));
                }
            }
        }
        Self::serialize_ltlv_map(map)
    }
    pub fn new() -> Self {
        let mut km = KeyManager::default();
        km.version = 1;
        km.generation = 0;
        km.manual_verification = false;
        km
    }

    pub fn is_ready(&self) -> bool {
        !self.priv_ed25519.is_empty() && !self.priv_cu25519.is_empty()
    }

    pub fn set_priv_keys(&mut self, ed: &[u8], cu: &[u8]) {
        self.priv_ed25519 = ed.to_vec();
        self.priv_cu25519 = cu.to_vec();
    }

    /// Insert or update a share key with explicit flag bits.
    pub fn add_share_key_with_flags(
        &mut self,
        handle_b64: &str,
        key: &[u8],
        trusted: bool,
        in_use: bool,
    ) {
        if key.len() != 16 {
            return;
        }
        let Some(handle) = Self::decode_handle(handle_b64) else {
            return;
        };
        let mut flags = 0u8;
        if trusted {
            flags |= SHAREKEY_FLAG_TRUSTED;
        }
        if in_use {
            flags |= SHAREKEY_FLAG_IN_USE;
        }

        if let Some(entry) = self
            .share_keys
            .iter_mut()
            .find(|e| e.handle == handle.as_slice())
        {
            entry.key.copy_from_slice(key);
            entry.flags |= flags;
            return;
        }

        let mut k = [0u8; 16];
        k.copy_from_slice(key);
        self.share_keys.push(ShareKeyEntry {
            handle,
            key: k,
            flags,
        });
    }

    pub fn add_share_key_from_str(&mut self, handle_b64: &str, key: &[u8]) {
        self.add_share_key_with_flags(handle_b64, key, false, false);
    }

    pub fn add_share_key(&mut self, handle_b64: String, key: Vec<u8>) {
        self.add_share_key_with_flags(&handle_b64, &key, false, false);
    }

    pub fn share_key_flags(&self, handle_b64: &str) -> Option<u8> {
        let decoded = Self::decode_handle(handle_b64)?;
        self.share_keys
            .iter()
            .find(|e| e.handle == decoded)
            .map(|e| e.flags)
    }

    pub fn is_share_key_trusted(&self, handle_b64: &str) -> bool {
        self.share_key_flags(handle_b64)
            .map(|f| f & SHAREKEY_FLAG_TRUSTED != 0)
            .unwrap_or(false)
    }

    pub fn is_share_key_in_use(&self, handle_b64: &str) -> bool {
        self.share_key_flags(handle_b64)
            .map(|f| f & SHAREKEY_FLAG_IN_USE != 0)
            .unwrap_or(false)
    }

    pub fn set_share_key_in_use(&mut self, handle_b64: &str, in_use: bool) -> bool {
        self.set_share_key_flag(handle_b64, SHAREKEY_FLAG_IN_USE, in_use)
    }

    pub fn set_share_key_trusted(&mut self, handle_b64: &str, trusted: bool) -> bool {
        self.set_share_key_flag(handle_b64, SHAREKEY_FLAG_TRUSTED, trusted)
    }

    /// Contact verification gating (manual verification feature flag)
    pub fn set_manual_verification(&mut self, enabled: bool) {
        self.manual_verification = enabled;
    }

    pub fn manual_verification(&self) -> bool {
        self.manual_verification
    }

    /// Warning flag "cv" (contact verification required) mirrors SDK behavior.
    pub fn set_contact_verification_warning(&mut self, enabled: bool) {
        let val = if enabled {
            b"1".to_vec()
        } else {
            b"0".to_vec()
        };
        if let Some(entry) = self.warnings.0.iter_mut().find(|(k, _)| k == "cv") {
            entry.1 = val;
        } else {
            self.warnings.0.push(("cv".to_string(), val));
        }
    }

    pub fn contact_verification_warning(&self) -> bool {
        self.warnings
            .0
            .iter()
            .find(|(k, _)| k == "cv")
            .map(|(_, v)| v != b"0")
            .unwrap_or(false)
    }

    /// Set raw backups blob.
    pub fn set_backups(&mut self, blob: Vec<u8>) {
        self.backups = blob;
    }

    pub fn set_authring_ed25519(&mut self, blob: Vec<u8>) {
        self.auth_ed25519 = blob;
    }

    pub fn set_authring_cu25519(&mut self, blob: Vec<u8>) {
        self.auth_cu25519 = blob;
    }

    pub fn warnings(&self) -> &Warnings {
        &self.warnings
    }

    pub fn set_warnings(&mut self, warnings: Warnings) {
        self.warnings = warnings;
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

    pub fn add_pending_out_email(&mut self, handle_b64: &str, email: &str) {
        if email.is_empty() || email.len() >= 256 {
            return;
        }
        let Some(handle) = Self::decode_handle(handle_b64) else {
            return;
        };
        let uid = PendingUid::Email(email.to_string());
        if self
            .pending_out
            .iter()
            .any(|e| e.node_handle == handle && matches_pending_uid(&e.uid, &uid))
        {
            return;
        }
        self.pending_out.push(PendingOutEntry {
            node_handle: handle,
            uid,
        });
    }

    pub fn add_pending_out_user_handle(&mut self, handle_b64: &str, user_handle: &[u8; 8]) {
        let Some(handle) = Self::decode_handle(handle_b64) else {
            return;
        };
        let uid = PendingUid::UserHandle(*user_handle);
        if self
            .pending_out
            .iter()
            .any(|e| e.node_handle == handle && matches_pending_uid(&e.uid, &uid))
        {
            return;
        }
        self.pending_out.push(PendingOutEntry {
            node_handle: handle,
            uid,
        });
    }

    pub fn remove_pending_out(&mut self, handle_b64: &str, uid: &PendingUid) -> bool {
        let Some(handle) = Self::decode_handle(handle_b64) else {
            return false;
        };
        let before = self.pending_out.len();
        self.pending_out
            .retain(|e| !(e.node_handle == handle && matches_pending_uid(&e.uid, uid)));
        before != self.pending_out.len()
    }

    pub fn add_pending_in(&mut self, handle_b64: &str, user_handle: &[u8; 8], share_key: Vec<u8>) {
        if share_key.is_empty() {
            return;
        }
        if self
            .pending_in
            .iter()
            .any(|e| e.node_handle_b64 == handle_b64 && e.user_handle == *user_handle)
        {
            return;
        }
        self.pending_in.push(PendingInEntry {
            node_handle_b64: handle_b64.to_string(),
            user_handle: *user_handle,
            share_key,
        });
    }

    pub fn remove_pending_in(&mut self, handle_b64: &str, user_handle: &[u8; 8]) -> bool {
        let before = self.pending_in.len();
        self.pending_in
            .retain(|e| !(e.node_handle_b64 == handle_b64 && e.user_handle == *user_handle));
        before != self.pending_in.len()
    }

    /// Clear the IN_USE flag for any share key not present in the provided handle set.
    pub fn clear_in_use_not_in(&mut self, handles_b64: &HashSet<String>) -> bool {
        let mut changed = false;
        for sk in &mut self.share_keys {
            let handle_b64 = crate::base64::base64url_encode(&sk.handle);
            if !handles_b64.contains(&handle_b64) && (sk.flags & SHAREKEY_FLAG_IN_USE != 0) {
                sk.flags &= !SHAREKEY_FLAG_IN_USE;
                changed = true;
            }
        }
        changed
    }

    /// Clear the TRUSTED flag for any share key not present in the provided handle set.
    pub fn clear_trusted_not_in(&mut self, handles_b64: &HashSet<String>) -> bool {
        let mut changed = false;
        for sk in &mut self.share_keys {
            let handle_b64 = crate::base64::base64url_encode(&sk.handle);
            if !handles_b64.contains(&handle_b64) && (sk.flags & SHAREKEY_FLAG_TRUSTED != 0) {
                sk.flags &= !SHAREKEY_FLAG_TRUSTED;
                changed = true;
            }
        }
        changed
    }

    fn set_share_key_flag(&mut self, handle_b64: &str, flag: u8, enabled: bool) -> bool {
        let Some(handle) = Self::decode_handle(handle_b64) else {
            return false;
        };
        if let Some(entry) = self
            .share_keys
            .iter_mut()
            .find(|e| e.handle == handle.as_slice())
        {
            if enabled {
                entry.flags |= flag;
            } else {
                entry.flags &= !flag;
            }
            return true;
        }
        false
    }

    fn decode_handle(handle_b64: &str) -> Option<[u8; 6]> {
        let decoded = base64url_decode(handle_b64).ok()?;
        if decoded.len() != 6 {
            return None;
        }
        let mut h = [0u8; 6];
        h.copy_from_slice(&decoded);
        Some(h)
    }

    /// Remove a share key entry (and associated flags) by handle.
    pub fn remove_share_key(&mut self, handle_b64: &str) -> bool {
        if let Some(handle) = Self::decode_handle(handle_b64) {
            let before = self.share_keys.len();
            self.share_keys.retain(|e| e.handle != handle);
            return self.share_keys.len() != before;
        }
        false
    }

    /// Clear TRUSTED flag on all share keys.
    pub fn clear_trusted_all(&mut self) -> bool {
        let mut changed = false;
        for sk in &mut self.share_keys {
            if (sk.flags & SHAREKEY_FLAG_TRUSTED) != 0 {
                sk.flags &= !SHAREKEY_FLAG_TRUSTED;
                changed = true;
            }
        }
        changed
    }
    /// Encode to LTLV then AES-GCM encrypt with master key. Returns final ^!keys blob.
    pub fn encode_container(&self, master_key: &[u8; 16]) -> Result<Vec<u8>> {
        if !self.priv_rsa.is_empty() && self.priv_rsa.len() < 512 {
            return Err(MegaError::Custom(
                "Invalid RSA key length in ^!keys (expected empty or >=512 bytes)".into(),
            ));
        }
        let plain = self.serialize_ltlv()?;
        // GCM encrypt
        let derived = derive_keys_cipher(master_key);
        let cipher = Aes128Gcm::new_from_slice(&derived)
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
        let derived = derive_keys_cipher(master_key);
        let cipher = Aes128Gcm::new_from_slice(&derived)
            .map_err(|e| MegaError::CryptoError(format!("GCM init: {}", e)))?;
        let nonce = Nonce::from_slice(iv);
        let plain = cipher
            .decrypt(nonce, ct)
            .map_err(|e| MegaError::CryptoError(format!("GCM decrypt: {}", e)))?;
        // Parse payload
        let mut tmp = self.clone();
        tmp.deserialize_ltlv(&plain)?;

        // Downgrade protection: reject if received generation lower than current
        if tmp.generation < self.generation {
            return Err(MegaError::DowngradeDetected);
        }

        *self = tmp;
        Ok(())
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
        // generation stored on wire as (gen + 1) like SDK
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
        out.extend_from_slice(&Self::tag_header(
            TAG_AUTHRING_ED25519,
            self.auth_ed25519.len(),
        ));
        out.extend_from_slice(&self.auth_ed25519);
        out.extend_from_slice(&Self::tag_header(
            TAG_AUTHRING_CU25519,
            self.auth_cu25519.len(),
        ));
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
                        let gen_wire = u32::from_be_bytes(slice.try_into().unwrap());
                        // SDK stores generation+1 on wire; avoid underflow on legacy zero
                        self.generation = gen_wire.saturating_sub(1);
                    }
                }
                TAG_ATTR => self.attr = slice.to_vec(),
                TAG_PRIV_ED25519 => self.priv_ed25519 = slice.to_vec(),
                TAG_PRIV_CU25519 => self.priv_cu25519 = slice.to_vec(),
                TAG_PRIV_RSA => {
                    // SDK expects empty or >=512 bytes (short format); otherwise invalid.
                    if !slice.is_empty() && slice.len() < 512 {
                        return Err(MegaError::InvalidResponse);
                    }
                    self.priv_rsa = slice.to_vec();
                }
                TAG_AUTHRING_ED25519 => {
                    Self::validate_authring(slice)?;
                    self.auth_ed25519 = slice.to_vec()
                }
                TAG_AUTHRING_CU25519 => {
                    Self::validate_authring(slice)?;
                    self.auth_cu25519 = slice.to_vec()
                }
                TAG_SHAREKEYS => self.share_keys = Self::parse_share_keys(slice)?,
                TAG_PENDING_OUTSHARES => self.pending_out = Self::parse_pending_out(slice)?,
                TAG_PENDING_INSHARES => self.pending_in = Self::parse_pending_in(slice)?,
                TAG_BACKUPS => {
                    // Backups are opaque; guard against absurdly large payloads (cap 1 MiB).
                    if slice.len() > 1_048_576 {
                        return Err(MegaError::InvalidResponse);
                    }
                    self.backups = slice.to_vec();
                }
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
            out.push(ShareKeyEntry {
                handle: h,
                key: k,
                flags,
            });
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
            // Legacy edge case: SDK used to store pending inshare value as base64 string.
            let decoded_value =
                if !value.is_empty() && value.iter().all(|b| b.is_ascii()) && value.len() > 12 {
                    if let Ok(txt) = std::str::from_utf8(&value) {
                        base64url_decode(txt).unwrap_or(value.clone())
                    } else {
                        value.clone()
                    }
                } else {
                    value.clone()
                };

            if decoded_value.len() < 8 {
                continue;
            }
            let mut uh = [0u8; 8];
            uh.copy_from_slice(&decoded_value[..8]);
            let share_key = decoded_value[8..].to_vec();
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
        if data.len() > 64 * 1024 {
            return Err(MegaError::InvalidResponse);
        }
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

    /// Merge another KeyManager into this one, preserving existing keys and unioning new entries.
    pub fn merge_from(&mut self, other: &KeyManager) {
        // Merge share keys (overwrite key+flags if handle matches, OR together flags).
        for entry in &other.share_keys {
            if let Some(existing) = self
                .share_keys
                .iter_mut()
                .find(|e| e.handle == entry.handle)
            {
                existing.key = entry.key;
                existing.flags |= entry.flags;
            } else {
                self.share_keys.push(entry.clone());
            }
        }

        // Merge pending out shares without duplicates.
        for entry in &other.pending_out {
            if !self.pending_out.iter().any(|e| {
                e.node_handle == entry.node_handle && matches_pending_uid(&e.uid, &entry.uid)
            }) {
                self.pending_out.push(entry.clone());
            }
        }

        // Merge pending in shares without duplicates.
        for entry in &other.pending_in {
            if !self.pending_in.iter().any(|e| {
                e.node_handle_b64 == entry.node_handle_b64 && e.user_handle == entry.user_handle
            }) {
                self.pending_in.push(entry.clone());
            }
        }

        if self.creation_time == 0 {
            self.creation_time = other.creation_time;
        }
        if self.identity == 0 {
            self.identity = other.identity;
        }
        if self.attr.is_empty() {
            self.attr = other.attr.clone();
        }
        if self.priv_ed25519.is_empty() {
            self.priv_ed25519 = other.priv_ed25519.clone();
        }
        if self.priv_cu25519.is_empty() {
            self.priv_cu25519 = other.priv_cu25519.clone();
        }
        if self.priv_rsa.is_empty() {
            self.priv_rsa = other.priv_rsa.clone();
        }
        // Union authrings to retain all entries
        self.auth_ed25519 = Self::union_authring(&self.auth_ed25519, &other.auth_ed25519);
        self.auth_cu25519 = Self::union_authring(&self.auth_cu25519, &other.auth_cu25519);
        if self.backups.is_empty() {
            self.backups = other.backups.clone();
        }
        // Merge warnings map: keep existing entries, add missing from other.
        for (tag, val) in &other.warnings.0 {
            if !self.warnings.0.iter().any(|(k, _)| k == tag) {
                self.warnings.0.push((tag.clone(), val.clone()));
            }
        }
        self.manual_verification |= other.manual_verification;

        self.generation = self.generation.max(other.generation);
    }
}

fn matches_pending_uid(a: &PendingUid, b: &PendingUid) -> bool {
    match (a, b) {
        (PendingUid::Email(ae), PendingUid::Email(be)) => ae == be,
        (PendingUid::UserHandle(ah), PendingUid::UserHandle(bh)) => ah == bh,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base64::base64url_encode;

    #[test]
    fn roundtrip_keys_container_uses_hkdf() {
        let master = [3u8; 16];
        let mut km = KeyManager::new();
        km.creation_time = 1234;
        km.identity = 0x1122334455667788;
        km.generation = 1;
        km.priv_ed25519 = vec![9u8; 32];
        km.priv_cu25519 = vec![8u8; 32];
        km.priv_rsa = Vec::new();
        km.auth_ed25519 = vec![1, 2, 3];
        km.auth_cu25519 = vec![4, 5, 6];
        km.share_keys.push(ShareKeyEntry {
            handle: [1u8; 6],
            key: [7u8; 16],
            flags: 0b11,
        });

        let blob = km.encode_container(&master).expect("encode");
        assert_eq!(blob[0], 20);
        assert_eq!(blob[1], 0);

        let mut decoded = KeyManager::new();
        decoded
            .decode_container(&blob, &master)
            .expect("decode with derived key");

        assert_eq!(decoded.priv_ed25519, km.priv_ed25519);
        assert_eq!(decoded.priv_cu25519, km.priv_cu25519);
        assert_eq!(decoded.share_keys.len(), 1);
        assert_eq!(decoded.share_keys[0].key, [7u8; 16]);
        assert_eq!(decoded.generation, km.generation);
    }

    #[test]
    fn reject_downgrade_on_decode() {
        let master = [9u8; 16];
        let mut current = KeyManager::new();
        current.generation = 5;
        current.priv_ed25519 = vec![1u8; 32];
        current.priv_cu25519 = vec![2u8; 32];

        let mut older = KeyManager::new();
        older.generation = 2;
        older.priv_ed25519 = vec![1u8; 32];
        older.priv_cu25519 = vec![2u8; 32];
        let blob = older.encode_container(&master).expect("encode older");

        let res = current.decode_container(&blob, &master);
        assert!(res.is_err(), "downgrade should be rejected");
    }

    #[test]
    fn merge_unions_flags_and_pending() {
        let handle_a = base64url_encode(&[0u8; 6]);
        let handle_b = base64url_encode(&[1u8; 6]);
        let handle_c = base64url_encode(&[2u8; 6]);

        let mut km1 = KeyManager::new();
        km1.generation = 1;
        km1.priv_ed25519 = vec![1u8; 32];
        km1.priv_cu25519 = vec![2u8; 32];
        km1.add_share_key_with_flags(&handle_a, &[7u8; 16], true, false);
        km1.add_pending_out_email(&handle_a, "a@example.com");

        let mut km2 = KeyManager::new();
        km2.generation = 3;
        km2.priv_ed25519 = vec![1u8; 32];
        km2.priv_cu25519 = vec![2u8; 32];
        km2.add_share_key_with_flags(&handle_a, &[7u8; 16], false, true);
        km2.add_pending_out_user_handle(&handle_b, &[9u8; 8]);
        km2.add_pending_in(&handle_c, &[5u8; 8], vec![1, 2, 3]);

        km1.merge_from(&km2);

        let flags = km1.share_key_flags(&handle_a).unwrap();
        assert!(flags & SHAREKEY_FLAG_TRUSTED != 0);
        assert!(flags & SHAREKEY_FLAG_IN_USE != 0);
        assert_eq!(km1.pending_out.len(), 2);
        assert_eq!(km1.pending_in.len(), 1);
        assert_eq!(km1.generation, 3);
    }

    #[test]
    fn generation_wire_roundtrip_plus_one() {
        let master = [4u8; 16];
        let mut km = KeyManager::new();
        km.generation = 4;
        km.priv_ed25519 = vec![1u8; 32];
        km.priv_cu25519 = vec![2u8; 32];
        let blob = km.encode_container(&master).expect("encode");

        let mut decoded = KeyManager::new();
        decoded.decode_container(&blob, &master).expect("decode");
        assert_eq!(decoded.generation, 4);
    }
}
