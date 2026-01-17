//! Upload state for resume support.
//!
//! This module provides structures for saving and resuming interrupted uploads.

use serde::{Deserialize, Serialize};
#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(not(target_arch = "wasm32"))]
use crate::error::{MegaError, Result};

/// Saved upload state for resuming interrupted uploads.
///
/// This struct is serialized to a temporary file next to the source file
/// and contains all information needed to resume an interrupted upload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadState {
    /// MEGA upload URL (expires after ~24h)
    pub upload_url: String,
    /// File encryption key (randomly generated at upload start)
    pub file_key: [u8; 16],
    /// Encryption nonce (randomly generated at upload start)  
    pub nonce: [u8; 8],
    /// MAC values for already-uploaded chunks
    pub chunk_macs: Vec<[u8; 16]>,
    /// Bytes already uploaded
    pub offset: u64,
    /// Total file size
    pub file_size: u64,
    /// Remote file name
    pub file_name: String,
    /// Parent folder handle
    pub parent_handle: String,
    /// SHA-256 hash of first 1MB to verify same file
    pub file_hash: String,
    /// Unix timestamp when upload started
    pub created_at: i64,
}

impl UploadState {
    /// Create a new upload state.
    pub fn new(
        upload_url: String,
        file_key: [u8; 16],
        nonce: [u8; 8],
        file_size: u64,
        file_name: String,
        parent_handle: String,
        file_hash: String,
    ) -> Self {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        Self {
            upload_url,
            file_key,
            nonce,
            chunk_macs: Vec::new(),
            offset: 0,
            file_size,
            file_name,
            parent_handle,
            file_hash,
            created_at,
        }
    }

    /// Get the state file path for a given source file.
    ///
    /// This method is only available on native targets (not WASM).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn state_file_path<P: AsRef<Path>>(source_path: P) -> std::path::PathBuf {
        let source = source_path.as_ref();
        let file_name = source
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "upload".to_string());
        source.with_file_name(format!("{}.megalib_upload", file_name))
    }

    /// Save state to file.
    ///
    /// This method is only available on native targets (not WASM).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| MegaError::Custom(format!("Failed to serialize upload state: {}", e)))?;
        std::fs::write(path, json)
            .map_err(|e| MegaError::Custom(format!("Failed to write upload state: {}", e)))?;
        Ok(())
    }

    /// Load state from file.
    ///
    /// This method is only available on native targets (not WASM).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Option<Self>> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(None);
        }

        let json = std::fs::read_to_string(path)
            .map_err(|e| MegaError::Custom(format!("Failed to read upload state: {}", e)))?;
        let state: Self = serde_json::from_str(&json)
            .map_err(|e| MegaError::Custom(format!("Failed to parse upload state: {}", e)))?;
        Ok(Some(state))
    }

    /// Delete state file.
    ///
    /// This method is only available on native targets (not WASM).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn delete<P: AsRef<Path>>(path: P) -> Result<()> {
        let path = path.as_ref();
        if path.exists() {
            std::fs::remove_file(path)
                .map_err(|e| MegaError::Custom(format!("Failed to delete upload state: {}", e)))?;
        }
        Ok(())
    }

    /// Check if the upload URL might still be valid (less than 24h old).
    pub fn is_likely_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        // Upload URLs expire after ~24 hours
        let age_hours = (now - self.created_at) / 3600;
        age_hours < 24
    }

    /// Add a chunk MAC after successful chunk upload.
    pub fn add_chunk_mac(&mut self, mac: [u8; 16], chunk_size: u64) {
        self.chunk_macs.push(mac);
        self.offset += chunk_size;
    }
}

/// Calculate a simple hash of the first 1MB of a file for verification.
///
/// This function is only available on native targets (not WASM).
#[cfg(not(target_arch = "wasm32"))]
pub fn calculate_file_hash<P: AsRef<Path>>(path: P) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let mut file = std::fs::File::open(path.as_ref())
        .map_err(|e| MegaError::Custom(format!("Failed to open file for hashing: {}", e)))?;

    let mut buffer = vec![0u8; 1024 * 1024]; // 1MB
    let bytes_read = file
        .read(&mut buffer)
        .map_err(|e| MegaError::Custom(format!("Failed to read file for hashing: {}", e)))?;

    let mut hasher = Sha256::new();
    hasher.update(&buffer[..bytes_read]);
    let hash = hasher.finalize();

    Ok(hex::encode(hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_file_path() {
        let path = UploadState::state_file_path("/home/user/myfile.zip");
        assert!(path
            .to_string_lossy()
            .ends_with("myfile.zip.megalib_upload"));
    }

    #[test]
    fn test_upload_state_serialization() {
        let state = UploadState::new(
            "https://example.com/upload".to_string(),
            [1u8; 16],
            [2u8; 8],
            1024,
            "test.txt".to_string(),
            "HANDLE123".to_string(),
            "abc123".to_string(),
        );

        let json = serde_json::to_string(&state).unwrap();
        let restored: UploadState = serde_json::from_str(&json).unwrap();

        assert_eq!(state.upload_url, restored.upload_url);
        assert_eq!(state.file_key, restored.file_key);
        assert_eq!(state.nonce, restored.nonce);
        assert_eq!(state.file_size, restored.file_size);
    }

    #[test]
    fn test_add_chunk_mac() {
        let mut state = UploadState::new(
            "url".to_string(),
            [0u8; 16],
            [0u8; 8],
            1000,
            "file".to_string(),
            "handle".to_string(),
            "hash".to_string(),
        );

        assert_eq!(state.offset, 0);
        assert!(state.chunk_macs.is_empty());

        state.add_chunk_mac([1u8; 16], 100);
        assert_eq!(state.offset, 100);
        assert_eq!(state.chunk_macs.len(), 1);
        assert_eq!(state.chunk_macs[0], [1u8; 16]);

        state.add_chunk_mac([2u8; 16], 200);
        assert_eq!(state.offset, 300);
        assert_eq!(state.chunk_macs.len(), 2);
        assert_eq!(state.chunk_macs[1], [2u8; 16]);
    }
}
