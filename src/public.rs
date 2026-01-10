//! Public link download without authentication.
//!
//! Download files from mega.nz using public links without requiring login.

use std::io::Write;

use serde_json::{json, Value};

use crate::api::ApiClient;
use crate::base64::{base64url_decode, base64url_encode};
use crate::crypto::aes::{aes128_cbc_decrypt, aes128_ctr_decrypt};
use crate::error::{MegaError, Result};

/// Information about a public file from a MEGA link.
#[derive(Debug, Clone)]
pub struct PublicFile {
    /// File name
    pub name: String,
    /// File size in bytes
    pub size: u64,
    /// File handle
    pub handle: String,
    /// Decrypted file key
    key: [u8; 32],
    /// Download URL
    download_url: String,
}

impl PublicFile {
    /// Get the decryption key as base64.
    pub fn get_key(&self) -> String {
        base64url_encode(&self.key)
    }

    /// Get the full MEGA link.
    pub fn get_link(&self) -> String {
        format!("https://mega.nz/file/{}#{}", self.handle, self.get_key())
    }
}

/// Parse a MEGA public link URL.
///
/// Supports formats:
/// - `https://mega.nz/file/HANDLE#KEY`
/// - `https://mega.nz/#!HANDLE!KEY` (legacy)
///
/// # Returns
/// Tuple of (handle, key) on success
pub fn parse_mega_link(url: &str) -> Result<(String, String)> {
    // New format: https://mega.nz/file/HANDLE#KEY
    if url.contains("/file/") {
        if let Some(pos) = url.find("/file/") {
            let rest = &url[pos + 6..];
            if let Some(hash_pos) = rest.find('#') {
                let handle = rest[..hash_pos].to_string();
                let key = rest[hash_pos + 1..].to_string();
                return Ok((handle, key));
            }
        }
    }

    // Legacy format: https://mega.nz/#!HANDLE!KEY
    if url.contains("#!") {
        if let Some(pos) = url.find("#!") {
            let rest = &url[pos + 2..];
            if let Some(bang_pos) = rest.find('!') {
                let handle = rest[..bang_pos].to_string();
                let key = rest[bang_pos + 1..].to_string();
                return Ok((handle, key));
            }
        }
    }

    Err(MegaError::Custom(format!(
        "Invalid MEGA link format: {}",
        url
    )))
}

/// Get information about a public file without downloading.
///
/// # Arguments
/// * `url` - MEGA public link URL
///
/// # Example
/// ```no_run
/// use mega_rs::public::get_public_file_info;
///
/// # async fn example() -> mega_rs::error::Result<()> {
/// let info = get_public_file_info("https://mega.nz/file/ABC123#key").await?;
/// println!("File: {} ({} bytes)", info.name, info.size);
/// # Ok(())
/// # }
/// ```
pub async fn get_public_file_info(url: &str) -> Result<PublicFile> {
    let (handle, key_b64) = parse_mega_link(url)?;

    // Decode the key
    let key_bytes = base64url_decode(&key_b64)?;
    if key_bytes.len() != 32 {
        return Err(MegaError::Custom(format!(
            "Invalid key length: expected 32, got {}",
            key_bytes.len()
        )));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);

    // Make API request (no auth needed)
    let mut api = ApiClient::new();
    let response = api
        .request(json!({
            "a": "g",
            "g": 1,
            "p": handle
        }))
        .await?;

    // Parse response
    let size = response
        .get("s")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| MegaError::Custom("Missing file size".to_string()))?;

    let download_url = response
        .get("g")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MegaError::Custom("Missing download URL".to_string()))?
        .to_string();

    let attrs_b64 = response
        .get("at")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MegaError::Custom("Missing attributes".to_string()))?;

    // Decrypt attributes to get file name
    let name = decrypt_public_attrs(attrs_b64, &key)?;

    Ok(PublicFile {
        name,
        size,
        handle,
        key,
        download_url,
    })
}

/// Download a public file to a writer.
///
/// # Arguments
/// * `url` - MEGA public link URL
/// * `writer` - Writer to receive decrypted file data
///
/// # Example
/// ```no_run
/// use mega_rs::public::download_public_file;
/// use std::fs::File;
/// use std::io::BufWriter;
///
/// # async fn example() -> mega_rs::error::Result<()> {
/// let file = File::create("output.zip")?;
/// let mut writer = BufWriter::new(file);
/// let info = download_public_file("https://mega.nz/file/ABC123#key", &mut writer).await?;
/// println!("Downloaded: {}", info.name);
/// # Ok(())
/// # }
/// ```
pub async fn download_public_file<W: Write>(url: &str, writer: &mut W) -> Result<PublicFile> {
    let info = get_public_file_info(url).await?;
    download_public_file_data(&info, writer).await?;
    Ok(info)
}

/// Download a public file using pre-fetched info.
///
/// Useful when you want to display file info before downloading.
pub async fn download_public_file_data<W: Write>(info: &PublicFile, writer: &mut W) -> Result<()> {
    // Derive AES key and nonce from the 32-byte file key
    let mut aes_key = [0u8; 16];
    let mut nonce = [0u8; 8];

    for i in 0..16 {
        aes_key[i] = info.key[i] ^ info.key[i + 16];
    }
    nonce.copy_from_slice(&info.key[16..24]);

    // Download and decrypt
    let client = reqwest::Client::new();
    let mut response = client
        .get(&info.download_url)
        .send()
        .await
        .map_err(MegaError::RequestError)?;

    if !response.status().is_success() {
        return Err(MegaError::Custom(format!(
            "Download failed with status: {}",
            response.status()
        )));
    }

    let mut offset = 0u64;
    while let Some(chunk) = response.chunk().await.map_err(MegaError::RequestError)? {
        let decrypted = aes128_ctr_decrypt(&chunk, &aes_key, &nonce, offset);
        writer
            .write_all(&decrypted)
            .map_err(|e| MegaError::Custom(format!("Write error: {}", e)))?;
        offset += chunk.len() as u64;
    }

    Ok(())
}

/// Decrypt file attributes from a public file response.
fn decrypt_public_attrs(attrs_b64: &str, key: &[u8; 32]) -> Result<String> {
    let encrypted = base64url_decode(attrs_b64)?;

    // Derive AES key: XOR first and second 16-byte halves
    let mut aes_key = [0u8; 16];
    for i in 0..16 {
        aes_key[i] = key[i] ^ key[i + 16];
    }

    let decrypted = aes128_cbc_decrypt(&encrypted, &aes_key);
    let text = String::from_utf8_lossy(&decrypted);

    if !text.starts_with("MEGA") {
        return Err(MegaError::Custom("Invalid decryption key".to_string()));
    }

    let json_str = text.trim_start_matches("MEGA").trim_end_matches('\0');
    let attrs: Value = serde_json::from_str(json_str)
        .map_err(|_| MegaError::Custom("Failed to parse attributes".to_string()))?;

    attrs
        .get("n")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| MegaError::Custom("Missing file name".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mega_link_new_format() {
        let (handle, key) = parse_mega_link("https://mega.nz/file/ABC123#keydata123").unwrap();
        assert_eq!(handle, "ABC123");
        assert_eq!(key, "keydata123");
    }

    #[test]
    fn test_parse_mega_link_legacy_format() {
        let (handle, key) = parse_mega_link("https://mega.nz/#!ABC123!keydata123").unwrap();
        assert_eq!(handle, "ABC123");
        assert_eq!(key, "keydata123");
    }

    #[test]
    fn test_parse_mega_link_invalid() {
        assert!(parse_mega_link("https://example.com/file").is_err());
    }
}
