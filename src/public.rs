//! Public link download without authentication.
//!
//! Download files from mega.nz using public links without requiring login.

use std::collections::HashMap;
use std::io::Write;

use futures::StreamExt;
use serde_json::{Value, json};

use crate::api::ApiClient;
use crate::base64::{base64url_decode, base64url_encode};
use crate::crypto::aes::{aes128_cbc_decrypt, aes128_ctr_decrypt, aes128_ecb_decrypt};
use crate::error::{MegaError, Result};
use crate::fs::node::{Node, NodeType};

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
/// use megalib::public::get_public_file_info;
///
/// # async fn example() -> megalib::error::Result<()> {
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
/// use megalib::public::download_public_file;
/// use std::fs::File;
/// use std::io::BufWriter;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
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
    let response = client
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
    let mut stream = response.bytes_stream();

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.map_err(MegaError::RequestError)?;
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

// ============================================================================
// PUBLIC FOLDER BROWSING
// ============================================================================

/// A public folder session for browsing shared folders without login.
///
/// Returned by `open_folder`, this struct holds the structure of a shared folder.
/// You can explore the folder contents using `list()` and `stat()`, and download
/// files using `download()`.
#[derive(Debug)]
pub struct PublicFolder {
    /// Folder handle
    pub handle: String,
    /// Nodes in the folder
    nodes: Vec<Node>,
}

impl PublicFolder {
    /// Get all nodes in the folder.
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// List files in a path within the folder.
    pub fn list(&self, path: &str, recursive: bool) -> Vec<&Node> {
        let normalized = normalize_folder_path(path);
        let search_prefix = if normalized == "/" {
            "/".to_string()
        } else {
            format!("{}/", normalized)
        };

        let mut results = Vec::new();
        for node in &self.nodes {
            if let Some(node_path) = &node.path {
                if recursive {
                    if node_path.starts_with(&search_prefix) && node_path != &normalized {
                        results.push(node);
                    }
                } else {
                    if let Some(stripped) = node_path.strip_prefix(&search_prefix) {
                        if !stripped.contains('/') && !stripped.is_empty() {
                            results.push(node);
                        }
                    }
                }
            }
        }
        results
    }

    /// Get a node by path.
    pub fn stat(&self, path: &str) -> Option<&Node> {
        let normalized = normalize_folder_path(path);
        self.nodes
            .iter()
            .find(|n| n.path.as_deref() == Some(&normalized))
    }

    /// Download a file from the public folder.
    pub async fn download<W: Write>(&self, node: &Node, writer: &mut W) -> Result<()> {
        if node.node_type != NodeType::File {
            return Err(MegaError::Custom("Node is not a file".to_string()));
        }

        // Get download URL
        let mut api = ApiClient::new();
        let response = api
            .request(json!({
                "a": "g",
                "g": 1,
                "n": node.handle
            }))
            .await?;

        let url = response
            .get("g")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MegaError::Custom("Missing download URL".to_string()))?;

        // Get node key and derive AES key + nonce
        let k = &node.key;
        if k.len() < 32 {
            return Err(MegaError::Custom("Invalid node key".to_string()));
        }

        let mut aes_key = [0u8; 16];
        let mut nonce = [0u8; 8];
        for i in 0..16 {
            aes_key[i] = k[i] ^ k[i + 16];
        }
        nonce.copy_from_slice(&k[16..24]);

        // Download and decrypt
        let client = reqwest::Client::new();
        let response = client
            .get(url)
            .send()
            .await
            .map_err(MegaError::RequestError)?;

        let mut offset = 0u64;
        let mut stream = response.bytes_stream();

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.map_err(MegaError::RequestError)?;
            let decrypted = aes128_ctr_decrypt(&chunk, &aes_key, &nonce, offset);
            writer
                .write_all(&decrypted)
                .map_err(|e| MegaError::Custom(format!("Write error: {}", e)))?;
            offset += chunk.len() as u64;
        }

        Ok(())
    }
}

/// Parse a MEGA folder link URL.
///
/// Supports formats:
/// - `https://mega.nz/folder/HANDLE#KEY`
/// - `https://mega.nz/#F!HANDLE!KEY` (legacy)
///
/// Returns tuple of (handle, key) on success.
pub fn parse_folder_link(url: &str) -> Result<(String, String)> {
    // New format: https://mega.nz/folder/HANDLE#KEY
    if url.contains("/folder/") {
        if let Some(pos) = url.find("/folder/") {
            let rest = &url[pos + 8..];
            if let Some(hash_pos) = rest.find('#') {
                let handle = rest[..hash_pos].to_string();
                let key = rest[hash_pos + 1..].to_string();
                return Ok((handle, key));
            }
        }
    }

    // Legacy format: https://mega.nz/#F!HANDLE!KEY
    if url.contains("#F!") {
        if let Some(pos) = url.find("#F!") {
            let rest = &url[pos + 3..];
            if let Some(bang_pos) = rest.find('!') {
                let handle = rest[..bang_pos].to_string();
                let key = rest[bang_pos + 1..].to_string();
                return Ok((handle, key));
            }
        }
    }

    Err(MegaError::Custom(format!(
        "Invalid folder link format: {}",
        url
    )))
}

/// Open a public folder from a MEGA folder link.
///
/// This allows browsing and downloading from shared folders without login.
///
/// # Arguments
/// * `url` - MEGA folder link (e.g. `https://mega.nz/folder/...`)
///
/// # Returns
/// A `PublicFolder` instance containing the folder structure and file list.
///
/// # Example
/// ```no_run
/// use megalib::public::open_folder;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let folder = open_folder("https://mega.nz/folder/ABC123#key").await?;
///
/// // List all files
/// for node in folder.list("/", true) {
///     println!("{} ({} bytes)", node.name, node.size);
/// }
///
/// // Download a specific file
/// if let Some(node) = folder.stat("/Photos/vacation.jpg") {
///     let mut file = std::fs::File::create("vacation.jpg")?;
///     folder.download(node, &mut file).await?;
/// }
/// # Ok(())
/// # }
/// ```
pub async fn open_folder(url: &str) -> Result<PublicFolder> {
    let (handle, key_b64) = parse_folder_link(url)?;

    // Decode the folder key (16 bytes for folders)
    let key_bytes = base64url_decode(&key_b64)?;
    if key_bytes.len() != 16 {
        return Err(MegaError::Custom(format!(
            "Invalid folder key length: expected 16, got {}",
            key_bytes.len()
        )));
    }

    let mut folder_key = [0u8; 16];
    folder_key.copy_from_slice(&key_bytes);

    // Make API request with folder handle

    // Folder API uses 'n' parameter in URL
    let url = format!(
        "https://g.api.mega.co.nz/cs?id={}&n={}",
        rand::random::<u32>(),
        handle
    );

    let body = serde_json::to_string(&vec![json!({"a": "f", "c": 1, "r": 1})])?;

    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(MegaError::RequestError)?;

    let response_text = response.text().await.map_err(MegaError::RequestError)?;
    let response: Value = serde_json::from_str(&response_text)?;

    // Extract first response from array
    let response = response
        .as_array()
        .and_then(|arr| arr.first().cloned())
        .ok_or(MegaError::InvalidResponse)?;

    // Parse nodes
    let nodes_array = response
        .get("f")
        .and_then(|v| v.as_array())
        .ok_or(MegaError::InvalidResponse)?;

    let mut share_keys: HashMap<String, [u8; 16]> = HashMap::new();
    let mut nodes = Vec::new();

    for (idx, node_json) in nodes_array.iter().enumerate() {
        // First node is the root folder - set its share key
        if idx == 0 {
            if let Some(h) = node_json.get("h").and_then(|v| v.as_str()) {
                share_keys.insert(h.to_string(), folder_key);
            }
        }

        if let Some(node) = parse_public_node(node_json, &folder_key, &share_keys, idx == 0) {
            nodes.push(node);
        }
    }

    // Build node paths
    build_public_node_paths(&mut nodes);

    Ok(PublicFolder { handle, nodes })
}

/// Parse a node from public folder response.
fn parse_public_node(
    json: &Value,
    folder_key: &[u8; 16],
    share_keys: &HashMap<String, [u8; 16]>,
    is_root: bool,
) -> Option<Node> {
    let handle = json.get("h")?.as_str()?.to_string();
    let parent_handle = if is_root {
        None
    } else {
        json.get("p")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };
    let node_type_int = json.get("t")?.as_i64()?;
    let node_type = NodeType::from_i64(node_type_int)?;
    let size = json.get("s").and_then(|v| v.as_u64()).unwrap_or(0);
    let timestamp = json.get("ts").and_then(|v| v.as_i64()).unwrap_or(0);

    // For root folder, the key is the folder_key itself
    // For other nodes, try to decrypt from k field, or use folder key if k is empty
    let (node_key, name) = if is_root {
        // Root node: use folder key directly for attribute decryption
        let key = folder_key.to_vec();
        let attrs_b64 = json.get("a").and_then(|v| v.as_str());
        let name = attrs_b64
            .and_then(|a| decrypt_public_node_attrs(a, &key))
            .unwrap_or_else(|| "Shared Folder".to_string());
        (key, name)
    } else {
        // Regular node: try to decrypt key from k field
        let key_str = json.get("k").and_then(|v| v.as_str()).unwrap_or("");

        let node_key = if key_str.is_empty() {
            // Empty k field: use folder key directly (common in public folders)
            folder_key.to_vec()
        } else {
            // Non-empty k: decrypt using standard method
            decrypt_public_node_key(key_str, folder_key, share_keys)?
        };

        let attrs_b64 = json.get("a")?.as_str()?;
        let name = decrypt_public_node_attrs(attrs_b64, &node_key)?;
        (node_key, name)
    };

    let file_attr = json.get("fa").and_then(|v| v.as_str()).map(|s| s.to_string());

    Some(Node {
        name,
        handle,
        parent_handle,
        node_type,
        size,
        timestamp,
        key: node_key,
        path: None,
        link: None,
        file_attr,
    })
}

/// Decrypt a node key for public folder.
fn decrypt_public_node_key(
    key_str: &str,
    folder_key: &[u8; 16],
    share_keys: &HashMap<String, [u8; 16]>,
) -> Option<Vec<u8>> {
    for part in key_str.split('/') {
        if let Some((key_handle, encrypted_key)) = part.split_once(':') {
            // Try folder key first, then share keys
            let decrypt_key = if share_keys.contains_key(key_handle) {
                share_keys.get(key_handle)?
            } else {
                folder_key
            };

            if let Ok(encrypted) = base64url_decode(encrypted_key) {
                return Some(aes128_ecb_decrypt(&encrypted, decrypt_key));
            }
        }
    }
    None
}

/// Decrypt node attributes for public folder.
fn decrypt_public_node_attrs(attrs_b64: &str, node_key: &[u8]) -> Option<String> {
    let encrypted = base64url_decode(attrs_b64).ok()?;

    let aes_key: [u8; 16] = if node_key.len() >= 32 {
        let mut key = [0u8; 16];
        for i in 0..16 {
            key[i] = node_key[i] ^ node_key[i + 16];
        }
        key
    } else if node_key.len() >= 16 {
        node_key[..16].try_into().ok()?
    } else {
        return None;
    };

    let decrypted = aes128_cbc_decrypt(&encrypted, &aes_key);
    let text = String::from_utf8_lossy(&decrypted);

    if !text.starts_with("MEGA") {
        return None;
    }

    let json_str = text.trim_start_matches("MEGA").trim_end_matches('\0');
    let attrs: Value = serde_json::from_str(json_str).ok()?;
    attrs
        .get("n")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Build paths for public folder nodes.
fn build_public_node_paths(nodes: &mut [Node]) {
    let handle_map: HashMap<&str, usize> = nodes
        .iter()
        .enumerate()
        .map(|(i, n)| (n.handle.as_str(), i))
        .collect();

    let paths: Vec<String> = (0..nodes.len())
        .map(|i| build_public_path(nodes, i, &handle_map, 0))
        .collect();

    for (i, path) in paths.into_iter().enumerate() {
        nodes[i].path = Some(path);
    }
}

fn build_public_path(
    nodes: &[Node],
    idx: usize,
    handle_map: &HashMap<&str, usize>,
    depth: usize,
) -> String {
    if depth > 100 {
        return format!("/{}", nodes[idx].name);
    }

    let node = &nodes[idx];

    // Root node (no parent)
    if node.parent_handle.is_none() {
        return format!("/{}", node.name);
    }

    if let Some(parent_handle) = &node.parent_handle {
        if let Some(&parent_idx) = handle_map.get(parent_handle.as_str()) {
            let parent_path = build_public_path(nodes, parent_idx, handle_map, depth + 1);
            return format!("{}/{}", parent_path.trim_end_matches('/'), node.name);
        }
    }

    format!("/{}", node.name)
}

fn normalize_folder_path(path: &str) -> String {
    let mut result = path.replace("//", "/");
    while result.ends_with('/') && result.len() > 1 {
        result.pop();
    }
    if !result.starts_with('/') {
        result = format!("/{}", result);
    }
    result
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

    #[test]
    fn test_parse_folder_link_new_format() {
        let (handle, key) =
            parse_folder_link("https://mega.nz/folder/XYZ789#folderkey123").unwrap();
        assert_eq!(handle, "XYZ789");
        assert_eq!(key, "folderkey123");
    }

    #[test]
    fn test_parse_folder_link_legacy_format() {
        let (handle, key) = parse_folder_link("https://mega.nz/#F!XYZ789!folderkey123").unwrap();
        assert_eq!(handle, "XYZ789");
        assert_eq!(key, "folderkey123");
    }
}
