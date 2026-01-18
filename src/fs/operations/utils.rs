//! Shared helpers for filesystem operations.

use crate::base64::base64url_encode;

/// Normalize a path (remove trailing slashes, handle //).
pub(crate) fn normalize_path(path: &str) -> String {
    let mut result = path.replace("//", "/");
    while result.ends_with('/') && result.len() > 1 {
        result.pop();
    }
    if !result.starts_with('/') {
        result = format!("/{}", result);
    }
    result
}

pub(crate) fn get_chunk_size(chunk_index: usize, offset: u64, total_size: u64) -> u64 {
    // Mega chunk sizes:
    // Chunks 1-8: idx * 128KB (128, 256, 384, 512, 640, 768, 896, 1024 KB)
    // After that: 1MB fixed.

    let size = if chunk_index < 8 {
        (chunk_index as u64 + 1) * 128 * 1024
    } else {
        1024 * 1024
    };

    if offset + size > total_size {
        total_size - offset
    } else {
        size
    }
}

pub(crate) fn upload_checksum(data: &[u8]) -> String {
    let mut crc = [0u8; 12];

    // Rolling XOR checksum
    for (i, &byte) in data.iter().enumerate() {
        crc[i % 12] ^= byte;
    }

    base64url_encode(&crc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_path() {
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path("/foo"), "/foo");
        assert_eq!(normalize_path("/foo/"), "/foo");
        assert_eq!(normalize_path("/foo//bar"), "/foo/bar");
        assert_eq!(normalize_path("foo"), "/foo");
    }
}
