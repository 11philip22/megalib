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
    base64url_encode(&upload_crc12(data, 0))
}

/// Compute the SDK-style CRC12 for upload chunks.
///
/// Matches `EncryptByChunks::updateCRC` in the MEGA SDK.
pub(crate) fn upload_crc12(data: &[u8], offset: usize) -> [u8; 12] {
    let mut crc = [0u8; 12];

    if data.is_empty() {
        return crc;
    }

    let mut idx = 0usize;
    let mut size = data.len();

    let mut ol = offset % 12;
    if ol != 0 {
        let mut ll = 12 - ol;
        if ll > size {
            ll = size;
        }
        size -= ll;
        while ll > 0 {
            crc[ol] ^= data[idx];
            ol += 1;
            idx += 1;
            ll -= 1;
        }
    }

    let full = size / 12;
    let rem = size % 12;
    for block in 0..full {
        let base = idx + block * 12;
        for i in 0..12 {
            crc[i] ^= data[base + i];
        }
    }
    idx += full * 12;

    if rem > 0 {
        let start = idx + rem;
        for i in 0..rem {
            crc[i] ^= data[start - rem + i];
        }
    }

    crc
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
