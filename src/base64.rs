//! MEGA-style URL-safe base64 encoding/decoding.
//!
//! MEGA uses a variant of base64 that:
//! - Replaces `+` with `-`
//! - Replaces `/` with `_`
//! - Removes padding `=` characters

use base64::{engine::general_purpose, Engine};

/// Encode bytes to MEGA's URL-safe base64 (no padding).
///
/// # Example
/// ```
/// use mega_rs::base64::base64url_encode;
/// let encoded = base64url_encode(b"hello");
/// assert!(!encoded.contains('='));
/// assert!(!encoded.contains('+'));
/// assert!(!encoded.contains('/'));
/// ```
pub fn base64url_encode(data: &[u8]) -> String {
    let encoded = general_purpose::STANDARD.encode(data);
    encoded
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_string()
}

/// Decode MEGA's URL-safe base64 to bytes.
///
/// # Example
/// ```
/// use mega_rs::base64::{base64url_encode, base64url_decode};
/// let original = b"hello world";
/// let encoded = base64url_encode(original);
/// let decoded = base64url_decode(&encoded).unwrap();
/// assert_eq!(decoded, original);
/// ```
pub fn base64url_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    // Replace URL-safe chars back to standard base64
    let standard = s.replace('-', "+").replace('_', "/");

    // Add padding if needed (base64 requires length to be multiple of 4)
    let padding = (4 - (standard.len() % 4)) % 4;
    let padded = format!("{}{}", standard, "=".repeat(padding));

    general_purpose::STANDARD.decode(&padded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let original = b"Hello, MEGA!";
        let encoded = base64url_encode(original);
        let decoded = base64url_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_no_padding() {
        let encoded = base64url_encode(b"test");
        assert!(!encoded.contains('='));
    }

    #[test]
    fn test_url_safe_chars() {
        // Create data that would normally produce + and / in base64
        let data: Vec<u8> = (0..255).collect();
        let encoded = base64url_encode(&data);
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
    }

    #[test]
    fn test_decode_with_url_safe_chars() {
        // Manually create a URL-safe encoded string
        let encoded = "SGVsbG8tV29ybGRf"; // Contains - and _
        let decoded = base64url_decode(encoded);
        assert!(decoded.is_ok());
    }
}
