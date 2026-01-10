//! Random key generation.

use rand::RngCore;

/// Generate a random 16-byte AES-128 key.
///
/// Uses the system's cryptographically secure random number generator.
///
/// # Example
/// ```
/// use mega_rs::crypto::make_random_key;
/// let key = make_random_key();
/// assert_eq!(key.len(), 16);
/// ```
pub fn make_random_key() -> [u8; 16] {
    let mut key = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_key_length() {
        let key = make_random_key();
        assert_eq!(key.len(), 16);
    }

    #[test]
    fn test_random_keys_are_different() {
        let key1 = make_random_key();
        let key2 = make_random_key();
        assert_ne!(key1, key2);
    }
}
