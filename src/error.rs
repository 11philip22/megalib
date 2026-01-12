//! Error types for the megalib library.

use thiserror::Error;

/// Main error type for megalib operations.
#[derive(Error, Debug)]
pub enum MegaError {
    /// HTTP request failed with status code.
    #[error("HTTP error: {0}")]
    HttpError(u16),

    /// Network request error.
    #[error("Request error: {0}")]
    RequestError(#[from] reqwest::Error),

    /// JSON parsing error.
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// Server is busy, retry later.
    #[error("Server busy, try again later")]
    ServerBusy,

    /// Invalid or unexpected response from server.
    #[error("Invalid response from server")]
    InvalidResponse,

    /// MEGA API returned an error code.
    #[error("API error: {code} - {message}")]
    ApiError { code: i32, message: String },

    /// Cryptographic operation failed.
    #[error("Crypto error: {0}")]
    CryptoError(String),

    /// Challenge verification failed during registration.
    #[error("Invalid challenge response")]
    InvalidChallenge,

    /// Base64 decoding error.
    #[error("Base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    /// Invalid state format.
    #[error("Invalid state format: {0}")]
    InvalidState(String),

    /// Custom error message.
    #[error("{0}")]
    Custom(String),
}

/// Result type alias for megalib operations.
pub type Result<T> = std::result::Result<T, MegaError>;
