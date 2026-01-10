//! MEGA API client with request/response handling.

use crate::error::{MegaError, Result};
use crate::http::HttpClient;
use serde_json::Value;
use std::time::Duration;
use tokio::time::sleep;

/// Base URL for MEGA API
const API_URL: &str = "https://g.api.mega.co.nz/cs";

/// MEGA API error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiErrorCode {
    /// Internal error
    Internal = -1,
    /// Invalid arguments
    Args = -2,
    /// Try again (rate limited)
    Again = -3,
    /// Rate limit exceeded
    RateLimit = -4,
    /// Upload failed
    Failed = -5,
    /// Too many IPs
    TooManyIps = -6,
    /// Access denied
    AccessDenied = -7,
    /// Resource already exists
    Exist = -8,
    /// Resource does not exist
    NotExist = -9,
    /// Circular linking
    Circular = -10,
    /// Access violation
    AccessViolation = -11,
    /// Application key required
    AppKey = -12,
    /// Session expired
    Expired = -13,
    /// Not confirmed
    NotConfirmed = -14,
    /// Resource blocked
    Blocked = -15,
    /// Over quota
    OverQuota = -16,
    /// Temporarily unavailable
    TempUnavail = -17,
    /// Too many connections
    TooManyConnections = -18,
    /// Unknown error
    Unknown = -9999,
}

impl From<i64> for ApiErrorCode {
    fn from(code: i64) -> Self {
        match code {
            -1 => ApiErrorCode::Internal,
            -2 => ApiErrorCode::Args,
            -3 => ApiErrorCode::Again,
            -4 => ApiErrorCode::RateLimit,
            -5 => ApiErrorCode::Failed,
            -6 => ApiErrorCode::TooManyIps,
            -7 => ApiErrorCode::AccessDenied,
            -8 => ApiErrorCode::Exist,
            -9 => ApiErrorCode::NotExist,
            -10 => ApiErrorCode::Circular,
            -11 => ApiErrorCode::AccessViolation,
            -12 => ApiErrorCode::AppKey,
            -13 => ApiErrorCode::Expired,
            -14 => ApiErrorCode::NotConfirmed,
            -15 => ApiErrorCode::Blocked,
            -16 => ApiErrorCode::OverQuota,
            -17 => ApiErrorCode::TempUnavail,
            -18 => ApiErrorCode::TooManyConnections,
            _ => ApiErrorCode::Unknown,
        }
    }
}

impl ApiErrorCode {
    /// Get human-readable description of the error.
    pub fn description(&self) -> &'static str {
        match self {
            ApiErrorCode::Internal => "Internal error",
            ApiErrorCode::Args => "Invalid arguments",
            ApiErrorCode::Again => "Try again",
            ApiErrorCode::RateLimit => "Rate limit exceeded",
            ApiErrorCode::Failed => "Upload failed",
            ApiErrorCode::TooManyIps => "Too many IPs",
            ApiErrorCode::AccessDenied => "Access denied",
            ApiErrorCode::Exist => "Resource already exists",
            ApiErrorCode::NotExist => "Resource does not exist",
            ApiErrorCode::Circular => "Circular linking",
            ApiErrorCode::AccessViolation => "Access violation",
            ApiErrorCode::AppKey => "Application key required",
            ApiErrorCode::Expired => "Session expired",
            ApiErrorCode::NotConfirmed => "Not confirmed",
            ApiErrorCode::Blocked => "Resource blocked",
            ApiErrorCode::OverQuota => "Over quota",
            ApiErrorCode::TempUnavail => "Temporarily unavailable",
            ApiErrorCode::TooManyConnections => "Too many connections",
            ApiErrorCode::Unknown => "Unknown error",
        }
    }
}

/// MEGA API client.
pub struct ApiClient {
    http: HttpClient,
    request_id: u32,
    session_id: Option<String>,
}

impl ApiClient {
    /// Create a new API client.
    pub fn new() -> Self {
        Self {
            http: HttpClient::new(),
            request_id: rand::random(),
            session_id: None,
        }
    }

    /// Set the session ID for authenticated requests.
    pub fn set_session_id(&mut self, sid: String) {
        self.session_id = Some(sid);
    }

    /// Clear the session ID.
    pub fn clear_session_id(&mut self) {
        self.session_id = None;
    }

    /// Get the current session ID, if any.
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// Make an API request to MEGA.
    ///
    /// Handles retry logic with exponential backoff for EAGAIN responses.
    ///
    /// # Arguments
    /// * `request` - JSON request object
    ///
    /// # Returns
    /// JSON response from the API
    pub async fn request(&mut self, request: Value) -> Result<Value> {
        self.request_id = self.request_id.wrapping_add(1);

        let url = match &self.session_id {
            Some(sid) => format!("{}?id={}&sid={}", API_URL, self.request_id, sid),
            None => format!("{}?id={}", API_URL, self.request_id),
        };

        // MEGA API expects array of commands
        let body = serde_json::to_string(&vec![request])?;

        // Retry logic with exponential backoff
        let mut delay_ms = 250u64;
        let max_delay_ms = 256_000u64; // ~4 minutes max

        loop {
            // Small delay to avoid rate limiting
            sleep(Duration::from_millis(20)).await;

            let response_text = self.http.post(&url, &body).await?;
            let response: Value = serde_json::from_str(&response_text)?;

            // Check for EAGAIN (-3) error - server asks us to retry
            if let Some(code) = response.as_i64() {
                let error_code = ApiErrorCode::from(code);

                if error_code == ApiErrorCode::Again {
                    sleep(Duration::from_millis(delay_ms)).await;
                    delay_ms *= 2;

                    if delay_ms > max_delay_ms {
                        return Err(MegaError::ServerBusy);
                    }
                    continue;
                }

                // Other error codes
                return Err(MegaError::ApiError {
                    code: code as i32,
                    message: error_code.description().to_string(),
                });
            }

            // Extract first response from array
            return response
                .as_array()
                .and_then(|arr| arr.first().cloned())
                .ok_or(MegaError::InvalidResponse);
        }
    }
}

impl Default for ApiClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_conversion() {
        assert_eq!(ApiErrorCode::from(-3), ApiErrorCode::Again);
        assert_eq!(ApiErrorCode::from(-9), ApiErrorCode::NotExist);
        assert_eq!(ApiErrorCode::from(-999), ApiErrorCode::Unknown);
    }
}
