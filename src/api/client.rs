//! MEGA API client with request/response handling.

use crate::error::{MegaError, Result};
use crate::http::HttpClient;
use serde_json::Value;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tracing::{info_span, trace};
use super::ApiErrorCode;

async fn sleep(duration: Duration) {
    tokio::time::sleep(duration).await;
}

/// Base URL for MEGA API
const API_URL: &str = "https://g.api.mega.co.nz/cs";
/// Base URL for SC polling (action packets)
const WSC_URL: &str = "https://g.api.mega.co.nz/wsc";
const SC_URL: &str = "https://g.api.mega.co.nz/sc";
/// Base URL for user alerts polling
const SC_ALERTS_URL: &str = "https://g.api.mega.co.nz/sc?c=50";

/// MEGA API client.
#[derive(Debug)]
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

    /// Create a new API client with a proxy.
    ///
    /// # Arguments
    /// * `proxy` - Proxy URL (e.g., "http://proxy:8080" or "socks5://proxy:1080")
    pub fn with_proxy(proxy: &str) -> crate::error::Result<Self> {
        Ok(Self {
            http: HttpClient::with_proxy(proxy)?,
            request_id: rand::random(),
            session_id: None,
        })
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
        self.request_with_allowed(request, &[]).await
    }

    /// Same as `request` but treat specific negative codes as non-fatal and return them.
    pub async fn request_with_allowed(
        &mut self,
        request: Value,
        allowed_errors: &[i64],
    ) -> Result<Value> {
        let action_name = request.get("a").and_then(|v| v.as_str()).unwrap_or("");
        let span = info_span!(
            "mega.api.request",
            action = action_name,
            sid_present = self.session_id.is_some(),
            allowed_errors = ?allowed_errors
        );
        let _guard = span.enter();

        // MEGA API expects array of commands
        let body = serde_json::to_string(&vec![request.clone()])?;

        // Retry logic with exponential backoff
        let mut delay_ms = 250u64;
        let max_delay_ms = 256_000u64; // ~4 minutes max
        let mut attempts = 0;
        let max_attempts = if action_name == "s2" { 6 } else { 8 };

        loop {
            // Small delay to avoid rate limiting
            sleep(Duration::from_millis(20)).await;

            // Recompute request id and URL on every attempt to avoid server-side dedup
            self.request_id = self.request_id.wrapping_add(1);
            let mut url = match &self.session_id {
                Some(sid) => format!("{}?id={}&sid={}", API_URL, self.request_id, sid),
                None => format!("{}?id={}", API_URL, self.request_id),
            };
            url.push_str("&v=3");
            // Browser adds bc=1 on share calls; include it for s2 to match behavior.
            if action_name == "s2" {
                url.push_str("&bc=1");
            }
            let attempt = attempts + 1;
            let request_id = self.request_id;
            let start = Instant::now();
            let response_text =
                match timeout(Duration::from_secs(20), self.http.post(&url, &body)).await {
                    Ok(Ok(text)) => text,
                    Ok(Err(err)) => {
                        let elapsed_ms = start.elapsed().as_millis() as u64;
                        trace!(
                            request_id,
                            attempt,
                            url = %url,
                            body_bytes = body.len(),
                            body = %body,
                            elapsed_ms,
                            error = %err,
                            "api request"
                        );
                        return Err(err);
                    }
                    Err(_) => {
                        let elapsed_ms = start.elapsed().as_millis() as u64;
                        trace!(
                            request_id,
                            attempt,
                            url = %url,
                            body_bytes = body.len(),
                            body = %body,
                            elapsed_ms,
                            error = "timeout",
                            "api request"
                        );
                        return Err(MegaError::Custom("HTTP request timed out".to_string()));
                    }
                };

            let elapsed_ms = start.elapsed().as_millis() as u64;
            let response_bytes = response_text.len();

            let response: Value = match serde_json::from_str(&response_text) {
                Ok(value) => value,
                Err(err) => {
                    trace!(
                        request_id,
                        attempt,
                        url = %url,
                        body_bytes = body.len(),
                        body = %body,
                        response_bytes,
                        response_body = %response_text,
                        elapsed_ms,
                        error = %err,
                        "api request"
                    );
                    return Err(err.into());
                }
            };
            attempts += 1;

            // Handle single-number array like [-3] as errors (including EAGAIN)
            if let Some(arr) = response.as_array() {
                if arr.len() == 1 {
                    if let Some(code) = arr[0].as_i64() {
                        // MEGA returns [0] for success on some calls (e.g. uc); treat >=0 as success.
                        if code >= 0 {
                            trace!(
                                request_id,
                                attempt,
                                url = %url,
                                body_bytes = body.len(),
                                body = %body,
                                response_bytes,
                                response_body = %response_text,
                                elapsed_ms,
                                result = "ok",
                                api_code = code,
                                "api request"
                            );
                            return Ok(Value::from(code));
                        }
                        let error_code = ApiErrorCode::from(code);
                        if allowed_errors.contains(&code) {
                            trace!(
                                request_id,
                                attempt,
                                url = %url,
                                body_bytes = body.len(),
                                body = %body,
                                response_bytes,
                                response_body = %response_text,
                                elapsed_ms,
                                result = "allowed_error",
                                api_error = code,
                                "api request"
                            );
                            return Ok(Value::from(code));
                        }
                        if error_code == ApiErrorCode::Again {
                            sleep(Duration::from_millis(delay_ms)).await;
                            let next_delay = delay_ms.saturating_mul(2);
                            let retry_limit = attempts >= max_attempts || next_delay > max_delay_ms;
                            trace!(
                                request_id,
                                attempt,
                                url = %url,
                                body_bytes = body.len(),
                                body = %body,
                                response_bytes,
                                response_body = %response_text,
                                elapsed_ms,
                                result = if retry_limit { "server_busy" } else { "retry" },
                                api_error = code,
                                delay_ms,
                                next_delay,
                                max_attempts,
                                "api request"
                            );
                            if retry_limit {
                                return Err(MegaError::ServerBusy);
                            }
                            delay_ms = next_delay;
                            continue;
                        }
                        trace!(
                            request_id,
                            attempt,
                            url = %url,
                            body_bytes = body.len(),
                            body = %body,
                            response_bytes,
                            response_body = %response_text,
                            elapsed_ms,
                            result = "api_error",
                            api_error = code,
                            "api request"
                        );
                        return Err(MegaError::ApiError {
                            code: code as i32,
                            message: error_code.description().to_string(),
                        });
                    }
                }
                if let Some(first) = arr.first() {
                    trace!(
                        request_id,
                        attempt,
                        url = %url,
                        body_bytes = body.len(),
                        body = %body,
                        response_bytes,
                        response_body = %response_text,
                        elapsed_ms,
                        result = "ok",
                        "api request"
                    );
                    return Ok(first.clone());
                }
                trace!(
                    request_id,
                    attempt,
                    url = %url,
                    body_bytes = body.len(),
                    body = %body,
                    response_bytes,
                    response_body = %response_text,
                    elapsed_ms,
                    result = "invalid_response",
                    "api request"
                );
                return Err(MegaError::InvalidResponse);
            }

            // Check for scalar errors
            if let Some(code) = response.as_i64() {
                let error_code = ApiErrorCode::from(code);

                if error_code == ApiErrorCode::Again {
                    sleep(Duration::from_millis(delay_ms)).await;
                    let next_delay = delay_ms.saturating_mul(2);
                    let retry_limit = attempts >= max_attempts || next_delay > max_delay_ms;
                    trace!(
                        request_id,
                        attempt,
                        url = %url,
                        body_bytes = body.len(),
                        body = %body,
                        response_bytes,
                        response_body = %response_text,
                        elapsed_ms,
                        result = if retry_limit { "server_busy" } else { "retry" },
                        api_error = code,
                        delay_ms,
                        next_delay,
                        max_attempts,
                        "api request"
                    );
                    if retry_limit {
                        return Err(MegaError::ServerBusy);
                    }
                    delay_ms = next_delay;
                    continue;
                }

                // Other error codes
                trace!(
                    request_id,
                    attempt,
                    url = %url,
                    body_bytes = body.len(),
                    body = %body,
                    response_bytes,
                    response_body = %response_text,
                    elapsed_ms,
                    result = "api_error",
                    api_error = code,
                    "api request"
                );
                return Err(MegaError::ApiError {
                    code: code as i32,
                    message: error_code.description().to_string(),
                });
            }

            // Unexpected shape
            trace!(
                request_id,
                attempt,
                url = %url,
                body_bytes = body.len(),
                body = %body,
                response_bytes,
                response_body = %response_text,
                elapsed_ms,
                result = "invalid_response",
                "api request"
            );
            return Err(MegaError::InvalidResponse);
        }
    }

    /// Poll the SC (action packet) channel using the SDK-style WSC endpoint.
    ///
    /// Returns the list of action packets, the next sequence number, an optional
    /// WSC base URL (from the `w` field), and whether more packets are pending (`ir`).
    pub async fn poll_sc(
        &mut self,
        sn: Option<&str>,
        wsc_base: Option<&str>,
        use_sc: bool,
    ) -> Result<(Vec<Value>, String, Option<String>, bool)> {
        let sn = sn.ok_or_else(|| MegaError::Custom("Missing SC sequence number".to_string()))?;
        let sid = self
            .session_id
            .as_deref()
            .ok_or_else(|| MegaError::Custom("Session ID not set".to_string()))?;

        let base = if use_sc {
            SC_URL
        } else {
            wsc_base.unwrap_or(WSC_URL)
        };
        let mut url = base.to_string();
        let sep = if url.contains('?') { "&" } else { "?" };
        url.push_str(sep);
        url.push_str("sn=");
        url.push_str(sn);
        url.push_str("&sid=");
        url.push_str(sid);

        let response_text = self.http.post(&url, "").await?;
        let resp: Value = serde_json::from_str(&response_text)
            .map_err(|_| MegaError::InvalidResponse)?;

        if let Some(code) = resp.as_i64() {
            if code == 0 {
                return Ok((Vec::new(), sn.to_string(), None, false));
            }
            let error_code = ApiErrorCode::from(code);
            return Err(MegaError::ApiError {
                code: code as i32,
                message: error_code.description().to_string(),
            });
        }

        let obj = resp.as_object().ok_or(MegaError::InvalidResponse)?;
        let next_sn = obj
            .get("sn")
            .and_then(|v| v.as_str())
            .ok_or(MegaError::InvalidResponse)?
            .to_string();
        let wsc = obj.get("w").and_then(|v| v.as_str()).map(|s| s.to_string());
        let ir = obj
            .get("ir")
            .and_then(|v| v.as_i64())
            .map(|v| v == 1)
            .unwrap_or(false);
        let events = obj
            .get("a")
            .and_then(|v| v.as_array())
            .map(|arr| arr.clone())
            .unwrap_or_default();

        Ok((events, next_sn, wsc, ir))
    }

    /// Poll user alerts (SC50).
    ///
    /// Returns the list of alert objects and the last-seen sequence (`lsn`) if present.
    pub async fn poll_user_alerts(&mut self) -> Result<(Vec<Value>, Option<String>)> {
        let sid = self
            .session_id
            .as_deref()
            .ok_or_else(|| MegaError::Custom("Session ID not set".to_string()))?;
        let url = format!("{}&sid={}", SC_ALERTS_URL, sid);
        let response_text = self.http.post(&url, "").await?;
        let resp: Value = serde_json::from_str(&response_text)
            .map_err(|_| MegaError::InvalidResponse)?;

        if let Some(code) = resp.as_i64() {
            let error_code = ApiErrorCode::from(code);
            return Err(MegaError::ApiError {
                code: code as i32,
                message: error_code.description().to_string(),
            });
        }

        let obj = resp.as_object().ok_or(MegaError::InvalidResponse)?;
        let alerts = obj
            .get("c")
            .and_then(|v| v.as_array())
            .map(|arr| arr.clone())
            .unwrap_or_default();
        let lsn = obj.get("lsn").and_then(|v| v.as_str()).map(|s| s.to_string());
        Ok((alerts, lsn))
    }

    /// Make a batch API request to MEGA.
    ///
    /// Sends multiple commands in a single request.
    ///
    /// # Arguments
    /// * `requests` - Vector of JSON request objects
    ///
    /// # Returns
    /// JSON array of responses from the API
    pub async fn request_batch(&mut self, requests: Vec<Value>) -> Result<Value> {
        if requests.is_empty() {
            return Ok(Value::Array(vec![]));
        }

        let span = info_span!(
            "mega.api.request_batch",
            sid_present = self.session_id.is_some(),
            batch_len = requests.len()
        );
        let _guard = span.enter();

        self.request_id = self.request_id.wrapping_add(1);
        let request_id = self.request_id;

        let url = match &self.session_id {
            Some(sid) => format!("{}?id={}&sid={}", API_URL, self.request_id, sid),
            None => format!("{}?id={}", API_URL, self.request_id),
        };
        let url = format!("{}&v=3", url);

        let body = serde_json::to_string(&requests)?;

        // Retry logic
        let mut delay_ms = 250u64;
        let max_delay_ms = 256_000u64;

        loop {
            sleep(Duration::from_millis(20)).await;

            let start = Instant::now();
            let response_text = match self.http.post(&url, &body).await {
                Ok(text) => text,
                Err(err) => {
                    let elapsed_ms = start.elapsed().as_millis() as u64;
                    trace!(
                        request_id,
                        url = %url,
                        body_bytes = body.len(),
                        body = %body,
                        elapsed_ms,
                        error = %err,
                        "api batch request"
                    );
                    return Err(err);
                }
            };
            let elapsed_ms = start.elapsed().as_millis() as u64;
            let response_bytes = response_text.len();

            let response: Value = match serde_json::from_str(&response_text) {
                Ok(value) => value,
                Err(err) => {
                    trace!(
                        request_id,
                        url = %url,
                        body_bytes = body.len(),
                        body = %body,
                        response_bytes,
                        response_body = %response_text,
                        elapsed_ms,
                        error = %err,
                        "api batch request"
                    );
                    return Err(err.into());
                }
            };

            // Check for EAGAIN error
            if let Some(code) = response.as_i64() {
                let error_code = ApiErrorCode::from(code);

                if error_code == ApiErrorCode::Again {
                    sleep(Duration::from_millis(delay_ms)).await;
                    let next_delay = delay_ms.saturating_mul(2);
                    let retry_limit = next_delay > max_delay_ms;
                    trace!(
                        request_id,
                        url = %url,
                        body_bytes = body.len(),
                        body = %body,
                        response_bytes,
                        response_body = %response_text,
                        elapsed_ms,
                        result = if retry_limit { "server_busy" } else { "retry" },
                        api_error = code,
                        delay_ms,
                        next_delay,
                        "api batch request"
                    );
                    if retry_limit {
                        return Err(MegaError::ServerBusy);
                    }
                    delay_ms = next_delay;
                    continue;
                }

                trace!(
                    request_id,
                    url = %url,
                    body_bytes = body.len(),
                    body = %body,
                    response_bytes,
                    response_body = %response_text,
                    elapsed_ms,
                    result = "api_error",
                    api_error = code,
                    "api batch request"
                );
                return Err(MegaError::ApiError {
                    code: code as i32,
                    message: error_code.description().to_string(),
                });
            }

            // Return the full response array
            trace!(
                request_id,
                url = %url,
                body_bytes = body.len(),
                body = %body,
                response_bytes,
                response_body = %response_text,
                elapsed_ms,
                result = "ok",
                "api batch request"
            );
            return Ok(response);
        }
    }

    /// Fetch a user attribute (private or otherwise).
    ///
    /// Caller is responsible for decoding/decrypting the attribute contents.
    /// `attr` should be the raw attribute name, e.g. "^!keys" or "*keyring".
    pub async fn get_user_attribute(&mut self, attr: &str) -> Result<Value> {
        self.request(serde_json::json!({
            "a": "uga",
            "ua": attr
        }))
        .await
    }

    /// Set a versioned private user attribute (upv), used for attributes like ^!keys.
    ///
    /// `attr` is the attribute name, `value` is already base64url-encoded.
    /// `version` is the version token; SDK sends 0 on first set.
    pub async fn set_private_attribute(
        &mut self,
        attr: &str,
        value: &str,
        version: Option<&str>,
    ) -> Result<Value> {
        // One attribute per upv, matching SDK
        let mut obj = serde_json::Map::new();
        obj.insert("a".into(), serde_json::Value::from("upv"));
        let ver_value = match version {
            Some(v) => serde_json::Value::from(v),
            None => serde_json::Value::from(0),
        };
        obj.insert(
            attr.into(),
            serde_json::Value::Array(vec![serde_json::Value::from(value), ver_value]),
        );
        self.request(serde_json::Value::Object(obj)).await
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
    fn test_client_creation() {
        let client = ApiClient::new();
        assert!(client.session_id.is_none());
    }

    #[test]
    fn test_proxy_creation() {
        let client = ApiClient::with_proxy("http://127.0.0.1:8080");
        assert!(client.is_ok());
    }

    #[test]
    fn test_session_management() {
        let mut client = ApiClient::new();
        assert!(client.session_id().is_none());

        // Set session
        client.set_session_id("test_session_id".to_string());
        assert_eq!(client.session_id(), Some("test_session_id"));

        // Clear session
        client.clear_session_id();
        assert!(client.session_id().is_none());
    }
}
