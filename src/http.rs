//! HTTP client wrapper for MEGA API requests.

use crate::error::{MegaError, Result};
use reqwest::Client;
use std::time::Duration;

/// HTTP client for making requests to MEGA servers.
#[derive(Debug)]
pub struct HttpClient {
    client: Client,
}

impl HttpClient {
    /// Create a new HTTP client.
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .build()
                .expect("Failed to build reqwest client"),
        }
    }

    /// Create a new HTTP client with a proxy.
    ///
    /// This method is only available on native targets (not WASM).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_proxy(proxy: &str) -> Result<Self> {
        let proxy = reqwest::Proxy::all(proxy)
            .map_err(|e| MegaError::CryptoError(format!("Invalid proxy: {}", e)))?;

        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .proxy(proxy)
            .timeout(Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| MegaError::CryptoError(format!("Failed to build client: {}", e)))?;

        Ok(Self { client })
    }

    /// Make a POST request with JSON body.
    ///
    /// # Arguments
    /// * `url` - URL to post to
    /// * `body` - JSON body as string
    ///
    /// # Returns
    /// Response body as string
    pub async fn post(&self, url: &str, body: &str) -> Result<String> {
        let mut current = url.to_string();
        for _ in 0..10 {
            let response = self
                .client
                .post(&current)
                .header("Content-Type", "application/json")
                .body(body.to_string())
                .send()
                .await?;

            let status = response.status();
            if status.is_redirection() {
                if let Some(loc) = response.headers().get(reqwest::header::LOCATION) {
                    if let Ok(loc_str) = loc.to_str() {
                        let next =
                            if loc_str.starts_with("http://") || loc_str.starts_with("https://") {
                                loc_str.to_string()
                            } else {
                                let base = reqwest::Url::parse(&current)
                                    .map_err(|_| MegaError::HttpError(status.as_u16()))?;
                                base.join(loc_str)
                                    .map_err(|_| MegaError::HttpError(status.as_u16()))?
                                    .to_string()
                            };
                        current = next;
                        continue;
                    }
                }
                return Err(MegaError::HttpError(status.as_u16()));
            }

            if !status.is_success() {
                return Err(MegaError::HttpError(status.as_u16()));
            }

            return Ok(response.text().await?);
        }

        Err(MegaError::Custom("Too many redirects".to_string()))
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let _client = HttpClient::new();
        let _default = HttpClient::default();
    }

    #[test]
    fn test_proxy_creation() {
        let client = HttpClient::with_proxy("http://127.0.0.1:8080");
        assert!(client.is_ok());
    }

    #[test]
    fn test_proxy_invalid() {
        // reqwest::Proxy::all fails on empty or really bad URLs?
        // Actually reqwest might be lenient on "all". Let's try something clearly invalid or empty.
        // If "invalid-proxy" is accepted by reqwest but fails at connection time, this test might need adjustment.
        // However, `reqwest::Proxy::all` usually parses the URI.

        // "http" is not a valid proxy URL by itself (needs host)
        let res = HttpClient::with_proxy(":::::::");
        assert!(res.is_err());
    }
}
