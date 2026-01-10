//! HTTP client wrapper for MEGA API requests.

use crate::error::{MegaError, Result};
use reqwest::Client;

/// HTTP client for making requests to MEGA servers.
pub struct HttpClient {
    client: Client,
}

impl HttpClient {
    /// Create a new HTTP client.
    pub fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }

    /// Create a new HTTP client with a proxy.
    pub fn with_proxy(proxy: &str) -> Result<Self> {
        let proxy = reqwest::Proxy::all(proxy)
            .map_err(|e| MegaError::CryptoError(format!("Invalid proxy: {}", e)))?;

        let client = Client::builder()
            .proxy(proxy)
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
        let response = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(MegaError::HttpError(response.status().as_u16()));
        }

        Ok(response.text().await?)
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new()
    }
}
