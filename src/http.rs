//! HTTP client wrapper for MEGA API requests.

use crate::error::{MegaError, Result};
use reqwest::Client;
use std::time::Duration;

const INSECURE_PROXY_TLS_ENV: &str = "MEGALIB_INSECURE_PROXY_TLS";

/// Transport request classes, used to apply request-specific HTTP policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    ApiJson,
    ScPoll,
    ScUserAlerts,
    TransferUpload,
    TransferDownload,
    PublicApi,
    PublicTransfer,
}

#[derive(Debug, Clone, Copy)]
struct RequestPolicy {
    timeout: Option<Duration>,
    follow_redirects: bool,
    max_redirects: usize,
}

impl RequestPolicy {
    fn for_kind(kind: RequestKind) -> Self {
        match kind {
            RequestKind::ApiJson => Self {
                timeout: Some(Duration::from_secs(20)),
                follow_redirects: true,
                max_redirects: 10,
            },
            RequestKind::ScPoll => Self {
                // SDK SCREQUESTTIMEOUT intent: ~40 seconds on the SC long-poll lane.
                timeout: Some(Duration::from_secs(40)),
                follow_redirects: true,
                max_redirects: 10,
            },
            RequestKind::ScUserAlerts => Self {
                // SDK user-alert catch-up (`sc?c=50`) is sent on SC lane without long-poll timeout semantics.
                timeout: None,
                follow_redirects: true,
                max_redirects: 10,
            },
            RequestKind::TransferUpload
            | RequestKind::TransferDownload
            | RequestKind::PublicTransfer => Self {
                timeout: Some(Duration::from_secs(120)),
                follow_redirects: true,
                max_redirects: 10,
            },
            RequestKind::PublicApi => Self {
                timeout: Some(Duration::from_secs(30)),
                follow_redirects: true,
                max_redirects: 10,
            },
        }
    }
}

/// HTTP client for making requests to MEGA servers.
#[derive(Debug, Clone)]
pub struct HttpClient {
    client: Client,
}

fn insecure_proxy_tls_enabled() -> bool {
    std::env::var_os(INSECURE_PROXY_TLS_ENV).is_some()
}

impl HttpClient {
    /// Create a new HTTP client.
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("Failed to build reqwest client"),
        }
    }

    /// Create a new HTTP client with a proxy.
    ///
    /// Set `MEGALIB_INSECURE_PROXY_TLS` to any value to disable certificate and
    /// hostname validation for proxy debugging.
    pub fn with_proxy(proxy: &str) -> Result<Self> {
        let proxy = reqwest::Proxy::all(proxy)
            .map_err(|e| MegaError::CryptoError(format!("Invalid proxy: {}", e)))?;

        let mut builder = Client::builder()
            .proxy(proxy)
            .redirect(reqwest::redirect::Policy::none());

        if insecure_proxy_tls_enabled() {
            builder = builder
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true);
        }

        let client = builder
            .build()
            .map_err(|e| MegaError::CryptoError(format!("Failed to build client: {}", e)))?;

        Ok(Self { client })
    }

    async fn send_with_policy(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<Vec<u8>>,
        headers: &[(&str, String)],
        kind: RequestKind,
    ) -> Result<reqwest::Response> {
        let policy = RequestPolicy::for_kind(kind);
        let mut current = url.to_string();
        for _ in 0..=policy.max_redirects {
            let mut request = self.client.request(method.clone(), &current);
            if let Some(timeout) = policy.timeout {
                request = request.timeout(timeout);
            }
            for (name, value) in headers {
                request = request.header(*name, value);
            }
            if let Some(payload) = &body {
                request = request.body(payload.clone());
            }
            let response = request.send().await?;

            let status = response.status();
            if status.is_redirection() && policy.follow_redirects {
                if let Some(loc) = response.headers().get(reqwest::header::LOCATION)
                    && let Ok(loc_str) = loc.to_str()
                {
                    let next = if loc_str.starts_with("http://") || loc_str.starts_with("https://")
                    {
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
                return Err(MegaError::HttpError(status.as_u16()));
            }

            return Ok(response);
        }

        Err(MegaError::Custom("Too many redirects".to_string()))
    }

    /// Make a POST request with JSON body.
    pub async fn post_json(&self, url: &str, body: &str, kind: RequestKind) -> Result<String> {
        let response = self
            .send_with_policy(
                reqwest::Method::POST,
                url,
                Some(body.as_bytes().to_vec()),
                &[("Content-Type", "application/json".to_string())],
                kind,
            )
            .await?;
        if !response.status().is_success() {
            return Err(MegaError::HttpError(response.status().as_u16()));
        }
        Ok(response.text().await?)
    }

    /// Make a POST request with binary body.
    pub async fn post_binary(
        &self,
        url: &str,
        body: Vec<u8>,
        kind: RequestKind,
    ) -> Result<reqwest::Response> {
        self.send_with_policy(
            reqwest::Method::POST,
            url,
            Some(body),
            &[("Content-Type", "application/octet-stream".to_string())],
            kind,
        )
        .await
    }

    /// Make a GET request, optionally with an HTTP byte range.
    pub async fn get(
        &self,
        url: &str,
        kind: RequestKind,
        range: Option<(u64, Option<u64>)>,
    ) -> Result<reqwest::Response> {
        let mut headers: Vec<(&str, String)> = Vec::new();
        if let Some((start, end)) = range {
            let range_value = match end {
                Some(end_inclusive) => format!("bytes={}-{}", start, end_inclusive),
                None => format!("bytes={}-", start),
            };
            headers.push(("Range", range_value));
        }
        self.send_with_policy(reqwest::Method::GET, url, None, &headers, kind)
            .await
    }

    /// Backward-compatible API helper.
    pub async fn post(&self, url: &str, body: &str) -> Result<String> {
        self.post_json(url, body, RequestKind::ApiJson).await
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
