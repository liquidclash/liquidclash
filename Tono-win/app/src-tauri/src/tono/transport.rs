//! `tono_core::HttpTransport` over the app's reqwest stack (product-contract.md §1):
//! redirects disabled, cookies disabled, 30 s connect / 45 s total timeouts (the
//! mainland-link budget), and a 2 MiB response cap. The Bearer token is computed by
//! `ApiClient` and carried on the request; this layer only passes it through.
//!
//! F1: the API hostname is DNS-pinned to the bootstrap IPs (see
//! `tono::bootstrap`). Pinning is safe because TLS/SNI still validates the
//! hostname against Cloudflare's certificate — it changes only where the
//! TCP connection lands, and it keeps the control plane reachable while the
//! kill switch blocks the system resolver. This is the *only* HTTP client
//! the account/catalog API traffic uses; the mihomo controller client
//! (loopback) is separate and unpinned by design.
//!
//! Retries do NOT live here: the bounded retry policy (GET any kind once,
//! POST only Dns/Connect) is inside `ApiClient` in tono-core — this layer
//! only classifies failures so it can decide.

use std::time::Duration;

use anyhow::{Context as _, Result};
use async_trait::async_trait;
use tono_core::auth::{ApiError, ApiRequest, ApiResponse, HttpMethod, HttpTransport, TransportKind};

use crate::tono::bootstrap;

/// §1 response size cap.
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
/// §1 mainland-link timeouts (connect 30 s / total 45 s).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(45);

/// Map a reqwest failure onto the retry-policy classification (§1).
/// Ordering matters: `is_timeout()` first, then `is_connect()` — which on
/// reqwest covers *both* DNS resolution and TCP connect (no finer split is
/// available; in either phase HTTP bytes provably never went out, so the
/// retry policy's Connect bucket is the correct home). TLS-layer failures
/// surface only in the debug chain (handshake/certificate/rustls).
fn classify(err: &reqwest::Error) -> TransportKind {
    if err.is_timeout() {
        return TransportKind::Timeout;
    }
    if err.is_connect() {
        return TransportKind::Connect;
    }
    let debug = format!("{err:?}").to_lowercase();
    if debug.contains("tls")
        || debug.contains("certificate")
        || debug.contains("handshake")
        || debug.contains("ssl")
        || debug.contains("rustls")
    {
        return TransportKind::Tls;
    }
    TransportKind::Other
}

pub struct TonoTransport {
    client: reqwest::Client,
}

impl TonoTransport {
    pub fn new() -> Result<Self> {
        let pinned: Vec<std::net::SocketAddr> = bootstrap::pinned_bootstrap_ips()
            .into_iter()
            .map(|ip| std::net::SocketAddr::new(std::net::IpAddr::V4(ip), 443))
            .collect();
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .cookie_store(false)
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(TOTAL_TIMEOUT)
            // F1: resolve the API host to the pinned bootstrap IPs.
            .resolve_to_addrs(bootstrap::API_HOST, &pinned)
            .build()
            .context("failed to build the Tono HTTP client")?;
        Ok(Self { client })
    }
}

fn method_of(method: HttpMethod) -> reqwest::Method {
    match method {
        HttpMethod::Get => reqwest::Method::GET,
        HttpMethod::Post => reqwest::Method::POST,
        HttpMethod::Delete => reqwest::Method::DELETE,
    }
}

#[async_trait]
impl HttpTransport for TonoTransport {
    async fn send(&self, request: ApiRequest) -> Result<ApiResponse, ApiError> {
        let transport = |err: &reqwest::Error| ApiError::Transport {
            kind: classify(err),
            message: err.to_string(),
        };
        let mut builder = self.client.request(method_of(request.method), &request.url);
        if let Some(bearer) = &request.bearer {
            builder = builder.bearer_auth(bearer);
        }
        if let Some(body) = &request.json_body {
            builder = builder
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.clone());
        }

        let mut response = builder.send().await.map_err(|err| transport(&err))?;
        let status = response.status().as_u16();
        if response
            .content_length()
            .is_some_and(|length| length as usize > MAX_RESPONSE_BYTES)
        {
            return Err(ApiError::InvalidResponse);
        }
        // Stream the body with a hard cap: a missing or lying Content-Length
        // must not turn into an unbounded read.
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|err| transport(&err))? {
            if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(ApiError::InvalidResponse);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(ApiResponse { status, body })
    }
}

#[cfg(test)]
mod tests {
    use super::{CONNECT_TIMEOUT, MAX_RESPONSE_BYTES, TOTAL_TIMEOUT, method_of};
    use tono_core::auth::HttpMethod;

    #[test]
    fn http_method_mapping() {
        assert_eq!(method_of(HttpMethod::Get), reqwest::Method::GET);
        assert_eq!(method_of(HttpMethod::Post), reqwest::Method::POST);
        assert_eq!(method_of(HttpMethod::Delete), reqwest::Method::DELETE);
    }

    #[test]
    fn response_cap_is_two_mib() {
        assert_eq!(MAX_RESPONSE_BYTES, 2 * 1024 * 1024);
    }

    #[test]
    fn mainland_link_timeouts_are_30s_connect_45s_total() {
        assert_eq!(CONNECT_TIMEOUT, std::time::Duration::from_secs(30));
        assert_eq!(TOTAL_TIMEOUT, std::time::Duration::from_secs(45));
    }
}
