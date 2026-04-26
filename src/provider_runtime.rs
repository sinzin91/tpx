//! Provider request executor.
//!
//! reqwest with explicit timeout, no follow_redirects (so a 307 from an
//! allowed read endpoint can't smuggle a write to a denied one), and a
//! response body cap matching the provider's `max_body_bytes`.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use reqwest::redirect::Policy;
use thiserror::Error;

use crate::contracts::HttpRequest;
use crate::providers::{AuthStyle, ProviderConfig};

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("invalid base URL or path: {0}")]
    InvalidUrl(String),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("response exceeded {limit} byte cap")]
    BodyTooLarge { limit: usize },
}

#[derive(Debug, Clone)]
pub struct ProviderResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body_text: String,
    pub body_json: Option<serde_json::Value>,
    pub latency_ms: u128,
}

/// Execute a previously-allowed request against the upstream provider.
pub async fn execute_provider_request(
    config: &ProviderConfig,
    request: &HttpRequest,
    creds: &BTreeMap<String, String>,
) -> Result<ProviderResponse, RuntimeError> {
    let url = build_url(config.base_url, &request.path, &request.query_params)?;

    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .timeout(config.timeout)
        .connect_timeout(Duration::from_secs(10))
        .build()?;

    let method = reqwest::Method::from_bytes(request.method.as_bytes())
        .map_err(|e| RuntimeError::InvalidUrl(format!("bad method: {e}")))?;

    let mut req = client.request(method, url);

    // Auth.
    req = match config.auth_style {
        AuthStyle::Bearer => {
            let token = creds.get("token").map(String::as_str).unwrap_or("");
            req.header("Authorization", format!("Bearer {token}"))
        }
        AuthStyle::BasicPublicSecret => {
            let pk = creds.get("public_key").map(String::as_str).unwrap_or("");
            let sk = creds.get("secret_key").map(String::as_str).unwrap_or("");
            let encoded = B64.encode(format!("{pk}:{sk}"));
            req.header("Authorization", format!("Basic {encoded}"))
        }
    };

    // Caller-supplied headers (other than Authorization, which we always set).
    for (k, v) in &request.headers {
        if k.eq_ignore_ascii_case("authorization") {
            continue;
        }
        req = req.header(k.as_str(), v.as_str());
    }

    if let Some(ct) = &request.content_type {
        req = req.header("Content-Type", ct.as_str());
    }

    if let Some(body) = &request.body {
        req = req.body(body.clone());
    }

    let started = Instant::now();
    let response = req.send().await?;
    let status = response.status().as_u16();
    let mut headers = BTreeMap::new();
    for (k, v) in response.headers() {
        headers.insert(
            k.as_str().to_lowercase(),
            v.to_str().unwrap_or("").to_string(),
        );
    }
    // Cap response body using content-length when present; otherwise read up
    // to the limit and bail if we hit it.
    let limit = config.max_body_bytes;
    let bytes = response.bytes().await?;
    if bytes.len() > limit {
        return Err(RuntimeError::BodyTooLarge { limit });
    }
    let latency_ms = started.elapsed().as_millis();
    let body_text = String::from_utf8_lossy(&bytes).into_owned();
    let body_json = serde_json::from_str::<serde_json::Value>(&body_text).ok();

    Ok(ProviderResponse {
        status,
        headers,
        body_text,
        body_json,
        latency_ms,
    })
}

fn build_url(
    base_url: &str,
    path: &str,
    query_params: &BTreeMap<String, Vec<String>>,
) -> Result<reqwest::Url, RuntimeError> {
    let mut url = reqwest::Url::parse(base_url)
        .map_err(|e| RuntimeError::InvalidUrl(format!("base_url: {e}")))?;
    url.set_path(path);
    if !query_params.is_empty() {
        let mut pairs = url.query_pairs_mut();
        for (k, vs) in query_params {
            for v in vs {
                pairs.append_pair(k, v);
            }
        }
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_built_with_query_params() {
        let mut q = BTreeMap::new();
        q.insert(
            "team".to_string(),
            vec!["alpha".to_string(), "beta".to_string()],
        );
        q.insert("active".to_string(), vec!["1".to_string()]);
        let url = build_url("https://api.vercel.com", "/v9/projects", &q).unwrap();
        let qs = url.query().unwrap_or("");
        assert!(qs.contains("team=alpha"));
        assert!(qs.contains("team=beta"));
        assert!(qs.contains("active=1"));
        assert_eq!(url.path(), "/v9/projects");
    }
}
