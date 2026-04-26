//! Core tpx contracts for normalized requests and policy outcomes.
//!
//! `HttpRequest` applies seven normalization rules so every validator receives
//! the same shape:
//!
//! 1. `method` is stored as uppercase.
//! 2. `host` is stored lowercase with any scheme and port removed.
//! 3. `path` always starts with `/`.
//! 4. `path` never includes a query string or fragment.
//! 5. `query_params` uses `BTreeMap<String, Vec<String>>` with stringified values.
//! 6. `headers` uses lowercase keys; duplicate-key values are joined with `", "`.
//! 7. `content_type` stores only the media type and `body` stores UTF-8 text or `None`.
//!
//! Ported from `zot/src/tool_proxy/contracts.py` with audit-ceremony fields stripped.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

const HEADER_JOIN: &str = ", ";
const BODY_DETAIL_KEYS: &[&str] = &[
    "body",
    "body_text",
    "raw_body",
    "request_body",
    "response_body",
];
const MAX_DETAIL_STRING_LEN: usize = 200;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("{0}")]
pub struct ContractError(pub String);

impl ContractError {
    fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

type Result<T> = std::result::Result<T, ContractError>;

// ─── Enums ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InspectionDisposition {
    MatchedRule,
    NoMatchingRule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestClassification {
    Read,
    Write,
    Mixed,
    Auth,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InspectionConfidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionCode {
    Allow,
    NoMatchingToolValidator,
    UnsupportedContentType,
    BodyTooLarge,
    PluginException,
    UnknownOperation,
    AuthOperation,
    DefaultDeny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionSource {
    RuleEngine,
    DefaultDeny,
    PluginRule,
}

// ─── Detail values ──────────────────────────────────────────────────────────

/// Log-safe scalar accepted in `InspectionResult.details`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DetailValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
}

impl DetailValue {
    fn validate_for_details(&self) -> Result<()> {
        if let DetailValue::Str(s) = self {
            if s.contains('\n') || s.contains('\r') {
                return Err(ContractError::new(
                    "details string values must be single-line",
                ));
            }
            if s.len() > MAX_DETAIL_STRING_LEN {
                return Err(ContractError::new(
                    "details string values must stay concise and log-safe",
                ));
            }
        }
        Ok(())
    }
}

impl From<&str> for DetailValue {
    fn from(v: &str) -> Self {
        DetailValue::Str(v.to_string())
    }
}
impl From<String> for DetailValue {
    fn from(v: String) -> Self {
        DetailValue::Str(v)
    }
}
impl From<i64> for DetailValue {
    fn from(v: i64) -> Self {
        DetailValue::Int(v)
    }
}
impl From<bool> for DetailValue {
    fn from(v: bool) -> Self {
        DetailValue::Bool(v)
    }
}
impl From<f64> for DetailValue {
    fn from(v: f64) -> Self {
        DetailValue::Float(v)
    }
}

// ─── Reason normalization ───────────────────────────────────────────────────

pub fn normalize_reason(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ContractError::new("reason must not be empty"));
    }
    if trimmed.contains('\n') || trimmed.contains('\r') {
        return Err(ContractError::new(
            "reason must be a single-line plain-English message",
        ));
    }
    Ok(trimmed.to_string())
}

// ─── HttpRequest ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub host: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub query_params: BTreeMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

impl HttpRequest {
    pub fn builder() -> HttpRequestBuilder {
        HttpRequestBuilder::default()
    }
}

/// Body input accepted by the builder — either UTF-8 text or raw bytes.
pub enum Body {
    Text(String),
    Bytes(Vec<u8>),
}

impl From<&str> for Body {
    fn from(v: &str) -> Self {
        Body::Text(v.to_string())
    }
}
impl From<String> for Body {
    fn from(v: String) -> Self {
        Body::Text(v)
    }
}
impl From<Vec<u8>> for Body {
    fn from(v: Vec<u8>) -> Self {
        Body::Bytes(v)
    }
}

#[derive(Default)]
pub struct HttpRequestBuilder {
    method: Option<String>,
    host: Option<String>,
    path: Option<String>,
    query_params: BTreeMap<String, Vec<String>>,
    headers: Vec<(String, String)>,
    content_type: Option<String>,
    body: Option<Body>,
}

impl HttpRequestBuilder {
    pub fn method(mut self, v: impl Into<String>) -> Self {
        self.method = Some(v.into());
        self
    }
    pub fn host(mut self, v: impl Into<String>) -> Self {
        self.host = Some(v.into());
        self
    }
    pub fn path(mut self, v: impl Into<String>) -> Self {
        self.path = Some(v.into());
        self
    }
    pub fn query(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.query_params
            .entry(k.into())
            .or_default()
            .push(v.into());
        self
    }
    pub fn header(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.headers.push((k.into(), v.into()));
        self
    }
    pub fn content_type(mut self, v: impl Into<String>) -> Self {
        self.content_type = Some(v.into());
        self
    }
    pub fn body(mut self, v: impl Into<Body>) -> Self {
        self.body = Some(v.into());
        self
    }

    pub fn build(self) -> Result<HttpRequest> {
        let method = normalize_method(self.method.as_deref().unwrap_or(""))?;
        let host = normalize_host(self.host.as_deref().unwrap_or(""))?;

        let raw_path = self.path.as_deref().unwrap_or("").trim();
        let (path_only, path_query) = split_path_query(raw_path);
        let path = normalize_path(&path_only);

        let mut query_params = self.query_params.clone();
        if let Some(query_str) = path_query {
            if !query_params.is_empty() {
                return Err(ContractError::new(
                    "query_params must not be set when path already includes a query string",
                ));
            }
            for (k, v) in url::form_urlencoded::parse(query_str.as_bytes()) {
                query_params
                    .entry(k.into_owned())
                    .or_default()
                    .push(v.into_owned());
            }
        }

        let mut headers: BTreeMap<String, String> = BTreeMap::new();
        for (k, v) in self.headers {
            insert_header(&mut headers, &k, &v)?;
        }

        let content_type = match self.content_type.as_deref() {
            Some(v) => normalize_content_type(v),
            None => headers
                .get("content-type")
                .and_then(|v| normalize_content_type(v)),
        };

        let body = match self.body {
            None => None,
            Some(Body::Text(s)) => Some(s),
            Some(Body::Bytes(bytes)) => Some(
                String::from_utf8(bytes)
                    .map_err(|_| ContractError::new("body must be valid UTF-8"))?,
            ),
        };

        Ok(HttpRequest {
            method,
            host,
            path,
            query_params,
            headers,
            content_type,
            body,
        })
    }
}

// ─── Field normalizers ──────────────────────────────────────────────────────

fn normalize_method(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(ContractError::new("method must not be empty"));
    }
    Ok(trimmed.to_uppercase())
}

fn normalize_host(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(ContractError::new("host must not be empty"));
    }
    // Accept bare host, host:port, scheme://host, scheme://host:port, or //host.
    let candidate = if trimmed.contains("://") {
        trimmed.to_string()
    } else if let Some(rest) = trimmed.strip_prefix("//") {
        format!("http://{rest}")
    } else {
        format!("http://{trimmed}")
    };
    let parsed = Url::parse(&candidate)
        .map_err(|_| ContractError::new("host must contain a valid hostname"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| ContractError::new("host must contain a valid hostname"))?;
    Ok(host.to_lowercase())
}

fn split_path_query(raw: &str) -> (String, Option<String>) {
    if raw.is_empty() {
        return ("/".to_string(), None);
    }
    // Strip fragment first, then split on the first '?'.
    let without_fragment = raw.split('#').next().unwrap_or("");
    if let Some(idx) = without_fragment.find('?') {
        let (p, q) = without_fragment.split_at(idx);
        (p.to_string(), Some(q[1..].to_string()))
    } else {
        (without_fragment.to_string(), None)
    }
}

fn normalize_path(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return "/".to_string();
    }
    if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{}", trimmed.trim_start_matches('/'))
    }
}

fn insert_header(map: &mut BTreeMap<String, String>, key: &str, value: &str) -> Result<()> {
    let key = key.trim().to_lowercase();
    if key.is_empty() {
        return Err(ContractError::new("headers keys must not be empty"));
    }
    let value = value.trim().to_string();
    if let Some(existing) = map.get_mut(&key) {
        if !value.is_empty() && !existing.is_empty() {
            existing.push_str(HEADER_JOIN);
            existing.push_str(&value);
        } else if !value.is_empty() {
            *existing = value;
        }
    } else {
        map.insert(key, value);
    }
    Ok(())
}

fn normalize_content_type(input: &str) -> Option<String> {
    let media = input.split(';').next().unwrap_or("").trim().to_lowercase();
    if media.is_empty() { None } else { Some(media) }
}

// ─── InspectionResult ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InspectionResult {
    pub classification: RequestClassification,
    pub confidence: InspectionConfidence,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<BTreeMap<String, DetailValue>>,
    pub disposition: InspectionDisposition,
}

impl InspectionResult {
    pub fn new(
        classification: RequestClassification,
        confidence: InspectionConfidence,
        reason: impl AsRef<str>,
        details: Option<BTreeMap<String, DetailValue>>,
        disposition: InspectionDisposition,
    ) -> Result<Self> {
        let reason = normalize_reason(reason.as_ref())?;
        let details = match details {
            Some(map) => Some(validate_details(map)?),
            None => None,
        };
        if disposition == InspectionDisposition::NoMatchingRule
            && classification != RequestClassification::Unknown
        {
            return Err(ContractError::new(
                "NO_MATCHING_RULE disposition requires classification=UNKNOWN",
            ));
        }
        Ok(Self {
            classification,
            confidence,
            reason,
            details,
            disposition,
        })
    }
}

fn validate_details(raw: BTreeMap<String, DetailValue>) -> Result<BTreeMap<String, DetailValue>> {
    let mut out = BTreeMap::new();
    for (key, value) in raw {
        let trimmed = key.trim().to_string();
        if trimmed.is_empty() {
            return Err(ContractError::new("details keys must not be empty"));
        }
        if BODY_DETAIL_KEYS.contains(&trimmed.to_lowercase().as_str()) {
            return Err(ContractError::new("details must not include raw body text"));
        }
        value.validate_for_details()?;
        out.insert(trimmed, value);
    }
    Ok(out)
}

// ─── ToolPermissionDecision ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolPermissionDecision {
    pub allowed: bool,
    pub reason: String,
    pub permission_source: PermissionSource,
    pub code: DecisionCode,
}

impl ToolPermissionDecision {
    pub fn allow(reason: impl AsRef<str>, permission_source: PermissionSource) -> Result<Self> {
        Ok(Self {
            allowed: true,
            reason: normalize_reason(reason.as_ref())?,
            permission_source,
            code: DecisionCode::Allow,
        })
    }

    pub fn deny(
        code: DecisionCode,
        reason: impl AsRef<str>,
        permission_source: PermissionSource,
    ) -> Result<Self> {
        if code == DecisionCode::Allow {
            return Err(ContractError::new(
                "deny decisions must use a non-Allow code",
            ));
        }
        Ok(Self {
            allowed: false,
            reason: normalize_reason(reason.as_ref())?,
            permission_source,
            code,
        })
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_request() -> HttpRequestBuilder {
        HttpRequest::builder()
            .method("get")
            .host("api.vercel.com")
            .path("/v9/projects")
    }

    // (1) method uppercase
    #[test]
    fn method_is_uppercased() {
        let r = ok_request().method("get").build().unwrap();
        assert_eq!(r.method, "GET");
    }

    #[test]
    fn method_empty_rejected() {
        let err = ok_request().method("   ").build().unwrap_err();
        assert!(err.0.contains("method"));
    }

    // (2) host lowercase, no scheme/port
    #[test]
    fn host_lowercased_and_stripped() {
        let cases = [
            "api.vercel.com",
            "API.VERCEL.COM",
            "api.vercel.com:443",
            "https://api.vercel.com",
            "https://API.vercel.com:8443",
            "//api.vercel.com",
        ];
        for input in cases {
            let r = ok_request().host(input).build().unwrap();
            assert_eq!(r.host, "api.vercel.com", "input was {input}");
        }
    }

    #[test]
    fn host_invalid_rejected() {
        let err = ok_request().host("").build().unwrap_err();
        assert!(err.0.contains("host"));
    }

    // (3) path always /-prefixed
    #[test]
    fn path_is_prefixed_with_slash() {
        let r = ok_request().path("v9/projects").build().unwrap();
        assert_eq!(r.path, "/v9/projects");
    }

    #[test]
    fn empty_path_becomes_root() {
        let r = ok_request().path("").build().unwrap();
        assert_eq!(r.path, "/");
    }

    // (4) path strips query and fragment
    #[test]
    fn path_strips_query_string() {
        let r = ok_request().path("/v9/projects?team=foo").build().unwrap();
        assert_eq!(r.path, "/v9/projects");
        assert_eq!(r.query_params.get("team"), Some(&vec!["foo".to_string()]));
    }

    #[test]
    fn path_strips_fragment() {
        let r = ok_request().path("/v9/projects#anchor").build().unwrap();
        assert_eq!(r.path, "/v9/projects");
    }

    #[test]
    fn path_query_conflicts_with_query_params() {
        let err = ok_request()
            .path("/v9/projects?team=foo")
            .query("other", "x")
            .build()
            .unwrap_err();
        assert!(err.0.contains("query_params"));
    }

    // (5) query_params: dict[str, list[str]] with stringified values
    #[test]
    fn query_params_collect_repeated_keys() {
        let r = ok_request()
            .query("team", "alpha")
            .query("team", "beta")
            .build()
            .unwrap();
        assert_eq!(
            r.query_params.get("team"),
            Some(&vec!["alpha".to_string(), "beta".to_string()])
        );
    }

    // (6) headers lowercase, multi-value join with ", "
    #[test]
    fn headers_lowercased() {
        let r = ok_request()
            .header("Authorization", "Bearer x")
            .build()
            .unwrap();
        assert_eq!(
            r.headers.get("authorization"),
            Some(&"Bearer x".to_string())
        );
    }

    #[test]
    fn headers_multi_value_joined() {
        let r = ok_request()
            .header("X-Foo", "a")
            .header("x-foo", "b")
            .build()
            .unwrap();
        assert_eq!(r.headers.get("x-foo"), Some(&"a, b".to_string()));
    }

    #[test]
    fn empty_header_key_rejected() {
        let err = ok_request().header("  ", "x").build().unwrap_err();
        assert!(err.0.contains("headers"));
    }

    // (7) content_type is media-type-only; pulled from headers when not given
    #[test]
    fn content_type_strips_parameters() {
        let r = ok_request()
            .content_type("application/json; charset=utf-8")
            .build()
            .unwrap();
        assert_eq!(r.content_type.as_deref(), Some("application/json"));
    }

    #[test]
    fn content_type_pulled_from_headers() {
        let r = ok_request()
            .header("Content-Type", "application/JSON; charset=utf-8")
            .build()
            .unwrap();
        assert_eq!(r.content_type.as_deref(), Some("application/json"));
    }

    #[test]
    fn body_bytes_decoded_as_utf8() {
        let r = ok_request().body(b"hello".to_vec()).build().unwrap();
        assert_eq!(r.body.as_deref(), Some("hello"));
    }

    #[test]
    fn body_invalid_utf8_rejected() {
        let bad = vec![0xff, 0xfe, 0xfd];
        let err = ok_request().body(bad).build().unwrap_err();
        assert!(err.0.contains("UTF-8"));
    }

    // ─── enums + decision invariants ────────────────────────────────────────

    #[test]
    fn decision_code_serializes_snake_case() {
        let s = serde_json::to_string(&DecisionCode::DefaultDeny).unwrap();
        assert_eq!(s, "\"default_deny\"");
    }

    #[test]
    fn classification_serializes_snake_case() {
        let s = serde_json::to_string(&RequestClassification::Read).unwrap();
        assert_eq!(s, "\"read\"");
    }

    #[test]
    fn allow_decision_constructed() {
        let d =
            ToolPermissionDecision::allow("rule matched", PermissionSource::RuleEngine).unwrap();
        assert!(d.allowed);
        assert_eq!(d.code, DecisionCode::Allow);
    }

    #[test]
    fn deny_with_allow_code_rejected() {
        let err =
            ToolPermissionDecision::deny(DecisionCode::Allow, "no", PermissionSource::DefaultDeny)
                .unwrap_err();
        assert!(err.0.contains("Allow"));
    }

    #[test]
    fn no_matching_rule_requires_unknown_classification() {
        let err = InspectionResult::new(
            RequestClassification::Read,
            InspectionConfidence::Low,
            "x",
            None,
            InspectionDisposition::NoMatchingRule,
        )
        .unwrap_err();
        assert!(err.0.contains("NO_MATCHING_RULE"));
    }

    #[test]
    fn inspection_result_details_reject_body_keys() {
        let mut details = BTreeMap::new();
        details.insert("body".to_string(), DetailValue::Str("contents".into()));
        let err = InspectionResult::new(
            RequestClassification::Read,
            InspectionConfidence::High,
            "x",
            Some(details),
            InspectionDisposition::MatchedRule,
        )
        .unwrap_err();
        assert!(err.0.contains("body"));
    }

    #[test]
    fn inspection_result_details_reject_multiline_strings() {
        let mut details = BTreeMap::new();
        details.insert("note".to_string(), DetailValue::Str("a\nb".into()));
        let err = InspectionResult::new(
            RequestClassification::Read,
            InspectionConfidence::High,
            "x",
            Some(details),
            InspectionDisposition::MatchedRule,
        )
        .unwrap_err();
        assert!(err.0.contains("single-line"));
    }

    #[test]
    fn reason_rejects_multiline() {
        let err = normalize_reason("a\nb").unwrap_err();
        assert!(err.0.contains("single-line"));
    }
}
