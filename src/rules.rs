//! Slim YAML rule schema + first-match-wins matcher.
//!
//! Ported from `zot/src/tool_proxy/{yaml_rule_defs,yaml_rules_models,yaml_rules_matching}.py`
//! with audit ceremony stripped per spec §2 / §11. What remains:
//!
//! - `TpxProviderRules` — `schema_version`, `name`, `host_patterns`, `default_policy`, `rules`.
//! - `TpxRule` — `match`, `classification`, `action`, `reason`.
//! - `RuleMatch` — `host`, `methods`, `path`, `path_match`, `content_types`.
//! - `path_matches` — exact / prefix (segment-aware) / template (`{var}` per segment).
//! - `find_matching_rule` — first match wins.

use std::collections::HashSet;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::contracts::{HttpRequest, RequestClassification};

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("{0}")]
pub struct RuleError(pub String);

impl RuleError {
    fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

type Result<T> = std::result::Result<T, RuleError>;

// ─── Enums ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
}

impl HttpMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Head => "HEAD",
            HttpMethod::Options => "OPTIONS",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathMatchType {
    Exact,
    Prefix,
    Template,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultPolicy {
    Deny,
}

// ─── Schema ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleMatch {
    pub host: String,
    pub methods: Vec<HttpMethod>,
    pub path: String,
    pub path_match: PathMatchType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_types: Option<Vec<String>>,
}

impl RuleMatch {
    pub fn matches_request(&self, request: &HttpRequest) -> bool {
        if request.host != self.host {
            return false;
        }
        let req_method = request.method.as_str();
        if !self.methods.iter().any(|m| m.as_str() == req_method) {
            return false;
        }
        if let Some(allowed) = &self.content_types {
            let Some(ct) = request.content_type.as_deref() else {
                return false;
            };
            let normalized = match normalize_content_type(ct) {
                Some(v) => v,
                None => return false,
            };
            if !allowed.iter().any(|t| t == &normalized) {
                return false;
            }
        }
        path_matches(&self.path, self.path_match, &request.path)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TpxRule {
    #[serde(rename = "match")]
    pub r#match: RuleMatch,
    pub classification: RequestClassification,
    pub action: RuleAction,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TpxProviderRules {
    pub schema_version: u32,
    pub name: String,
    pub host_patterns: Vec<String>,
    pub default_policy: DefaultPolicy,
    pub rules: Vec<TpxRule>,
}

impl TpxProviderRules {
    /// Parse + validate from a YAML string.
    pub fn from_yaml(text: &str) -> Result<Self> {
        let raw: TpxProviderRules = serde_yaml_ng::from_str(text)
            .map_err(|e| RuleError::new(format!("invalid YAML: {e}")))?;
        raw.validate()
    }

    fn validate(mut self) -> Result<Self> {
        if self.schema_version != 1 {
            return Err(RuleError::new("schema_version must be 1"));
        }
        let name = self.name.trim().to_string();
        if name.is_empty() {
            return Err(RuleError::new("name must not be empty"));
        }
        self.name = name;

        if self.host_patterns.is_empty() {
            return Err(RuleError::new("host_patterns must not be empty"));
        }
        let mut normalized_hosts = Vec::with_capacity(self.host_patterns.len());
        let mut seen_hosts = HashSet::new();
        for raw in &self.host_patterns {
            let host = normalize_host_pattern(raw)?;
            if !seen_hosts.insert(host.clone()) {
                return Err(RuleError::new("host_patterns must not contain duplicates"));
            }
            normalized_hosts.push(host);
        }
        self.host_patterns = normalized_hosts;

        if self.rules.is_empty() {
            return Err(RuleError::new("rules must not be empty"));
        }

        let host_set: HashSet<&String> = self.host_patterns.iter().collect();
        for (idx, rule) in self.rules.iter_mut().enumerate() {
            validate_rule(idx, rule, &host_set)?;
        }
        Ok(self)
    }
}

fn validate_rule(idx: usize, rule: &mut TpxRule, host_patterns: &HashSet<&String>) -> Result<()> {
    let match_ = &mut rule.r#match;

    let host = normalize_host_pattern(&match_.host)
        .map_err(|e| RuleError::new(format!("rule {idx}: {}", e.0)))?;
    match_.host = host;

    if match_.methods.is_empty() {
        return Err(RuleError::new(format!(
            "rule {idx}: methods must not be empty"
        )));
    }
    let mut seen_methods = HashSet::new();
    for m in &match_.methods {
        if !seen_methods.insert(*m) {
            return Err(RuleError::new(format!(
                "rule {idx}: methods must not contain duplicates"
            )));
        }
    }

    match_.path = normalize_rule_path(&match_.path);

    if let Some(types) = &mut match_.content_types {
        if types.is_empty() {
            return Err(RuleError::new(format!(
                "rule {idx}: content_types must not be empty when provided"
            )));
        }
        let mut normalized = Vec::with_capacity(types.len());
        let mut seen = HashSet::new();
        for t in types.iter() {
            let n = normalize_content_type(t).ok_or_else(|| {
                RuleError::new(format!(
                    "rule {idx}: content_type entries must not be empty"
                ))
            })?;
            if !seen.insert(n.clone()) {
                return Err(RuleError::new(format!(
                    "rule {idx}: content_types must not contain duplicates"
                )));
            }
            normalized.push(n);
        }
        *types = normalized;
    }

    validate_template_path(idx, &match_.path, match_.path_match)?;

    let reason = rule.reason.trim();
    if reason.is_empty() {
        return Err(RuleError::new(format!(
            "rule {idx}: reason must not be empty"
        )));
    }
    if reason.contains('\n') || reason.contains('\r') {
        return Err(RuleError::new(format!(
            "rule {idx}: reason must be single-line text"
        )));
    }
    rule.reason = reason.to_string();

    if !host_patterns.contains(&match_.host) {
        return Err(RuleError::new(format!(
            "rule {idx} host {} is not listed in host_patterns",
            match_.host
        )));
    }
    Ok(())
}

fn normalize_host_pattern(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(RuleError::new("host_patterns entries must not be empty"));
    }
    if trimmed.contains('*') {
        return Err(RuleError::new(
            "host_patterns wildcard matching is not supported in v1",
        ));
    }
    let candidate = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    };
    let parsed = Url::parse(&candidate)
        .map_err(|_| RuleError::new("host_patterns entries must contain a valid hostname"))?;
    if !matches!(parsed.path(), "" | "/") {
        return Err(RuleError::new(
            "host_patterns must be plain hostnames without path components",
        ));
    }
    if parsed.port().is_some() {
        return Err(RuleError::new(
            "host_patterns must be plain hostnames without port",
        ));
    }
    if parsed.query().is_some() {
        return Err(RuleError::new(
            "host_patterns must be plain hostnames without query string",
        ));
    }
    if parsed.fragment().is_some() {
        return Err(RuleError::new(
            "host_patterns must be plain hostnames without fragment",
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| RuleError::new("host_patterns entries must contain a valid hostname"))?;
    Ok(host.to_lowercase())
}

fn normalize_rule_path(raw: &str) -> String {
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

fn normalize_content_type(input: &str) -> Option<String> {
    let media = input.split(';').next().unwrap_or("").trim().to_lowercase();
    if media.is_empty() { None } else { Some(media) }
}

fn validate_template_path(idx: usize, path: &str, kind: PathMatchType) -> Result<()> {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let mut template_count = 0;
    let mut brace_count = 0;
    for seg in &segments {
        let is_template_seg = is_template_segment(seg);
        if is_template_seg {
            template_count += 1;
        }
        if seg.contains('{') || seg.contains('}') {
            brace_count += 1;
            if !is_template_seg {
                return Err(RuleError::new(format!(
                    "rule {idx}: template placeholders must occupy an entire path segment"
                )));
            }
        }
    }
    match kind {
        PathMatchType::Template => {
            if template_count == 0 {
                return Err(RuleError::new(format!(
                    "rule {idx}: path_match=template requires at least one {{variable}} placeholder"
                )));
            }
        }
        _ => {
            if brace_count > 0 {
                return Err(RuleError::new(format!(
                    "rule {idx}: path contains template brace syntax but path_match is not template"
                )));
            }
        }
    }
    Ok(())
}

fn is_template_segment(seg: &str) -> bool {
    if !seg.starts_with('{') || !seg.ends_with('}') || seg.len() < 3 {
        return false;
    }
    let name = &seg[1..seg.len() - 1];
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

// ─── path_matches ───────────────────────────────────────────────────────────

pub fn path_matches(rule_path: &str, kind: PathMatchType, request_path: &str) -> bool {
    match kind {
        PathMatchType::Exact => request_path == rule_path,
        PathMatchType::Prefix => {
            if rule_path == "/" {
                return true;
            }
            request_path == rule_path || request_path.starts_with(&format!("{rule_path}/"))
        }
        PathMatchType::Template => template_matches(rule_path, request_path),
    }
}

fn template_matches(template: &str, request_path: &str) -> bool {
    let template_segs: Vec<&str> = template.split('/').collect();
    let request_segs: Vec<&str> = request_path.split('/').collect();
    if template_segs.len() != request_segs.len() {
        return false;
    }
    for (t, r) in template_segs.iter().zip(request_segs.iter()) {
        if is_template_segment(t) {
            if r.is_empty() {
                return false;
            }
        } else if t != r {
            return false;
        }
    }
    true
}

// ─── find_matching_rule ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct MatchedRule<'a> {
    pub index: usize,
    pub rule: &'a TpxRule,
}

pub fn find_matching_rule<'a>(
    provider: &'a TpxProviderRules,
    request: &HttpRequest,
) -> Option<MatchedRule<'a>> {
    for (index, rule) in provider.rules.iter().enumerate() {
        if rule.r#match.matches_request(request) {
            return Some(MatchedRule { index, rule });
        }
    }
    None
}

// Suppress unused-import warning until other modules consume this.
#[allow(dead_code)]
static _UNUSED: OnceLock<()> = OnceLock::new();

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::HttpRequest;

    fn req(method: &str, host: &str, path: &str) -> HttpRequest {
        HttpRequest::builder()
            .method(method)
            .host(host)
            .path(path)
            .build()
            .unwrap()
    }

    fn vercel_yaml() -> &'static str {
        r#"
schema_version: 1
name: vercel
host_patterns: [api.vercel.com]
default_policy: deny
rules:
  - match:
      host: api.vercel.com
      methods: [GET]
      path: /v9/projects
      path_match: prefix
    classification: read
    action: allow
    reason: List and inspect projects.
  - match:
      host: api.vercel.com
      methods: [GET]
      path: /v6/deployments/{id}
      path_match: template
    classification: read
    action: allow
    reason: Inspect a single deployment by id.
  - match:
      host: api.vercel.com
      methods: [DELETE]
      path: /
      path_match: prefix
    classification: write
    action: deny
    reason: All DELETE explicitly blocked.
"#
    }

    // ─── path_matches ───────────────────────────────────────────────────────

    #[test]
    fn prefix_matches_segment_boundary_only() {
        assert!(path_matches(
            "/v9/projects",
            PathMatchType::Prefix,
            "/v9/projects"
        ));
        assert!(path_matches(
            "/v9/projects",
            PathMatchType::Prefix,
            "/v9/projects/abc"
        ));
        assert!(!path_matches(
            "/v9/projects",
            PathMatchType::Prefix,
            "/v9/projects-archive"
        ));
    }

    #[test]
    fn root_prefix_matches_everything() {
        assert!(path_matches("/", PathMatchType::Prefix, "/anything/at/all"));
    }

    #[test]
    fn exact_requires_full_equality() {
        assert!(path_matches(
            "/v9/projects",
            PathMatchType::Exact,
            "/v9/projects"
        ));
        assert!(!path_matches(
            "/v9/projects",
            PathMatchType::Exact,
            "/v9/projects/abc"
        ));
    }

    #[test]
    fn template_matches_single_segment_only() {
        assert!(path_matches(
            "/v6/deployments/{id}",
            PathMatchType::Template,
            "/v6/deployments/abc",
        ));
        assert!(!path_matches(
            "/v6/deployments/{id}",
            PathMatchType::Template,
            "/v6/deployments/abc/files",
        ));
        assert!(!path_matches(
            "/v6/deployments/{id}",
            PathMatchType::Template,
            "/v6/deployments/",
        ));
    }

    // ─── YAML round-trip ────────────────────────────────────────────────────

    #[test]
    fn loads_vercel_yaml() {
        let p = TpxProviderRules::from_yaml(vercel_yaml()).unwrap();
        assert_eq!(p.name, "vercel");
        assert_eq!(p.host_patterns, vec!["api.vercel.com"]);
        assert_eq!(p.rules.len(), 3);
        assert_eq!(p.rules[0].action, RuleAction::Allow);
        assert_eq!(p.rules[2].action, RuleAction::Deny);
    }

    #[test]
    fn rejects_wrong_schema_version() {
        let yaml = r#"
schema_version: 2
name: vercel
host_patterns: [api.vercel.com]
default_policy: deny
rules: [{match: {host: api.vercel.com, methods: [GET], path: /, path_match: prefix}, classification: read, action: allow, reason: x}]
"#;
        let err = TpxProviderRules::from_yaml(yaml).unwrap_err();
        assert!(err.0.contains("schema_version"));
    }

    #[test]
    fn rejects_default_policy_other_than_deny() {
        let yaml = r#"
schema_version: 1
name: vercel
host_patterns: [api.vercel.com]
default_policy: allow
rules: [{match: {host: api.vercel.com, methods: [GET], path: /, path_match: prefix}, classification: read, action: allow, reason: x}]
"#;
        let err = TpxProviderRules::from_yaml(yaml).unwrap_err();
        // serde_yaml_ng surfaces this as a deser error on the enum variant.
        assert!(err.0.contains("YAML") || err.0.contains("default_policy"));
    }

    #[test]
    fn rejects_rule_host_outside_host_patterns() {
        let yaml = r#"
schema_version: 1
name: vercel
host_patterns: [api.vercel.com]
default_policy: deny
rules:
  - match:
      host: other.example.com
      methods: [GET]
      path: /
      path_match: prefix
    classification: read
    action: allow
    reason: x
"#;
        let err = TpxProviderRules::from_yaml(yaml).unwrap_err();
        assert!(err.0.contains("host_patterns"));
    }

    #[test]
    fn rejects_template_without_placeholder() {
        let yaml = r#"
schema_version: 1
name: vercel
host_patterns: [api.vercel.com]
default_policy: deny
rules:
  - match:
      host: api.vercel.com
      methods: [GET]
      path: /v9/projects
      path_match: template
    classification: read
    action: allow
    reason: x
"#;
        let err = TpxProviderRules::from_yaml(yaml).unwrap_err();
        assert!(err.0.contains("template"));
    }

    // ─── matches_request ────────────────────────────────────────────────────

    #[test]
    fn first_match_wins_allow() {
        let p = TpxProviderRules::from_yaml(vercel_yaml()).unwrap();
        let r = req("GET", "api.vercel.com", "/v9/projects/abc");
        let matched = find_matching_rule(&p, &r).unwrap();
        assert_eq!(matched.index, 0);
        assert_eq!(matched.rule.action, RuleAction::Allow);
    }

    #[test]
    fn template_rule_matches_single_segment() {
        let p = TpxProviderRules::from_yaml(vercel_yaml()).unwrap();
        let r = req("GET", "api.vercel.com", "/v6/deployments/abc");
        let matched = find_matching_rule(&p, &r).unwrap();
        assert_eq!(matched.index, 1);
    }

    #[test]
    fn delete_falls_through_to_explicit_deny() {
        let p = TpxProviderRules::from_yaml(vercel_yaml()).unwrap();
        let r = req("DELETE", "api.vercel.com", "/v9/projects/abc");
        let matched = find_matching_rule(&p, &r).unwrap();
        assert_eq!(matched.index, 2);
        assert_eq!(matched.rule.action, RuleAction::Deny);
    }

    #[test]
    fn unknown_host_returns_no_match() {
        let p = TpxProviderRules::from_yaml(vercel_yaml()).unwrap();
        let r = req("GET", "api.other.com", "/v9/projects");
        assert!(find_matching_rule(&p, &r).is_none());
    }

    #[test]
    fn unknown_method_returns_no_match() {
        let p = TpxProviderRules::from_yaml(vercel_yaml()).unwrap();
        let r = req("PATCH", "api.vercel.com", "/v9/projects");
        // No rule matches — only DELETE has an explicit catch-all.
        assert!(find_matching_rule(&p, &r).is_none());
    }
}
