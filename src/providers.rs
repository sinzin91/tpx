//! Per-provider runtime config (base URL, auth shape, body cap, timeout).
//!
//! Per spec §8 — narrow to the two shipping providers (Vercel + Langfuse).

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthStyle {
    /// `Authorization: Bearer <token>` from `credentials.<name>.token`.
    Bearer,
    /// `Authorization: Basic <base64(public_key:secret_key)>`.
    BasicPublicSecret,
}

#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub name: &'static str,
    pub base_url: &'static str,
    pub auth_style: AuthStyle,
    pub required_credentials: &'static [&'static str],
    pub timeout: Duration,
    pub max_body_bytes: usize,
    /// Bundled YAML rules (override at runtime by placing
    /// `~/.tpx/rules/<name>.yaml`).
    pub bundled_rules: &'static str,
}

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);
const DEFAULT_MAX_BODY: usize = 256 * 1024;

const VERCEL_RULES: &str = include_str!("rules/vercel.yaml");
const LANGFUSE_RULES: &str = include_str!("rules/langfuse.yaml");

pub fn registry() -> Vec<ProviderConfig> {
    vec![
        ProviderConfig {
            name: "vercel",
            base_url: "https://api.vercel.com",
            auth_style: AuthStyle::Bearer,
            required_credentials: &["token"],
            timeout: DEFAULT_TIMEOUT,
            max_body_bytes: DEFAULT_MAX_BODY,
            bundled_rules: VERCEL_RULES,
        },
        ProviderConfig {
            name: "langfuse",
            base_url: "https://cloud.langfuse.com",
            auth_style: AuthStyle::BasicPublicSecret,
            required_credentials: &["public_key", "secret_key"],
            timeout: DEFAULT_TIMEOUT,
            max_body_bytes: DEFAULT_MAX_BODY,
            bundled_rules: LANGFUSE_RULES,
        },
    ]
}

pub fn find(name: &str) -> Option<ProviderConfig> {
    registry().into_iter().find(|p| p.name == name)
}

pub fn names() -> Vec<&'static str> {
    registry().into_iter().map(|p| p.name).collect()
}
