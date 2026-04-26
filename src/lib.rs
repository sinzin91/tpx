//! tpx — Local CLI proxy for Claude Code.
//!
//! Turns a write-capable API key into an effectively read-only one by routing
//! every API call through a deny-closed YAML allowlist. See
//! `Projects/Specs/2026-04-26 tpx CLI - Dumb Proxy Spec.md` for the design.

pub mod cli;
pub mod contracts;
pub mod credentials;
pub mod engine;
pub mod log;
pub mod provider_runtime;
pub mod providers;
pub mod rules;
pub mod yaml_validator;
