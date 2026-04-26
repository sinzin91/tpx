//! `YamlValidator` — `Validator` impl driven by a `TpxProviderRules` doc.

use std::collections::HashSet;

use crate::contracts::{
    DecisionCode, HttpRequest, InspectionConfidence, InspectionDisposition, InspectionResult,
    PermissionSource, RequestClassification, ToolPermissionDecision,
};
use crate::engine::Validator;
use crate::rules::{RuleAction, TpxProviderRules, find_matching_rule};

pub struct YamlValidator {
    provider: TpxProviderRules,
    host_set: HashSet<String>,
    max_body_bytes: Option<usize>,
}

impl YamlValidator {
    pub fn new(provider: TpxProviderRules, max_body_bytes: Option<usize>) -> Self {
        let host_set: HashSet<String> = provider.host_patterns.iter().cloned().collect();
        Self {
            provider,
            host_set,
            max_body_bytes,
        }
    }

    pub fn provider(&self) -> &TpxProviderRules {
        &self.provider
    }
}

impl Validator for YamlValidator {
    fn name(&self) -> &str {
        &self.provider.name
    }

    fn max_body_bytes(&self) -> Option<usize> {
        self.max_body_bytes
    }

    fn matches(&self, request: &HttpRequest) -> bool {
        self.host_set.contains(&request.host)
    }

    fn inspect(&self, request: &HttpRequest) -> InspectionResult {
        match find_matching_rule(&self.provider, request) {
            Some(matched) => {
                let rule = matched.rule;
                InspectionResult::new(
                    rule.classification,
                    InspectionConfidence::High,
                    rule.reason.clone(),
                    None,
                    InspectionDisposition::MatchedRule,
                )
                .expect("matched rule produces valid inspection result")
            }
            None => {
                // Request-derived; sanitize to guarantee single-line.
                let reason = format!(
                    "No rule matches {} {}{}",
                    request.method, request.host, request.path
                )
                .replace(['\n', '\r'], " ");
                InspectionResult::new(
                    RequestClassification::Unknown,
                    InspectionConfidence::Low,
                    reason,
                    None,
                    InspectionDisposition::NoMatchingRule,
                )
                .expect("sanitized no-match inspection is well-formed")
            }
        }
    }

    fn evaluate_permission(
        &self,
        request: &HttpRequest,
        _inspection: &InspectionResult,
    ) -> (ToolPermissionDecision, Option<usize>) {
        let Some(matched) = find_matching_rule(&self.provider, request) else {
            // Reason includes request-derived path; sanitize to guarantee
            // single-line so deny() never panics on hostile input.
            return (
                ToolPermissionDecision::deny_safe(
                    DecisionCode::DefaultDeny,
                    format!(
                        "No rule matches {} {}{}",
                        request.method, request.host, request.path
                    ),
                    PermissionSource::DefaultDeny,
                ),
                None,
            );
        };
        match matched.rule.action {
            RuleAction::Allow => (
                ToolPermissionDecision::allow(
                    matched.rule.reason.clone(),
                    PermissionSource::RuleEngine,
                )
                .expect("allow reason validated at YAML load time"),
                Some(matched.index),
            ),
            RuleAction::Deny => (
                ToolPermissionDecision::deny_safe(
                    DecisionCode::DefaultDeny,
                    matched.rule.reason.clone(),
                    PermissionSource::RuleEngine,
                ),
                Some(matched.index),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{ValidatorRegistry, validate_request};

    fn yaml() -> &'static str {
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
      methods: [DELETE]
      path: /
      path_match: prefix
    classification: write
    action: deny
    reason: All DELETE explicitly blocked.
"#
    }

    fn registry() -> ValidatorRegistry {
        let mut r = ValidatorRegistry::new();
        let provider = TpxProviderRules::from_yaml(yaml()).unwrap();
        r.register(Box::new(YamlValidator::new(provider, Some(256 * 1024))))
            .unwrap();
        r
    }

    #[test]
    fn allowed_get_returns_allow() {
        let r = HttpRequest::builder()
            .method("GET")
            .host("api.vercel.com")
            .path("/v9/projects/abc")
            .build()
            .unwrap();
        let outcome = validate_request(&r, &registry());
        assert!(outcome.allowed);
        assert_eq!(outcome.permission.code, DecisionCode::Allow);
        assert_eq!(outcome.matched_rule_index, Some(0));
    }

    #[test]
    fn explicit_deny_returns_default_deny_code_with_rule_engine_source() {
        let r = HttpRequest::builder()
            .method("DELETE")
            .host("api.vercel.com")
            .path("/v9/projects/abc")
            .build()
            .unwrap();
        let outcome = validate_request(&r, &registry());
        assert!(!outcome.allowed);
        assert_eq!(
            outcome.permission.permission_source,
            PermissionSource::RuleEngine
        );
        assert_eq!(outcome.matched_rule_index, Some(1));
    }

    #[test]
    fn no_match_with_newline_in_path_does_not_panic() {
        // Regression: pre-fix the deny path used .expect() on a reason that
        // included request.path, which crashes when the path contains \n.
        let r = HttpRequest::builder()
            .method("PATCH")
            .host("api.vercel.com")
            .path("/v9/projects/foo\nbar")
            .build()
            .unwrap();
        let outcome = validate_request(&r, &registry());
        assert!(!outcome.allowed);
        assert!(!outcome.permission.reason.contains('\n'));
    }

    #[test]
    fn no_match_returns_default_deny() {
        let r = HttpRequest::builder()
            .method("PATCH")
            .host("api.vercel.com")
            .path("/v9/projects/abc")
            .build()
            .unwrap();
        let outcome = validate_request(&r, &registry());
        assert!(!outcome.allowed);
        assert_eq!(outcome.permission.code, DecisionCode::DefaultDeny);
        assert_eq!(
            outcome.permission.permission_source,
            PermissionSource::DefaultDeny
        );
        assert_eq!(outcome.matched_rule_index, None);
    }
}
