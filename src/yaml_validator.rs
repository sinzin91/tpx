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
            None => InspectionResult::new(
                RequestClassification::Unknown,
                InspectionConfidence::Low,
                format!(
                    "No rule matches {} {}{}",
                    request.method, request.host, request.path
                ),
                None,
                InspectionDisposition::NoMatchingRule,
            )
            .expect("no-match inspection result is well-formed"),
        }
    }

    fn evaluate_permission(
        &self,
        request: &HttpRequest,
        _inspection: &InspectionResult,
    ) -> (ToolPermissionDecision, Option<usize>) {
        let Some(matched) = find_matching_rule(&self.provider, request) else {
            return (
                ToolPermissionDecision::deny(
                    DecisionCode::DefaultDeny,
                    format!(
                        "No rule matches {} {}{}",
                        request.method, request.host, request.path
                    ),
                    PermissionSource::DefaultDeny,
                )
                .expect("default-deny reason is well-formed"),
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
                ToolPermissionDecision::deny(
                    DecisionCode::DefaultDeny,
                    matched.rule.reason.clone(),
                    PermissionSource::RuleEngine,
                )
                .expect("deny reason validated at YAML load time"),
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
