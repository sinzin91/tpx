//! Deny-closed validation pipeline.
//!
//! Slim Rust port of `zot/src/tool_proxy/engine.py`. Drops audit-gate ceremony
//! (every provider is implicitly "audited" in tpx) and the rich logging shim
//! — the JSONL log lives in `crate::log`, structured logging is per-CLI-call.
//!
//! Pipeline (spec §7):
//! 1. registry.find(request) → validator or NO_MATCHING_TOOL_VALIDATOR.
//! 2. precondition: content-type allowed + body size under cap.
//! 3. validator.inspect(request) → InspectionResult.
//! 4. validator.evaluate_permission(inspection) → ToolPermissionDecision.

use std::collections::HashSet;

use thiserror::Error;

use crate::contracts::{
    DecisionCode, HttpRequest, InspectionResult, PermissionSource, ToolPermissionDecision,
};

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EngineError {
    #[error("multiple validators matched request {host}{path}: {names}")]
    AmbiguousValidator {
        host: String,
        path: String,
        names: String,
    },
    #[error("validator name {0} is registered twice")]
    DuplicateValidator(String),
}

/// Outcome of running the validation pipeline against a request.
#[derive(Debug, Clone)]
pub struct ValidationOutcome {
    pub allowed: bool,
    pub permission: ToolPermissionDecision,
    pub inspection: Option<InspectionResult>,
    pub validator_name: Option<String>,
    pub matched_validator: bool,
    pub matched_rule_index: Option<usize>,
}

/// Trait every per-provider validator implements.
///
/// `matches` establishes ownership of the request; `inspect` produces semantic
/// metadata; `evaluate_permission` converts that metadata into the final
/// allow/deny.
pub trait Validator: Send + Sync {
    fn name(&self) -> &str;

    /// Optional cap for request body bytes; `None` means no validator-side cap.
    fn max_body_bytes(&self) -> Option<usize> {
        None
    }

    /// Optional whitelist of supported request `Content-Type` media types.
    /// `None` means no validator-side restriction.
    fn supported_content_types(&self) -> Option<&HashSet<String>> {
        None
    }

    fn matches(&self, request: &HttpRequest) -> bool;

    fn inspect(&self, request: &HttpRequest) -> InspectionResult;

    fn evaluate_permission(
        &self,
        request: &HttpRequest,
        inspection: &InspectionResult,
    ) -> (ToolPermissionDecision, Option<usize>);
}

/// Registry holding all per-provider validators.
#[derive(Default)]
pub struct ValidatorRegistry {
    validators: Vec<Box<dyn Validator>>,
    names: HashSet<String>,
}

impl ValidatorRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, v: Box<dyn Validator>) -> Result<(), EngineError> {
        let name = v.name().to_string();
        if !self.names.insert(name.clone()) {
            return Err(EngineError::DuplicateValidator(name));
        }
        self.validators.push(v);
        Ok(())
    }

    pub fn names(&self) -> Vec<&str> {
        self.validators.iter().map(|v| v.name()).collect()
    }

    pub fn find(&self, request: &HttpRequest) -> Result<Option<&dyn Validator>, EngineError> {
        let mut matches: Vec<&dyn Validator> = Vec::new();
        for v in &self.validators {
            if v.matches(request) {
                matches.push(v.as_ref());
            }
        }
        match matches.len() {
            0 => Ok(None),
            1 => Ok(Some(matches[0])),
            _ => {
                let mut names: Vec<&str> = matches.iter().map(|v| v.name()).collect();
                names.sort();
                Err(EngineError::AmbiguousValidator {
                    host: request.host.clone(),
                    path: request.path.clone(),
                    names: names.join(", "),
                })
            }
        }
    }
}

fn deny(
    code: DecisionCode,
    reason: &str,
    source: PermissionSource,
    validator_name: Option<&str>,
    matched_validator: bool,
) -> ValidationOutcome {
    let permission = ToolPermissionDecision::deny(code, reason, source).unwrap_or_else(|_| {
        // Fall back to a safe single-line reason if the upstream message is
        // malformed (e.g. multi-line). Should never happen in practice.
        ToolPermissionDecision::deny(code, "deny", source).expect("safe deny constructible")
    });
    ValidationOutcome {
        allowed: false,
        permission,
        inspection: None,
        validator_name: validator_name.map(String::from),
        matched_validator,
        matched_rule_index: None,
    }
}

/// Top-level deny-closed validation flow.
pub fn validate_request(request: &HttpRequest, registry: &ValidatorRegistry) -> ValidationOutcome {
    let validator = match registry.find(request) {
        Ok(Some(v)) => v,
        Ok(None) => {
            return deny(
                DecisionCode::NoMatchingToolValidator,
                &format!("No registered validator owns host {}", request.host),
                PermissionSource::DefaultDeny,
                None,
                false,
            );
        }
        Err(e @ EngineError::AmbiguousValidator { .. }) => {
            return deny(
                DecisionCode::DefaultDeny,
                &e.to_string(),
                PermissionSource::DefaultDeny,
                None,
                false,
            );
        }
        Err(_) => {
            return deny(
                DecisionCode::PluginException,
                "Validator matching raised an unexpected error",
                PermissionSource::PluginRule,
                None,
                false,
            );
        }
    };

    // Precondition: content-type + body size cap.
    if let Some(supported) = validator.supported_content_types() {
        if let Some(ct) = request.content_type.as_deref() {
            if !supported.contains(ct) {
                return deny(
                    DecisionCode::UnsupportedContentType,
                    &format!(
                        "Validator {} does not support content type {ct}",
                        validator.name()
                    ),
                    PermissionSource::DefaultDeny,
                    Some(validator.name()),
                    true,
                );
            }
        } else if has_body(request) {
            return deny(
                DecisionCode::UnsupportedContentType,
                &format!(
                    "Validator {} requires a supported content type for bodies",
                    validator.name()
                ),
                PermissionSource::DefaultDeny,
                Some(validator.name()),
                true,
            );
        }
    }
    if let Some(cap) = validator.max_body_bytes() {
        if body_bytes(request) > cap {
            return deny(
                DecisionCode::BodyTooLarge,
                &format!(
                    "Request body exceeds validator limit of {cap} bytes for {}",
                    validator.name()
                ),
                PermissionSource::DefaultDeny,
                Some(validator.name()),
                true,
            );
        }
    }

    let inspection = validator.inspect(request);
    let (permission, matched_rule_index) = validator.evaluate_permission(request, &inspection);
    ValidationOutcome {
        allowed: permission.allowed,
        permission,
        inspection: Some(inspection),
        validator_name: Some(validator.name().to_string()),
        matched_validator: true,
        matched_rule_index,
    }
}

fn has_body(request: &HttpRequest) -> bool {
    matches!(request.body.as_deref(), Some(s) if !s.is_empty())
}

fn body_bytes(request: &HttpRequest) -> usize {
    request.body.as_ref().map_or(0, |s| s.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::{InspectionConfidence, InspectionDisposition, RequestClassification};

    struct FakeValidator {
        name: String,
        host: String,
        max_body: Option<usize>,
        ct: Option<HashSet<String>>,
        always_allow: bool,
    }

    impl FakeValidator {
        fn new(name: &str, host: &str) -> Self {
            Self {
                name: name.to_string(),
                host: host.to_string(),
                max_body: None,
                ct: None,
                always_allow: true,
            }
        }
    }

    impl Validator for FakeValidator {
        fn name(&self) -> &str {
            &self.name
        }
        fn max_body_bytes(&self) -> Option<usize> {
            self.max_body
        }
        fn supported_content_types(&self) -> Option<&HashSet<String>> {
            self.ct.as_ref()
        }
        fn matches(&self, request: &HttpRequest) -> bool {
            request.host == self.host
        }
        fn inspect(&self, _request: &HttpRequest) -> InspectionResult {
            InspectionResult::new(
                if self.always_allow {
                    RequestClassification::Read
                } else {
                    RequestClassification::Unknown
                },
                InspectionConfidence::High,
                "fake",
                None,
                if self.always_allow {
                    InspectionDisposition::MatchedRule
                } else {
                    InspectionDisposition::NoMatchingRule
                },
            )
            .unwrap()
        }
        fn evaluate_permission(
            &self,
            _request: &HttpRequest,
            _inspection: &InspectionResult,
        ) -> (ToolPermissionDecision, Option<usize>) {
            if self.always_allow {
                (
                    ToolPermissionDecision::allow("ok", PermissionSource::RuleEngine).unwrap(),
                    Some(0),
                )
            } else {
                (
                    ToolPermissionDecision::deny(
                        DecisionCode::DefaultDeny,
                        "no rule",
                        PermissionSource::DefaultDeny,
                    )
                    .unwrap(),
                    None,
                )
            }
        }
    }

    fn req(host: &str) -> HttpRequest {
        HttpRequest::builder()
            .method("GET")
            .host(host)
            .path("/")
            .build()
            .unwrap()
    }

    #[test]
    fn no_validator_returns_no_matching_validator_deny() {
        let registry = ValidatorRegistry::new();
        let outcome = validate_request(&req("api.vercel.com"), &registry);
        assert!(!outcome.allowed);
        assert_eq!(
            outcome.permission.code,
            DecisionCode::NoMatchingToolValidator
        );
        assert!(!outcome.matched_validator);
    }

    #[test]
    fn matched_validator_runs_inspect_and_evaluate() {
        let mut registry = ValidatorRegistry::new();
        registry
            .register(Box::new(FakeValidator::new("vercel", "api.vercel.com")))
            .unwrap();
        let outcome = validate_request(&req("api.vercel.com"), &registry);
        assert!(outcome.allowed);
        assert_eq!(outcome.permission.code, DecisionCode::Allow);
        assert_eq!(outcome.matched_rule_index, Some(0));
    }

    #[test]
    fn ambiguous_validators_deny_default() {
        let mut registry = ValidatorRegistry::new();
        registry
            .register(Box::new(FakeValidator::new("a", "api.vercel.com")))
            .unwrap();
        registry
            .register(Box::new(FakeValidator::new("b", "api.vercel.com")))
            .unwrap();
        let outcome = validate_request(&req("api.vercel.com"), &registry);
        assert!(!outcome.allowed);
        assert_eq!(outcome.permission.code, DecisionCode::DefaultDeny);
    }

    #[test]
    fn duplicate_validator_name_rejected() {
        let mut registry = ValidatorRegistry::new();
        registry
            .register(Box::new(FakeValidator::new("v", "x")))
            .unwrap();
        let err = registry
            .register(Box::new(FakeValidator::new("v", "y")))
            .unwrap_err();
        assert!(matches!(err, EngineError::DuplicateValidator(_)));
    }

    #[test]
    fn body_too_large_rejected() {
        let mut v = FakeValidator::new("vercel", "api.vercel.com");
        v.max_body = Some(4);
        let mut registry = ValidatorRegistry::new();
        registry.register(Box::new(v)).unwrap();
        let request = HttpRequest::builder()
            .method("POST")
            .host("api.vercel.com")
            .path("/")
            .content_type("application/json")
            .body("hello world")
            .build()
            .unwrap();
        let outcome = validate_request(&request, &registry);
        assert_eq!(outcome.permission.code, DecisionCode::BodyTooLarge);
    }

    #[test]
    fn unsupported_content_type_rejected() {
        let mut v = FakeValidator::new("vercel", "api.vercel.com");
        v.ct = Some(HashSet::from(["application/json".to_string()]));
        let mut registry = ValidatorRegistry::new();
        registry.register(Box::new(v)).unwrap();
        let request = HttpRequest::builder()
            .method("POST")
            .host("api.vercel.com")
            .path("/")
            .content_type("text/plain")
            .body("data")
            .build()
            .unwrap();
        let outcome = validate_request(&request, &registry);
        assert_eq!(
            outcome.permission.code,
            DecisionCode::UnsupportedContentType
        );
    }
}
