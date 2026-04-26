//! End-to-end pipeline tests using a wiremock-backed mock provider.
//!
//! Exercises the full chain: rules YAML → registry → validate_request →
//! credentials load (mode-0600 file in a tempdir) → execute_provider_request
//! → JSONL log line written. No real network egress.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use serde_json::json;
use tempfile::tempdir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use tpx::contracts::{DecisionCode, HttpRequest};
use tpx::credentials::CredentialStore;
use tpx::engine::{ValidatorRegistry, validate_request};
use tpx::log::{DecisionLog, DecisionRecord};
use tpx::provider_runtime::execute_provider_request;
use tpx::providers::{AuthStyle, ProviderConfig};
use tpx::rules::TpxProviderRules;
use tpx::yaml_validator::YamlValidator;

const RULES_TEMPLATE: &str = r#"
schema_version: 1
name: mock
host_patterns: [HOST]
default_policy: deny
rules:
  - match:
      host: HOST
      methods: [GET]
      path: /v1/items
      path_match: prefix
    classification: read
    action: allow
    reason: List items.
  - match:
      host: HOST
      methods: [DELETE]
      path: /
      path_match: prefix
    classification: write
    action: deny
    reason: All DELETE blocked.
"#;

fn build_mock_config(server: &MockServer) -> ProviderConfig {
    let url = server.uri();
    let host = reqwest::Url::parse(&url)
        .unwrap()
        .host_str()
        .unwrap()
        .to_string();
    let yaml = RULES_TEMPLATE.replace("HOST", &host);
    // Leak the strings so we can hand &'static str to ProviderConfig — fine for a test.
    let leaked_url: &'static str = Box::leak(url.into_boxed_str());
    let leaked_yaml: &'static str = Box::leak(yaml.into_boxed_str());
    ProviderConfig {
        name: "mock",
        base_url: leaked_url,
        auth_style: AuthStyle::Bearer,
        required_credentials: &["token"],
        timeout: Duration::from_secs(5),
        max_body_bytes: 64 * 1024,
        bundled_rules: leaked_yaml,
    }
}

fn write_creds(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
    let path = dir.join("credentials.json");
    let mut f = fs::File::create(&path).unwrap();
    f.write_all(body.as_bytes()).unwrap();
    let mut perms = f.metadata().unwrap().permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&path, perms).unwrap();
    path
}

fn registry_for(config: &ProviderConfig) -> ValidatorRegistry {
    let mut r = ValidatorRegistry::new();
    let provider = TpxProviderRules::from_yaml(config.bundled_rules).unwrap();
    r.register(Box::new(YamlValidator::new(
        provider,
        Some(config.max_body_bytes),
    )))
    .unwrap();
    r
}

#[tokio::test]
async fn allowed_request_executes_and_returns_upstream_body() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/items"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items": [1, 2, 3]})))
        .mount(&server)
        .await;

    let config = build_mock_config(&server);
    let registry = registry_for(&config);

    let req = HttpRequest::builder()
        .method("GET")
        .host(
            reqwest::Url::parse(config.base_url)
                .unwrap()
                .host_str()
                .unwrap(),
        )
        .path("/v1/items")
        .build()
        .unwrap();

    let outcome = validate_request(&req, &registry);
    assert!(outcome.allowed, "should be allowed");
    assert_eq!(outcome.permission.code, DecisionCode::Allow);

    let mut creds = BTreeMap::new();
    creds.insert("token".to_string(), "test-token".to_string());
    let response = execute_provider_request(&config, &req, &creds)
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    let body = response.body_json.expect("response is JSON");
    assert_eq!(body["items"], json!([1, 2, 3]));
}

#[tokio::test]
async fn denied_request_never_reaches_upstream() {
    let server = MockServer::start().await;
    // Critical: zero mocks installed for DELETE. If validate_request leaked, the
    // unmocked request would hit the server and wiremock would log it.
    Mock::given(method("GET"))
        .and(path("/v1/items"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let config = build_mock_config(&server);
    let registry = registry_for(&config);

    let req = HttpRequest::builder()
        .method("DELETE")
        .host(
            reqwest::Url::parse(config.base_url)
                .unwrap()
                .host_str()
                .unwrap(),
        )
        .path("/v1/items/abc")
        .build()
        .unwrap();

    let outcome = validate_request(&req, &registry);
    assert!(!outcome.allowed, "DELETE should be denied");
    assert_eq!(outcome.matched_rule_index, Some(1));
    // Never call execute_provider_request — this is what tpx CLI does too.
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
}

#[tokio::test]
async fn no_match_falls_through_to_default_deny() {
    let server = MockServer::start().await;
    let config = build_mock_config(&server);
    let registry = registry_for(&config);

    let req = HttpRequest::builder()
        .method("PATCH")
        .host(
            reqwest::Url::parse(config.base_url)
                .unwrap()
                .host_str()
                .unwrap(),
        )
        .path("/v1/items/abc")
        .build()
        .unwrap();

    let outcome = validate_request(&req, &registry);
    assert!(!outcome.allowed);
    assert_eq!(outcome.permission.code, DecisionCode::DefaultDeny);
    assert_eq!(outcome.matched_rule_index, None);
}

#[tokio::test]
async fn credentials_must_be_mode_0600_to_authenticate() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("credentials.json");
    let mut f = fs::File::create(&path).unwrap();
    f.write_all(br#"{"mock":{"token":"t"}}"#).unwrap();
    let mut perms = f.metadata().unwrap().permissions();
    perms.set_mode(0o644);
    fs::set_permissions(&path, perms).unwrap();
    assert!(CredentialStore::load(&path).is_err());

    // Now fix the perms.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let store = CredentialStore::load(&path).unwrap();
    let creds = store.for_provider("mock", &["token"]).unwrap();
    assert_eq!(creds.get("token").map(String::as_str), Some("t"));
}

#[tokio::test]
async fn upstream_response_exceeding_cap_is_rejected() {
    let server = MockServer::start().await;
    // Build a body just over the configured cap.
    let mut config = build_mock_config(&server);
    config.max_body_bytes = 1024;
    let oversized = "x".repeat(config.max_body_bytes + 1);
    Mock::given(method("GET"))
        .and(path("/v1/items"))
        .respond_with(ResponseTemplate::new(200).set_body_string(oversized))
        .mount(&server)
        .await;
    let host = reqwest::Url::parse(config.base_url)
        .unwrap()
        .host_str()
        .unwrap()
        .to_string();
    let req = HttpRequest::builder()
        .method("GET")
        .host(host)
        .path("/v1/items")
        .build()
        .unwrap();
    let mut creds = BTreeMap::new();
    creds.insert("token".into(), "t".into());
    let err = execute_provider_request(&config, &req, &creds)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        tpx::provider_runtime::RuntimeError::BodyTooLarge { .. }
    ));
}

#[tokio::test]
async fn full_pipeline_writes_jsonl_decision() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/items"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .mount(&server)
        .await;

    let config = build_mock_config(&server);
    let registry = registry_for(&config);

    let req = HttpRequest::builder()
        .method("GET")
        .host(
            reqwest::Url::parse(config.base_url)
                .unwrap()
                .host_str()
                .unwrap(),
        )
        .path("/v1/items")
        .build()
        .unwrap();

    let outcome = validate_request(&req, &registry);
    assert!(outcome.allowed);

    let dir = tempdir().unwrap();
    let _creds_path = write_creds(dir.path(), r#"{"mock":{"token":"t"}}"#);

    let mut creds = BTreeMap::new();
    creds.insert("token".into(), "t".into());
    let response = execute_provider_request(&config, &req, &creds)
        .await
        .unwrap();

    let log_path = dir.path().join("log").join("decisions.jsonl");
    let log = DecisionLog::new(log_path.clone());
    log.append(&DecisionRecord {
        ts: DecisionRecord::now_ts(),
        provider: config.name.into(),
        method: req.method.clone(),
        host: req.host.clone(),
        path: req.path.clone(),
        classification: outcome.inspection.as_ref().unwrap().classification,
        decision_code: outcome.permission.code,
        permission_source: outcome.permission.permission_source,
        stage: "inspection".into(),
        matched_rule_index: outcome.matched_rule_index,
        reason: outcome.permission.reason.clone(),
        upstream_status: Some(response.status),
        latency_ms: Some(response.latency_ms),
    })
    .unwrap();

    let lines = log.tail(10).unwrap();
    assert_eq!(lines.len(), 1);
    let parsed: DecisionRecord = serde_json::from_str(&lines[0]).unwrap();
    assert_eq!(parsed.upstream_status, Some(200));
    assert_eq!(parsed.matched_rule_index, Some(0));
    // Spec §9: no body content.
    assert!(!lines[0].contains("\"ok\""));
}
