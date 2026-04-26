//! `tpx` CLI surface.
//!
//! Per spec §6:
//!
//! ```text
//! tpx <provider> <method> <path> [--query k=v]... [--header k:v]... [--body @file|-|<json>]
//! tpx --list-providers
//! tpx --check <provider> <method> <path>
//! tpx --explain <provider> <method> <path>
//! tpx --tail-log [-n 50]
//! ```
//!
//! Output is always JSON on stdout. Exit codes:
//! 0 success, 1 policy deny, 2 validation error, 3 credentials error, 4 upstream error.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde_json::{Value, json};

use crate::contracts::{HttpRequest, RequestClassification, ToolPermissionDecision};
use crate::credentials::CredentialStore;
use crate::engine::{ValidationOutcome, ValidatorRegistry, validate_request};
use crate::log::{DecisionLog, DecisionRecord};
use crate::provider_runtime::{ProviderResponse, RuntimeError, execute_provider_request};
use crate::providers::{self, ProviderConfig};
use crate::rules::TpxProviderRules;
use crate::yaml_validator::YamlValidator;

const EXIT_SUCCESS: u8 = 0;
const EXIT_POLICY_DENY: u8 = 1;
const EXIT_VALIDATION_ERROR: u8 = 2;
const EXIT_CREDENTIALS_ERROR: u8 = 3;
const EXIT_UPSTREAM_ERROR: u8 = 4;

#[derive(Parser, Debug)]
#[command(
    name = "tpx",
    about = "Local CLI proxy: deny-closed allowlist over write-capable API keys.",
    version,
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// List the providers tpx knows about and exit.
    #[arg(long, global = true)]
    list_providers: bool,

    /// Override the credentials path (default: $HOME/.tpx/credentials.json).
    #[arg(long, global = true)]
    creds_path: Option<PathBuf>,

    /// Override the decisions log path (default: $HOME/.tpx/log/decisions.jsonl).
    #[arg(long, global = true)]
    log_path: Option<PathBuf>,

    /// Override the rules directory (default: $HOME/.tpx/rules/, falling back to bundled).
    #[arg(long, global = true)]
    rules_dir: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Execute a request: `tpx <provider> <method> <path>`.
    #[command(external_subcommand)]
    Provider(Vec<String>),
    /// Print the decision for the request without making a network call.
    Check(RequestArgs),
    /// Print which rule matched (or didn't) and the resulting decision.
    Explain(RequestArgs),
    /// Print the last N decisions from the JSONL log.
    TailLog {
        #[arg(short = 'n', long, default_value_t = 50)]
        n: usize,
    },
}

#[derive(clap::Args, Debug)]
struct RequestArgs {
    provider: String,
    method: String,
    path: String,
    #[arg(long = "query", value_parser = parse_kv_eq)]
    query: Vec<(String, String)>,
    #[arg(long = "header", value_parser = parse_kv_colon)]
    header: Vec<(String, String)>,
    #[arg(long)]
    body: Option<String>,
    #[arg(long)]
    content_type: Option<String>,
}

fn parse_kv_eq(s: &str) -> Result<(String, String), String> {
    let (k, v) = s
        .split_once('=')
        .ok_or_else(|| format!("expected key=value, got {s}"))?;
    Ok((k.to_string(), v.to_string()))
}

fn parse_kv_colon(s: &str) -> Result<(String, String), String> {
    let (k, v) = s
        .split_once(':')
        .ok_or_else(|| format!("expected key:value, got {s}"))?;
    Ok((k.trim().to_string(), v.trim().to_string()))
}

pub fn run() -> ExitCode {
    let mut cli = Cli::parse();

    if cli.list_providers {
        let providers: Vec<String> = providers::names().into_iter().map(String::from).collect();
        emit_json(&json!({"status": "success", "data": {"providers": providers}}));
        return ExitCode::from(EXIT_SUCCESS);
    }

    let command = cli.command.take();
    let result = match command {
        Some(Command::Provider(args)) => run_execute(&cli, args),
        Some(Command::Check(args)) => run_check(&cli, args),
        Some(Command::Explain(args)) => run_explain(&cli, args),
        Some(Command::TailLog { n }) => run_tail_log(&cli, n),
        None => {
            emit_error("validation", "missing command", None);
            return ExitCode::from(EXIT_VALIDATION_ERROR);
        }
    };

    ExitCode::from(result)
}

fn run_check(cli: &Cli, args: RequestArgs) -> u8 {
    let (config, request) = match prepare(&args) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let registry = match build_registry(cli, &config) {
        Ok(r) => r,
        Err(code) => return code,
    };
    let outcome = validate_request(&request, &registry);
    emit_decision(&outcome, None);
    if outcome.allowed {
        EXIT_SUCCESS
    } else {
        EXIT_POLICY_DENY
    }
}

fn run_explain(cli: &Cli, args: RequestArgs) -> u8 {
    let (config, request) = match prepare(&args) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let registry = match build_registry(cli, &config) {
        Ok(r) => r,
        Err(code) => return code,
    };
    let outcome = validate_request(&request, &registry);
    let extra = json!({
        "provider": config.name,
        "request": {
            "method": request.method,
            "host": request.host,
            "path": request.path,
        },
        "matched_rule_index": outcome.matched_rule_index,
        "rule": outcome.matched_rule_index.and_then(|idx| {
            // Look up the matching rule for diagnostics.
            let provider = TpxProviderRules::from_yaml(config.bundled_rules).ok()?;
            provider.rules.get(idx).map(|r| json!({
                "match": {
                    "host": r.r#match.host,
                    "methods": r.r#match.methods.iter().map(|m| m.as_str()).collect::<Vec<_>>(),
                    "path": r.r#match.path,
                    "path_match": format!("{:?}", r.r#match.path_match).to_lowercase(),
                },
                "action": format!("{:?}", r.action).to_lowercase(),
                "classification": format!("{:?}", r.classification).to_lowercase(),
                "reason": r.reason,
            }))
        }),
    });
    emit_decision(&outcome, Some(extra));
    if outcome.allowed {
        EXIT_SUCCESS
    } else {
        EXIT_POLICY_DENY
    }
}

fn run_tail_log(cli: &Cli, n: usize) -> u8 {
    let path = cli
        .log_path
        .clone()
        .unwrap_or_else(crate::log::default_path);
    let log = DecisionLog::new(path);
    match log.tail(n) {
        Ok(lines) => {
            let entries: Vec<Value> = lines
                .into_iter()
                .map(|line| serde_json::from_str::<Value>(&line).unwrap_or(Value::String(line)))
                .collect();
            emit_json(&json!({"status": "success", "data": {"entries": entries}}));
            EXIT_SUCCESS
        }
        Err(e) => {
            emit_error("io_error", &e.to_string(), None);
            EXIT_VALIDATION_ERROR
        }
    }
}

fn run_execute(cli: &Cli, raw_args: Vec<String>) -> u8 {
    let args = match parse_provider_args(raw_args) {
        Ok(v) => v,
        Err(msg) => {
            emit_error("validation", &msg, None);
            return EXIT_VALIDATION_ERROR;
        }
    };
    let (config, request) = match prepare(&args) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let registry = match build_registry(cli, &config) {
        Ok(r) => r,
        Err(code) => return code,
    };
    let outcome = validate_request(&request, &registry);

    if !outcome.allowed {
        log_decision(cli, &config, &request, &outcome, None, None);
        emit_decision(&outcome, None);
        return EXIT_POLICY_DENY;
    }

    // Allowed → load credentials and execute.
    let creds_path = cli
        .creds_path
        .clone()
        .unwrap_or_else(crate::credentials::default_path);
    let store = match CredentialStore::load(&creds_path) {
        Ok(s) => s,
        Err(e) => {
            emit_error(
                "credentials",
                &e.to_string(),
                Some(json!({"path": creds_path})),
            );
            return EXIT_CREDENTIALS_ERROR;
        }
    };
    let creds = match store.for_provider(config.name, config.required_credentials) {
        Ok(c) => c.clone(),
        Err(e) => {
            emit_error("credentials", &e.to_string(), None);
            return EXIT_CREDENTIALS_ERROR;
        }
    };

    let runtime_result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime is constructible")
        .block_on(execute_provider_request(&config, &request, &creds));

    match runtime_result {
        Ok(response) => {
            log_decision(
                cli,
                &config,
                &request,
                &outcome,
                Some(response.status),
                Some(response.latency_ms),
            );
            emit_response(&response);
            EXIT_SUCCESS
        }
        Err(e) => {
            log_decision(cli, &config, &request, &outcome, None, None);
            emit_runtime_error(&e);
            EXIT_UPSTREAM_ERROR
        }
    }
}

fn parse_provider_args(raw: Vec<String>) -> Result<RequestArgs, String> {
    let mut iter = raw.into_iter();
    let provider = iter.next().ok_or("missing <provider>")?;
    let method = iter.next().ok_or("missing <method>")?;
    let path = iter.next().ok_or("missing <path>")?;
    let mut args = RequestArgs {
        provider,
        method,
        path,
        query: Vec::new(),
        header: Vec::new(),
        body: None,
        content_type: None,
    };
    while let Some(flag) = iter.next() {
        match flag.as_str() {
            "--query" => {
                let kv = iter.next().ok_or("--query needs key=value")?;
                args.query.push(parse_kv_eq(&kv)?);
            }
            "--header" => {
                let kv = iter.next().ok_or("--header needs key:value")?;
                args.header.push(parse_kv_colon(&kv)?);
            }
            "--body" => {
                args.body = Some(iter.next().ok_or("--body needs a value")?);
            }
            "--content-type" => {
                args.content_type = Some(iter.next().ok_or("--content-type needs a value")?);
            }
            other => return Err(format!("unknown flag {other}")),
        }
    }
    Ok(args)
}

fn prepare(args: &RequestArgs) -> Result<(ProviderConfig, HttpRequest), u8> {
    let Some(config) = providers::find(&args.provider) else {
        emit_error(
            "validation",
            &format!("unknown provider {}", args.provider),
            Some(json!({"known_providers": providers::names()})),
        );
        return Err(EXIT_VALIDATION_ERROR);
    };

    let host = match reqwest::Url::parse(config.base_url) {
        Ok(u) => u.host_str().unwrap_or("").to_string(),
        Err(e) => {
            emit_error("validation", &format!("invalid base_url: {e}"), None);
            return Err(EXIT_VALIDATION_ERROR);
        }
    };

    let mut builder = HttpRequest::builder()
        .method(args.method.clone())
        .host(host)
        .path(args.path.clone());
    for (k, v) in &args.query {
        builder = builder.query(k.clone(), v.clone());
    }
    for (k, v) in &args.header {
        builder = builder.header(k.clone(), v.clone());
    }
    if let Some(ct) = &args.content_type {
        builder = builder.content_type(ct.clone());
    }
    if let Some(b) = &args.body {
        builder = builder.body(b.clone());
    }

    match builder.build() {
        Ok(r) => Ok((config, r)),
        Err(e) => {
            emit_error("validation", &e.0, None);
            Err(EXIT_VALIDATION_ERROR)
        }
    }
}

fn build_registry(cli: &Cli, config: &ProviderConfig) -> Result<ValidatorRegistry, u8> {
    let yaml_text = load_rules_yaml(cli, config)?;
    let provider = match TpxProviderRules::from_yaml(&yaml_text) {
        Ok(p) => p,
        Err(e) => {
            emit_error("validation", &format!("rules: {}", e.0), None);
            return Err(EXIT_VALIDATION_ERROR);
        }
    };
    let mut registry = ValidatorRegistry::new();
    if let Err(e) = registry.register(Box::new(YamlValidator::new(
        provider,
        Some(config.max_body_bytes),
    ))) {
        emit_error("validation", &e.to_string(), None);
        return Err(EXIT_VALIDATION_ERROR);
    }
    Ok(registry)
}

fn load_rules_yaml(cli: &Cli, config: &ProviderConfig) -> Result<String, u8> {
    if let Some(dir) = &cli.rules_dir {
        let path = dir.join(format!("{}.yaml", config.name));
        if path.exists() {
            return std::fs::read_to_string(&path).map_err(|e| {
                emit_error("validation", &format!("rules read {path:?}: {e}"), None);
                EXIT_VALIDATION_ERROR
            });
        }
    } else {
        let default = crate::credentials::default_path()
            .parent()
            .map(|p| p.join("rules").join(format!("{}.yaml", config.name)));
        if let Some(path) = default {
            if path.exists() {
                return std::fs::read_to_string(&path).map_err(|e| {
                    emit_error("validation", &format!("rules read {path:?}: {e}"), None);
                    EXIT_VALIDATION_ERROR
                });
            }
        }
    }
    Ok(config.bundled_rules.to_string())
}

fn log_decision(
    cli: &Cli,
    config: &ProviderConfig,
    request: &HttpRequest,
    outcome: &ValidationOutcome,
    upstream_status: Option<u16>,
    latency_ms: Option<u128>,
) {
    let path = cli
        .log_path
        .clone()
        .unwrap_or_else(crate::log::default_path);
    let log = DecisionLog::new(path);
    let classification = outcome
        .inspection
        .as_ref()
        .map(|i| i.classification)
        .unwrap_or(RequestClassification::Unknown);
    let record = DecisionRecord {
        ts: DecisionRecord::now_ts(),
        provider: config.name.to_string(),
        method: request.method.clone(),
        host: request.host.clone(),
        path: request.path.clone(),
        classification,
        decision_code: outcome.permission.code,
        permission_source: outcome.permission.permission_source,
        stage: stage_name(outcome),
        matched_rule_index: outcome.matched_rule_index,
        reason: outcome.permission.reason.clone(),
        upstream_status,
        latency_ms,
    };
    if let Err(e) = log.append(&record) {
        eprintln!("tpx: log write failed: {e}");
    }
}

fn stage_name(outcome: &ValidationOutcome) -> String {
    if !outcome.matched_validator {
        "tool_validator_resolution".into()
    } else if outcome.inspection.is_some() {
        "inspection".into()
    } else {
        "precondition".into()
    }
}

// ─── output formatters ─────────────────────────────────────────────────────

fn emit_json(value: &Value) {
    println!(
        "{}",
        serde_json::to_string(value).expect("Value is serializable")
    );
}

fn emit_decision(outcome: &ValidationOutcome, extra: Option<Value>) {
    let mut payload = if outcome.allowed {
        json!({
            "status": "success",
            "decision": "allow",
            "decision_code": outcome.permission.code,
            "matched_rule_index": outcome.matched_rule_index,
            "reason": outcome.permission.reason,
        })
    } else {
        decision_deny_value(&outcome.permission, outcome.matched_rule_index)
    };
    if let Some(extra) = extra {
        if let Value::Object(map) = &mut payload {
            if let Value::Object(extras) = extra {
                for (k, v) in extras {
                    map.insert(k, v);
                }
            }
        }
    }
    emit_json(&payload);
}

fn decision_deny_value(d: &ToolPermissionDecision, matched_rule_index: Option<usize>) -> Value {
    json!({
        "status": "error",
        "error_type": "policy_deny",
        "decision_code": d.code,
        "permission_source": d.permission_source,
        "message": d.reason,
        "matched_rule_index": matched_rule_index,
    })
}

fn emit_error(error_type: &str, message: &str, extra: Option<Value>) {
    let mut payload = json!({
        "status": "error",
        "error_type": error_type,
        "message": message,
    });
    if let Some(extra) = extra {
        if let (Value::Object(map), Value::Object(extras)) = (&mut payload, extra) {
            for (k, v) in extras {
                map.insert(k, v);
            }
        }
    }
    emit_json(&payload);
}

fn emit_runtime_error(e: &RuntimeError) {
    let payload = match e {
        RuntimeError::BodyTooLarge { limit } => json!({
            "status": "error",
            "error_type": "upstream_response_too_large",
            "limit_bytes": limit,
            "message": e.to_string(),
        }),
        _ => json!({
            "status": "error",
            "error_type": "http_error",
            "message": e.to_string(),
        }),
    };
    emit_json(&payload);
}

fn emit_response(response: &ProviderResponse) {
    let body = response
        .body_json
        .clone()
        .unwrap_or_else(|| Value::String(response.body_text.clone()));
    emit_json(&json!({
        "status": "success",
        "upstream_status": response.status,
        "latency_ms": response.latency_ms,
        "data": body,
    }));
}
