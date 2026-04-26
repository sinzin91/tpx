//! JSONL decision log at `~/.tpx/log/decisions.jsonl`.
//!
//! Per spec §9: one decision per line, no body content / header values /
//! query values. Rotates at 10 MiB to a single `.1` rollover.

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::contracts::{DecisionCode, PermissionSource, RequestClassification};

const ROTATION_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum LogError {
    #[error("log io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionRecord {
    pub ts: String,
    pub provider: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub classification: RequestClassification,
    pub decision_code: DecisionCode,
    pub permission_source: PermissionSource,
    pub stage: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_rule_index: Option<usize>,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u128>,
}

impl DecisionRecord {
    pub fn now_ts() -> String {
        Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
    }
}

pub struct DecisionLog {
    path: PathBuf,
}

impl DecisionLog {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn append(&self, record: &DecisionRecord) -> Result<(), LogError> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| LogError::Io {
                    path: parent.to_path_buf(),
                    source: e,
                })?;
            }
        }
        self.maybe_rotate()?;
        let line = serde_json::to_string(record).expect("DecisionRecord is always serializable");
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| LogError::Io {
                path: self.path.clone(),
                source: e,
            })?;
        writeln!(file, "{line}").map_err(|e| LogError::Io {
            path: self.path.clone(),
            source: e,
        })?;
        Ok(())
    }

    fn maybe_rotate(&self) -> Result<(), LogError> {
        let metadata = match fs::metadata(&self.path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(LogError::Io {
                    path: self.path.clone(),
                    source: e,
                });
            }
        };
        if metadata.len() < ROTATION_BYTES {
            return Ok(());
        }
        let rolled = self.rolled_path();
        // Best-effort: remove a stale .1 then rename current to .1.
        let _ = fs::remove_file(&rolled);
        fs::rename(&self.path, &rolled).map_err(|e| LogError::Io {
            path: self.path.clone(),
            source: e,
        })?;
        Ok(())
    }

    fn rolled_path(&self) -> PathBuf {
        let mut name = self.path.file_name().unwrap_or_default().to_os_string();
        name.push(".1");
        self.path.with_file_name(name)
    }

    /// Read the last `n` lines for `--tail-log`. Skips silently if the log
    /// doesn't exist yet.
    pub fn tail(&self, n: usize) -> Result<Vec<String>, LogError> {
        let file = match File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(LogError::Io {
                    path: self.path.clone(),
                    source: e,
                });
            }
        };
        let reader = BufReader::new(file);
        // VecDeque + pop_front gives an O(1) sliding window; the previous
        // Vec::remove(0) was O(n) per insert past the cap. push then trim
        // (rather than trim-then-push) preserves the n=0 case correctly.
        let mut window: VecDeque<String> = VecDeque::with_capacity(n);
        for line in reader.lines() {
            let line = line.map_err(|e| LogError::Io {
                path: self.path.clone(),
                source: e,
            })?;
            window.push_back(line);
            while window.len() > n {
                window.pop_front();
            }
        }
        Ok(window.into_iter().collect())
    }
}

pub fn default_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"));
    home.join(".tpx").join("log").join("decisions.jsonl")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn record() -> DecisionRecord {
        DecisionRecord {
            ts: "2026-04-26T19:14:02Z".to_string(),
            provider: "vercel".to_string(),
            method: "GET".to_string(),
            host: "api.vercel.com".to_string(),
            path: "/v9/projects".to_string(),
            classification: RequestClassification::Read,
            decision_code: DecisionCode::Allow,
            permission_source: PermissionSource::RuleEngine,
            stage: "inspection".to_string(),
            matched_rule_index: Some(0),
            reason: "List and inspect projects.".to_string(),
            upstream_status: Some(200),
            latency_ms: Some(123),
        }
    }

    #[test]
    fn append_then_tail_round_trips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nested").join("decisions.jsonl");
        let log = DecisionLog::new(path);
        log.append(&record()).unwrap();
        let mut second = record();
        second.matched_rule_index = Some(1);
        log.append(&second).unwrap();

        let tail = log.tail(10).unwrap();
        assert_eq!(tail.len(), 2);
        let parsed: DecisionRecord = serde_json::from_str(&tail[0]).unwrap();
        assert_eq!(parsed.matched_rule_index, Some(0));
    }

    #[test]
    fn rotation_at_threshold() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("decisions.jsonl");
        // Pre-seed the log past the rotation threshold.
        fs::write(&path, vec![b'a'; (ROTATION_BYTES + 1) as usize]).unwrap();
        let log = DecisionLog::new(path.clone());
        log.append(&record()).unwrap();
        assert!(path.exists());
        let rolled = path.with_file_name("decisions.jsonl.1");
        assert!(rolled.exists(), "old log should be rotated to .1");
    }

    #[test]
    fn tail_on_missing_log_is_empty() {
        let dir = tempdir().unwrap();
        let log = DecisionLog::new(dir.path().join("nope.jsonl"));
        assert!(log.tail(5).unwrap().is_empty());
    }
}
