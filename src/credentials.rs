//! `~/.tpx/credentials.json` loader with mode-0600 enforcement.
//!
//! Format:
//! ```json
//! {
//!   "vercel":   { "token": "..." },
//!   "langfuse": { "public_key": "pk-...", "secret_key": "sk-..." }
//! }
//! ```
//!
//! Anything other than mode `0600` is rejected. Symlinks to wider-mode files
//! count — we stat the resolved path.

use std::collections::BTreeMap;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("credentials file {0} not found")]
    NotFound(PathBuf),
    #[cfg(unix)]
    #[error("credentials file {path} must be mode 0600 (got {mode:#o})")]
    BadMode { path: PathBuf, mode: u32 },
    #[error("credentials file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("credentials file {path} is not valid JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("no credentials for provider {0}")]
    MissingProvider(String),
    #[error("provider {provider} is missing required field {field}")]
    MissingField { provider: String, field: String },
}

#[derive(Debug, Deserialize)]
struct CredentialsFile(BTreeMap<String, BTreeMap<String, String>>);

#[derive(Debug, Clone)]
pub struct CredentialStore {
    by_provider: BTreeMap<String, BTreeMap<String, String>>,
}

impl CredentialStore {
    pub fn load(path: &Path) -> Result<Self, CredentialError> {
        let metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(CredentialError::NotFound(path.to_path_buf()));
            }
            Err(e) => {
                return Err(CredentialError::Io {
                    path: path.to_path_buf(),
                    source: e,
                });
            }
        };
        // Mode-0600 enforcement is the boundary on Unix. On other platforms
        // we can't represent the same check, so we trust the user to keep
        // the file private. Spec is explicit about the unix-only target.
        #[cfg(unix)]
        {
            let mode = metadata.permissions().mode() & 0o777;
            if mode != 0o600 {
                return Err(CredentialError::BadMode {
                    path: path.to_path_buf(),
                    mode,
                });
            }
        }
        #[cfg(not(unix))]
        let _ = metadata;
        let text = fs::read_to_string(path).map_err(|e| CredentialError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        let parsed: CredentialsFile =
            serde_json::from_str(&text).map_err(|e| CredentialError::Parse {
                path: path.to_path_buf(),
                source: e,
            })?;
        Ok(Self {
            by_provider: parsed.0,
        })
    }

    pub fn for_provider(
        &self,
        provider: &str,
        required: &[&str],
    ) -> Result<&BTreeMap<String, String>, CredentialError> {
        let entry = self
            .by_provider
            .get(provider)
            .ok_or_else(|| CredentialError::MissingProvider(provider.to_string()))?;
        for field in required {
            if !entry.contains_key(*field) {
                return Err(CredentialError::MissingField {
                    provider: provider.to_string(),
                    field: (*field).to_string(),
                });
            }
        }
        Ok(entry)
    }
}

pub fn default_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"));
    home.join(".tpx").join("credentials.json")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    fn write_creds(dir: &Path, body: &str, mode: u32) -> PathBuf {
        let path = dir.join("credentials.json");
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        let mut perms = f.metadata().unwrap().permissions();
        perms.set_mode(mode);
        fs::set_permissions(&path, perms).unwrap();
        path
    }

    #[test]
    fn rejects_world_readable_credentials() {
        let dir = tempdir().unwrap();
        let path = write_creds(dir.path(), r#"{"vercel":{"token":"x"}}"#, 0o644);
        let err = CredentialStore::load(&path).unwrap_err();
        assert!(matches!(err, CredentialError::BadMode { .. }));
    }

    #[test]
    fn loads_mode_0600_file() {
        let dir = tempdir().unwrap();
        let path = write_creds(
            dir.path(),
            r#"{"vercel":{"token":"abc"},"langfuse":{"public_key":"pk","secret_key":"sk"}}"#,
            0o600,
        );
        let store = CredentialStore::load(&path).unwrap();
        let v = store.for_provider("vercel", &["token"]).unwrap();
        assert_eq!(v.get("token").map(String::as_str), Some("abc"));
        let l = store
            .for_provider("langfuse", &["public_key", "secret_key"])
            .unwrap();
        assert_eq!(l.get("secret_key").map(String::as_str), Some("sk"));
    }

    #[test]
    fn missing_required_field_rejected() {
        let dir = tempdir().unwrap();
        let path = write_creds(dir.path(), r#"{"langfuse":{"public_key":"pk"}}"#, 0o600);
        let store = CredentialStore::load(&path).unwrap();
        let err = store
            .for_provider("langfuse", &["public_key", "secret_key"])
            .unwrap_err();
        assert!(matches!(err, CredentialError::MissingField { .. }));
    }

    #[test]
    fn missing_file_reports_not_found() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("missing.json");
        let err = CredentialStore::load(&path).unwrap_err();
        assert!(matches!(err, CredentialError::NotFound(_)));
    }
}
