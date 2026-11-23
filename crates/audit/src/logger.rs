use crate::redactor::redact_secrets;
use chrono::{DateTime, Utc};
use creatingj_core::CoreError;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,
    pub action: String,
    pub outcome: String,
    pub tool: Option<String>,
    pub target: Option<String>,
    pub detail: String,
}

impl AuditEvent {
    pub fn new(
        action: impl Into<String>,
        outcome: impl Into<String>,
        tool: Option<String>,
        target: Option<String>,
        detail: impl AsRef<str>,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            action: action.into(),
            outcome: outcome.into(),
            tool,
            target: target.map(|t| redact_secrets(&t)),
            detail: redact_secrets(detail.as_ref()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuditTrail {
    path: PathBuf,
}

impl AuditTrail {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn default_path() -> Result<PathBuf, CoreError> {
        Ok(creatingj_core::AgentConfig::default_config_dir()?.join("audit.jsonl"))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn record(&self, event: &AuditEvent) -> Result<(), CoreError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut sanitized = event.clone();
        sanitized.detail = redact_secrets(&sanitized.detail);
        sanitized.target = sanitized.target.map(|t| redact_secrets(&t));
        let line = serde_json::to_string(&sanitized)
            .map_err(|e| CoreError::Validation(format!("falha ao serializar auditoria: {e}")))?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{line}")?;
        Ok(())
    }
}

pub fn init_tracing(json: bool, verbose: bool) {
    let default_level = if verbose { "debug" } else { "info" };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));

    if json {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .with_writer(std::io::stderr)
            .try_init();
    } else {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .without_time()
            .try_init();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn audit_trail_redacts_secrets_before_writing() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let trail = AuditTrail::new(path.clone());
        let event = AuditEvent::new(
            "runner.auth",
            "ok",
            None,
            None,
            "connected with Bearer very_secret_token_999999 and api_key=sk-1234567890abcdef1234",
        );
        trail.record(&event).expect("record");
        let content = fs::read_to_string(&path).expect("read");
        assert!(!content.contains("very_secret_token_999999"));
        assert!(!content.contains("sk-1234567890abcdef1234"));
        assert!(content.contains("[REDACTED]"));
    }
}
