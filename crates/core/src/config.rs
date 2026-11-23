use crate::error::CoreError;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use url::Url;

pub const DEFAULT_API_BASE_URL: &str = "http://127.0.0.1:8080";
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 60;
pub const DEFAULT_STREAM_TIMEOUT_SECS: u64 = 300;
pub const DEFAULT_MAX_FILE_BYTES: usize = 256 * 1024;
pub const DEFAULT_MAX_SEARCH_RESULTS: usize = 200;
pub const DEFAULT_COMMAND_TIMEOUT_SECS: u64 = 120;
pub const DEFAULT_HEARTBEAT_INTERVAL_SECS: u64 = 20;
pub const DEFAULT_LEASE_POLL_INTERVAL_SECS: u64 = 3;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct AgentConfig {
    pub api_base_url: String,
    pub default_model_id: Option<String>,
    pub request_timeout_secs: u64,
    pub stream_timeout_secs: u64,
    pub max_file_bytes: usize,
    pub max_search_results: usize,
    pub command_timeout_secs: u64,
    pub runner: RunnerConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RunnerConfig {
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub workspace_root: Option<PathBuf>,
    pub heartbeat_interval_secs: u64,
    pub lease_poll_interval_secs: u64,
    pub max_backoff_secs: u64,
}

impl Default for RunnerConfig {
    fn default() -> Self {
        Self {
            device_id: None,
            device_name: None,
            workspace_root: None,
            heartbeat_interval_secs: DEFAULT_HEARTBEAT_INTERVAL_SECS,
            lease_poll_interval_secs: DEFAULT_LEASE_POLL_INTERVAL_SECS,
            max_backoff_secs: 60,
        }
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            api_base_url: DEFAULT_API_BASE_URL.to_owned(),
            default_model_id: None,
            request_timeout_secs: DEFAULT_REQUEST_TIMEOUT_SECS,
            stream_timeout_secs: DEFAULT_STREAM_TIMEOUT_SECS,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_search_results: DEFAULT_MAX_SEARCH_RESULTS,
            command_timeout_secs: DEFAULT_COMMAND_TIMEOUT_SECS,
            runner: RunnerConfig::default(),
        }
    }
}

impl AgentConfig {
    pub fn default_config_dir() -> Result<PathBuf, CoreError> {
        let home = dirs::home_dir()
            .ok_or_else(|| CoreError::InvalidConfig("diretorio home indisponivel".to_owned()))?;
        Ok(home.join(".creatingj"))
    }

    pub fn default_config_path() -> Result<PathBuf, CoreError> {
        Ok(Self::default_config_dir()?.join("config.toml"))
    }

    pub fn load_or_default(path: &Path) -> Result<Self, CoreError> {
        let mut cfg = if path.exists() {
            let raw = fs::read_to_string(path)?;
            toml::from_str::<Self>(&raw)
                .map_err(|e| CoreError::InvalidConfig(format!("config.toml invalido: {e}")))?
        } else {
            Self::default()
        };

        if let Ok(env_url) = std::env::var("CREATINGJ_API_URL")
            && !env_url.trim().is_empty()
        {
            env_url.trim().clone_into(&mut cfg.api_base_url);
        }
        if let Ok(env_model) = std::env::var("CREATINGJ_MODEL_ID")
            && !env_model.trim().is_empty()
        {
            cfg.default_model_id = Some(env_model.trim().to_owned());
        }

        cfg.validate()?;
        Ok(cfg)
    }

    pub fn save(&self, path: &Path) -> Result<(), CoreError> {
        self.validate()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let encoded = toml::to_string_pretty(self)
            .map_err(|e| CoreError::InvalidConfig(format!("falha ao serializar config: {e}")))?;
        fs::write(path, encoded)?;
        Ok(())
    }

    pub fn validate(&self) -> Result<(), CoreError> {
        let parsed = Url::parse(&self.api_base_url)
            .map_err(|e| CoreError::InvalidConfig(format!("api_base_url invalida: {e}")))?;

        let scheme = parsed.scheme();
        let host = parsed.host_str().unwrap_or_default();
        let is_loopback = matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]");

        match scheme {
            "https" => {}
            "http" if is_loopback => {}
            "http" => {
                return Err(CoreError::InvalidConfig(
                    "HTTP sem TLS e permitido apenas para loopback local; use HTTPS para servidores remotos".to_owned(),
                ));
            }
            other => {
                return Err(CoreError::InvalidConfig(format!(
                    "esquema nao suportado em api_base_url: {other}"
                )));
            }
        }

        if self.request_timeout_secs == 0 || self.request_timeout_secs > 600 {
            return Err(CoreError::InvalidConfig(
                "request_timeout_secs deve estar entre 1 e 600".to_owned(),
            ));
        }
        if self.max_file_bytes == 0 || self.max_file_bytes > 4 * 1024 * 1024 {
            return Err(CoreError::InvalidConfig(
                "max_file_bytes deve estar entre 1 e 4 MiB".to_owned(),
            ));
        }
        if self.runner.heartbeat_interval_secs < 5 {
            return Err(CoreError::InvalidConfig(
                "heartbeat_interval_secs deve ser >= 5".to_owned(),
            ));
        }
        if self.runner.lease_poll_interval_secs == 0 {
            return Err(CoreError::InvalidConfig(
                "lease_poll_interval_secs deve ser >= 1".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn default_config_is_valid() {
        let cfg = AgentConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn rejects_plaintext_http_for_remote_host() {
        let cfg = AgentConfig {
            api_base_url: "http://api.creatingj.dev".to_owned(),
            ..AgentConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn accepts_https_for_remote_host() {
        let cfg = AgentConfig {
            api_base_url: "https://api.creatingj.dev".to_owned(),
            ..AgentConfig::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        let cfg = AgentConfig {
            api_base_url: "https://api.example.com".to_owned(),
            default_model_id: Some("glm-4.7".to_owned()),
            ..AgentConfig::default()
        };
        cfg.save(&path).expect("save");
        let loaded = AgentConfig::load_or_default(&path).expect("load");
        assert_eq!(loaded.api_base_url, "https://api.example.com");
        assert_eq!(loaded.default_model_id.as_deref(), Some("glm-4.7"));
    }
}
