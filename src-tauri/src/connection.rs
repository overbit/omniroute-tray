//! Persisted connection mode and remote endpoint. The API key never goes to the UI.
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use serde::{Deserialize, Serialize};

use crate::omniauth::Credentials;

pub const DEFAULT_SERVER_URL: &str = "http://127.0.0.1:20128";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectionMode {
    #[default]
    Managed,
    TrayOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ConnectionConfig {
    pub mode: ConnectionMode,
    pub server_url: String,
    pub api_key: Option<String>,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            mode: ConnectionMode::Managed,
            server_url: DEFAULT_SERVER_URL.into(),
            api_key: None,
        }
    }
}

/// Settings returned through IPC: never serialize the stored API key.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionSettings {
    pub mode: ConnectionMode,
    pub server_url: String,
    pub key_configured: bool,
}

impl ConnectionConfig {
    pub fn visible(&self) -> ConnectionSettings {
        ConnectionSettings {
            mode: self.mode,
            server_url: self.server_url.clone(),
            key_configured: self.api_key.is_some(),
        }
    }

    /// A missing key field preserves the old key; an empty string explicitly clears it.
    pub fn updated(
        &self,
        mode: ConnectionMode,
        server_url: &str,
        api_key: Option<String>,
    ) -> Result<Self, String> {
        let server_url = validate_url(server_url)?;
        let api_key = match api_key {
            None => self.api_key.clone(),
            Some(key) if key.trim().is_empty() => None,
            Some(key) => Some(key.trim().to_string()),
        };
        Ok(Self {
            mode,
            server_url,
            api_key,
        })
    }

    pub fn server_url_for_use(&self) -> String {
        if self.mode == ConnectionMode::Managed { DEFAULT_SERVER_URL.into() } else { self.server_url.clone() }
    }

    pub fn remote_credentials(&self) -> Credentials {
        Credentials {
            api_key: self.api_key.clone(),
            cli_token: None, // The machine-bound token only works on loopback.
        }
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let raw = match fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(format!("Could not read connection settings: {e}")),
        };
        let mut config: Self =
            serde_json::from_str(&raw).map_err(|e| format!("Invalid connection settings: {e}"))?;
        config.server_url = validate_url(&config.server_url)?;
        Ok(config)
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let parent = path
            .parent()
            .ok_or("Connection settings path has no parent")?;
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        let temp = path.with_extension("json.tmp");
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temp).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
        let contents = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        file.write_all(&contents).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        fs::rename(&temp, path).map_err(|e| e.to_string())
    }
}

/// Accept a server root (including a reverse-proxy path), but never allow a URL
/// that would leak credentials in userinfo, a query string, or a fragment.
pub fn validate_url(raw: &str) -> Result<String, String> {
    let url = url::Url::parse(raw.trim())
        .map_err(|_| "Enter a valid http:// or https:// server URL".to_string())?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("Use an HTTP(S) server URL without credentials, query or fragment".into());
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_managing_the_local_server() {
        let config = ConnectionConfig::default();
        assert_eq!(config.mode, ConnectionMode::Managed);
        assert_eq!(config.server_url, DEFAULT_SERVER_URL);
        assert!(config.api_key.is_none());
    }

    #[test]
    fn validates_and_normalises_remote_urls() {
        assert_eq!(
            validate_url(" https://example.org/router/ ").unwrap(),
            "https://example.org/router"
        );
        assert_eq!(
            validate_url("http://localhost:20128").unwrap(),
            "http://localhost:20128"
        );
        for invalid in [
            "",
            "localhost:20128",
            "ftp://host",
            "https://user:pass@host",
            "https://host/?key=secret",
            "https://host/#secret",
        ] {
            assert!(validate_url(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn remote_key_is_private_and_can_be_kept_replaced_or_cleared() {
        let config = ConnectionConfig::default()
            .updated(
                ConnectionMode::TrayOnly,
                "https://omniroute.example",
                Some("secret".into()),
            )
            .unwrap();
        let visible = serde_json::to_string(&config.visible()).unwrap();
        assert!(!visible.contains("secret"));
        assert!(visible.contains("key_configured"));
        assert_eq!(config.remote_credentials().cli_token, None);
        assert_eq!(config.remote_credentials().api_key.as_deref(), Some("secret"));
        let keep = config
            .updated(ConnectionMode::TrayOnly, &config.server_url, None)
            .unwrap();
        assert_eq!(keep.api_key.as_deref(), Some("secret"));
        let replace = keep
            .updated(
                ConnectionMode::TrayOnly,
                &config.server_url,
                Some("changed".into()),
            )
            .unwrap();
        assert_eq!(replace.api_key.as_deref(), Some("changed"));
        let clear = replace
            .updated(
                ConnectionMode::TrayOnly,
                &config.server_url,
                Some(String::new()),
            )
            .unwrap();
        assert!(clear.api_key.is_none());
    }

    #[test]
    fn saves_and_loads_the_mode_url_and_key() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state/connection.json");
        assert_eq!(ConnectionConfig::load(&path).unwrap().mode, ConnectionMode::Managed);
        let config = ConnectionConfig::default()
            .updated(
                ConnectionMode::TrayOnly,
                "https://router.example/prefix/",
                Some("key".into()),
            )
            .unwrap();
        config.save(&path).unwrap();
        assert_eq!(ConnectionConfig::load(&path).unwrap(), config);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn corrupt_settings_do_not_silently_enable_the_server() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("connection.json");
        fs::write(&path, "{not json").unwrap();
        assert!(ConnectionConfig::load(&path).is_err());
    }
}
