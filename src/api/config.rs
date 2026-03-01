use axum::http::StatusCode;
use std::path::Path;

use super::types::{make_error, ApiError};

pub(crate) struct VaultConfig {
    pub public_key: String,
    pub allow_subfolders: bool,
}

/// Loads inbox configuration from .inbox-age.config.
pub(crate) async fn read_vault_config(vault_dir: &Path) -> Result<VaultConfig, ApiError> {
    let config_path = vault_dir.join(".inbox-age.config");
    let content = tokio::fs::read_to_string(&config_path)
        .await
        .map_err(|_| make_error(StatusCode::NOT_FOUND, "Vault config missing"))?;

    let mut public_key = String::new();
    let mut allow_subfolders = false;

    for line in content.lines() {
        if line.starts_with("public-key: ") {
            public_key = line.trim_start_matches("public-key: ").to_string();
        } else if line.starts_with("allow-subfolders: true") {
            allow_subfolders = true;
        }
    }

    if public_key.is_empty() {
        return Err(make_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Invalid config",
        ));
    }

    Ok(VaultConfig {
        public_key,
        allow_subfolders,
    })
}

/// Writes inbox configuration to disk.
pub(crate) async fn write_vault_config(
    vault_dir: &Path,
    inbox_name: &str,
    public_key: &str,
    allow_subfolders: bool,
) -> Result<(), ApiError> {
    let config_path = vault_dir.join(".inbox-age.config");
    let allow_subfolders_str = if allow_subfolders { "true" } else { "false" };
    let config_content = format!(
        "inbox-name: {}\npublic-key: {}\nallow-subfolders: {}\n",
        inbox_name, public_key, allow_subfolders_str
    );

    tokio::fs::write(config_path, config_content)
        .await
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(())
}