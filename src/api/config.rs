use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use std::path::Path;

use super::types::{make_error, ApiError};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultPermissions {
    pub allow_upload: bool,
    pub allow_download: bool,
    pub allow_list: bool,
    pub allow_delete: bool,
    pub allow_metadata: bool,
    pub allow_lock_unlock: bool,
}

impl Default for VaultPermissions {
    fn default() -> Self {
        VaultPermissions {
            allow_upload: true,
            allow_download: true,
            allow_list: true,
            allow_delete: true,
            allow_metadata: true,
            allow_lock_unlock: true,
        }
    }
}

pub(crate) struct VaultConfig {
    pub public_key: String,
    pub allow_subfolders: bool,
    pub permissions: VaultPermissions,
}

/// Loads inbox configuration from .inbox-age.config.
pub(crate) async fn read_vault_config(vault_dir: &Path) -> Result<VaultConfig, ApiError> {
    let config_path = vault_dir.join(".inbox-age.config");
    let content = tokio::fs::read_to_string(&config_path)
        .await
        .map_err(|_| make_error(StatusCode::NOT_FOUND, "Vault config missing"))?;

    let mut public_key = String::new();
    let mut allow_subfolders = false;
    let mut permissions = VaultPermissions::default();

    for line in content.lines() {
        if line.starts_with("public-key: ") {
            public_key = line.trim_start_matches("public-key: ").to_string();
        } else if line.starts_with("allow-subfolders: ") {
            allow_subfolders = line.contains("true");
        } else if line.starts_with("permissions: ") {
            let perm_json = line.trim_start_matches("permissions: ");
            if let Ok(perms) = serde_json::from_str::<VaultPermissions>(perm_json) {
                permissions = perms;
            }
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
        permissions,
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
    let permissions = VaultPermissions::default();
    let permissions_json = serde_json::to_string(&permissions)
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let config_content = format!(
        "inbox-name: {}\npublic-key: {}\nallow-subfolders: {}\npermissions: {}\n",
        inbox_name, public_key, allow_subfolders_str, permissions_json
    );

    tokio::fs::write(config_path, config_content)
        .await
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(())
}