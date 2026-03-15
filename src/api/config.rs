use axum::http::StatusCode;
use std::path::Path;

use crate::inbox_core::{InboxCoreError, VaultConfig, read_vault_config_file};

use super::types::{make_error, ApiError};

fn map_core_err(err: InboxCoreError) -> ApiError {
    match err {
        InboxCoreError::VaultConfigMissing => {
            make_error(StatusCode::NOT_FOUND, "Vault config missing")
        }
        InboxCoreError::InvalidConfig => make_error(StatusCode::INTERNAL_SERVER_ERROR, "Invalid config"),
        InboxCoreError::Io(msg)
        | InboxCoreError::Crypto(msg)
        | InboxCoreError::Serialize(msg) => make_error(StatusCode::INTERNAL_SERVER_ERROR, msg),
        other => make_error(StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
    }
}

/// Loads inbox configuration from .inbox-age.config.
pub(crate) async fn read_vault_config(vault_dir: &Path) -> Result<VaultConfig, ApiError> {
    read_vault_config_file(vault_dir).await.map_err(map_core_err)
}
