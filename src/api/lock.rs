use crate::inbox_core::{lock_vault, InboxCoreError};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};

use super::{
    config::read_vault_config,
    types::{make_error, permission_denied, ApiError, AppState, GenericRes},
    validation::is_valid_name,
};

fn map_core_error(err: InboxCoreError) -> ApiError {
    match err {
        InboxCoreError::InvalidName => make_error(StatusCode::BAD_REQUEST, "Invalid vault name"),
        InboxCoreError::VaultNotFound => make_error(StatusCode::NOT_FOUND, "Vault not found"),
        InboxCoreError::Io(msg) | InboxCoreError::Crypto(msg) | InboxCoreError::Serialize(msg) => {
            make_error(StatusCode::INTERNAL_SERVER_ERROR, msg)
        }
        other => make_error(StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
    }
}

/// Removes an unlocked vault from memory.
pub(crate) async fn lock(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<GenericRes>, ApiError> {
    if !is_valid_name(&name) {
        return Err(make_error(StatusCode::BAD_REQUEST, "Invalid vault name"));
    }

    let vault_dir = state.vaults_dir.join(&name);
    if !vault_dir.exists() {
        return Err(make_error(StatusCode::NOT_FOUND, "Vault not found"));
    }

    let config = read_vault_config(&vault_dir).await?;

    // Check lock_unlock permission
    if !config.permissions.allow_lock_unlock {
        return Err(permission_denied());
    }

    let mut vaults = state.unlocked_vaults.write().await;
    let was_locked = lock_vault(&mut *vaults, &state.vaults_dir, &name)
        .await
        .map_err(map_core_error)?;

    if was_locked {
        Ok(Json(GenericRes {
            message: format!("Vault {} locked", name),
        }))
    } else {
        Err(make_error(StatusCode::NOT_FOUND, "Vault not unlocked"))
    }
}
