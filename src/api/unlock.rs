use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use tokio::time::Duration;
use crate::inbox_core::{InboxCoreError, unlock_vault};

use super::{
    config::read_vault_config,
    types::{make_error, ApiError, AppState, GenericRes, UnlockReq, permission_denied},
    validation::is_valid_name,
};

fn map_core_error(err: InboxCoreError) -> ApiError {
    match err {
        InboxCoreError::InvalidName => make_error(StatusCode::BAD_REQUEST, "Invalid vault name"),
        InboxCoreError::VaultNotFound => make_error(StatusCode::NOT_FOUND, "Vault not found"),
        InboxCoreError::InvalidPassword => make_error(StatusCode::UNAUTHORIZED, "Invalid password"),
        InboxCoreError::Io(msg)
        | InboxCoreError::Crypto(msg)
        | InboxCoreError::Serialize(msg) => make_error(StatusCode::INTERNAL_SERVER_ERROR, msg),
        other => make_error(StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
    }
}

/// Unlocks a vault for one hour when the password matches.
pub(crate) async fn unlock(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(payload): Json<UnlockReq>,
) -> Result<Json<GenericRes>, ApiError> {
    if !is_valid_name(&name) {
        return Err(make_error(StatusCode::BAD_REQUEST, "Invalid vault name"));
    }

    let vault_dir = state.vaults_dir.join(&name);
    let config = read_vault_config(&vault_dir).await?;

    // Check lock_unlock permission
    if !config.permissions.allow_lock_unlock {
        return Err(permission_denied());
    }

    unlock_vault(
        &state.unlocked_vaults,
        &state.vaults_dir,
        &name,
        payload.password,
        Duration::from_secs(3600),
    )
    .await
    .map_err(map_core_error)?;

    Ok(Json(GenericRes {
        message: format!("Vault {} unlocked for 1 hour", name),
    }))
}