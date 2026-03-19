use crate::inbox_core::{unlock_vault, InboxCoreError};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use std::time::Duration;

use super::{
    config::read_vault_config,
    types::{make_error, permission_denied, ApiError, AppState, GenericRes, UnlockReq},
    validation::is_valid_name,
};

fn map_core_error(err: InboxCoreError) -> ApiError {
    match err {
        InboxCoreError::InvalidName => make_error(StatusCode::BAD_REQUEST, "Invalid vault name"),
        InboxCoreError::VaultNotFound => make_error(StatusCode::NOT_FOUND, "Vault not found"),
        InboxCoreError::InvalidPassword => make_error(StatusCode::UNAUTHORIZED, "Invalid password"),
        InboxCoreError::Io(msg) | InboxCoreError::Crypto(msg) | InboxCoreError::Serialize(msg) => {
            make_error(StatusCode::INTERNAL_SERVER_ERROR, msg)
        }
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

    let vaults_dir = state.vaults_dir.clone();
    let name_clone = name.clone();
    
    let mut vaults = state.unlocked_vaults.write_owned().await;
    let (_vaults, res) = tokio::task::spawn_blocking(move || {
        let handle = tokio::runtime::Handle::current();
        let res = handle.block_on(async {
            unlock_vault(
                &mut *vaults,
                &vaults_dir,
                &name_clone,
                payload.password,
                Duration::from_secs(3600),
            )
            .await
        });
        (vaults, res)
    })
    .await
    .unwrap();

    res.map_err(map_core_error)?;

    Ok(Json(GenericRes {
        message: format!("Vault {} unlocked for 1 hour", name),
    }))
}
