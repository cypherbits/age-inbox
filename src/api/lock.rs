use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};

use super::{
    config::read_vault_config,
    types::{make_error, ApiError, AppState, GenericRes, permission_denied},
    validation::is_valid_name,
};

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

    if vaults.remove(&name).is_some() {
        Ok(Json(GenericRes {
            message: format!("Vault {} locked", name),
        }))
    } else {
        Err(make_error(StatusCode::NOT_FOUND, "Vault not unlocked"))
    }
}