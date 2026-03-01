use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use tokio::time::{Duration, Instant};

use crate::crypto::derive_keys;

use super::{
    config::read_vault_config,
    types::{make_error, ApiError, AppState, GenericRes, UnlockReq, UnlockedVault},
    validation::is_valid_name,
};

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
    let keys = derive_keys(&payload.password, &name)
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if keys.recipient.to_string() != config.public_key {
        return Err(make_error(StatusCode::UNAUTHORIZED, "Invalid password"));
    }

    let mut vaults = state.unlocked_vaults.write().await;
    vaults.insert(
        name.clone(),
        UnlockedVault {
            identity: keys.identity,
            expires_at: Instant::now() + Duration::from_secs(3600),
        },
    );

    Ok(Json(GenericRes {
        message: format!("Vault {} unlocked for 1 hour", name),
    }))
}