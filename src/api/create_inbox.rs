use axum::{extract::State, http::StatusCode, Json};

use crate::crypto::derive_keys;

use super::{
    config::write_vault_config,
    types::{make_error, ApiError, AppState, CreateInboxReq, CreateInboxRes},
    validation::is_valid_name,
};

/// Creates a new inbox vault and stores its public configuration.
pub(crate) async fn create_inbox(
    State(state): State<AppState>,
    Json(payload): Json<CreateInboxReq>,
) -> Result<Json<CreateInboxRes>, ApiError> {
    if !is_valid_name(&payload.name) {
        return Err(make_error(StatusCode::BAD_REQUEST, "Invalid vault name"));
    }

    let vault_dir = state.vaults_dir.join(&payload.name);
    if vault_dir.exists() {
        return Err(make_error(StatusCode::CONFLICT, "Vault already exists"));
    }

    let keys = derive_keys(&payload.password, &payload.name)
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    tokio::fs::create_dir_all(&vault_dir)
        .await
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let public_key = keys.recipient.to_string();
    write_vault_config(
        &vault_dir,
        &payload.name,
        &public_key,
        payload.allow_subfolders.unwrap_or(false),
    )
    .await?;

    Ok(Json(CreateInboxRes {
        success: true,
        public_key,
    }))
}