use axum::{extract::State, http::StatusCode, Json};
use crate::inbox_core::{InboxCoreError, create_vault};

use super::{
    types::{make_error, ApiError, AppState, CreateInboxReq, CreateInboxRes},
    validation::is_valid_name,
};

fn map_core_error(err: InboxCoreError) -> ApiError {
    match err {
        InboxCoreError::InvalidName => make_error(StatusCode::BAD_REQUEST, "Invalid vault name"),
        InboxCoreError::VaultExists => make_error(StatusCode::CONFLICT, "Vault already exists"),
        InboxCoreError::Io(msg)
        | InboxCoreError::Crypto(msg)
        | InboxCoreError::Serialize(msg) => make_error(StatusCode::INTERNAL_SERVER_ERROR, msg),
        other => make_error(StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
    }
}

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

    let created = create_vault(
        &state.vaults_dir,
        &payload.name,
        payload.password,
        payload.allow_subfolders.unwrap_or(false),
    )
    .await
    .map_err(map_core_error)?;

    Ok(Json(CreateInboxRes {
        success: true,
        public_key: created.public_key,
    }))
}