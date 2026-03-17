use crate::inbox_core::{create_vault, InboxCoreError, VaultPermissions};
use axum::{extract::State, http::StatusCode, Json};

use super::{
    types::{make_error, ApiError, AppState, CreateInboxReq, CreateInboxRes},
    validation::is_valid_name,
};

fn build_permissions(payload: &CreateInboxReq) -> VaultPermissions {
    let mut permissions = VaultPermissions::default();

    if let Some(custom) = &payload.permissions {
        if let Some(value) = custom.allow_subfolders {
            permissions.allow_subfolders = value;
        }
        if let Some(value) = custom.allow_upload {
            permissions.allow_upload = value;
        }
        if let Some(value) = custom.allow_download {
            permissions.allow_download = value;
        }
        if let Some(value) = custom.allow_list {
            permissions.allow_list = value;
        }
        if let Some(value) = custom.allow_delete {
            permissions.allow_delete = value;
        }
        if let Some(value) = custom.allow_metadata {
            permissions.allow_metadata = value;
        }
        if let Some(value) = custom.allow_lock_unlock {
            permissions.allow_lock_unlock = value;
        }
    }

    permissions
}

fn map_core_error(err: InboxCoreError) -> ApiError {
    match err {
        InboxCoreError::InvalidName => make_error(StatusCode::BAD_REQUEST, "Invalid vault name"),
        InboxCoreError::VaultExists => make_error(StatusCode::CONFLICT, "Vault already exists"),
        InboxCoreError::Io(msg) | InboxCoreError::Crypto(msg) | InboxCoreError::Serialize(msg) => {
            make_error(StatusCode::INTERNAL_SERVER_ERROR, msg)
        }
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

    let permissions = build_permissions(&payload);

    let created = create_vault(
        &state.vaults_dir,
        &payload.name,
        payload.password,
        permissions,
    )
    .await
    .map_err(map_core_error)?;

    Ok(Json(CreateInboxRes {
        success: true,
        public_key: created.public_key,
    }))
}
