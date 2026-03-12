use axum::{extract::State, http::StatusCode, Json};

use super::{
    config::read_vault_config,
    types::{make_error, ApiError, AppState},
    validation::is_valid_name,
};

#[derive(serde::Serialize)]
pub struct VaultConfigRes {
    pub allow_subfolders: bool,
    pub permissions: serde_json::Value,
}

/// Gets vault configuration (public settings only).
pub(crate) async fn get_vault_config(
    State(state): State<AppState>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Result<Json<VaultConfigRes>, ApiError> {
    if !is_valid_name(&name) {
        return Err(make_error(StatusCode::BAD_REQUEST, "Invalid vault name"));
    }

    let vault_dir = state.vaults_dir.join(&name);
    if !vault_dir.exists() {
        return Err(make_error(StatusCode::NOT_FOUND, "Vault not found"));
    }

    let config = read_vault_config(&vault_dir).await?;

    Ok(Json(VaultConfigRes {
        allow_subfolders: config.allow_subfolders,
        permissions: serde_json::to_value(&config.permissions)
            .unwrap_or(serde_json::json!({})),
    }))
}

