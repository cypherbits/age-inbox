use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};

use super::{
    config::read_vault_config,
    list_files::walk_dir,
    types::{make_error, ApiError, AppState, RawListedFile, permission_denied},
    validation::is_valid_name,
};

/// Lists stored encrypted files without requiring an unlocked vault.
pub(crate) async fn list_files_raw(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<Vec<RawListedFile>>, ApiError> {
    if !is_valid_name(&name) {
        return Err(make_error(StatusCode::BAD_REQUEST, "Invalid vault name"));
    }

    let vault_dir = state.vaults_dir.join(&name);
    if !vault_dir.exists() {
        return Err(make_error(StatusCode::NOT_FOUND, "Vault not found"));
    }

    // Check list permission
    let config = read_vault_config(&vault_dir).await?;
    if !config.permissions.allow_list {
        return Err(permission_denied());
    }

    let files = walk_dir(vault_dir)
        .await
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let mut listed = Vec::new();
    for relative_path in files {
        if !relative_path.ends_with(".age") || relative_path.ends_with(".meta.age") {
            continue;
        }

        let full_path = state.vaults_dir.join(&name).join(&relative_path);
        let size = tokio::fs::metadata(&full_path)
            .await
            .map(|m| m.len())
            .unwrap_or(0);
        listed.push(RawListedFile {
            path: relative_path,
            size,
        });
    }

    Ok(Json(listed))
}
