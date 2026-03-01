use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use std::path::PathBuf;
use tokio::time::Instant;

use super::{
    types::{make_error, ApiError, AppState},
    validation::is_valid_name,
};

/// Lists stored encrypted files for an unlocked vault.
pub(crate) async fn list_files(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<Vec<String>>, ApiError> {
    if !is_valid_name(&name) {
        return Err(make_error(StatusCode::BAD_REQUEST, "Invalid vault name"));
    }

    let vaults = state.unlocked_vaults.read().await;
    if let Some(vault) = vaults.get(&name) {
        if Instant::now() > vault.expires_at {
            return Err(make_error(StatusCode::UNAUTHORIZED, "Vault unlock expired"));
        }
    } else {
        return Err(make_error(StatusCode::UNAUTHORIZED, "Vault is locked"));
    }

    let vault_dir = state.vaults_dir.join(&name);
    let files = walk_dir(vault_dir)
        .await
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(files))
}

async fn walk_dir(root: PathBuf) -> Result<Vec<String>, String> {
    let mut all_files = Vec::new();
    let mut stack = vec![(root, String::new())];

    while let Some((dir, prefix)) = stack.pop() {
        let mut entries = tokio::fs::read_dir(&dir).await.map_err(|e| e.to_string())?;

        while let Some(entry) = entries.next_entry().await.map_err(|e| e.to_string())? {
            let name = entry.file_name().into_string().unwrap_or_default();
            if name.starts_with('.') {
                continue;
            }

            let path = entry.path();
            let file_type = entry.file_type().await.map_err(|e| e.to_string())?;
            let relative = if prefix.is_empty() {
                name
            } else {
                format!("{}/{}", prefix, name)
            };

            if file_type.is_dir() {
                stack.push((path, relative));
            } else {
                all_files.push(relative);
            }
        }
    }

    Ok(all_files)
}