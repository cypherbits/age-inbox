use axum::{
    extract::{Path, State},
    http::StatusCode,
};

use super::{
    types::{make_error, ApiError, AppState},
    validation::{is_valid_name, is_valid_subpath},
};

fn metadata_path_for(path: &std::path::Path) -> Option<std::path::PathBuf> {
    let file_name = path.file_name()?.to_str()?;
    if !file_name.ends_with(".age") || file_name.ends_with(".meta.age") {
        return None;
    }

    let meta_name = file_name.trim_end_matches(".age").to_string() + ".meta.age";
    Some(path.with_file_name(meta_name))
}

/// Deletes a raw encrypted file and its associated metadata (if exists).
/// Works regardless of vault lock state.
pub(crate) async fn delete_raw(
    State(state): State<AppState>,
    Path((name, path)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    if !is_valid_name(&name) || !is_valid_subpath(&path) {
        return Err(make_error(StatusCode::BAD_REQUEST, "Invalid name or path"));
    }

    let vault_dir = state.vaults_dir.join(&name);
    if !vault_dir.exists() {
        return Err(make_error(StatusCode::NOT_FOUND, "Vault not found"));
    }

    let file_path = vault_dir.join(&path);

    // Validate that the file is within the vault directory
    if !file_path.starts_with(&vault_dir) {
        return Err(make_error(StatusCode::BAD_REQUEST, "Invalid path"));
    }

    // Check if file exists
    if !file_path.exists() {
        return Err(make_error(StatusCode::NOT_FOUND, "File not found"));
    }

    // Delete the main file
    tokio::fs::remove_file(&file_path)
        .await
        .map_err(|_| make_error(StatusCode::INTERNAL_SERVER_ERROR, "Failed to delete file"))?;

    // Delete metadata if it exists
    if let Some(meta_path) = metadata_path_for(&file_path) {
        if meta_path.exists() {
            let _ = tokio::fs::remove_file(meta_path).await;
        }
    }

    Ok(StatusCode::OK)
}

