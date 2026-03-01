use age::Decryptor;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use tokio::io::AsyncReadExt;
use tokio::time::Instant;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use super::{
    types::{make_error, ApiError, AppState, FileMetadata},
    validation::{is_valid_name, is_valid_subpath},
};

fn metadata_sidecar(path: &std::path::Path) -> Option<std::path::PathBuf> {
    let file_name = path.file_name()?.to_str()?;
    if !file_name.ends_with(".age") || file_name.ends_with(".meta.age") {
        return None;
    }

    let meta_name = file_name.trim_end_matches(".age").to_string() + ".meta.age";
    Some(path.with_file_name(meta_name))
}

/// Decrypts and returns metadata for an encrypted file.
pub(crate) async fn download_metadata(
    State(state): State<AppState>,
    Path((name, path)): Path<(String, String)>,
) -> Result<Json<FileMetadata>, ApiError> {
    if !is_valid_name(&name) || !is_valid_subpath(&path) {
        return Err(make_error(StatusCode::BAD_REQUEST, "Invalid name or path"));
    }

    if !path.ends_with(".age") || path.ends_with(".meta.age") {
        return Err(make_error(
            StatusCode::BAD_REQUEST,
            "Path must point to an encrypted file (.age), not a metadata sidecar",
        ));
    }

    let identity = {
        let mut vaults = state.unlocked_vaults.write().await;
        if let Some(vault) = vaults.get(&name) {
            if Instant::now() > vault.expires_at {
                vaults.remove(&name);
                return Err(make_error(StatusCode::UNAUTHORIZED, "Vault unlock expired"));
            }
            vault.identity.clone()
        } else {
            return Err(make_error(StatusCode::UNAUTHORIZED, "Vault is locked"));
        }
    };

    let encrypted_file = state.vaults_dir.join(&name).join(&path);
    let metadata_file = metadata_sidecar(&encrypted_file)
        .ok_or_else(|| make_error(StatusCode::BAD_REQUEST, "Invalid encrypted file path"))?;

    if !metadata_file.exists() {
        return Err(make_error(StatusCode::NOT_FOUND, "Metadata not found"));
    }

    let fs_file = tokio::fs::File::open(&metadata_file)
        .await
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let decryptor = match Decryptor::new_async(fs_file.compat()).await {
        Ok(Decryptor::Recipients(d)) => d,
        Ok(_) => {
            return Err(make_error(
                StatusCode::BAD_REQUEST,
                "Passphrase encryption not supported",
            ))
        }
        Err(e) => return Err(make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    };

    let async_reader = decryptor
        .decrypt_async(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut reader = async_reader.compat();
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .await
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let metadata: FileMetadata = serde_json::from_slice(&bytes)
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(metadata))
}
