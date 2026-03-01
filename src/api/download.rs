use age::Decryptor;
use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, StatusCode},
    response::Response,
};
use tokio::io::AsyncReadExt;
use tokio::time::Instant;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use super::{
    types::{make_error, ApiError, AppState, FileMetadata},
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

async fn metadata_filename(
    encrypted_file_path: &std::path::Path,
    identity: &age::x25519::Identity,
) -> Option<String> {
    let meta_path = metadata_path_for(encrypted_file_path)?;
    if !meta_path.exists() {
        return None;
    }

    let meta_file = tokio::fs::File::open(meta_path).await.ok()?;
    let decryptor = match Decryptor::new_async(meta_file.compat()).await.ok()? {
        Decryptor::Recipients(d) => d,
        _ => return None,
    };

    let async_reader = decryptor
        .decrypt_async(std::iter::once(identity as &dyn age::Identity))
        .ok()?;
    let mut reader = async_reader.compat();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).await.ok()?;

    let metadata: FileMetadata = serde_json::from_slice(&bytes).ok()?;
    metadata
        .filename
        .and_then(|name| {
            std::path::Path::new(&name)
                .file_name()
                .and_then(|n| n.to_str())
                .map(ToString::to_string)
        })
}

/// Downloads and decrypts a file from an unlocked vault.
pub(crate) async fn download_file(
    State(state): State<AppState>,
    Path((name, path)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    if !is_valid_name(&name) || !is_valid_subpath(&path) {
        return Err(make_error(StatusCode::BAD_REQUEST, "Invalid name or path"));
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

    let filepath = state.vaults_dir.join(&name).join(&path);
    if !filepath.exists() {
        return Err(make_error(StatusCode::NOT_FOUND, "File not found"));
    }

    let fs_file = tokio::fs::File::open(&filepath)
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

    let stream = tokio_util::io::ReaderStream::new(async_reader.compat());
    let body = Body::from_stream(stream);

    let content_type = if path.ends_with(".meta.age") {
        "application/json"
    } else {
        "application/octet-stream"
    };

    let display_filename = std::path::Path::new(&path)
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.trim_end_matches(".age"))
        .unwrap_or("file");

    let resolved_filename = if path.ends_with(".meta.age") {
        display_filename.to_string()
    } else {
        metadata_filename(&filepath, &identity)
            .await
            .unwrap_or_else(|| display_filename.to_string())
    };

    axum::response::Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", resolved_filename),
        )
        .header(header::CONTENT_TYPE, content_type)
        .body(body)
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}