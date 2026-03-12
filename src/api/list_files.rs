use age::Decryptor;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use std::path::PathBuf;
use tokio::io::AsyncReadExt;
use tokio::time::Instant;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use super::{
    types::{make_error, ApiError, AppState, FileMetadata, ListedFile},
    validation::is_valid_name,
};

/// Lists stored encrypted files for an unlocked vault.
pub(crate) async fn list_files(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<Vec<ListedFile>>, ApiError> {
    if !is_valid_name(&name) {
        return Err(make_error(StatusCode::BAD_REQUEST, "Invalid vault name"));
    }

    let identity = {
        let vaults = state.unlocked_vaults.read().await;
        if let Some(vault) = vaults.get(&name) {
            if Instant::now() > vault.expires_at {
                return Err(make_error(StatusCode::UNAUTHORIZED, "Vault unlock expired"));
            }
            vault.identity.clone()
        } else {
            return Err(make_error(StatusCode::UNAUTHORIZED, "Vault is locked"));
        }
    };

    let vault_dir = state.vaults_dir.join(&name);
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
        let (filename, origin) = read_metadata_fields(&full_path, &identity).await;
        listed.push(ListedFile {
            path: relative_path,
            filename,
            origin,
            size,
        });
    }

    Ok(Json(listed))
}

fn metadata_path_for(path: &std::path::Path) -> Option<std::path::PathBuf> {
    let file_name = path.file_name()?.to_str()?;
    if !file_name.ends_with(".age") || file_name.ends_with(".meta.age") {
        return None;
    }

    let meta_name = file_name.trim_end_matches(".age").to_string() + ".meta.age";
    Some(path.with_file_name(meta_name))
}

async fn read_metadata_fields(
    encrypted_file_path: &std::path::Path,
    identity: &age::x25519::Identity,
) -> (Option<String>, Option<String>) {
    let Some(meta_path) = metadata_path_for(encrypted_file_path) else {
        return (None, None);
    };
    if !meta_path.exists() {
        return (None, None);
    }

    let Ok(meta_file) = tokio::fs::File::open(meta_path).await else {
        return (None, None);
    };
    let Ok(decryptor) = Decryptor::new_async(meta_file.compat()).await else {
        return (None, None);
    };
    if decryptor.is_scrypt() {
        return (None, None);
    }

    let Ok(async_reader) = decryptor.decrypt_async(std::iter::once(identity as &dyn age::Identity))
    else {
        return (None, None);
    };

    let mut reader = async_reader.compat();
    let mut bytes = Vec::new();
    if reader.read_to_end(&mut bytes).await.is_err() {
        return (None, None);
    }

    let Ok(metadata) = serde_json::from_slice::<FileMetadata>(&bytes) else {
        return (None, None);
    };

    let filename = metadata.filename.and_then(|name| {
        std::path::Path::new(&name)
            .file_name()
            .and_then(|n| n.to_str())
            .map(ToString::to_string)
    });

    (filename, metadata.origin)
}

pub(crate) async fn walk_dir(root: PathBuf) -> Result<Vec<String>, String> {
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