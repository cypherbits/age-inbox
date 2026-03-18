use age::Decryptor;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use futures_util::stream::StreamExt;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::time::Instant;
use tokio::io::AsyncReadExt;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use super::{
    config::read_vault_config,
    types::{make_error, permission_denied, ApiError, AppState, FileMetadata, ListedFile},
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

    // Check list permission
    let vault_dir = state.vaults_dir.join(&name);
    let config = read_vault_config(&vault_dir).await?;
    if !config.permissions.allow_list {
        return Err(permission_denied());
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
    let files = walk_dir(vault_dir)
        .await
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let futures = files.into_iter().filter_map(|relative_path| {
        if !relative_path.ends_with(".age") || relative_path.ends_with(".meta.age") {
            return None;
        }

        let name = name.clone();
        let state_vaults_dir = state.vaults_dir.clone();
        let identity = identity.clone();

        Some(async move {
            let full_path = state_vaults_dir.join(&name).join(&relative_path);
            let size = tokio::fs::metadata(&full_path)
                .await
                .map(|m| m.len())
                .map_err(|e| {
                    make_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Failed to read encrypted file metadata for '{}': {}", relative_path, e),
                    )
                })?;
            let meta_result = read_metadata_fields(&name, &relative_path, &full_path, &identity).await;
            let (filename, origin) = match meta_result {
                Ok(res) => res,
                Err(e) => {
                    tracing::error!(
                        vault = %name,
                        file = %relative_path,
                        error = %e,
                        "Metadata sidecar missing or decryption failed; skipping file in list",
                    );
                    return Ok(None);
                }
            };
            Ok(Some(ListedFile {
                path: relative_path,
                filename,
                origin,
                size,
            }))
        })
    });

    let stream = futures_util::stream::iter(futures).buffer_unordered(5);
    let results: Vec<_> = stream.collect().await;

    let mut listed = Vec::new();
    for res in results {
        if let Some(file) = res? {
            listed.push(file);
        }
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
    vault_name: &str,
    relative_path: &str,
    encrypted_file_path: &std::path::Path,
    identity: &age::x25519::Identity,
) -> Result<(Option<String>, Option<String>), String> {
    let Some(meta_path) = metadata_path_for(encrypted_file_path) else {
        return Err("invalid encrypted file path for metadata sidecar".to_string());
    };

    match tokio::fs::metadata(&meta_path).await {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {
            tracing::error!(
                vault = %vault_name,
                file = %relative_path,
                sidecar = %meta_path.to_string_lossy(),
                "Metadata sidecar not found",
            );
            return Err("metadata sidecar not found".to_string());
        }
        Err(e) => {
            return Err(format!(
                "failed to stat metadata sidecar '{}': {}",
                meta_path.to_string_lossy(),
                e
            ));
        }
    }

    let meta_file = tokio::fs::File::open(&meta_path)
        .await
        .map_err(|e| format!("failed to open metadata sidecar '{}': {}", meta_path.to_string_lossy(), e))?;
    let decryptor = Decryptor::new_async(meta_file.compat()).await.map_err(|e| {
        format!(
            "failed to initialize metadata decryptor for '{}': {}",
            meta_path.to_string_lossy(),
            e
        )
    })?;
    if decryptor.is_scrypt() {
        return Err(format!(
            "metadata sidecar '{}' uses unsupported scrypt encryption",
            meta_path.to_string_lossy()
        ));
    }

    let async_reader = decryptor
        .decrypt_async(std::iter::once(identity as &dyn age::Identity))
        .map_err(|e| {
            format!(
                "failed to decrypt metadata sidecar '{}': {}",
                meta_path.to_string_lossy(),
                e
            )
        })?;

    let mut reader = async_reader.compat();
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).await.map_err(|e| {
        format!(
            "failed to read decrypted metadata sidecar '{}': {}",
            meta_path.to_string_lossy(),
            e
        )
    })?;

    let metadata = serde_json::from_slice::<FileMetadata>(&bytes).map_err(|e| {
        format!(
            "failed to parse metadata JSON from '{}': {}",
            meta_path.to_string_lossy(),
            e
        )
    })?;

    let filename = metadata.filename.and_then(|name| {
        std::path::Path::new(&name)
            .file_name()
            .and_then(|n| n.to_str())
            .map(ToString::to_string)
    });

    Ok((filename, metadata.origin))
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
