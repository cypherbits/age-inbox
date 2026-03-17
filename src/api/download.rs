use age::Decryptor;
use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::Response,
};
use std::time::Instant;
use tokio::io::AsyncReadExt;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use age_inbox_core::inbox_core::decrypt_age_file_range_to_writer;

use super::{
    config::read_vault_config,
    http_range::{parse_single_range, unsatisfied_content_range},
    types::{make_error, permission_denied, ApiError, AppState, FileMetadata},
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

/// Returns (filename, filesize) from the encrypted metadata sidecar.
async fn metadata_info(
    vault_name: &str,
    relative_path: &str,
    encrypted_file_path: &std::path::Path,
    identity: &age::x25519::Identity,
) -> (Option<String>, Option<u64>) {
    let meta_path = match metadata_path_for(encrypted_file_path) {
        Some(p) => p,
        None => {
            tracing::warn!(
                vault = %vault_name,
                file = %relative_path,
                "Invalid encrypted file path for metadata sidecar",
            );
            return (None, None);
        }
    };

    match tokio::fs::metadata(&meta_path).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(
                vault = %vault_name,
                file = %relative_path,
                "Metadata sidecar not found; download will use fallback metadata",
            );
            return (None, None);
        }
        Err(e) => {
            tracing::error!(
                vault = %vault_name,
                file = %relative_path,
                error = %e,
                "Failed to stat metadata sidecar",
            );
            return (None, None);
        }
    }

    let meta_file = match tokio::fs::File::open(meta_path).await {
        Ok(f) => f,
        Err(e) => {
            tracing::error!(
                vault = %vault_name,
                file = %relative_path,
                error = %e,
                "Failed to open metadata sidecar",
            );
            return (None, None);
        }
    };
    let decryptor = match Decryptor::new_async(meta_file.compat()).await {
        Ok(d) if !d.is_scrypt() => d,
        Ok(_) => {
            tracing::error!(
                vault = %vault_name,
                file = %relative_path,
                "Metadata sidecar uses unsupported scrypt encryption",
            );
            return (None, None);
        }
        Err(e) => {
            tracing::error!(
                vault = %vault_name,
                file = %relative_path,
                error = %e,
                "Failed to initialize metadata decryptor",
            );
            return (None, None);
        }
    };

    let async_reader = match decryptor
        .decrypt_async(std::iter::once(identity as &dyn age::Identity))
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(
                vault = %vault_name,
                file = %relative_path,
                error = %e,
                "Failed to decrypt metadata sidecar",
            );
            return (None, None);
        }
    };
    let mut reader = async_reader.compat();
    let mut bytes = Vec::new();
    if let Err(e) = reader.read_to_end(&mut bytes).await {
        tracing::error!(
            vault = %vault_name,
            file = %relative_path,
            error = %e,
            "Failed to read decrypted metadata sidecar",
        );
        return (None, None);
    }

    let metadata: FileMetadata = match serde_json::from_slice(&bytes) {
        Ok(m) => m,
        Err(e) => {
            tracing::error!(
                vault = %vault_name,
                file = %relative_path,
                error = %e,
                "Failed to parse metadata JSON",
            );
            return (None, None);
        }
    };

    let filename = metadata.filename.as_deref().and_then(|name| {
        std::path::Path::new(name)
            .file_name()
            .and_then(|n| n.to_str())
            .map(ToString::to_string)
    });

    (filename, metadata.filesize)
}

/// Downloads and decrypts a file from an unlocked vault.
/// Supports HTTP Range requests on the decrypted content.
pub(crate) async fn download_file(
    State(state): State<AppState>,
    Path((name, path)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if !is_valid_name(&name) || !is_valid_subpath(&path) {
        return Err(make_error(StatusCode::BAD_REQUEST, "Invalid name or path"));
    }

    if !path.ends_with(".age") || path.ends_with(".meta.age") {
        return Err(make_error(
            StatusCode::BAD_REQUEST,
            "Path must point to an encrypted file (.age). Use /metadata for metadata.",
        ));
    }

    let vault_dir = state.vaults_dir.join(&name);

    // Check download permission
    let config = read_vault_config(&vault_dir).await?;
    if !config.permissions.allow_download {
        return Err(permission_denied());
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
        Ok(d) if d.is_scrypt() => {
            tracing::error!(
                vault = %name,
                file = %path,
                "Encrypted payload uses unsupported scrypt encryption",
            );
            return Err(make_error(
                StatusCode::BAD_REQUEST,
                "Passphrase encryption not supported",
            ))
        }
        Ok(d) => d,
        Err(e) => {
            tracing::error!(
                vault = %name,
                file = %path,
                error = %e,
                "Failed to initialize payload decryptor",
            );
            return Err(make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()));
        }
    };

    let async_reader = decryptor
        .decrypt_async(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| {
            tracing::error!(
                vault = %name,
                file = %path,
                error = %e,
                "Failed to decrypt payload",
            );
            make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        })?;

    let content_type = "application/octet-stream";

    let display_filename = std::path::Path::new(&path)
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.trim_end_matches(".age"))
        .unwrap_or("file");

    let (meta_filename, meta_filesize) = metadata_info(&name, &path, &filepath, &identity).await;
    let resolved_filename = meta_filename.unwrap_or_else(|| display_filename.to_string());

    // Check for Range header
    let range_value = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    if let Some(range_header_value) = range_value {
        if let Some(total_size) = meta_filesize {
            // Fast path: filesize known from metadata — stream only the requested range.
            let (start, end) =
                if let Some(range) = parse_single_range(&range_header_value, total_size) {
                    range
                } else {
                    tracing::warn!(
                        vault = %name,
                        file = %path,
                        range = %range_header_value,
                        total_size,
                        "Invalid or unsatisfiable range request",
                    );
                    let body = Body::from("Range not satisfiable");
                    let response = Response::builder()
                        .status(StatusCode::RANGE_NOT_SATISFIABLE)
                        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                        .header(header::CONTENT_RANGE, unsatisfied_content_range(total_size))
                        .body(body)
                        .map_err(|e| {
                            make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
                        })?;
                    return Ok(response);
                };

            let length = end - start + 1;
            let mut body_bytes = Vec::with_capacity(length as usize);
            decrypt_age_file_range_to_writer(&identity, &filepath, &mut body_bytes, start, end)
                .await
                .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            Response::builder()
                .status(StatusCode::PARTIAL_CONTENT)
                .header(header::CONTENT_TYPE, content_type)
                .header(
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{}\"", resolved_filename),
                )
                .header(header::CONTENT_LENGTH, length.to_string())
                .header(header::ACCEPT_RANGES, "bytes")
                .header(
                    header::CONTENT_RANGE,
                    format!("bytes {}-{}/{}", start, end, total_size),
                )
                .body(Body::from(body_bytes))
                .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        } else {
            // Fallback: no filesize in metadata — decrypt full payload to resolve total size,
            // then serve a standards-compliant 206 response for Range clients.
            tracing::warn!(
                vault = %name,
                file = %path,
                "Missing metadata filesize; decrypting full file for range response",
            );
            let mut reader = async_reader.compat();
            let mut all_bytes = Vec::new();
            reader
                .read_to_end(&mut all_bytes)
                .await
                .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            let total_size = all_bytes.len() as u64;
            let (start, end) =
                if let Some(range) = parse_single_range(&range_header_value, total_size) {
                    range
                } else {
                    tracing::warn!(
                        vault = %name,
                        file = %path,
                        range = %range_header_value,
                        total_size,
                        "Invalid or unsatisfiable range request",
                    );
                    let body = Body::from("Range not satisfiable");
                    let response = Response::builder()
                        .status(StatusCode::RANGE_NOT_SATISFIABLE)
                        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                        .header(header::CONTENT_RANGE, unsatisfied_content_range(total_size))
                        .body(body)
                        .map_err(|e| {
                            make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
                        })?;
                    return Ok(response);
                };

            let slice = &all_bytes[start as usize..=end as usize];
            let length = slice.len() as u64;

            Response::builder()
                .status(StatusCode::PARTIAL_CONTENT)
                .header(header::CONTENT_TYPE, content_type)
                .header(
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{}\"", resolved_filename),
                )
                .header(header::CONTENT_LENGTH, length.to_string())
                .header(header::ACCEPT_RANGES, "bytes")
                .header(
                    header::CONTENT_RANGE,
                    format!("bytes {}-{}/{}", start, end, total_size),
                )
                .body(Body::from(slice.to_vec()))
                .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    } else {
        // No range — stream the full decrypted content
        let stream = tokio_util::io::ReaderStream::new(async_reader.compat());
        let body = Body::from_stream(stream);

        Response::builder()
            .status(StatusCode::OK)
            .header(
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", resolved_filename),
            )
            .header(header::CONTENT_TYPE, content_type)
            .header(header::ACCEPT_RANGES, "bytes")
            .body(body)
            .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
    }
}
