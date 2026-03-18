use age::{x25519::Recipient, Encryptor};
use axum::{
    extract::{Path, Request, State},
    http::{header, StatusCode},
    Json,
};
use std::str::FromStr;
use tokio_util::compat::TokioAsyncWriteCompatExt;

use age_inbox_core::inbox_core::{generate_drop_filename, metadata_sidecar_for};

use super::{
    config::read_vault_config,
    types::{make_error, permission_denied, ApiError, AppState, FileMetadata, GenericRes},
    validation::{is_valid_name, is_valid_subpath},
};

/// Upload endpoint for root-level files.
pub(crate) async fn upload_root(
    State(state): State<AppState>,
    Path(name): Path<String>,
    req: Request,
) -> Result<Json<GenericRes>, ApiError> {
    handle_upload(state, name, None, req).await
}

/// Upload endpoint for files under a configured subpath.
pub(crate) async fn upload_path(
    State(state): State<AppState>,
    Path((name, path)): Path<(String, String)>,
    req: Request,
) -> Result<Json<GenericRes>, ApiError> {
    handle_upload(state, name, Some(path), req).await
}

async fn handle_upload(
    state: AppState,
    name: String,
    subpath: Option<String>,
    req: Request,
) -> Result<Json<GenericRes>, ApiError> {
    if !is_valid_name(&name) {
        return Err(make_error(StatusCode::BAD_REQUEST, "Invalid vault name"));
    }

    let vault_dir = state.vaults_dir.join(&name);
    if !vault_dir.exists() {
        return Err(make_error(StatusCode::NOT_FOUND, "Vault not found"));
    }

    let config = read_vault_config(&vault_dir).await?;

    // Check upload permission
    if !config.permissions.allow_upload {
        return Err(permission_denied());
    }

    let mut target_dir = vault_dir.clone();

    if let Some(ref p) = subpath {
        if !config.permissions.allow_subfolders {
            return Err(make_error(
                StatusCode::FORBIDDEN,
                "Subfolders not allowed by vault config",
            ));
        }
        if !is_valid_subpath(p) {
            return Err(make_error(
                StatusCode::BAD_REQUEST,
                "Invalid subfolder path",
            ));
        }

        target_dir = target_dir.join(p);
        tokio::fs::create_dir_all(&target_dir)
            .await
            .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    let recipient = Recipient::from_str(&config.public_key)
        .map_err(|_| make_error(StatusCode::INTERNAL_SERVER_ERROR, "Invalid public key"))?;

    let drop_name = generate_drop_filename();
    let filepath = target_dir.join(&drop_name);
    let meta_filepath =
        metadata_sidecar_for(&filepath).expect("generated filename is a valid .age path");

    let filepath_tmp = target_dir.join(format!("{}.tmp", drop_name));
    let meta_filepath_tmp = target_dir.join(format!(
        "{}.tmp",
        meta_filepath.file_name().unwrap().to_string_lossy()
    ));

    struct CleanupGuard {
        paths: Vec<std::path::PathBuf>,
        success: bool,
    }
    impl Drop for CleanupGuard {
        fn drop(&mut self) {
            if !self.success {
                for path in &self.paths {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
    }

    let mut guard = CleanupGuard {
        paths: vec![meta_filepath_tmp.clone(), filepath_tmp.clone()],
        success: false,
    };

    let meta_file = tokio::fs::File::create(&meta_filepath_tmp)
        .await
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let file = tokio::fs::File::create(&filepath_tmp)
        .await
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let encryptor = Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
        .expect("we provided a recipient");
    let mut async_writer = encryptor
        .wrap_async_output(file.compat_write())
        .await
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let is_multipart = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|val| val.to_str().ok())
        .is_some_and(|s| s.starts_with("multipart/form-data"));

    if !is_multipart {
        return Err(make_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type must be multipart/form-data",
        ));
    }

    let metadata = handle_multipart_upload(req, &state, &mut async_writer).await?;

    futures_util::AsyncWriteExt::flush(&mut async_writer)
        .await
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    futures_util::AsyncWriteExt::close(&mut async_writer)
        .await
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let meta_encryptor =
        Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .expect("we provided a recipient");
    let mut meta_writer = meta_encryptor
        .wrap_async_output(meta_file.compat_write())
        .await
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let meta_json = serde_json::to_vec(&metadata).unwrap_or_default();
    futures_util::AsyncWriteExt::write_all(&mut meta_writer, &meta_json)
        .await
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    futures_util::AsyncWriteExt::flush(&mut meta_writer)
        .await
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    futures_util::AsyncWriteExt::close(&mut meta_writer)
        .await
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    tokio::fs::rename(&meta_filepath_tmp, &meta_filepath)
        .await
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save metadata: {}", e)))?;
        
    tokio::fs::rename(&filepath_tmp, &filepath)
        .await
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save file: {}", e)))?;

    guard.success = true;

    let uploaded_path = if let Some(p) = subpath {
        format!("{}/{}", p, drop_name)
    } else {
        drop_name
    };

    Ok(Json(GenericRes {
        message: format!("File {} uploaded successfully", uploaded_path),
    }))
}

async fn handle_multipart_upload(
    req: Request,
    state: &AppState,
    async_writer: &mut (impl futures_util::AsyncWriteExt + Unpin),
) -> Result<FileMetadata, ApiError> {
    use axum::extract::FromRequest;

    let mut multipart = axum::extract::Multipart::from_request(req, state)
        .await
        .map_err(|e| make_error(StatusCode::BAD_REQUEST, format!("Invalid multipart: {}", e)))?;

    let mut metadata = FileMetadata::default();
    let mut multipart_file_name: Option<String> = None;
    let mut form_filename: Option<String> = None;
    let mut found_file = false;

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|e| make_error(StatusCode::BAD_REQUEST, e.to_string()))?
    {
        let field_name = field.name().unwrap_or("").to_string();

        if field_name == "file" || (field_name.is_empty() && !found_file) {
            if let Some(fname) = field.file_name() {
                let trimmed = fname.trim();
                if !trimmed.is_empty() {
                    multipart_file_name = Some(trimmed.to_string());
                }
            }
            found_file = true;

            let mut file_bytes_written: u64 = 0;
            while let Some(chunk) = field
                .chunk()
                .await
                .map_err(|e| make_error(StatusCode::BAD_REQUEST, e.to_string()))?
            {
                file_bytes_written += chunk.len() as u64;
                futures_util::AsyncWriteExt::write_all(async_writer, &chunk)
                    .await
                    .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            }
            metadata.filesize = Some(file_bytes_written);
        } else if field_name == "origin" {
            if let Ok(text) = field.text().await {
                metadata.origin = Some(text);
            }
        } else if field_name == "filename" {
            if let Ok(text) = field.text().await {
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    form_filename = Some(trimmed.to_string());
                }
            }
        } else if field_name == "extended" {
            if let Ok(text) = field.text().await {
                if let Ok(ext_map) = serde_json::from_str(&text) {
                    metadata.extended = ext_map;
                }
            }
        } else if let Ok(text) = field.text().await {
            metadata
                .extended
                .insert(field_name, serde_json::Value::String(text));
        }
    }

    if !found_file {
        return Err(make_error(
            StatusCode::BAD_REQUEST,
            "Missing 'file' field in multipart form",
        ));
    }

    metadata.filename = form_filename.or(multipart_file_name);
    if metadata.filename.is_none() {
        return Err(make_error(
            StatusCode::BAD_REQUEST,
            "Missing filename: provide non-empty 'filename' field or a filename in the multipart file part",
        ));
    }

    Ok(metadata)
}
