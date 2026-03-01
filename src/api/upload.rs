use age::{
    x25519::Recipient,
    Encryptor,
};
use axum::{
    body::Body,
    extract::{Path, Request, State},
    http::{header, StatusCode},
    Json,
};
use futures_util::StreamExt;
use std::str::FromStr;
use tokio_util::compat::TokioAsyncWriteCompatExt;

use super::{
    config::read_vault_config,
    types::{make_error, ApiError, AppState, FileMetadata, GenericRes},
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
    let mut target_dir = vault_dir.clone();

    if let Some(ref p) = subpath {
        if !config.allow_subfolders {
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
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros();

    let filepath = target_dir.join(format!("upload_{}.age", timestamp));
    let meta_filepath = target_dir.join(format!("upload_{}.meta.age", timestamp));

    let file = tokio::fs::File::create(&filepath)
        .await
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let encryptor = Encryptor::with_recipients(vec![Box::new(recipient.clone())])
        .expect("we provided a recipient");
    let mut async_writer = encryptor
        .wrap_async_output(file.compat_write())
        .await
        .map_err(|e: age::EncryptError| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let is_multipart = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|val| val.to_str().ok())
        .is_some_and(|s| s.starts_with("multipart/form-data"));

    let metadata = if is_multipart {
        handle_multipart_upload(req, &state, &mut async_writer).await?
    } else {
        handle_raw_upload(req, &mut async_writer).await?
    };

    futures_util::AsyncWriteExt::flush(&mut async_writer)
        .await
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    futures_util::AsyncWriteExt::close(&mut async_writer)
        .await
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let meta_file = tokio::fs::File::create(&meta_filepath)
        .await
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let meta_encryptor =
        Encryptor::with_recipients(vec![Box::new(recipient)]).expect("we provided a recipient");
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

    let uploaded_path = if let Some(p) = subpath {
        format!("{}/upload_{}.age", p, timestamp)
    } else {
        format!("upload_{}.age", timestamp)
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
    let mut found_file = false;

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|e| make_error(StatusCode::BAD_REQUEST, e.to_string()))?
    {
        let field_name = field.name().unwrap_or("").to_string();

        if field_name == "file" || (field_name.is_empty() && !found_file) {
            if let Some(fname) = field.file_name() {
                metadata.filename = Some(fname.to_string());
            }
            found_file = true;

            while let Some(chunk) = field
                .chunk()
                .await
                .map_err(|e| make_error(StatusCode::BAD_REQUEST, e.to_string()))?
            {
                futures_util::AsyncWriteExt::write_all(async_writer, &chunk)
                    .await
                    .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            }
        } else if field_name == "origin" {
            if let Ok(text) = field.text().await {
                metadata.origin = Some(text);
            }
        } else if field_name == "filename" {
            if let Ok(text) = field.text().await {
                metadata.filename = Some(text);
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

    Ok(metadata)
}

async fn handle_raw_upload(
    req: Request,
    async_writer: &mut (impl futures_util::AsyncWriteExt + Unpin),
) -> Result<FileMetadata, ApiError> {
    let mut metadata = FileMetadata::default();

    if let Some(orig) = req.headers().get("X-File-Origin") {
        metadata.origin = orig.to_str().ok().map(ToString::to_string);
    }
    if let Some(fname) = req.headers().get("X-Filename") {
        metadata.filename = fname.to_str().ok().map(ToString::to_string);
    }
    if let Some(ext) = req.headers().get("X-Extended-Metadata") {
        if let Some(ext_str) = ext.to_str().ok() {
            if let Ok(ext_map) = serde_json::from_str(ext_str) {
                metadata.extended = ext_map;
            }
        }
    }

    let body: Body = req.into_body();
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let data = chunk.map_err(|e| make_error(StatusCode::BAD_REQUEST, e.to_string()))?;
        futures_util::AsyncWriteExt::write_all(async_writer, &data)
            .await
            .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    Ok(metadata)
}