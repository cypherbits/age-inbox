use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::Response,
};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use super::{
    config::read_vault_config,
    http_range::{parse_single_range, unsatisfied_content_range},
    types::{make_error, permission_denied, ApiError, AppState},
    validation::{is_valid_name, is_valid_subpath},
};

/// Downloads an encrypted `.age` file as-is (without decryption).
/// Works regardless of vault lock state. Supports HTTP Range requests.
pub(crate) async fn download_raw(
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
            "Path must point to an encrypted file (.age).",
        ));
    }

    let vault_dir = state.vaults_dir.join(&name);
    if !vault_dir.exists() {
        return Err(make_error(StatusCode::NOT_FOUND, "Vault not found"));
    }

    // Check download permission
    let config = read_vault_config(&vault_dir).await?;
    if !config.permissions.allow_download {
        return Err(permission_denied());
    }

    let filepath = vault_dir.join(&path);
    if !filepath.exists() {
        return Err(make_error(StatusCode::NOT_FOUND, "File not found"));
    }

    let file_meta = tokio::fs::metadata(&filepath)
        .await
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let file_size = file_meta.len();

    let display_filename = std::path::Path::new(&path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file.age");

    // Check for Range header
    let range_header = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .map(|v| parse_single_range(v, file_size));

    if let Some(None) = range_header {
        let body = Body::from("Range not satisfiable");
        let response = Response::builder()
            .status(StatusCode::RANGE_NOT_SATISFIABLE)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .header(header::CONTENT_RANGE, unsatisfied_content_range(file_size))
            .body(body)
            .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        return Ok(response);
    }

    if let Some(Some((start, end))) = range_header {
        let length = end - start + 1;
        let mut file = tokio::fs::File::open(&filepath)
            .await
            .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        file.seek(std::io::SeekFrom::Start(start))
            .await
            .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let limited = file.take(length);
        let stream = tokio_util::io::ReaderStream::new(limited);
        let body = Body::from_stream(stream);

        Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", display_filename),
            )
            .header(header::CONTENT_LENGTH, length.to_string())
            .header(header::ACCEPT_RANGES, "bytes")
            .header(
                header::CONTENT_RANGE,
                format!("bytes {}-{}/{}", start, end, file_size),
            )
            .body(body)
            .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
    } else {
        let file = tokio::fs::File::open(&filepath)
            .await
            .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let stream = tokio_util::io::ReaderStream::new(file);
        let body = Body::from_stream(stream);

        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", display_filename),
            )
            .header(header::CONTENT_LENGTH, file_size.to_string())
            .header(header::ACCEPT_RANGES, "bytes")
            .body(body)
            .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
    }
}
