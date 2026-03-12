use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::Response,
};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use super::{
    config::read_vault_config,
    types::{make_error, ApiError, AppState, permission_denied},
    validation::{is_valid_name, is_valid_subpath},
};

/// Parses a single-range `Range: bytes=start-end` header.
/// Returns `(start, Option<end>)`. `end` is inclusive if present.
fn parse_range(header_value: &str, file_size: u64) -> Option<(u64, u64)> {
    let s = header_value.strip_prefix("bytes=")?;
    let (start_str, end_str) = s.split_once('-')?;

    if start_str.is_empty() {
        // suffix range: bytes=-500 means last 500 bytes
        let suffix_len: u64 = end_str.parse().ok()?;
        if suffix_len == 0 || suffix_len > file_size {
            return None;
        }
        Some((file_size - suffix_len, file_size - 1))
    } else {
        let start: u64 = start_str.parse().ok()?;
        let end = if end_str.is_empty() {
            file_size - 1
        } else {
            end_str.parse().ok()?
        };
        if start > end || start >= file_size {
            return None;
        }
        Some((start, end.min(file_size - 1)))
    }
}

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
        .and_then(|v| parse_range(v, file_size));

    if let Some((start, end)) = range_header {
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
