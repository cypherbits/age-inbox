use age::Decryptor;
use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
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
    let decryptor = Decryptor::new_async(meta_file.compat()).await.ok()?;
    if decryptor.is_scrypt() {
        return None;
    }

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

/// Parses a single-range `Range: bytes=start-end` header.
fn parse_range(header_value: &str) -> Option<(u64, Option<u64>)> {
    let s = header_value.strip_prefix("bytes=")?;
    let (start_str, end_str) = s.split_once('-')?;

    if start_str.is_empty() {
        // suffix range: bytes=-500
        let suffix_len: u64 = end_str.parse().ok()?;
        if suffix_len == 0 {
            return None;
        }
        // We use None as start to signal suffix mode
        // Encode as: start=u64::MAX marker, end=suffix_len
        return Some((u64::MAX, Some(suffix_len)));
    }

    let start: u64 = start_str.parse().ok()?;
    let end = if end_str.is_empty() {
        None
    } else {
        Some(end_str.parse::<u64>().ok()?)
    };

    if let Some(e) = end {
        if start > e {
            return None;
        }
    }

    Some((start, end))
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
            return Err(make_error(
                StatusCode::BAD_REQUEST,
                "Passphrase encryption not supported",
            ))
        }
        Ok(d) => d,
        Err(e) => return Err(make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    };

    let async_reader = decryptor
        .decrypt_async(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let content_type = "application/octet-stream";

    let display_filename = std::path::Path::new(&path)
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.trim_end_matches(".age"))
        .unwrap_or("file");

    let resolved_filename = metadata_filename(&filepath, &identity)
        .await
        .unwrap_or_else(|| display_filename.to_string());

    // Check for Range header
    let range_request = headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_range);

    if let Some((range_start, range_end)) = range_request {
        // We must decrypt the entire stream and skip/take bytes for the range.
        let mut reader = async_reader.compat();
        let mut all_bytes = Vec::new();
        reader
            .read_to_end(&mut all_bytes)
            .await
            .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let total_size = all_bytes.len() as u64;

        let (start, end) = if range_start == u64::MAX {
            // suffix range
            let suffix_len = range_end.unwrap_or(0);
            if suffix_len > total_size {
                return Err(make_error(
                    StatusCode::RANGE_NOT_SATISFIABLE,
                    "Range not satisfiable",
                ));
            }
            (total_size - suffix_len, total_size - 1)
        } else {
            let end = range_end.map(|e| e.min(total_size - 1)).unwrap_or(total_size - 1);
            if range_start >= total_size {
                return Err(make_error(
                    StatusCode::RANGE_NOT_SATISFIABLE,
                    "Range not satisfiable",
                ));
            }
            (range_start, end)
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