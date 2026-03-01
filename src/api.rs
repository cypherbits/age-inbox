use age::{
    x25519::{Identity, Recipient},
    Decryptor, Encryptor,
};
use axum::{
    body::Body,
    extract::{Path, Request, State},
    http::{header, StatusCode},
    response::Response,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};

use futures_util::StreamExt;
use std::str::FromStr;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

use crate::crypto::derive_keys;

#[derive(Clone)]
pub struct AppState {
    pub unlocked_vaults: Arc<RwLock<HashMap<String, UnlockedVault>>>,
    pub vaults_dir: PathBuf,
}

pub struct UnlockedVault {
    pub identity: Identity,
    pub expires_at: Instant,
}

#[derive(Deserialize)]
pub struct CreateInboxReq {
    pub name: String,
    pub password: String,
    pub allow_subfolders: Option<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct CreateInboxRes {
    pub success: bool,
    pub public_key: String,
}

#[derive(Serialize)]
pub struct GenericRes {
    pub message: String,
}

#[derive(Serialize)]
pub struct ErrorRes {
    pub error: String,
}

type ApiError = (StatusCode, Json<ErrorRes>);

fn make_error(code: StatusCode, msg: impl Into<String>) -> ApiError {
    (code, Json(ErrorRes { error: msg.into() }))
}

#[derive(Deserialize)]
pub struct UnlockReq {
    pub password: String,
}

#[derive(Serialize, Deserialize, Default)]
pub struct FileMetadata {
    pub filename: Option<String>,
    pub origin: Option<String>,
    #[serde(flatten)]
    pub extended: HashMap<String, serde_json::Value>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/inbox", post(create_inbox))
        .route("/inbox/:name/upload", post(upload_root))
        .route("/inbox/:name/upload/*path", post(upload_path))
        .route("/inbox/:name/unlock", post(unlock))
        .route("/inbox/:name/lock", post(lock))
        .route("/inbox/:name/list", get(list_files))
        .route("/inbox/:name/download/*path", get(download_file))
        .with_state(state)
}

fn is_valid_name(name: &str) -> bool {
    !name.is_empty() && !name.contains('/') && !name.contains('\\') && !name.contains("..")
}

fn is_valid_subpath(path: &str) -> bool {
    !path.contains("..") && !path.starts_with('/') && !path.contains('\\')
}

async fn create_inbox(
    State(state): State<AppState>,
    Json(payload): Json<CreateInboxReq>,
) -> Result<Json<CreateInboxRes>, ApiError> {
    if !is_valid_name(&payload.name) {
        return Err(make_error(StatusCode::BAD_REQUEST, "Invalid vault name"));
    }

    let vault_dir = state.vaults_dir.join(&payload.name);
    if vault_dir.exists() {
        return Err(make_error(StatusCode::CONFLICT, "Vault already exists"));
    }

    let keys = derive_keys(&payload.password, &payload.name)
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tokio::fs::create_dir_all(&vault_dir)
        .await
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let config_path = vault_dir.join(".inbox-age.config");
    let pub_key_str = keys.recipient.to_string();
    let allow_subfolders_str = if payload.allow_subfolders.unwrap_or(false) {
        "true"
    } else {
        "false"
    };

    let config_content = format!(
        "inbox-name: {}\npublic-key: {}\nallow-subfolders: {}\n",
        payload.name, pub_key_str, allow_subfolders_str
    );
    tokio::fs::write(&config_path, config_content)
        .await
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(CreateInboxRes {
        success: true,
        public_key: pub_key_str,
    }))
}

async fn upload_root(
    State(state): State<AppState>,
    Path(name): Path<String>,
    req: Request,
) -> Result<Json<GenericRes>, ApiError> {
    handle_upload(state, name, None, req).await
}

async fn upload_path(
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

    let config_path = vault_dir.join(".inbox-age.config");
    let config_content = tokio::fs::read_to_string(&config_path)
        .await
        .map_err(|_| make_error(StatusCode::NOT_FOUND, "Vault config missing"))?;
    let mut pub_key_str = String::new();
    let mut allow_subfolders = false;
    for line in config_content.lines() {
        if line.starts_with("public-key: ") {
            pub_key_str = line.trim_start_matches("public-key: ").to_string();
        } else if line.starts_with("allow-subfolders: true") {
            allow_subfolders = true;
        }
    }

    if pub_key_str.is_empty() {
        return Err(make_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Invalid config",
        ));
    }

    let mut target_dir = vault_dir.clone();
    if let Some(ref p) = subpath {
        if !allow_subfolders {
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

    let recipient = Recipient::from_str(&pub_key_str)
        .map_err(|_e| make_error(StatusCode::INTERNAL_SERVER_ERROR, "Invalid public key"))?;
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
        .map_err(|e: age::EncryptError| {
            make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        })?;

    let is_multipart = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|val| val.to_str().ok())
        .map_or(false, |s| s.starts_with("multipart/form-data"));

    let mut metadata = FileMetadata::default();

    if is_multipart {
        use axum::extract::FromRequest;
        let mut multipart = axum::extract::Multipart::from_request(req, &state)
            .await
            .map_err(|e| {
                make_error(StatusCode::BAD_REQUEST, format!("Invalid multipart: {}", e))
            })?;

        let mut found_file = false;
        while let Some(mut field) = multipart
            .next_field()
            .await
            .map_err(|e| make_error(StatusCode::BAD_REQUEST, e.to_string()))?
        {
            let field_name = field.name().unwrap_or("").to_string();
            if field_name == "file" || field_name == "" && !found_file {
                if let Some(fname) = field.file_name() {
                    metadata.filename = Some(fname.to_string());
                }
                found_file = true;
                while let Some(chunk) = field
                    .chunk()
                    .await
                    .map_err(|e| make_error(StatusCode::BAD_REQUEST, e.to_string()))?
                {
                    futures_util::AsyncWriteExt::write_all(&mut async_writer, &chunk)
                        .await
                        .map_err(|e| {
                            make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
                        })?;
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
            } else {
                if let Ok(text) = field.text().await {
                    metadata
                        .extended
                        .insert(field_name, serde_json::Value::String(text));
                }
            }
        }
        if !found_file {
            return Err(make_error(
                StatusCode::BAD_REQUEST,
                "Missing 'file' field in multipart form",
            ));
        }
    } else {
        if let Some(orig) = req.headers().get("X-File-Origin") {
            metadata.origin = orig.to_str().ok().map(|s| s.to_string());
        }
        if let Some(fname) = req.headers().get("X-Filename") {
            metadata.filename = fname.to_str().ok().map(|s| s.to_string());
        }
        if let Some(ext) = req.headers().get("X-Extended-Metadata") {
            if let Some(ext_str) = ext.to_str().ok() {
                if let Ok(ext_map) = serde_json::from_str(ext_str) {
                    metadata.extended = ext_map;
                }
            }
        }

        let body = req.into_body();
        let mut stream = body.into_data_stream();
        while let Some(chunk) = stream.next().await {
            let data = chunk.map_err(|e| make_error(StatusCode::BAD_REQUEST, e.to_string()))?;
            futures_util::AsyncWriteExt::write_all(&mut async_writer, &data)
                .await
                .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
    }

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

async fn unlock(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(payload): Json<UnlockReq>,
) -> Result<Json<GenericRes>, ApiError> {
    if !is_valid_name(&name) {
        return Err(make_error(StatusCode::BAD_REQUEST, "Invalid vault name"));
    }

    let vault_dir = state.vaults_dir.join(&name);
    let config_path = vault_dir.join(".inbox-age.config");
    let config_content = tokio::fs::read_to_string(&config_path)
        .await
        .map_err(|_| make_error(StatusCode::NOT_FOUND, "Vault config missing"))?;
    let mut pub_key_str = String::new();
    for line in config_content.lines() {
        if line.starts_with("public-key: ") {
            pub_key_str = line.trim_start_matches("public-key: ").to_string();
            break;
        }
    }

    let keys = derive_keys(&payload.password, &name)
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if keys.recipient.to_string() != pub_key_str {
        return Err(make_error(StatusCode::UNAUTHORIZED, "Invalid password"));
    }

    let mut vaults = state.unlocked_vaults.write().await;
    vaults.insert(
        name.clone(),
        UnlockedVault {
            identity: keys.identity,
            expires_at: Instant::now() + Duration::from_secs(3600),
        },
    );

    Ok(Json(GenericRes {
        message: format!("Vault {} unlocked for 1 hour", name),
    }))
}

async fn lock(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<GenericRes>, ApiError> {
    let mut vaults = state.unlocked_vaults.write().await;
    if vaults.remove(&name).is_some() {
        Ok(Json(GenericRes {
            message: format!("Vault {} locked", name),
        }))
    } else {
        Err(make_error(StatusCode::NOT_FOUND, "Vault not unlocked"))
    }
}

fn walk_dir(
    dir: PathBuf,
    prefix: String,
) -> Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send>> {
    Box::pin(async move {
        let mut files = Vec::new();
        let mut entries = tokio::fs::read_dir(&dir).await.map_err(|e| e.to_string())?;
        while let Some(entry) = entries.next_entry().await.unwrap_or(None) {
            let name = entry.file_name().into_string().unwrap_or_default();
            if name.starts_with('.') {
                continue;
            }
            let path = entry.path();
            if path.is_dir() {
                let subdir_prefix = if prefix.is_empty() {
                    name
                } else {
                    format!("{}/{}", prefix, name)
                };
                if let Ok(mut subfiles) = walk_dir(path, subdir_prefix).await {
                    files.append(&mut subfiles);
                }
            } else {
                let file_path = if prefix.is_empty() {
                    name
                } else {
                    format!("{}/{}", prefix, name)
                };
                files.push(file_path);
            }
        }
        Ok(files)
    })
}

async fn list_files(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<Vec<String>>, ApiError> {
    if !is_valid_name(&name) {
        return Err(make_error(StatusCode::BAD_REQUEST, "Invalid vault name"));
    }

    let vaults = state.unlocked_vaults.read().await;
    if let Some(vault) = vaults.get(&name) {
        if Instant::now() > vault.expires_at {
            return Err(make_error(StatusCode::UNAUTHORIZED, "Vault unlock expired"));
        }
    } else {
        return Err(make_error(StatusCode::UNAUTHORIZED, "Vault is locked"));
    }

    let vault_dir = state.vaults_dir.join(&name);
    let files = walk_dir(vault_dir, String::new())
        .await
        .map_err(|e| make_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(files))
}

async fn download_file(
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

    use tokio_util::compat::FuturesAsyncReadCompatExt;
    let stream = tokio_util::io::ReaderStream::new(async_reader.compat());
    let body = Body::from_stream(stream);

    let content_type = if path.ends_with(".meta.age") {
        "application/json"
    } else {
        "application/octet-stream"
    };

    let display_filename = match std::path::Path::new(&path)
        .file_name()
        .and_then(|n| n.to_str())
    {
        Some(n) => n.trim_end_matches(".age"),
        None => "file",
    };

    Ok(axum::response::Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", display_filename),
        )
        .header(header::CONTENT_TYPE, content_type)
        .body(body)
        .unwrap())
}
