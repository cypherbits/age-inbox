use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, StatusCode},
    response::Response,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Instant, Duration};
use age::{Encryptor, Decryptor, x25519::{Identity, Recipient}};
use std::path::PathBuf;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio_util::compat::{TokioAsyncWriteCompatExt, TokioAsyncReadCompatExt};
use std::str::FromStr;
use futures_util::StreamExt;

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
}

#[derive(Serialize)]
pub struct CreateInboxRes {
    pub success: bool,
    pub public_key: String,
}

#[derive(Deserialize)]
pub struct UnlockReq {
    pub password: String,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/inbox", post(create_inbox))
        .route("/inbox/:name/upload", post(upload))
        .route("/inbox/:name/unlock", post(unlock))
        .route("/inbox/:name/lock", post(lock))
        .route("/inbox/:name/list", get(list_files))
        .route("/inbox/:name/download/:file", get(download_file))
        .with_state(state)
}

fn is_valid_name(name: &str) -> bool {
    !name.is_empty() && !name.contains('/') && !name.contains('\\') && !name.contains("..")
}

async fn create_inbox(
    State(state): State<AppState>,
    Json(payload): Json<CreateInboxReq>,
) -> Result<Json<CreateInboxRes>, (StatusCode, String)> {
    if !is_valid_name(&payload.name) {
        return Err((StatusCode::BAD_REQUEST, "Invalid vault name".to_string()));
    }

    let vault_dir = state.vaults_dir.join(&payload.name);
    if vault_dir.exists() {
        return Err((StatusCode::CONFLICT, "Vault already exists".to_string()));
    }

    let keys = derive_keys(&payload.password, &payload.name)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    tokio::fs::create_dir_all(&vault_dir)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let config_path = vault_dir.join(".inbox-age.config");
    let pub_key_str = keys.recipient.to_string();
    
    let config_content = format!("inbox-name: {}\npublic-key: {}\n", payload.name, pub_key_str);
    
    tokio::fs::write(&config_path, config_content)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(CreateInboxRes {
        success: true,
        public_key: pub_key_str,
    }))
}

async fn upload(
    State(state): State<AppState>,
    Path(name): Path<String>,
    mut body: Body,
) -> Result<String, (StatusCode, String)> {
    if !is_valid_name(&name) {
        return Err((StatusCode::BAD_REQUEST, "Invalid vault name".to_string()));
    }

    let vault_dir = state.vaults_dir.join(&name);
    if !vault_dir.exists() {
        return Err((StatusCode::NOT_FOUND, "Vault not found".to_string()));
    }

    let config_path = vault_dir.join(".inbox-age.config");
    let config_content = tokio::fs::read_to_string(&config_path).await.map_err(|_| (StatusCode::NOT_FOUND, "Vault config missing".to_string()))?;
    
    let mut pub_key_str = String::new();
    for line in config_content.lines() {
        if line.starts_with("public-key: ") {
            pub_key_str = line.trim_start_matches("public-key: ").to_string();
            break;
        }
    }

    if pub_key_str.is_empty() {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "Invalid config".to_string()));
    }

    let recipient = Recipient::from_str(&pub_key_str).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid public key".to_string()))?;
    
    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let filename = format!("upload_{}.age", timestamp);
    let filepath = vault_dir.join(&filename);

    let mut file = tokio::fs::File::create(&filepath).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let encryptor = Encryptor::with_recipients(vec![Box::new(recipient)]).expect("we provided a recipient");
    let mut async_writer = encryptor.wrap_async_output(file.compat_write()).await.map_err(|e: age::EncryptError| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let data = chunk.map_err(|e: axum::Error| (StatusCode::BAD_REQUEST, e.to_string()))?;
        futures_util::AsyncWriteExt::write_all(&mut async_writer, &data).await.map_err(|e: std::io::Error| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    
    futures_util::AsyncWriteExt::flush(&mut async_writer).await.map_err(|e: std::io::Error| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    futures_util::AsyncWriteExt::close(&mut async_writer).await.map_err(|e: std::io::Error| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(format!("File {} uploaded successfully", filename))
}

async fn unlock(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(payload): Json<UnlockReq>,
) -> Result<String, (StatusCode, String)> {
    if !is_valid_name(&name) {
        return Err((StatusCode::BAD_REQUEST, "Invalid vault name".to_string()));
    }
    
    let vault_dir = state.vaults_dir.join(&name);
    let config_path = vault_dir.join(".inbox-age.config");
    let config_content = tokio::fs::read_to_string(&config_path).await.map_err(|_| (StatusCode::NOT_FOUND, "Vault config missing".to_string()))?;
    
    let mut pub_key_str = String::new();
    for line in config_content.lines() {
        if line.starts_with("public-key: ") {
            pub_key_str = line.trim_start_matches("public-key: ").to_string();
            break;
        }
    }
    
    let keys = derive_keys(&payload.password, &name)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        
    if keys.recipient.to_string() != pub_key_str {
        return Err((StatusCode::UNAUTHORIZED, "Invalid password".to_string()));
    }
    
    let mut vaults = state.unlocked_vaults.write().await;
    vaults.insert(name.clone(), UnlockedVault {
        identity: keys.identity,
        expires_at: Instant::now() + Duration::from_secs(3600),
    });

    Ok(format!("Vault {} unlocked for 1 hour", name))
}

async fn lock(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<String, (StatusCode, String)> {
    let mut vaults = state.unlocked_vaults.write().await;
    if vaults.remove(&name).is_some() {
        Ok(format!("Vault {} locked", name))
    } else {
        Err((StatusCode::NOT_FOUND, "Vault not unlocked".to_string()))
    }
}

async fn list_files(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<Vec<String>>, (StatusCode, String)> {
    if !is_valid_name(&name) {
        return Err((StatusCode::BAD_REQUEST, "Invalid vault name".to_string()));
    }

    let vaults = state.unlocked_vaults.read().await;
    if let Some(vault) = vaults.get(&name) {
        if Instant::now() > vault.expires_at {
            return Err((StatusCode::UNAUTHORIZED, "Vault unlock expired".to_string()));
        }
    } else {
        return Err((StatusCode::UNAUTHORIZED, "Vault is locked".to_string()));
    }

    let vault_dir = state.vaults_dir.join(&name);
    let mut entries = tokio::fs::read_dir(vault_dir).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    let mut files = Vec::new();
    while let Some(entry) = entries.next_entry().await.unwrap_or(None) {
        if let Ok(name) = entry.file_name().into_string() {
            if !name.starts_with('.') {
                files.push(name);
            }
        }
    }

    Ok(Json(files))
}

async fn download_file(
    State(state): State<AppState>,
    Path((name, file)): Path<(String, String)>,
) -> Result<Response, (StatusCode, String)> {
    if !is_valid_name(&name) || !is_valid_name(&file) {
        return Err((StatusCode::BAD_REQUEST, "Invalid name".to_string()));
    }
    
    let identity = {
        let mut vaults = state.unlocked_vaults.write().await;
        if let Some(vault) = vaults.get(&name) {
            if Instant::now() > vault.expires_at {
                vaults.remove(&name);
                return Err((StatusCode::UNAUTHORIZED, "Vault unlock expired".to_string()));
            }
            vault.identity.clone()
        } else {
            return Err((StatusCode::UNAUTHORIZED, "Vault is locked".to_string()));
        }
    };
    
    let filepath = state.vaults_dir.join(&name).join(&file);
    if !filepath.exists() {
        return Err((StatusCode::NOT_FOUND, "File not found".to_string()));
    }
    
    // Decryption is streaming? For download we could just decrypt entirely if it's small, 
    // or stream. The rust age Decryptor requires us to read the header first.
    let fs_file = tokio::fs::File::open(filepath).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // age Decryptor wrap_async is tricky because of multiple files maybe? 
    // age provides `Decryptor::new_async(file).await`
    let decryptor = match Decryptor::new_async(fs_file.compat()).await {
        Ok(Decryptor::Recipients(d)) => d,
        Ok(_) => return Err((StatusCode::BAD_REQUEST, "Passphrase encryption not supported".to_string())),
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    };
    
    let async_reader = decryptor.decrypt_async(std::iter::once(&identity as &dyn age::Identity)).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    
    // we can stream `async_reader` using `tokio_util::io::ReaderStream` but through compat
    use tokio_util::compat::FuturesAsyncReadCompatExt;
    let stream = tokio_util::io::ReaderStream::new(async_reader.compat());
    let body = Body::from_stream(stream);
    
    Ok(axum::response::Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", file))
        .body(body)
        .unwrap())
}
