use age::x25519::Identity;
use axum::{http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tokio::sync::RwLock;
use tokio::time::Instant;

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

pub type ApiError = (StatusCode, Json<ErrorRes>);

pub fn make_error(code: StatusCode, msg: impl Into<String>) -> ApiError {
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filesize: Option<u64>,
    #[serde(flatten)]
    pub extended: HashMap<String, serde_json::Value>,
}

#[derive(Serialize, Deserialize)]
pub struct ListedFile {
    pub path: String,
    pub filename: Option<String>,
    pub origin: Option<String>,
    pub size: u64,
}

#[derive(Serialize, Deserialize)]
pub struct RawListedFile {
    pub path: String,
    pub size: u64,
}

pub fn permission_denied() -> ApiError {
    make_error(StatusCode::FORBIDDEN, "Permission denied for this operation")
}

