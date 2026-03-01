use axum::{
    routing::{get, post},
    Router,
};

mod config;
mod create_inbox;
mod download;
mod list_files;
mod lock;
mod types;
mod unlock;
mod upload;
mod validation;

pub use types::{AppState, CreateInboxRes, FileMetadata};

/// Builds the API router with all inbox endpoints.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/inbox", post(create_inbox::create_inbox))
        .route("/inbox/:name/upload", post(upload::upload_root))
        .route("/inbox/:name/upload/*path", post(upload::upload_path))
        .route("/inbox/:name/unlock", post(unlock::unlock))
        .route("/inbox/:name/lock", post(lock::lock))
        .route("/inbox/:name/list", get(list_files::list_files))
        .route("/inbox/:name/download/*path", get(download::download_file))
        .with_state(state)
}