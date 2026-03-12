use axum::{
    routing::{get, post},
    http::{HeaderName, HeaderValue, Method},
    Router,
};
use std::{env, str::FromStr, time::Duration};
use tower_http::cors::{Any, CorsLayer};

mod config;
mod create_inbox;
mod delete;
mod delete_raw;
mod download;
mod download_raw;
mod list_files;
mod list_files_raw;
mod lock;
mod metadata;
mod types;
mod unlock;
mod upload;
mod validation;
mod vault_config;

pub use types::{AppState, CreateInboxRes, FileMetadata, ListedFile, RawListedFile};

fn env_var(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn parse_csv(raw: &str) -> impl Iterator<Item = &str> {
    raw.split(',').map(str::trim).filter(|v| !v.is_empty())
}

fn parse_bool(raw: &str) -> bool {
    matches!(raw.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

fn cors_layer_from_env() -> Option<CorsLayer> {
    let origins_raw = env_var("CORS_ALLOWED_ORIGINS")?;
    let mut cors = CorsLayer::new();

    if origins_raw == "*" {
        cors = cors.allow_origin(Any);
    } else {
        let origins = parse_csv(&origins_raw)
            .filter_map(|o| HeaderValue::from_str(o).ok())
            .collect::<Vec<_>>();

        if origins.is_empty() {
            tracing::warn!("CORS_ALLOWED_ORIGINS is set but contains no valid origins; CORS disabled");
            return None;
        }

        cors = cors.allow_origin(origins);
    }

    if let Some(methods_raw) = env_var("CORS_ALLOWED_METHODS") {
        if methods_raw == "*" {
            cors = cors.allow_methods(Any);
        } else {
            let methods = parse_csv(&methods_raw)
                .filter_map(|m| Method::from_str(m).ok())
                .collect::<Vec<_>>();

            if !methods.is_empty() {
                cors = cors.allow_methods(methods);
            }
        }
    }

    if let Some(headers_raw) = env_var("CORS_ALLOWED_HEADERS") {
        if headers_raw == "*" {
            cors = cors.allow_headers(Any);
        } else {
            let headers = parse_csv(&headers_raw)
                .filter_map(|h| HeaderName::from_str(h).ok())
                .collect::<Vec<_>>();

            if !headers.is_empty() {
                cors = cors.allow_headers(headers);
            }
        }
    }

    if let Some(expose_raw) = env_var("CORS_EXPOSE_HEADERS") {
        let expose_headers = parse_csv(&expose_raw)
            .filter_map(|h| HeaderName::from_str(h).ok())
            .collect::<Vec<_>>();
        if !expose_headers.is_empty() {
            cors = cors.expose_headers(expose_headers);
        }
    }

    if let Some(credentials_raw) = env_var("CORS_ALLOW_CREDENTIALS") {
        if parse_bool(&credentials_raw) {
            cors = cors.allow_credentials(true);
        }
    }

    if let Some(max_age_raw) = env_var("CORS_MAX_AGE_SECS") {
        if let Ok(max_age) = max_age_raw.parse::<u64>() {
            cors = cors.max_age(Duration::from_secs(max_age));
        }
    }

    Some(cors)
}

/// Builds the API router with all inbox endpoints.
pub fn router(state: AppState) -> Router {
    let router = Router::new()
        .route("/inbox", post(create_inbox::create_inbox))
        .route("/inbox/{name}/config", get(vault_config::get_vault_config))
        .route("/inbox/{name}/upload", post(upload::upload_root))
        .route("/inbox/{name}/upload/{*path}", post(upload::upload_path))
        .route("/inbox/{name}/unlock", post(unlock::unlock))
        .route("/inbox/{name}/lock", post(lock::lock))
        .route("/inbox/{name}/list", get(list_files::list_files))
        .route("/inbox/{name}/download/{*path}", get(download::download_file))
        .route("/inbox/{name}/metadata/{*path}", get(metadata::download_metadata))
        .route("/inbox/{name}/delete/{*path}", axum::routing::delete(delete::delete_file))
        // Raw endpoints (work without vault unlock)
        .route("/inbox/{name}/raw/list", get(list_files_raw::list_files_raw))
        .route("/inbox/{name}/raw/download/{*path}", get(download_raw::download_raw))
        .route("/inbox/{name}/raw/delete/{*path}", axum::routing::delete(delete_raw::delete_raw))
        .with_state(state);

    if let Some(cors) = cors_layer_from_env() {
        tracing::info!("CORS enabled via environment variables");
        router.layer(cors)
    } else {
        router
    }
}