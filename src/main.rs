mod api;
mod crypto;

use api::AppState;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();
    
    let vaults_dir = std::path::PathBuf::from("./vaults");
    tokio::fs::create_dir_all(&vaults_dir).await.unwrap();

    let state = AppState {
        unlocked_vaults: Arc::new(RwLock::new(HashMap::new())),
        vaults_dir,
    };

    let app = api::router(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    tracing::info!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
