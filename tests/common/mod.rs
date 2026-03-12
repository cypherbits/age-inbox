#![allow(dead_code)]

use age_inbox::api::{router, AppState};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Bootstraps an in-memory test server and isolated vault directory.
pub async fn setup_app() -> (String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState {
        unlocked_vaults: Arc::new(RwLock::new(HashMap::new())),
        vaults_dir: dir.path().to_path_buf(),
    };

    let app = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;
    (format!("http://{}", addr), dir)
}

/// Creates a vault with default password for tests.
pub async fn create_vault(client: &reqwest::Client, base_url: &str, allow_subfolders: bool) {
    let response = client
        .post(format!("{}/inbox", base_url))
        .json(&json!({
            "name": "testvault",
            "password": "mypassword",
            "allow_subfolders": allow_subfolders
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
}

/// Unlocks the default test vault.
pub async fn unlock_vault(client: &reqwest::Client, base_url: &str, password: &str) {
    let response = client
        .post(format!("{}/inbox/testvault/unlock", base_url))
        .json(&json!({ "password": password }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
}

/// Locks the default test vault.
pub async fn lock_vault(client: &reqwest::Client, base_url: &str) {
    let response = client
        .post(format!("{}/inbox/testvault/lock", base_url))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
}
