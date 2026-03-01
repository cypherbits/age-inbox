use age_inbox::api::{router, AppState, CreateInboxRes, FileMetadata};
use age_inbox::crypto::derive_keys;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use axum::http::StatusCode;
use serde_json::json;
use tempfile::tempdir;

async fn setup_app() -> (String, tempfile::TempDir) {
    let dir = tempdir().unwrap();
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

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    (format!("http://{}", addr), dir)
}

#[tokio::test]
async fn test_full_flow() {
    let (base_url, _dir) = setup_app().await;
    let client = reqwest::Client::new();

    let res = client
        .post(&format!("{}/inbox", base_url))
        .json(&json!({
            "name": "testvault",
            "password": "mypassword",
            "allow_subfolders": true
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body: CreateInboxRes = res.json().await.unwrap();
    assert!(body.success);

    let res = client
        .post(&format!("{}/inbox", base_url))
        .json(&json!({
            "name": "testvault",
            "password": "mypassword"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT);

    let res = client
        .post(&format!("{}/inbox/testvault/upload", base_url))
        .header("X-Filename", "secret.txt")
        .header("X-File-Origin", "https://example.com")
        .header("X-Extended-Metadata", "{\"key\":\"value\"}")
        .body("hello world raw!")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let form = reqwest::multipart::Form::new()
        .text("filename", "subfile.txt")
        .text("origin", "local")
        .text("extended", "{\"type\":\"doc\"}")
        .text("random_extra", "xyz")
        .part(
            "file",
            reqwest::multipart::Part::bytes(b"hello folder!".to_vec()).file_name("subfile.txt"),
        );

    let res = client
        .post(&format!("{}/inbox/testvault/upload/my/folder", base_url))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let res = client
        .post(&format!("{}/inbox/testvault/unlock", base_url))
        .json(&json!({"password": "mypassword"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let res = client
        .get(&format!("{}/inbox/testvault/list", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let files: Vec<String> = res.json().await.unwrap();
    assert!(!files.is_empty());

    let root_file = files
        .iter()
        .find(|f| !f.starts_with("my/folder") && !f.ends_with(".meta.age"))
        .unwrap();
    let res = client
        .get(&format!(
            "{}/inbox/testvault/download/{}",
            base_url, root_file
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let downloaded_body = res.text().await.unwrap();
    assert_eq!(downloaded_body, "hello world raw!");

    let sub_meta = files
        .iter()
        .find(|f| f.starts_with("my/folder") && f.ends_with(".meta.age"))
        .unwrap();
    let res = client
        .get(&format!(
            "{}/inbox/testvault/download/{}",
            base_url, sub_meta
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let meta_json: FileMetadata = res.json().await.unwrap();
    assert_eq!(meta_json.filename, Some("subfile.txt".to_string()));
}

#[tokio::test]
async fn test_derive_keys() {
    let keys = derive_keys("mypassword", "myvault").unwrap();
    let rec = keys.recipient.to_string();
    assert!(rec.starts_with("age1"));
}
