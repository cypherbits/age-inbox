mod common;

use age_inbox::api::ListedFile;
use axum::http::StatusCode;
use serde_json::Value;

fn sidecar_path_from_encrypted(path: &str) -> String {
    format!("{}.meta.age", path.trim_end_matches(".age"))
}

/// List endpoint requires vault to be unlocked first.
#[tokio::test]
async fn list_requires_unlock() {
    let (base_url, _dir) = common::setup_app().await;
    let client = reqwest::Client::new();
    common::create_vault(&client, &base_url, true).await;

    let response = client
        .get(format!("{}/inbox/testvault/list", base_url))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// List endpoint returns uploaded files after unlock.
#[tokio::test]
async fn list_returns_uploaded_files() {
    let (base_url, _dir) = common::setup_app().await;
    let client = reqwest::Client::new();
    common::create_vault(&client, &base_url, true).await;

    let form = reqwest::multipart::Form::new()
        .text("filename", "root.txt")
        .text("origin", "unit-test")
        .part(
            "file",
            reqwest::multipart::Part::bytes(b"hello".to_vec()).file_name("root.txt"),
        );

    let upload = client
        .post(format!("{}/inbox/testvault/upload", base_url))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(upload.status(), StatusCode::OK);

    common::unlock_vault(&client, &base_url, "mypassword").await;

    let list = client
        .get(format!("{}/inbox/testvault/list", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);

    let files: Vec<ListedFile> = list.json().await.unwrap();
    assert!(!files.is_empty());
    assert!(files.iter().all(|entry| entry.path.ends_with(".age")));
    assert!(files.iter().all(|entry| !entry.path.ends_with(".meta.age")));
    assert!(files
        .iter()
        .any(|entry| entry.filename.as_deref() == Some("root.txt")));
    assert!(files
        .iter()
        .any(|entry| entry.origin.as_deref() == Some("unit-test")));
    assert!(files.iter().all(|entry| entry.size > 0));
}

/// List endpoint keeps listing files (with size) when sidecar metadata is missing.
#[tokio::test]
async fn list_warns_and_falls_back_when_metadata_is_missing() {
    let (base_url, dir) = common::setup_app().await;
    let client = reqwest::Client::new();
    common::create_vault(&client, &base_url, true).await;

    let form = reqwest::multipart::Form::new()
        .text("filename", "no-meta.txt")
        .text("origin", "unit-test")
        .part(
            "file",
            reqwest::multipart::Part::bytes(b"hello without metadata".to_vec())
                .file_name("no-meta.txt"),
        );

    let upload = client
        .post(format!("{}/inbox/testvault/upload", base_url))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(upload.status(), StatusCode::OK);

    let raw_list = client
        .get(format!("{}/inbox/testvault/raw/list", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(raw_list.status(), StatusCode::OK);
    let files: Vec<Value> = raw_list.json().await.unwrap();
    let encrypted_path = files
        .first()
        .and_then(|v| v.get("path"))
        .and_then(Value::as_str)
        .unwrap()
        .to_string();

    let sidecar = dir
        .path()
        .join("testvault")
        .join(sidecar_path_from_encrypted(&encrypted_path));
    tokio::fs::remove_file(sidecar).await.unwrap();

    common::unlock_vault(&client, &base_url, "mypassword").await;

    let list = client
        .get(format!("{}/inbox/testvault/list", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);

    let files: Vec<ListedFile> = list.json().await.unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].filename, None);
    assert_eq!(files[0].origin, None);
    assert!(files[0].size > 0);
}

/// List endpoint fails when metadata decryption/parsing fails.
#[tokio::test]
async fn list_errors_when_metadata_sidecar_is_corrupted() {
    let (base_url, dir) = common::setup_app().await;
    let client = reqwest::Client::new();
    common::create_vault(&client, &base_url, true).await;

    let form = reqwest::multipart::Form::new()
        .text("filename", "bad-meta.txt")
        .text("origin", "unit-test")
        .part(
            "file",
            reqwest::multipart::Part::bytes(b"hello with broken metadata".to_vec())
                .file_name("bad-meta.txt"),
        );

    let upload = client
        .post(format!("{}/inbox/testvault/upload", base_url))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(upload.status(), StatusCode::OK);

    let raw_list = client
        .get(format!("{}/inbox/testvault/raw/list", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(raw_list.status(), StatusCode::OK);
    let files: Vec<Value> = raw_list.json().await.unwrap();
    let encrypted_path = files
        .first()
        .and_then(|v| v.get("path"))
        .and_then(Value::as_str)
        .unwrap()
        .to_string();

    let sidecar = dir
        .path()
        .join("testvault")
        .join(sidecar_path_from_encrypted(&encrypted_path));
    tokio::fs::write(sidecar, b"not-age-data").await.unwrap();

    common::unlock_vault(&client, &base_url, "mypassword").await;

    let list = client
        .get(format!("{}/inbox/testvault/list", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

