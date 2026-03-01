mod common;

use age_inbox::api::ListedFile;
use axum::http::StatusCode;

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
    assert!(files.iter().any(|entry| entry.filename.as_deref() == Some("root.txt")));
    assert!(files.iter().any(|entry| entry.origin.as_deref() == Some("unit-test")));
}