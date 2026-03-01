mod common;

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

    let upload = client
        .post(format!("{}/inbox/testvault/upload", base_url))
        .header("X-Filename", "root.txt")
        .body("hello")
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

    let files: Vec<String> = list.json().await.unwrap();
    assert!(!files.is_empty());
    assert!(files.iter().any(|name| name.ends_with(".age")));
}