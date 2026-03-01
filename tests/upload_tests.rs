mod common;

use axum::http::StatusCode;

/// Accepts raw body uploads at vault root.
#[tokio::test]
async fn upload_root_raw_success() {
    let (base_url, _dir) = common::setup_app().await;
    let client = reqwest::Client::new();
    common::create_vault(&client, &base_url, false).await;

    let response = client
        .post(format!("{}/inbox/testvault/upload", base_url))
        .header("X-Filename", "root.txt")
        .header("X-File-Origin", "unit-test")
        .body("hello world")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

/// Rejects subfolder uploads when vault config forbids them.
#[tokio::test]
async fn upload_subfolder_forbidden_when_disabled() {
    let (base_url, _dir) = common::setup_app().await;
    let client = reqwest::Client::new();
    common::create_vault(&client, &base_url, false).await;

    let form = reqwest::multipart::Form::new().part(
        "file",
        reqwest::multipart::Part::bytes(b"hello".to_vec()).file_name("sub.txt"),
    );

    let response = client
        .post(format!("{}/inbox/testvault/upload/my/folder", base_url))
        .multipart(form)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// Accepts multipart uploads in allowed subfolders.
#[tokio::test]
async fn upload_subfolder_multipart_success() {
    let (base_url, _dir) = common::setup_app().await;
    let client = reqwest::Client::new();
    common::create_vault(&client, &base_url, true).await;

    let form = reqwest::multipart::Form::new()
        .text("origin", "local")
        .text("filename", "doc.txt")
        .part(
            "file",
            reqwest::multipart::Part::bytes(b"folder-data".to_vec()).file_name("doc.txt"),
        );

    let response = client
        .post(format!("{}/inbox/testvault/upload/folder/a", base_url))
        .multipart(form)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}