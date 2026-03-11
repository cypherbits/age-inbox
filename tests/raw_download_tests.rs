mod common;

use axum::http::StatusCode;

/// Raw download serves the encrypted file without unlock.
#[tokio::test]
async fn raw_download_without_unlock() {
    let (base_url, _dir) = common::setup_app().await;
    let client = reqwest::Client::new();
    common::create_vault(&client, &base_url, true).await;

    let form = reqwest::multipart::Form::new()
        .text("filename", "secret.bin")
        .part(
            "file",
            reqwest::multipart::Part::bytes(b"encrypted content test".to_vec())
                .file_name("secret.bin"),
        );

    let upload = client
        .post(format!("{}/inbox/testvault/upload", base_url))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(upload.status(), StatusCode::OK);

    // Get file path from raw list (no unlock)
    let list = client
        .get(format!("{}/inbox/testvault/raw/list", base_url))
        .send()
        .await
        .unwrap();
    let files: Vec<serde_json::Value> = list.json().await.unwrap();
    let file_path = files[0]["path"].as_str().unwrap().to_string();

    // Download raw (encrypted) — should work without unlock
    let response = client
        .get(format!("{}/inbox/testvault/raw/download/{}", base_url, file_path))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("accept-ranges").is_some());
    assert!(response.headers().get("content-length").is_some());

    let body = response.bytes().await.unwrap();
    // The content should be encrypted (Age header starts with "age-encryption.org")
    assert!(body.len() > 0);
    let header_text = String::from_utf8_lossy(&body[..core::cmp::min(40, body.len())]);
    assert!(
        header_text.contains("age-encryption.org"),
        "Raw download should return encrypted content"
    );
}

/// Raw download supports HTTP Range header.
#[tokio::test]
async fn raw_download_range_request() {
    let (base_url, _dir) = common::setup_app().await;
    let client = reqwest::Client::new();
    common::create_vault(&client, &base_url, true).await;

    let form = reqwest::multipart::Form::new()
        .text("filename", "rangefile.bin")
        .part(
            "file",
            reqwest::multipart::Part::bytes(b"range test data for raw download".to_vec())
                .file_name("rangefile.bin"),
        );

    let upload = client
        .post(format!("{}/inbox/testvault/upload", base_url))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(upload.status(), StatusCode::OK);

    let list = client
        .get(format!("{}/inbox/testvault/raw/list", base_url))
        .send()
        .await
        .unwrap();
    let files: Vec<serde_json::Value> = list.json().await.unwrap();
    let file_path = files[0]["path"].as_str().unwrap().to_string();

    // Full download to know total size
    let full = client
        .get(format!("{}/inbox/testvault/raw/download/{}", base_url, file_path))
        .send()
        .await
        .unwrap();
    let full_body = full.bytes().await.unwrap();

    // Partial range request
    let range_response = client
        .get(format!("{}/inbox/testvault/raw/download/{}", base_url, file_path))
        .header("Range", "bytes=0-9")
        .send()
        .await
        .unwrap();
    assert_eq!(range_response.status(), StatusCode::PARTIAL_CONTENT);
    assert!(range_response.headers().get("content-range").is_some());
    let range_body = range_response.bytes().await.unwrap();
    assert_eq!(range_body.len(), 10);
    assert_eq!(&range_body[..], &full_body[..10]);
}

/// Raw download returns 404 for non-existent vault.
#[tokio::test]
async fn raw_download_vault_not_found() {
    let (base_url, _dir) = common::setup_app().await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/inbox/nonexistent/raw/download/test.age", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// Raw download rejects .meta.age files.
#[tokio::test]
async fn raw_download_rejects_meta_age() {
    let (base_url, _dir) = common::setup_app().await;
    let client = reqwest::Client::new();
    common::create_vault(&client, &base_url, true).await;

    let response = client
        .get(format!(
            "{}/inbox/testvault/raw/download/test.meta.age",
            base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
