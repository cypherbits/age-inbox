mod common;

use age_inbox::api::RawListedFile;
use axum::http::StatusCode;

/// Raw list endpoint works without unlocking the vault.
#[tokio::test]
async fn raw_list_without_unlock() {
    let (base_url, _dir) = common::setup_app().await;
    let client = reqwest::Client::new();
    common::create_vault(&client, &base_url, true).await;

    let form = reqwest::multipart::Form::new()
        .text("filename", "rawfile.txt")
        .part(
            "file",
            reqwest::multipart::Part::bytes(b"raw list test data".to_vec())
                .file_name("rawfile.txt"),
        );

    let upload = client
        .post(format!("{}/inbox/testvault/upload", base_url))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(upload.status(), StatusCode::OK);

    // List without unlocking — should work
    let list = client
        .get(format!("{}/inbox/testvault/raw/list", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), StatusCode::OK);

    let files: Vec<RawListedFile> = list.json().await.unwrap();
    assert!(!files.is_empty());
    assert!(files.iter().all(|f| f.path.ends_with(".age")));
    assert!(files.iter().all(|f| !f.path.ends_with(".meta.age")));
    assert!(files.iter().all(|f| f.size > 0));
}

/// Raw list returns 404 for a non-existent vault.
#[tokio::test]
async fn raw_list_vault_not_found() {
    let (base_url, _dir) = common::setup_app().await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/inbox/nonexistent/raw/list", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
