mod common;

use age_inbox::api::FileMetadata;
use axum::http::StatusCode;

/// Download endpoint decrypts uploaded raw files.
#[tokio::test]
async fn download_returns_decrypted_file() {
    let (base_url, _dir) = common::setup_app().await;
    let client = reqwest::Client::new();
    common::create_vault(&client, &base_url, true).await;

    let upload = client
        .post(format!("{}/inbox/testvault/upload", base_url))
        .header("X-Filename", "secret.txt")
        .body("hello world raw!")
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
    let files: Vec<String> = list.json().await.unwrap();

    let root_file = files
        .iter()
        .find(|f| !f.ends_with(".meta.age"))
        .unwrap()
        .to_owned();

    let downloaded = client
        .get(format!("{}/inbox/testvault/download/{}", base_url, root_file))
        .send()
        .await
        .unwrap();

    assert_eq!(downloaded.status(), StatusCode::OK);
    assert_eq!(downloaded.text().await.unwrap(), "hello world raw!");
}

/// Metadata files are also decrypted and returned as JSON payloads.
#[tokio::test]
async fn download_metadata_json() {
    let (base_url, _dir) = common::setup_app().await;
    let client = reqwest::Client::new();
    common::create_vault(&client, &base_url, true).await;

    let form = reqwest::multipart::Form::new()
        .text("filename", "subfile.txt")
        .text("origin", "local")
        .text("extended", "{\"type\":\"doc\"}")
        .part(
            "file",
            reqwest::multipart::Part::bytes(b"hello folder!".to_vec()).file_name("subfile.txt"),
        );

    let upload = client
        .post(format!("{}/inbox/testvault/upload/sub/path", base_url))
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
    let files: Vec<String> = list.json().await.unwrap();

    let meta_file = files
        .iter()
        .find(|f| f.ends_with(".meta.age"))
        .unwrap()
        .to_owned();

    let metadata_response = client
        .get(format!("{}/inbox/testvault/download/{}", base_url, meta_file))
        .send()
        .await
        .unwrap();

    assert_eq!(metadata_response.status(), StatusCode::OK);
    let metadata: FileMetadata = metadata_response.json().await.unwrap();
    assert_eq!(metadata.filename, Some("subfile.txt".to_string()));
    assert_eq!(metadata.origin, Some("local".to_string()));
}