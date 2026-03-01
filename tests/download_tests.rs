mod common;

use age_inbox::api::FileMetadata;
use age_inbox::api::ListedFile;
use axum::http::StatusCode;

/// Download endpoint decrypts uploaded raw files.
#[tokio::test]
async fn download_returns_decrypted_file() {
    let (base_url, _dir) = common::setup_app().await;
    let client = reqwest::Client::new();
    common::create_vault(&client, &base_url, true).await;

    let form = reqwest::multipart::Form::new()
        .text("filename", "secret.txt")
        .part(
            "file",
            reqwest::multipart::Part::bytes(b"hello world raw!".to_vec())
                .file_name("secret.txt"),
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
    let files: Vec<ListedFile> = list.json().await.unwrap();

    let root_file = files
        .iter()
        .map(|f| f.path.clone())
        .find(|f| f.ends_with(".age") && !f.ends_with(".meta.age"))
        .unwrap()
        .to_string();

    let downloaded = client
        .get(format!("{}/inbox/testvault/download/{}", base_url, root_file))
        .send()
        .await
        .unwrap();

    assert_eq!(downloaded.status(), StatusCode::OK);
    let content_disposition = downloaded
        .headers()
        .get("content-disposition")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    assert!(content_disposition.contains("filename=\"secret.txt\""));
    assert!(!content_disposition.contains(".age\""));
    assert_eq!(downloaded.text().await.unwrap(), "hello world raw!");
}

/// Metadata is exposed via dedicated endpoint and metadata sidecars are rejected by download.
#[tokio::test]
async fn metadata_endpoint_returns_json_and_download_rejects_sidecar() {
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
    let files: Vec<ListedFile> = list.json().await.unwrap();

    let data_file = files
        .iter()
        .map(|f| f.path.clone())
        .find(|f| f.ends_with(".age") && !f.ends_with(".meta.age"))
        .unwrap()
        .to_string();

    let meta_file = format!("{}.meta.age", data_file.trim_end_matches(".age"));

    let invalid_download = client
        .get(format!("{}/inbox/testvault/download/{}", base_url, meta_file))
        .send()
        .await
        .unwrap();

    assert_eq!(invalid_download.status(), StatusCode::BAD_REQUEST);

    let metadata_response = client
        .get(format!("{}/inbox/testvault/metadata/{}", base_url, data_file))
        .send()
        .await
        .unwrap();

    assert_eq!(metadata_response.status(), StatusCode::OK);
    let metadata: FileMetadata = metadata_response.json().await.unwrap();
    assert_eq!(metadata.filename, Some("subfile.txt".to_string()));
    assert_eq!(metadata.origin, Some("local".to_string()));
}