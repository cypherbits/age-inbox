mod common;

use age_inbox::api::FileMetadata;
use age_inbox::api::ListedFile;
use axum::http::StatusCode;

#[derive(Debug, serde::Deserialize)]
struct RawListedFile {
    path: String,
}

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
            reqwest::multipart::Part::bytes(b"hello world raw!".to_vec()).file_name("secret.txt"),
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
        .get(format!(
            "{}/inbox/testvault/download/{}",
            base_url, root_file
        ))
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

/// Download still works when metadata sidecar is missing (fallback path).
#[tokio::test]
async fn download_without_metadata_sidecar_still_works() {
    let (base_url, dir) = common::setup_app().await;
    let client = reqwest::Client::new();
    common::create_vault(&client, &base_url, true).await;

    let payload = b"fallback-without-meta".to_vec();
    let form = reqwest::multipart::Form::new().part(
        "file",
        reqwest::multipart::Part::bytes(payload.clone()).file_name("nometa.txt"),
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
    let files: Vec<RawListedFile> = raw_list.json().await.unwrap();
    let data_file = files
        .iter()
        .find(|f| f.path.ends_with(".age") && !f.path.ends_with(".meta.age"))
        .map(|f| f.path.clone())
        .expect("expected uploaded data file");

    let meta_file = format!("{}.meta.age", data_file.trim_end_matches(".age"));
    let meta_path = dir.path().join("testvault").join(meta_file);
    tokio::fs::remove_file(meta_path).await.unwrap();

    common::unlock_vault(&client, &base_url, "mypassword").await;

    let downloaded = client
        .get(format!("{}/inbox/testvault/download/{}", base_url, data_file))
        .send()
        .await
        .unwrap();

    assert_eq!(downloaded.status(), StatusCode::OK);
    assert_eq!(downloaded.bytes().await.unwrap().to_vec(), payload);
}

/// If metadata sidecar is missing, Range requests still return partial content.
#[tokio::test]
async fn download_without_metadata_sidecar_with_range_returns_partial_content() {
    let (base_url, dir) = common::setup_app().await;
    let client = reqwest::Client::new();
    common::create_vault(&client, &base_url, true).await;

    let payload = b"range-fallback-no-meta".to_vec();
    let form = reqwest::multipart::Form::new().part(
        "file",
        reqwest::multipart::Part::bytes(payload.clone()).file_name("nometa-range.txt"),
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
    let files: Vec<RawListedFile> = raw_list.json().await.unwrap();
    let data_file = files
        .iter()
        .find(|f| f.path.ends_with(".age") && !f.path.ends_with(".meta.age"))
        .map(|f| f.path.clone())
        .expect("expected uploaded data file");

    let meta_file = format!("{}.meta.age", data_file.trim_end_matches(".age"));
    let meta_path = dir.path().join("testvault").join(meta_file);
    tokio::fs::remove_file(meta_path).await.unwrap();

    common::unlock_vault(&client, &base_url, "mypassword").await;

    let downloaded = client
        .get(format!("{}/inbox/testvault/download/{}", base_url, data_file))
        .header("Range", "bytes=0-4")
        .send()
        .await
        .unwrap();

    assert_eq!(downloaded.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(downloaded.bytes().await.unwrap().to_vec(), b"range".to_vec());
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
        .get(format!(
            "{}/inbox/testvault/download/{}",
            base_url, meta_file
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(invalid_download.status(), StatusCode::BAD_REQUEST);

    let metadata_response = client
        .get(format!(
            "{}/inbox/testvault/metadata/{}",
            base_url, data_file
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(metadata_response.status(), StatusCode::OK);
    let metadata: FileMetadata = metadata_response.json().await.unwrap();
    assert_eq!(metadata.filename, Some("subfile.txt".to_string()));
    assert_eq!(metadata.origin, Some("local".to_string()));
    assert!(
        metadata.filesize.is_some(),
        "Metadata should include filesize"
    );
    assert!(
        metadata.filesize.unwrap() > 0,
        "filesize should be positive"
    );
}

/// Download endpoint supports HTTP Range header on decrypted content.
#[tokio::test]
async fn download_range_returns_partial_content() {
    let (base_url, _dir) = common::setup_app().await;
    let client = reqwest::Client::new();
    common::create_vault(&client, &base_url, true).await;

    let original_content = b"hello world for range test!";
    let form = reqwest::multipart::Form::new()
        .text("filename", "rangetest.txt")
        .part(
            "file",
            reqwest::multipart::Part::bytes(original_content.to_vec()).file_name("rangetest.txt"),
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
    let data_file = files
        .iter()
        .map(|f| f.path.clone())
        .find(|f| f.ends_with(".age") && !f.ends_with(".meta.age"))
        .unwrap();

    // Range request: bytes 0-4 should return "hello"
    let range_response = client
        .get(format!(
            "{}/inbox/testvault/download/{}",
            base_url, data_file
        ))
        .header("Range", "bytes=0-4")
        .send()
        .await
        .unwrap();
    assert_eq!(range_response.status(), StatusCode::PARTIAL_CONTENT);
    assert!(range_response.headers().get("content-range").is_some());
    assert!(range_response.headers().get("accept-ranges").is_some());
    let partial = range_response.text().await.unwrap();
    assert_eq!(partial, "hello");
}

/// Out-of-bounds range requests return 416 with unsatisfied Content-Range.
#[tokio::test]
async fn download_range_unsatisfied_returns_416() {
    let (base_url, _dir) = common::setup_app().await;
    let client = reqwest::Client::new();
    common::create_vault(&client, &base_url, true).await;

    let form = reqwest::multipart::Form::new().part(
        "file",
        reqwest::multipart::Part::bytes(b"abc".to_vec()).file_name("tiny.txt"),
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
    let data_file = files
        .iter()
        .map(|f| f.path.clone())
        .find(|f| f.ends_with(".age") && !f.ends_with(".meta.age"))
        .unwrap();

    let response = client
        .get(format!("{}/inbox/testvault/download/{}", base_url, data_file))
        .header("Range", "bytes=100-200")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        response
            .headers()
            .get("content-range")
            .and_then(|h| h.to_str().ok()),
        Some("bytes */3")
    );
}

/// Open-ended ranges (bytes=start-) return partial content from start to end.
#[tokio::test]
async fn download_range_open_ended_returns_partial_content() {
    let (base_url, _dir) = common::setup_app().await;
    let client = reqwest::Client::new();
    common::create_vault(&client, &base_url, true).await;

    let original_content = b"hello world for range test!";
    let form = reqwest::multipart::Form::new().part(
        "file",
        reqwest::multipart::Part::bytes(original_content.to_vec()).file_name("open-ended.txt"),
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
    let data_file = files
        .iter()
        .map(|f| f.path.clone())
        .find(|f| f.ends_with(".age") && !f.ends_with(".meta.age"))
        .unwrap();

    let response = client
        .get(format!("{}/inbox/testvault/download/{}", base_url, data_file))
        .header("Range", "bytes=6-")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    let partial = response.text().await.unwrap();
    assert_eq!(partial, "world for range test!");
}

