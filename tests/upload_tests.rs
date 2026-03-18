mod common;

use axum::http::StatusCode;

/// Rejects non-multipart uploads at vault root.
#[tokio::test]
async fn upload_root_rejects_non_multipart() {
    let (base_url, _dir) = common::setup_app().await;
    let client = reqwest::Client::new();
    common::create_vault(&client, &base_url, false).await;

    let response = client
        .post(format!("{}/inbox/testvault/upload", base_url))
        .body("hello world")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
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

/// Uses multipart file part filename when the explicit `filename` field is omitted.
#[tokio::test]
async fn upload_root_uses_file_part_filename_when_missing_filename_field() {
    let (base_url, _dir) = common::setup_app().await;
    let client = reqwest::Client::new();
    common::create_vault(&client, &base_url, false).await;

    let form = reqwest::multipart::Form::new()
        .text("origin", "local")
        .part(
            "file",
            reqwest::multipart::Part::bytes(b"hello".to_vec()).file_name("fallback.txt"),
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

    let files: Vec<age_inbox::api::ListedFile> = list.json().await.unwrap();
    assert!(files
        .iter()
        .any(|entry| entry.filename.as_deref() == Some("fallback.txt")));
}

/// Fails upload when no filename can be resolved from field or file part.
#[tokio::test]
async fn upload_root_fails_without_any_filename() {
    let (base_url, _dir) = common::setup_app().await;
    let client = reqwest::Client::new();
    common::create_vault(&client, &base_url, false).await;

    let form = reqwest::multipart::Form::new().part(
        "file",
        reqwest::multipart::Part::bytes(b"hello".to_vec()),
    );

    let upload = client
        .post(format!("{}/inbox/testvault/upload", base_url))
        .multipart(form)
        .send()
        .await
        .unwrap();

    assert_eq!(upload.status(), StatusCode::BAD_REQUEST);
}

/// Verifies that failed uploads clean up any temporary `.tmp` files.
#[tokio::test]
async fn upload_failure_cleans_up_tmp_files() {
    let (base_url, dir) = common::setup_app().await;
    let client = reqwest::Client::new();
    common::create_vault(&client, &base_url, false).await;

    // Trigger a failure by omitting filename.
    // The server will stream and write the bytes to a .tmp file,
    // but ultimately fail the validation at the end of the multipart processing,
    // which should trigger the cleanup guard.
    let form = reqwest::multipart::Form::new().part(
        "file",
        reqwest::multipart::Part::bytes(b"large broken chunk data...".to_vec()),
    );

    let upload = client
        .post(format!("{}/inbox/testvault/upload", base_url))
        .multipart(form)
        .send()
        .await
        .unwrap();

    assert_eq!(upload.status(), StatusCode::BAD_REQUEST);

    // Verify there are no abandoned files.
    let vault_path = dir.path().join("testvault");
    let mut entries = tokio::fs::read_dir(&vault_path).await.unwrap();
    
    while let Some(entry) = entries.next_entry().await.unwrap() {
        let name = entry.file_name().to_string_lossy().to_string();
        
        assert!(!name.ends_with(".tmp"), "Found leftover tmp file: {}", name);
        assert!(!name.ends_with(".age"), "Found leftover age file: {}", name);
    }
}

/// Verifies that successful uploads do not leave `.tmp` files behind.
#[tokio::test]
async fn upload_success_renames_tmp_files_and_cleans_up() {
    let (base_url, dir) = common::setup_app().await;
    let client = reqwest::Client::new();
    common::create_vault(&client, &base_url, false).await;

    let form = reqwest::multipart::Form::new()
        .text("filename", "perfect.txt")
        .part(
            "file",
            reqwest::multipart::Part::bytes(b"perfect data".to_vec()).file_name("perfect.txt"),
        );

    let upload = client
        .post(format!("{}/inbox/testvault/upload", base_url))
        .multipart(form)
        .send()
        .await
        .unwrap();

    assert_eq!(upload.status(), StatusCode::OK);

    // Verify there are no temporary files, only final .age files
    let vault_path = dir.path().join("testvault");
    let mut entries = tokio::fs::read_dir(&vault_path).await.unwrap();
    
    let mut has_age = false;
    let mut has_meta = false;

    while let Some(entry) = entries.next_entry().await.unwrap() {
        let name = entry.file_name().to_string_lossy().to_string();
        
        assert!(!name.ends_with(".tmp"), "Found leftover tmp file after success: {}", name);
        
        if name.ends_with(".meta.age") {
            has_meta = true;
        } else if name.ends_with(".age") {
            has_age = true;
        }
    }

    assert!(has_age, "Upload should create a final .age file");
    assert!(has_meta, "Upload should create a final .meta.age sidecar");
}

