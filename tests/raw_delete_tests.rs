mod common;

use axum::http::StatusCode;

/// Raw delete endpoint removes files and metadata regardless of lock state.
#[tokio::test]
async fn raw_delete_file_removes_file_and_metadata() {
    let (base_url, _dir) = common::setup_app().await;
    let client = reqwest::Client::new();
    common::create_vault(&client, &base_url, true).await;

    // Upload a file
    let form = reqwest::multipart::Form::new()
        .text("filename", "test.txt")
        .part(
            "file",
            reqwest::multipart::Part::bytes(b"test content".to_vec())
                .file_name("test.txt"),
        );

    let upload = client
        .post(format!("{}/inbox/testvault/upload", base_url))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(upload.status(), StatusCode::OK);

    // Get file path from raw list (works without unlock)
    let list = client
        .get(format!("{}/inbox/testvault/raw/list", base_url))
        .send()
        .await
        .unwrap();
    let files: Vec<age_inbox::api::RawListedFile> = list.json().await.unwrap();

    let file_path = files
        .iter()
        .map(|f| f.path.clone())
        .find(|f| f.ends_with(".age") && !f.ends_with(".meta.age"))
        .unwrap()
        .to_string();

    // Delete the file using raw endpoint (without unlocking)
    let delete = client
        .delete(format!("{}/inbox/testvault/raw/delete/{}", base_url, file_path))
        .send()
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::OK);

    // Verify file is deleted
    let list_after = client
        .get(format!("{}/inbox/testvault/raw/list", base_url))
        .send()
        .await
        .unwrap();
    let files_after: Vec<age_inbox::api::RawListedFile> = list_after.json().await.unwrap();
    assert!(!files_after.iter().any(|f| f.path == file_path));
}

/// Raw delete endpoint works when vault is locked.
#[tokio::test]
async fn raw_delete_file_works_when_locked() {
    let (base_url, _dir) = common::setup_app().await;
    let client = reqwest::Client::new();
    common::create_vault(&client, &base_url, true).await;

    // Upload a file
    let form = reqwest::multipart::Form::new()
        .text("filename", "test.txt")
        .part(
            "file",
            reqwest::multipart::Part::bytes(b"test content".to_vec())
                .file_name("test.txt"),
        );

    let upload = client
        .post(format!("{}/inbox/testvault/upload", base_url))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(upload.status(), StatusCode::OK);

    // Get file path from raw list
    let list = client
        .get(format!("{}/inbox/testvault/raw/list", base_url))
        .send()
        .await
        .unwrap();
    let files: Vec<age_inbox::api::RawListedFile> = list.json().await.unwrap();

    let file_path = files
        .iter()
        .map(|f| f.path.clone())
        .find(|f| f.ends_with(".age") && !f.ends_with(".meta.age"))
        .unwrap()
        .to_string();

    // Delete while vault is locked (should work for raw endpoint)
    let delete = client
        .delete(format!("{}/inbox/testvault/raw/delete/{}", base_url, file_path))
        .send()
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::OK);

    // Verify file is deleted
    let list_after = client
        .get(format!("{}/inbox/testvault/raw/list", base_url))
        .send()
        .await
        .unwrap();
    let files_after: Vec<age_inbox::api::RawListedFile> = list_after.json().await.unwrap();
    assert!(!files_after.iter().any(|f| f.path == file_path));
}

/// Raw delete endpoint returns 404 when file doesn't exist.
#[tokio::test]
async fn raw_delete_file_returns_404_when_not_found() {
    let (base_url, _dir) = common::setup_app().await;
    let client = reqwest::Client::new();
    common::create_vault(&client, &base_url, true).await;

    // Try to delete non-existent file
    let delete = client
        .delete(format!("{}/inbox/testvault/raw/delete/nonexistent.age", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::NOT_FOUND);
}

/// Raw delete endpoint removes metadata file if it exists.
#[tokio::test]
async fn raw_delete_file_removes_metadata() {
    let (base_url, _dir) = common::setup_app().await;
    let client = reqwest::Client::new();
    common::create_vault(&client, &base_url, true).await;

    // Upload a file
    let form = reqwest::multipart::Form::new()
        .text("filename", "test.txt")
        .part(
            "file",
            reqwest::multipart::Part::bytes(b"test content".to_vec())
                .file_name("test.txt"),
        );

    let upload = client
        .post(format!("{}/inbox/testvault/upload", base_url))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(upload.status(), StatusCode::OK);

    // Get file path from raw list
    let list = client
        .get(format!("{}/inbox/testvault/raw/list", base_url))
        .send()
        .await
        .unwrap();
    let files: Vec<age_inbox::api::RawListedFile> = list.json().await.unwrap();

    let file_path = files
        .iter()
        .map(|f| f.path.clone())
        .find(|f| f.ends_with(".age") && !f.ends_with(".meta.age"))
        .unwrap()
        .to_string();

    let metadata_path = file_path.replace(".age", ".meta.age");

    // Delete the file (should also delete metadata)
    let delete = client
        .delete(format!("{}/inbox/testvault/raw/delete/{}", base_url, file_path))
        .send()
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::OK);

    // Verify both file and metadata are deleted
    let list_after = client
        .get(format!("{}/inbox/testvault/raw/list", base_url))
        .send()
        .await
        .unwrap();
    let files_after: Vec<age_inbox::api::RawListedFile> = list_after.json().await.unwrap();
    assert!(!files_after.iter().any(|f| f.path == file_path));
    assert!(!files_after.iter().any(|f| f.path == metadata_path));
}

