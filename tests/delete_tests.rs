mod common;

use axum::http::StatusCode;

/// Delete endpoint removes files and metadata when vault is unlocked.
#[tokio::test]
async fn delete_file_removes_file_and_metadata() {
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

    // Unlock the vault
    common::unlock_vault(&client, &base_url, "mypassword").await;

    // List files to get the filename
    let list = client
        .get(format!("{}/inbox/testvault/list", base_url))
        .send()
        .await
        .unwrap();
    let files: Vec<age_inbox::api::ListedFile> = list.json().await.unwrap();

    let file_path = files
        .iter()
        .map(|f| f.path.clone())
        .find(|f| f.ends_with(".age") && !f.ends_with(".meta.age"))
        .unwrap()
        .to_string();

    // Delete the file
    let delete = client
        .delete(format!("{}/inbox/testvault/delete/{}", base_url, file_path))
        .send()
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::OK);

    // Verify file is deleted
    let list_after = client
        .get(format!("{}/inbox/testvault/list", base_url))
        .send()
        .await
        .unwrap();
    let files_after: Vec<age_inbox::api::ListedFile> = list_after.json().await.unwrap();
    assert!(!files_after.iter().any(|f| f.path == file_path));
}

/// Delete endpoint fails when vault is locked.
#[tokio::test]
async fn delete_file_fails_when_locked() {
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

    // Unlock the vault to list files
    common::unlock_vault(&client, &base_url, "mypassword").await;

    let list = client
        .get(format!("{}/inbox/testvault/list", base_url))
        .send()
        .await
        .unwrap();
    let files: Vec<age_inbox::api::ListedFile> = list.json().await.unwrap();

    let file_path = files
        .iter()
        .map(|f| f.path.clone())
        .find(|f| f.ends_with(".age") && !f.ends_with(".meta.age"))
        .unwrap()
        .to_string();

    // Lock the vault
    common::lock_vault(&client, &base_url).await;

    // Try to delete while locked
    let delete = client
        .delete(format!("{}/inbox/testvault/delete/{}", base_url, file_path))
        .send()
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::FORBIDDEN);
}

/// Delete endpoint returns 404 when file doesn't exist.
#[tokio::test]
async fn delete_file_returns_404_when_not_found() {
    let (base_url, _dir) = common::setup_app().await;
    let client = reqwest::Client::new();
    common::create_vault(&client, &base_url, true).await;

    // Unlock the vault
    common::unlock_vault(&client, &base_url, "mypassword").await;

    // Try to delete non-existent file
    let delete = client
        .delete(format!("{}/inbox/testvault/delete/nonexistent.age", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(delete.status(), StatusCode::NOT_FOUND);
}

