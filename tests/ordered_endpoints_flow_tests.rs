mod common;

use axum::http::StatusCode;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct GenericRes {
    message: String,
}

#[derive(Debug, Deserialize)]
struct RawListedFile {
    path: String,
    size: u64,
}

#[derive(Debug, Deserialize)]
struct ListedFile {
    path: String,
    filename: Option<String>,
    origin: Option<String>,
    size: u64,
}

#[derive(Debug, Deserialize)]
struct FileMetadata {
    filename: Option<String>,
    origin: Option<String>,
    filesize: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct VaultConfigRes {
    permissions: VaultPermissions,
}

#[derive(Debug, Deserialize)]
struct VaultPermissions {
    allow_subfolders: bool,
    allow_upload: bool,
    allow_download: bool,
    allow_list: bool,
    allow_delete: bool,
    allow_metadata: bool,
    allow_lock_unlock: bool,
}

#[tokio::test]
async fn ordered_full_endpoints_flow() {
    let (base_url, _dir) = common::setup_app().await;
    let client = reqwest::Client::new();

    let vault = "flowvault";
    let password = "mypassword";
    let root_payload = b"root-binary-payload".to_vec();
    let sub_payload = b"subfolder-file-content".to_vec();

    // 1) POST /inbox
    let create_res = client
        .post(format!("{}/inbox", base_url))
        .json(&serde_json::json!({
            "name": vault,
            "password": password,
            "allow_subfolders": true
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(create_res.status(), StatusCode::OK);
    let create_body = create_res.json::<serde_json::Value>().await.unwrap();
    assert_eq!(create_body.get("success").and_then(|v| v.as_bool()), Some(true));
    assert!(create_body.get("public_key").and_then(|v| v.as_str()).is_some());

    // 2) GET /inbox/{name}/config
    let config_res = client
        .get(format!("{}/inbox/{}/config", base_url, vault))
        .send()
        .await
        .unwrap();
    assert_eq!(config_res.status(), StatusCode::OK);
    let config = config_res.json::<VaultConfigRes>().await.unwrap();
    assert!(config.permissions.allow_subfolders);
    assert!(config.permissions.allow_upload);
    assert!(config.permissions.allow_download);
    assert!(config.permissions.allow_list);
    assert!(config.permissions.allow_delete);
    assert!(config.permissions.allow_metadata);
    assert!(config.permissions.allow_lock_unlock);

    // 3) POST /inbox/{name}/upload (raw)
    let upload_root_res = client
        .post(format!("{}/inbox/{}/upload", base_url, vault))
        .body(root_payload.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(upload_root_res.status(), StatusCode::OK);
    let upload_root_body = upload_root_res.json::<GenericRes>().await.unwrap();
    assert!(upload_root_body.message.contains("uploaded successfully"));

    // 4) POST /inbox/{name}/upload/{path} (multipart)
    let form = reqwest::multipart::Form::new()
        .text("filename", "folder.txt")
        .text("origin", "integration-test")
        .text("extended", r#"{"tag":"ordered-flow"}"#)
        .part(
            "file",
            reqwest::multipart::Part::bytes(sub_payload.clone()).file_name("folder.txt"),
        );

    let upload_sub_res = client
        .post(format!("{}/inbox/{}/upload/folder/a", base_url, vault))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(upload_sub_res.status(), StatusCode::OK);
    let upload_sub_body = upload_sub_res.json::<GenericRes>().await.unwrap();
    assert!(upload_sub_body.message.contains("folder/a/upload_"));

    // 5) GET /inbox/{name}/raw/list
    let raw_list_res = client
        .get(format!("{}/inbox/{}/raw/list", base_url, vault))
        .send()
        .await
        .unwrap();
    assert_eq!(raw_list_res.status(), StatusCode::OK);
    let raw_list = raw_list_res.json::<Vec<RawListedFile>>().await.unwrap();
    assert!(raw_list.len() >= 2);

    let root_file_path = raw_list
        .iter()
        .find(|f| !f.path.contains('/'))
        .map(|f| f.path.clone())
        .expect("expected one root file");

    let sub_file_path = raw_list
        .iter()
        .find(|f| f.path.contains("folder/a/"))
        .map(|f| f.path.clone())
        .expect("expected one subfolder file");

    assert!(raw_list.iter().all(|f| f.size > 0));

    // 6) GET /inbox/{name}/raw/download/{path}
    let raw_download_res = client
        .get(format!("{}/inbox/{}/raw/download/{}", base_url, vault, sub_file_path))
        .send()
        .await
        .unwrap();
    assert_eq!(raw_download_res.status(), StatusCode::OK);
    assert_eq!(
        raw_download_res
            .headers()
            .get("accept-ranges")
            .and_then(|v| v.to_str().ok()),
        Some("bytes")
    );
    assert!(raw_download_res.headers().get("content-length").is_some());
    assert!(raw_download_res.headers().get("content-disposition").is_some());
    let raw_download_body = raw_download_res.bytes().await.unwrap();
    assert!(!raw_download_body.is_empty());

    // 7) POST /inbox/{name}/unlock
    let unlock_res = client
        .post(format!("{}/inbox/{}/unlock", base_url, vault))
        .json(&serde_json::json!({ "password": password }))
        .send()
        .await
        .unwrap();
    assert_eq!(unlock_res.status(), StatusCode::OK);
    let unlock_body = unlock_res.json::<GenericRes>().await.unwrap();
    assert!(unlock_body.message.contains("unlocked"));

    // 8) GET /inbox/{name}/list
    let list_res = client
        .get(format!("{}/inbox/{}/list", base_url, vault))
        .send()
        .await
        .unwrap();
    assert_eq!(list_res.status(), StatusCode::OK);
    let listed = list_res.json::<Vec<ListedFile>>().await.unwrap();
    assert!(listed.len() >= 2);
    assert!(listed.iter().all(|f| f.size > 0));

    let listed_sub = listed
        .iter()
        .find(|f| f.path == sub_file_path)
        .expect("subfolder file should be listed");
    assert_eq!(listed_sub.filename.as_deref(), Some("folder.txt"));
    assert_eq!(listed_sub.origin.as_deref(), Some("integration-test"));

    // 9) GET /inbox/{name}/download/{path}
    let download_res = client
        .get(format!("{}/inbox/{}/download/{}", base_url, vault, sub_file_path))
        .send()
        .await
        .unwrap();
    assert_eq!(download_res.status(), StatusCode::OK);
    assert_eq!(
        download_res
            .headers()
            .get("accept-ranges")
            .and_then(|v| v.to_str().ok()),
        Some("bytes")
    );
    assert!(download_res.headers().get("content-disposition").is_some());
    let download_body = download_res.bytes().await.unwrap();
    assert_eq!(download_body.to_vec(), sub_payload);

    // 10) GET /inbox/{name}/metadata/{path}
    let metadata_res = client
        .get(format!("{}/inbox/{}/metadata/{}", base_url, vault, sub_file_path))
        .send()
        .await
        .unwrap();
    assert_eq!(metadata_res.status(), StatusCode::OK);
    let metadata = metadata_res.json::<FileMetadata>().await.unwrap();
    assert_eq!(metadata.filename.as_deref(), Some("folder.txt"));
    assert_eq!(metadata.origin.as_deref(), Some("integration-test"));
    assert!(metadata.filesize.unwrap_or(0) > 0);

    // 11) POST /inbox/{name}/lock
    let lock_res = client
        .post(format!("{}/inbox/{}/lock", base_url, vault))
        .send()
        .await
        .unwrap();
    assert_eq!(lock_res.status(), StatusCode::OK);

    // 12) DELETE /inbox/{name}/raw/delete/{path}
    let raw_delete_res = client
        .delete(format!("{}/inbox/{}/raw/delete/{}", base_url, vault, root_file_path))
        .send()
        .await
        .unwrap();
    assert_eq!(raw_delete_res.status(), StatusCode::OK);

    // 13) Unlock again to test locked-delete endpoint.
    let unlock_again_res = client
        .post(format!("{}/inbox/{}/unlock", base_url, vault))
        .json(&serde_json::json!({ "password": password }))
        .send()
        .await
        .unwrap();
    assert_eq!(unlock_again_res.status(), StatusCode::OK);

    // 14) DELETE /inbox/{name}/delete/{path}
    let delete_res = client
        .delete(format!("{}/inbox/{}/delete/{}", base_url, vault, sub_file_path))
        .send()
        .await
        .unwrap();
    assert_eq!(delete_res.status(), StatusCode::OK);
}

