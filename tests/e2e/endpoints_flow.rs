use super::common;
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
async fn ordered_full_endpoints_flow_e2e() {
    let mut server = common::spawn_server().await;
    let client = reqwest::Client::new();

    let vault = "flowvault";
    let password = "mypassword";
    let root_payload = b"root-binary-payload".to_vec();
    let sub_payload = b"subfolder-file-content".to_vec();

    let create_res = client
        .post(format!("{}/inbox", server.base_url))
        .json(&serde_json::json!({
            "name": vault,
            "password": password,
            "permissions": {
                "allow_subfolders": true
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(create_res.status(), StatusCode::OK);
    let create_body = create_res.json::<serde_json::Value>().await.unwrap();
    assert_eq!(
        create_body.get("success").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert!(create_body
        .get("public_key")
        .and_then(|v| v.as_str())
        .is_some());

    let config_res = client
        .get(format!("{}/inbox/{}/config", server.base_url, vault))
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

    let root_form = reqwest::multipart::Form::new().part(
        "file",
        reqwest::multipart::Part::bytes(root_payload.clone()).file_name("root.bin"),
    );

    let upload_root_res = client
        .post(format!("{}/inbox/{}/upload", server.base_url, vault))
        .multipart(root_form)
        .send()
        .await
        .unwrap();
    assert_eq!(upload_root_res.status(), StatusCode::OK);
    let upload_root_body = upload_root_res.json::<GenericRes>().await.unwrap();
    assert!(upload_root_body.message.contains("uploaded successfully"));

    let form = reqwest::multipart::Form::new()
        .text("filename", "folder.txt")
        .text("origin", "integration-test")
        .text("extended", r#"{"tag":"ordered-flow"}"#)
        .part(
            "file",
            reqwest::multipart::Part::bytes(sub_payload.clone()).file_name("folder.txt"),
        );

    let upload_sub_res = client
        .post(format!("{}/inbox/{}/upload/folder/a", server.base_url, vault))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(upload_sub_res.status(), StatusCode::OK);
    let upload_sub_body = upload_sub_res.json::<GenericRes>().await.unwrap();
    assert!(upload_sub_body.message.contains("folder/a/drop-"));

    let raw_list_res = client
        .get(format!("{}/inbox/{}/raw/list", server.base_url, vault))
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

    let raw_download_res = client
        .get(format!(
            "{}/inbox/{}/raw/download/{}",
            server.base_url, vault, sub_file_path
        ))
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
    assert!(raw_download_res
        .headers()
        .get("content-disposition")
        .is_some());
    let raw_download_body = raw_download_res.bytes().await.unwrap();
    assert!(!raw_download_body.is_empty());

    let unlock_res = client
        .post(format!("{}/inbox/{}/unlock", server.base_url, vault))
        .json(&serde_json::json!({ "password": password }))
        .send()
        .await
        .unwrap();
    assert_eq!(unlock_res.status(), StatusCode::OK);
    let unlock_body = unlock_res.json::<GenericRes>().await.unwrap();
    assert!(unlock_body.message.contains("unlocked"));

    let list_res = client
        .get(format!("{}/inbox/{}/list", server.base_url, vault))
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

    let download_res = client
        .get(format!(
            "{}/inbox/{}/download/{}",
            server.base_url, vault, sub_file_path
        ))
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

    let root_download_res = client
        .get(format!(
            "{}/inbox/{}/download/{}",
            server.base_url, vault, root_file_path
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(root_download_res.status(), StatusCode::OK);
    let root_download_body = root_download_res.bytes().await.unwrap();
    assert_eq!(root_download_body.to_vec(), root_payload);

    let metadata_res = client
        .get(format!(
            "{}/inbox/{}/metadata/{}",
            server.base_url, vault, sub_file_path
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(metadata_res.status(), StatusCode::OK);
    let metadata = metadata_res.json::<FileMetadata>().await.unwrap();
    assert_eq!(metadata.filename.as_deref(), Some("folder.txt"));
    assert_eq!(metadata.origin.as_deref(), Some("integration-test"));
    assert!(metadata.filesize.unwrap_or(0) > 0);

    let lock_res = client
        .post(format!("{}/inbox/{}/lock", server.base_url, vault))
        .send()
        .await
        .unwrap();
    assert_eq!(lock_res.status(), StatusCode::OK);

    let raw_delete_res = client
        .delete(format!(
            "{}/inbox/{}/raw/delete/{}",
            server.base_url, vault, root_file_path
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(raw_delete_res.status(), StatusCode::OK);

    let unlock_again_res = client
        .post(format!("{}/inbox/{}/unlock", server.base_url, vault))
        .json(&serde_json::json!({ "password": password }))
        .send()
        .await
        .unwrap();
    assert_eq!(unlock_again_res.status(), StatusCode::OK);

    let delete_res = client
        .delete(format!(
            "{}/inbox/{}/delete/{}",
            server.base_url, vault, sub_file_path
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(delete_res.status(), StatusCode::OK);

    server.shutdown().await;
}

#[tokio::test]
async fn e2e_file_content_integrity_test() {
    let mut server = common::spawn_server().await;
    let client = reqwest::Client::new();
    let vault = "integrityvault";
    let password = "mypassword";

    client.post(format!("{}/inbox", server.base_url))
        .json(&serde_json::json!({
            "name": vault,
            "password": password,
            "permissions": { "allow_subfolders": true }
        }))
        .send().await.unwrap();

    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty.txt", vec![]),
        ("small.bin", b"hello world".to_vec()),
        ("large.bin", vec![0x42; 1024 * 50]),
        ("special_chars-@#$.txt", b"nasty name".to_vec()),
    ];

    for (name, payload) in &cases {
        let form = reqwest::multipart::Form::new().part(
            "file",
            reqwest::multipart::Part::bytes(payload.clone()).file_name(name.to_string()),
        );
        client.post(format!("{}/inbox/{}/upload", server.base_url, vault))
            .multipart(form).send().await.unwrap();
    }

    client.post(format!("{}/inbox/{}/unlock", server.base_url, vault))
        .json(&serde_json::json!({ "password": password }))
        .send().await.unwrap();

    let list_res = client.get(format!("{}/inbox/{}/list", server.base_url, vault))
        .send().await.unwrap();
    let listed = list_res.json::<Vec<ListedFile>>().await.unwrap();

    for (name, payload) in cases {
        let file_path = listed.iter().find(|f| f.filename.as_deref() == Some(name))
            .map(|f| f.path.clone()).unwrap();
        let download_res = client.get(format!("{}/inbox/{}/download/{}", server.base_url, vault, file_path))
            .send().await.unwrap();
        let downloaded_bytes = download_res.bytes().await.unwrap().to_vec();
        assert_eq!(downloaded_bytes, payload, "Payload mismatch for {}", name);
    }
    
    server.shutdown().await;
}

