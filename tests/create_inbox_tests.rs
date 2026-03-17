mod common;

use age_inbox::api::CreateInboxRes;
use axum::http::StatusCode;
use serde_json::json;

#[derive(serde::Deserialize)]
struct VaultConfigRes {
    permissions: VaultPermissionsRes,
}

#[derive(serde::Deserialize)]
struct VaultPermissionsRes {
    allow_subfolders: bool,
    allow_upload: bool,
    allow_download: bool,
    allow_list: bool,
    allow_delete: bool,
    allow_metadata: bool,
    allow_lock_unlock: bool,
}

/// Validates vault creation and duplicate protection.
#[tokio::test]
async fn create_inbox_success_and_conflict() {
    let (base_url, _dir) = common::setup_app().await;
    let client = reqwest::Client::new();

    let first = client
        .post(format!("{}/inbox", base_url))
        .json(&json!({
            "name": "testvault",
            "password": "mypassword",
            "permissions": {
                "allow_subfolders": true
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(first.status(), StatusCode::OK);
    let body: CreateInboxRes = first.json().await.unwrap();
    assert!(body.success);
    assert!(body.public_key.starts_with("age1"));

    let duplicate = client
        .post(format!("{}/inbox", base_url))
        .json(&json!({
            "name": "testvault",
            "password": "mypassword"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(duplicate.status(), StatusCode::CONFLICT);
}

/// Rejects invalid vault names.
#[tokio::test]
async fn create_inbox_rejects_invalid_name() {
    let (base_url, _dir) = common::setup_app().await;
    let client = reqwest::Client::new();

    let response = client
        .post(format!("{}/inbox", base_url))
        .json(&json!({
            "name": "../bad",
            "password": "mypassword"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// Applies full permission overrides at creation and persists them in vault config.
#[tokio::test]
async fn create_inbox_accepts_full_permissions_config() {
    let (base_url, _dir) = common::setup_app().await;
    let client = reqwest::Client::new();

    let create = client
        .post(format!("{}/inbox", base_url))
        .json(&json!({
            "name": "permvault",
            "password": "mypassword",
            "permissions": {
                "allow_subfolders": true,
                "allow_upload": false,
                "allow_download": false,
                "allow_list": true,
                "allow_delete": false,
                "allow_metadata": false,
                "allow_lock_unlock": false
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::OK);

    let config_res = client
        .get(format!("{}/inbox/{}/config", base_url, "permvault"))
        .send()
        .await
        .unwrap();
    assert_eq!(config_res.status(), StatusCode::OK);
    let config: VaultConfigRes = config_res.json().await.unwrap();

    assert!(config.permissions.allow_subfolders);
    assert!(!config.permissions.allow_upload);
    assert!(!config.permissions.allow_download);
    assert!(config.permissions.allow_list);
    assert!(!config.permissions.allow_delete);
    assert!(!config.permissions.allow_metadata);
    assert!(!config.permissions.allow_lock_unlock);
}

/// Rejects legacy top-level `allow_subfolders`; callers must use `permissions`.
#[tokio::test]
async fn create_inbox_rejects_legacy_top_level_allow_subfolders() {
    let (base_url, _dir) = common::setup_app().await;
    let client = reqwest::Client::new();

    let create = client
        .post(format!("{}/inbox", base_url))
        .json(&json!({
            "name": "legacyvault",
            "password": "mypassword",
            "allow_subfolders": true
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let config_res = client
        .get(format!("{}/inbox/{}/config", base_url, "legacyvault"))
        .send()
        .await
        .unwrap();
    assert_eq!(config_res.status(), StatusCode::NOT_FOUND);
}
