mod common;

use age_inbox::api::CreateInboxRes;
use axum::http::StatusCode;
use serde_json::json;

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
            "allow_subfolders": true
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