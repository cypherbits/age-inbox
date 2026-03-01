mod common;

use axum::http::StatusCode;
use serde_json::json;

/// Unlock fails with wrong password and succeeds with correct one.
#[tokio::test]
async fn unlock_password_validation() {
    let (base_url, _dir) = common::setup_app().await;
    let client = reqwest::Client::new();
    common::create_vault(&client, &base_url, true).await;

    let bad = client
        .post(format!("{}/inbox/testvault/unlock", base_url))
        .json(&json!({ "password": "wrong" }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), StatusCode::UNAUTHORIZED);

    let ok = client
        .post(format!("{}/inbox/testvault/unlock", base_url))
        .json(&json!({ "password": "mypassword" }))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
}

/// Lock endpoint removes unlocked vault state.
#[tokio::test]
async fn lock_flow() {
    let (base_url, _dir) = common::setup_app().await;
    let client = reqwest::Client::new();
    common::create_vault(&client, &base_url, true).await;

    let not_found = client
        .post(format!("{}/inbox/testvault/lock", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(not_found.status(), StatusCode::NOT_FOUND);

    common::unlock_vault(&client, &base_url, "mypassword").await;

    let locked = client
        .post(format!("{}/inbox/testvault/lock", base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(locked.status(), StatusCode::OK);
}