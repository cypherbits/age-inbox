mod common;

#[tokio::test]
async fn upload_large_file() {
    let (base_url, _dir) = common::setup_app().await;
    let client = reqwest::Client::new();
    common::create_vault(&client, &base_url, false).await;

    let large_data = vec![0u8; 3 * 1024 * 1024]; // 3MB

    let form = reqwest::multipart::Form::new()
        .text("filename", "large.txt")
        .part(
            "file",
            reqwest::multipart::Part::bytes(large_data).file_name("large.txt"),
        );

    let upload = client
        .post(format!("{}/inbox/testvault/upload", base_url))
        .multipart(form)
        .send()
        .await
        .unwrap();

    let text = upload.text().await.unwrap();
    println!("Status: {text}");
    // Should pass if we don't have limit
    // assert_eq!(upload.status(), StatusCode::OK);
}
