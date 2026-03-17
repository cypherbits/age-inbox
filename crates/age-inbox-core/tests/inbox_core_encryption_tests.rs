mod common;

use age_inbox_core::crypto::derive_keys;
use age_inbox_core::inbox_core::{
    decrypt_age_file_to_writer, decrypt_metadata_file, encrypt_metadata_file,
    encrypt_reader_to_age_file, FileMetadata,
};
use common::TestEnv;
use std::collections::HashMap;

// ============================================================================
// Encryption tests
// ============================================================================

/// Test: Encrypting and decrypting a file preserves content.
#[tokio::test]
async fn test_encrypt_decrypt_roundtrip() {
    let env = TestEnv::new();
    let test_content = b"Hello, World!";

    // Derive keys
    let keys = derive_keys("password", "vault").expect("Failed to derive keys");

    // Create input file
    let input_path = env.create_test_file("input.txt", test_content);

    // Encrypt file
    let encrypted_path = env.temp_dir.path().join("encrypted.age");
    let mut input_file = tokio::fs::File::open(&input_path)
        .await
        .expect("Failed to open input file");

    let encrypted_result = encrypt_reader_to_age_file(&keys.recipient, &mut input_file, &encrypted_path)
        .await;

    assert!(encrypted_result.is_ok(), "Encryption should succeed");
    assert!(encrypted_path.exists(), "Encrypted file should be created");

    // Decrypt file
    let mut output_file = Vec::new();
    let decrypt_result = decrypt_age_file_to_writer(&keys.identity, &encrypted_path, &mut output_file)
        .await;

    assert!(decrypt_result.is_ok(), "Decryption should succeed");
    assert_eq!(output_file, test_content, "Decrypted content should match original");
}

/// Test: Encrypting large file works correctly.
#[tokio::test]
async fn test_encrypt_large_file() {
    let env = TestEnv::new();
    let keys = derive_keys("password", "vault").expect("Failed to derive keys");

    // Create large test content (10MB)
    let large_content = vec![42u8; 10 * 1024 * 1024];
    let input_path = env.temp_dir.path().join("large.bin");
    tokio::fs::write(&input_path, &large_content)
        .await
        .expect("Failed to write large file");

    let encrypted_path = env.temp_dir.path().join("large.age");
    let mut input_file = tokio::fs::File::open(&input_path)
        .await
        .expect("Failed to open file");

    let result = encrypt_reader_to_age_file(&keys.recipient, &mut input_file, &encrypted_path)
        .await;

    assert!(result.is_ok(), "Large file encryption should succeed");
    let bytes_written = result.unwrap();
    assert_eq!(bytes_written as usize, large_content.len(), "All bytes should be written");
}

/// Test: Encrypting empty file.
#[tokio::test]
async fn test_encrypt_empty_file() {
    let env = TestEnv::new();
    let keys = derive_keys("password", "vault").expect("Failed to derive keys");

    let input_path = env.create_test_file("empty.txt", b"");

    let encrypted_path = env.temp_dir.path().join("empty.age");
    let mut input_file = tokio::fs::File::open(&input_path)
        .await
        .expect("Failed to open file");

    let result = encrypt_reader_to_age_file(&keys.recipient, &mut input_file, &encrypted_path)
        .await;

    assert!(result.is_ok(), "Empty file encryption should succeed");
    let bytes_written = result.unwrap();
    assert_eq!(bytes_written, 0, "Empty file should write 0 bytes");
}

/// Test: Different recipients produce incompatible encrypted files.
#[tokio::test]
async fn test_encrypt_with_different_recipients() {
    let env = TestEnv::new();
    let keys1 = derive_keys("password1", "vault1").expect("Failed to derive keys");
    let keys2 = derive_keys("password2", "vault2").expect("Failed to derive keys");

    let test_content = b"Secret content";
    let input_path = env.create_test_file("secret.txt", test_content);

    // Encrypt with keys1
    let encrypted_path = env.temp_dir.path().join("encrypted.age");
    let mut input_file = tokio::fs::File::open(&input_path)
        .await
        .expect("Failed to open file");

    encrypt_reader_to_age_file(&keys1.recipient, &mut input_file, &encrypted_path)
        .await
        .expect("Encryption failed");

    // Try to decrypt with keys2 (should fail)
    let mut output = Vec::new();
    let decrypt_result = decrypt_age_file_to_writer(&keys2.identity, &encrypted_path, &mut output)
        .await;

    assert!(
        decrypt_result.is_err(),
        "Decryption with wrong identity should fail"
    );
}

/// Test: Encrypted file is larger than original (due to age overhead).
#[tokio::test]
async fn test_encrypted_file_size() {
    let env = TestEnv::new();
    let keys = derive_keys("password", "vault").expect("Failed to derive keys");

    let test_content = b"Test content";
    let input_path = env.create_test_file("original.txt", test_content);

    let encrypted_path = env.temp_dir.path().join("encrypted.age");
    let mut input_file = tokio::fs::File::open(&input_path)
        .await
        .expect("Failed to open file");

    encrypt_reader_to_age_file(&keys.recipient, &mut input_file, &encrypted_path)
        .await
        .expect("Encryption failed");

    let original_size = tokio::fs::metadata(&input_path)
        .await
        .expect("Failed to read original size")
        .len();

    let encrypted_size = tokio::fs::metadata(&encrypted_path)
        .await
        .expect("Failed to read encrypted size")
        .len();

    assert!(encrypted_size > original_size, "Encrypted file should be larger than original");
}

// ============================================================================
// Metadata encryption tests
// ============================================================================

/// Test: Encrypting and decrypting metadata preserves content.
#[tokio::test]
async fn test_encrypt_decrypt_metadata_roundtrip() {
    let env = TestEnv::new();
    let keys = derive_keys("password", "vault").expect("Failed to derive keys");

    let mut metadata = FileMetadata {
        filename: Some("test.txt".to_string()),
        origin: Some("upload".to_string()),
        filesize: Some(12345),
        extended: HashMap::new(),
    };
    metadata.extended.insert("custom".to_string(), serde_json::json!("value"));

    let metadata_path = env.temp_dir.path().join("metadata.meta.age");

    // Encrypt metadata
    let encrypt_result = encrypt_metadata_file(&keys.recipient, &metadata, &metadata_path).await;
    assert!(encrypt_result.is_ok(), "Metadata encryption should succeed");

    // Decrypt metadata
    let decrypt_result = decrypt_metadata_file(&keys.identity, &metadata_path).await;
    assert!(decrypt_result.is_ok(), "Metadata decryption should succeed");

    let decrypted = decrypt_result.unwrap();
    assert_eq!(decrypted.filename, metadata.filename);
    assert_eq!(decrypted.filesize, metadata.filesize);
    assert_eq!(decrypted.extended.get("custom"), metadata.extended.get("custom"));
}

/// Test: Empty metadata can be encrypted and decrypted.
#[tokio::test]
async fn test_encrypt_decrypt_empty_metadata() {
    let env = TestEnv::new();
    let keys = derive_keys("password", "vault").expect("Failed to derive keys");

    let metadata = FileMetadata::default();
    let metadata_path = env.temp_dir.path().join("empty.meta.age");

    encrypt_metadata_file(&keys.recipient, &metadata, &metadata_path)
        .await
        .expect("Encryption failed");

    let decrypted = decrypt_metadata_file(&keys.identity, &metadata_path)
        .await
        .expect("Decryption failed");

    assert!(decrypted.filename.is_none());
    assert!(decrypted.filesize.is_none());
}

/// Test: Large metadata with extended fields.
#[tokio::test]
async fn test_encrypt_large_metadata() {
    let env = TestEnv::new();
    let keys = derive_keys("password", "vault").expect("Failed to derive keys");

    let mut metadata = FileMetadata {
        filename: Some("largefile.bin".to_string()),
        origin: Some("api".to_string()),
        filesize: Some(999_999_999),
        extended: HashMap::new(),
    };

    // Add many extended fields
    for i in 0..100 {
        metadata.extended.insert(
            format!("field_{}", i),
            serde_json::json!(format!("value_{}", i)),
        );
    }

    let metadata_path = env.temp_dir.path().join("large_meta.meta.age");

    encrypt_metadata_file(&keys.recipient, &metadata, &metadata_path)
        .await
        .expect("Encryption failed");

    let decrypted = decrypt_metadata_file(&keys.identity, &metadata_path)
        .await
        .expect("Decryption failed");

    assert_eq!(decrypted.extended.len(), 100, "All extended fields should be preserved");
}

/// Test: Special characters in metadata are preserved.
#[tokio::test]
async fn test_metadata_special_characters() {
    let env = TestEnv::new();
    let keys = derive_keys("password", "vault").expect("Failed to derive keys");

    let metadata = FileMetadata {
        filename: Some("文件名_ñame_🎉.txt".to_string()),
        origin: Some("source™".to_string()),
        filesize: Some(42),
        extended: HashMap::new(),
    };

    let metadata_path = env.temp_dir.path().join("unicode.meta.age");

    encrypt_metadata_file(&keys.recipient, &metadata, &metadata_path)
        .await
        .expect("Encryption failed");

    let decrypted = decrypt_metadata_file(&keys.identity, &metadata_path)
        .await
        .expect("Decryption failed");

    assert_eq!(decrypted.filename, metadata.filename, "Unicode filename should be preserved");
}

// ============================================================================
// Range decryption tests
// ============================================================================

/// Test: Decrypt specific range of bytes from encrypted file.
#[tokio::test]
async fn test_decrypt_range() {
    use age_inbox_core::inbox_core::decrypt_age_file_range_to_writer;

    let env = TestEnv::new();
    let keys = derive_keys("password", "vault").expect("Failed to derive keys");

    // Create test file with known content
    let test_content = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let input_path = env.create_test_file("range_test.txt", test_content);

    // Encrypt file
    let encrypted_path = env.temp_dir.path().join("range.age");
    let mut input_file = tokio::fs::File::open(&input_path)
        .await
        .expect("Failed to open file");

    encrypt_reader_to_age_file(&keys.recipient, &mut input_file, &encrypted_path)
        .await
        .expect("Encryption failed");

    // Decrypt specific range (bytes 10-19)
    let mut output = Vec::new();
    let result = decrypt_age_file_range_to_writer(&keys.identity, &encrypted_path, &mut output, 10, 19)
        .await;

    assert!(result.is_ok(), "Range decryption should succeed");
    assert_eq!(output.len(), 10, "Should decrypt exactly 10 bytes");
    assert_eq!(&output, &test_content[10..20], "Decrypted range should match original");
}

/// Test: Decrypt range starting at beginning.
#[tokio::test]
async fn test_decrypt_range_from_start() {
    use age_inbox_core::inbox_core::decrypt_age_file_range_to_writer;

    let env = TestEnv::new();
    let keys = derive_keys("password", "vault").expect("Failed to derive keys");

    let test_content = b"Start and end";
    let input_path = env.create_test_file("start.txt", test_content);

    let encrypted_path = env.temp_dir.path().join("start.age");
    let mut input_file = tokio::fs::File::open(&input_path)
        .await
        .expect("Failed to open file");

    encrypt_reader_to_age_file(&keys.recipient, &mut input_file, &encrypted_path)
        .await
        .expect("Encryption failed");

    // Decrypt first 5 bytes
    let mut output = Vec::new();
    decrypt_age_file_range_to_writer(&keys.identity, &encrypted_path, &mut output, 0, 4)
        .await
        .expect("Range decryption failed");

    assert_eq!(&output, b"Start");
}

/// Test: Decrypt single byte range.
#[tokio::test]
async fn test_decrypt_range_single_byte() {
    use age_inbox_core::inbox_core::decrypt_age_file_range_to_writer;

    let env = TestEnv::new();
    let keys = derive_keys("password", "vault").expect("Failed to derive keys");

    let test_content = b"X";
    let input_path = env.create_test_file("single.txt", test_content);

    let encrypted_path = env.temp_dir.path().join("single.age");
    let mut input_file = tokio::fs::File::open(&input_path)
        .await
        .expect("Failed to open file");

    encrypt_reader_to_age_file(&keys.recipient, &mut input_file, &encrypted_path)
        .await
        .expect("Encryption failed");

    // Decrypt single byte
    let mut output = Vec::new();
    decrypt_age_file_range_to_writer(&keys.identity, &encrypted_path, &mut output, 0, 0)
        .await
        .expect("Range decryption failed");

    assert_eq!(output.len(), 1);
    assert_eq!(&output, b"X");
}

