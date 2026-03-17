mod common;

use age_inbox_core::inbox_core::{
    create_vault, read_vault_config_file, write_vault_config_file, VaultConfig, VaultPermissions,
    InboxCoreError,
};
use common::TestEnv;

// ============================================================================
// Vault configuration tests
// ============================================================================

/// Test: Creating a vault with default permissions.
#[tokio::test]
async fn test_create_vault_with_default_permissions() {
    let env = TestEnv::new();
    let permissions = VaultPermissions::default();

    let result = create_vault(&env.vaults_dir, "test_vault", "password123".to_string(), permissions)
        .await;

    assert!(result.is_ok(), "Vault creation should succeed");
    let create_result = result.unwrap();
    assert!(!create_result.public_key.is_empty(), "Public key should not be empty");
    assert!(create_result.public_key.starts_with("age1"), "Public key should be in age1 format");
}

/// Test: Creating vault with invalid name (contains path separator).
#[tokio::test]
async fn test_create_vault_invalid_name_with_slash() {
    let env = TestEnv::new();
    let permissions = VaultPermissions::default();

    let result = create_vault(&env.vaults_dir, "vault/invalid", "password".to_string(), permissions)
        .await;

    assert!(
        matches!(result, Err(InboxCoreError::InvalidName)),
        "Should reject vault name with path separator"
    );
}

/// Test: Creating vault with empty name.
#[tokio::test]
async fn test_create_vault_empty_name() {
    let env = TestEnv::new();
    let permissions = VaultPermissions::default();

    let result = create_vault(&env.vaults_dir, "", "password".to_string(), permissions)
        .await;

    assert!(
        matches!(result, Err(InboxCoreError::InvalidName)),
        "Should reject empty vault name"
    );
}

/// Test: Cannot create vault that already exists.
#[tokio::test]
async fn test_create_vault_already_exists() {
    let env = TestEnv::new();
    let permissions = VaultPermissions::default();

    // First vault creation
    let first = create_vault(&env.vaults_dir, "existing", "password1".to_string(), permissions.clone())
        .await;
    assert!(first.is_ok(), "First vault creation should succeed");

    // Second vault creation with same name
    let second = create_vault(&env.vaults_dir, "existing", "password2".to_string(), permissions)
        .await;

    assert!(
        matches!(second, Err(InboxCoreError::VaultExists)),
        "Should reject duplicate vault creation"
    );
}

/// Test: Vault directory structure is created correctly.
#[tokio::test]
async fn test_create_vault_creates_directory() {
    let env = TestEnv::new();
    let permissions = VaultPermissions::default();

    let _ = create_vault(&env.vaults_dir, "new_vault", "password".to_string(), permissions)
        .await;

    let vault_path = env.vaults_dir.join("new_vault");
    assert!(vault_path.exists(), "Vault directory should be created");
    assert!(vault_path.is_dir(), "Vault path should be a directory");
}

/// Test: Vault config file is created and contains correct data.
#[tokio::test]
async fn test_create_vault_creates_config_file() {
    let env = TestEnv::new();
    let permissions = VaultPermissions::default();

    let result = create_vault(&env.vaults_dir, "config_test", "password".to_string(), permissions)
        .await;

    let public_key = result.unwrap().public_key;
    let vault_path = env.vaults_dir.join("config_test");
    let config_path = vault_path.join(".inbox-age.config");

    assert!(config_path.exists(), "Config file should be created");

    let config = read_vault_config_file(&vault_path)
        .await
        .expect("Should read config");

    assert_eq!(config.public_key, public_key, "Config should contain correct public key");
}

/// Test: Different passwords produce different public keys.
#[tokio::test]
async fn test_create_vault_different_passwords() {
    let env = TestEnv::new();
    let permissions = VaultPermissions::default();

    let result1 = create_vault(
        &env.vaults_dir,
        "vault1",
        "password1".to_string(),
        permissions.clone(),
    )
    .await;

    let result2 = create_vault(
        &env.vaults_dir,
        "vault2",
        "password2".to_string(),
        permissions,
    )
    .await;

    let key1 = result1.unwrap().public_key;
    let key2 = result2.unwrap().public_key;

    assert_ne!(key1, key2, "Different passwords should produce different keys");
}

// ============================================================================
// Vault config read/write tests
// ============================================================================

/// Test: Writing and reading vault config.
#[tokio::test]
async fn test_write_and_read_vault_config() {
    let env = TestEnv::new();
    let vault_path = env.vaults_dir.join("test_vault");
    tokio::fs::create_dir_all(&vault_path)
        .await
        .expect("Failed to create vault dir");

    let config = VaultConfig {
        public_key: "age1test123".to_string(),
        permissions: VaultPermissions::default(),
    };

    let write_result = write_vault_config_file(&vault_path, "test_vault", &config).await;
    assert!(write_result.is_ok(), "Should write config successfully");

    let read_result = read_vault_config_file(&vault_path).await;
    assert!(read_result.is_ok(), "Should read config successfully");

    let read_config = read_result.unwrap();
    assert_eq!(read_config.public_key, config.public_key, "Public key should match");
}

/// Test: Reading config from non-existent vault returns error.
#[tokio::test]
async fn test_read_vault_config_not_found() {
    let env = TestEnv::new();
    let vault_path = env.vaults_dir.join("nonexistent");

    let result = read_vault_config_file(&vault_path).await;

    assert!(
        matches!(result, Err(InboxCoreError::VaultConfigMissing)),
        "Should return VaultConfigMissing error"
    );
}

/// Test: Custom permissions are preserved in config.
#[tokio::test]
async fn test_vault_config_preserves_custom_permissions() {
    let env = TestEnv::new();
    let vault_path = env.vaults_dir.join("perms_test");
    tokio::fs::create_dir_all(&vault_path)
        .await
        .expect("Failed to create vault dir");

    let mut permissions = VaultPermissions::default();
    permissions.allow_download = false;
    permissions.allow_delete = false;

    let config = VaultConfig {
        public_key: "age1test456".to_string(),
        permissions: permissions.clone(),
    };

    write_vault_config_file(&vault_path, "perms_test", &config)
        .await
        .expect("Failed to write config");

    let read_config = read_vault_config_file(&vault_path)
        .await
        .expect("Failed to read config");

    assert_eq!(
        read_config.permissions.allow_download, false,
        "allow_download should be false"
    );
    assert_eq!(read_config.permissions.allow_delete, false, "allow_delete should be false");
    assert_eq!(read_config.permissions.allow_upload, true, "allow_upload should be true");
}

/// Test: Vault config file contains inbox name.
#[tokio::test]
async fn test_vault_config_contains_inbox_name() {
    let env = TestEnv::new();
    let vault_path = env.vaults_dir.join("named_vault");
    tokio::fs::create_dir_all(&vault_path)
        .await
        .expect("Failed to create vault dir");

    let config = VaultConfig {
        public_key: "age1test789".to_string(),
        permissions: VaultPermissions::default(),
    };

    write_vault_config_file(&vault_path, "my_inbox", &config)
        .await
        .expect("Failed to write config");

    // Read file directly to verify content format
    let content = tokio::fs::read_to_string(vault_path.join(".inbox-age.config"))
        .await
        .expect("Failed to read config file");

    assert!(content.contains("my_inbox"), "Config should contain inbox name");
}

// ============================================================================
// File metadata tests
// ============================================================================

/// Test: FileMetadata serialization and deserialization.
#[test]
fn test_file_metadata_serialization() {
    use age_inbox_core::inbox_core::FileMetadata;
    use std::collections::HashMap;

    let mut metadata = FileMetadata {
        filename: Some("test.txt".to_string()),
        origin: Some("upload".to_string()),
        filesize: Some(1024),
        extended: HashMap::new(),
    };

    metadata.extended.insert("custom_key".to_string(), serde_json::json!("custom_value"));

    let json = serde_json::to_string(&metadata).expect("Serialization failed");
    let deserialized: FileMetadata = serde_json::from_str(&json).expect("Deserialization failed");

    assert_eq!(deserialized.filename, Some("test.txt".to_string()));
    assert_eq!(deserialized.filesize, Some(1024));
    assert!(deserialized.extended.contains_key("custom_key"));
}

/// Test: Default FileMetadata has all fields as None.
#[test]
fn test_file_metadata_default() {
    use age_inbox_core::inbox_core::FileMetadata;

    let metadata = FileMetadata::default();

    assert!(metadata.filename.is_none(), "Default filename should be None");
    assert!(metadata.origin.is_none(), "Default origin should be None");
    assert!(metadata.filesize.is_none(), "Default filesize should be None");
    assert!(metadata.extended.is_empty(), "Default extended should be empty");
}

// ============================================================================
// Permissions tests
// ============================================================================

/// Test: Default permissions allow all operations.
#[test]
fn test_vault_permissions_default() {
    let perms = VaultPermissions::default();

    assert!(perms.allow_upload, "Default should allow upload");
    assert!(perms.allow_download, "Default should allow download");
    assert!(perms.allow_delete, "Default should allow delete");
    assert!(perms.allow_list, "Default should allow list");
    assert!(perms.allow_metadata, "Default should allow metadata");
    assert!(perms.allow_lock_unlock, "Default should allow lock/unlock");
    assert!(!perms.allow_subfolders, "Default should not allow subfolders");
}

/// Test: Permissions can be cloned.
#[test]
fn test_vault_permissions_clone() {
    let mut perms1 = VaultPermissions::default();
    perms1.allow_download = false;

    let perms2 = perms1.clone();

    assert_eq!(perms1.allow_download, perms2.allow_download);
    assert_eq!(perms1.allow_upload, perms2.allow_upload);
}

