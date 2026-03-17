mod common;

use age_inbox_core::inbox_core::{
    create_vault, unlock_vault, lock_vault, get_unlocked_identity, VaultPermissions,
    InboxCoreError,
};
use common::TestEnv;
use std::collections::HashMap;
use std::time::{Duration, Instant};

// ============================================================================
// Vault unlock tests
// ============================================================================

/// Test: Unlocking a vault with correct password.
#[tokio::test]
async fn test_unlock_vault_with_correct_password() {
    let env = TestEnv::new();
    let password = "correct_password";
    let permissions = VaultPermissions::default();

    // Create vault
    create_vault(&env.vaults_dir, "test_vault", password.to_string(), permissions)
        .await
        .expect("Failed to create vault");

    // Unlock vault
    let mut unlocked_vaults = HashMap::new();
    let result = unlock_vault(
        &mut unlocked_vaults,
        &env.vaults_dir,
        "test_vault",
        password.to_string(),
        Duration::from_secs(3600),
    )
    .await;

    assert!(result.is_ok(), "Unlock with correct password should succeed");
    assert!(unlocked_vaults.contains_key("test_vault"), "Vault should be in unlocked_vaults map");
}

/// Test: Unlocking a vault with incorrect password fails.
#[tokio::test]
async fn test_unlock_vault_with_incorrect_password() {
    let env = TestEnv::new();
    let permissions = VaultPermissions::default();

    // Create vault
    create_vault(&env.vaults_dir, "test_vault", "correct_password".to_string(), permissions)
        .await
        .expect("Failed to create vault");

    // Try to unlock with wrong password
    let mut unlocked_vaults = HashMap::new();
    let result = unlock_vault(
        &mut unlocked_vaults,
        &env.vaults_dir,
        "test_vault",
        "wrong_password".to_string(),
        Duration::from_secs(3600),
    )
    .await;

    assert!(
        matches!(result, Err(InboxCoreError::InvalidPassword)),
        "Unlock with wrong password should fail"
    );
    assert!(!unlocked_vaults.contains_key("test_vault"), "Vault should not be unlocked");
}

/// Test: Unlocking non-existent vault fails.
#[tokio::test]
async fn test_unlock_nonexistent_vault() {
    let env = TestEnv::new();
    let mut unlocked_vaults = HashMap::new();

    let result = unlock_vault(
        &mut unlocked_vaults,
        &env.vaults_dir,
        "nonexistent",
        "password".to_string(),
        Duration::from_secs(3600),
    )
    .await;

    assert!(
        matches!(result, Err(InboxCoreError::VaultNotFound)),
        "Unlocking non-existent vault should fail"
    );
}

/// Test: Unlocking vault with invalid name fails.
#[tokio::test]
async fn test_unlock_vault_invalid_name() {
    let env = TestEnv::new();
    let mut unlocked_vaults = HashMap::new();

    let result = unlock_vault(
        &mut unlocked_vaults,
        &env.vaults_dir,
        "vault/invalid",
        "password".to_string(),
        Duration::from_secs(3600),
    )
    .await;

    assert!(
        matches!(result, Err(InboxCoreError::InvalidName)),
        "Unlocking with invalid name should fail"
    );
}

/// Test: Unlock with lock/unlock disabled fails.
#[tokio::test]
async fn test_unlock_vault_when_disabled() {
    let env = TestEnv::new();
    let mut permissions = VaultPermissions::default();
    permissions.allow_lock_unlock = false;

    create_vault(&env.vaults_dir, "locked_vault", "password".to_string(), permissions)
        .await
        .expect("Failed to create vault");

    let mut unlocked_vaults = HashMap::new();
    let result = unlock_vault(
        &mut unlocked_vaults,
        &env.vaults_dir,
        "locked_vault",
        "password".to_string(),
        Duration::from_secs(3600),
    )
    .await;

    assert!(
        result.is_err(),
        "Unlock should fail when lock/unlock is disabled"
    );
}

/// Test: Unlock duration is stored correctly.
#[tokio::test]
async fn test_unlock_vault_duration() {
    let env = TestEnv::new();
    let password = "password";
    let permissions = VaultPermissions::default();

    create_vault(&env.vaults_dir, "test_vault", password.to_string(), permissions)
        .await
        .expect("Failed to create vault");

    let unlock_duration = Duration::from_secs(60);
    let before_unlock = Instant::now();

    let mut unlocked_vaults = HashMap::new();
    unlock_vault(
        &mut unlocked_vaults,
        &env.vaults_dir,
        "test_vault",
        password.to_string(),
        unlock_duration,
    )
    .await
    .expect("Unlock failed");

    let vault = unlocked_vaults
        .get("test_vault")
        .expect("Vault should be in map");

    let _elapsed = Instant::now() - before_unlock;
    let expires_in = vault.expires_at - Instant::now();

    assert!(
        expires_in > Duration::from_secs(59) && expires_in <= unlock_duration,
        "Expiration time should be approximately unlock_duration in the future"
    );
}

// ============================================================================
// Vault lock tests
// ============================================================================

/// Test: Locking an unlocked vault.
#[tokio::test]
async fn test_lock_unlocked_vault() {
    let env = TestEnv::new();
    let password = "password";
    let permissions = VaultPermissions::default();

    create_vault(&env.vaults_dir, "test_vault", password.to_string(), permissions)
        .await
        .expect("Failed to create vault");

    let mut unlocked_vaults = HashMap::new();
    unlock_vault(
        &mut unlocked_vaults,
        &env.vaults_dir,
        "test_vault",
        password.to_string(),
        Duration::from_secs(3600),
    )
    .await
    .expect("Unlock failed");

    assert!(
        unlocked_vaults.contains_key("test_vault"),
        "Vault should be unlocked"
    );

    let result = lock_vault(&mut unlocked_vaults, &env.vaults_dir, "test_vault").await;

    assert!(result.is_ok(), "Lock should succeed");
    assert!(result.unwrap(), "Should return true for previously unlocked vault");
    assert!(
        !unlocked_vaults.contains_key("test_vault"),
        "Vault should be removed from unlocked_vaults"
    );
}

/// Test: Locking an already locked vault.
#[tokio::test]
async fn test_lock_already_locked_vault() {
    let env = TestEnv::new();
    let permissions = VaultPermissions::default();

    create_vault(&env.vaults_dir, "test_vault", "password".to_string(), permissions)
        .await
        .expect("Failed to create vault");

    let mut unlocked_vaults = HashMap::new();

    let result = lock_vault(&mut unlocked_vaults, &env.vaults_dir, "test_vault").await;

    assert!(result.is_ok(), "Lock should succeed even on locked vault");
    assert!(!result.unwrap(), "Should return false for vault that wasn't unlocked");
}

/// Test: Locking non-existent vault fails.
#[tokio::test]
async fn test_lock_nonexistent_vault() {
    let env = TestEnv::new();
    let mut unlocked_vaults = HashMap::new();

    let result = lock_vault(&mut unlocked_vaults, &env.vaults_dir, "nonexistent").await;

    assert!(
        matches!(result, Err(InboxCoreError::VaultNotFound)),
        "Lock non-existent vault should fail"
    );
}

/// Test: Locking vault with invalid name fails.
#[tokio::test]
async fn test_lock_vault_invalid_name() {
    let env = TestEnv::new();
    let mut unlocked_vaults = HashMap::new();

    let result = lock_vault(&mut unlocked_vaults, &env.vaults_dir, "vault/invalid").await;

    assert!(
        matches!(result, Err(InboxCoreError::InvalidName)),
        "Lock with invalid name should fail"
    );
}

/// Test: Lock when lock/unlock disabled fails.
#[tokio::test]
async fn test_lock_vault_when_disabled() {
    let env = TestEnv::new();
    let mut permissions = VaultPermissions::default();
    permissions.allow_lock_unlock = false;

    create_vault(&env.vaults_dir, "locked_vault", "password".to_string(), permissions)
        .await
        .expect("Failed to create vault");

    let mut unlocked_vaults = HashMap::new();
    let result = lock_vault(&mut unlocked_vaults, &env.vaults_dir, "locked_vault").await;

    assert!(
        result.is_err(),
        "Lock should fail when lock/unlock is disabled"
    );
}

// ============================================================================
// Get unlocked identity tests
// ============================================================================

/// Test: Getting identity of unlocked vault.
#[tokio::test]
async fn test_get_unlocked_identity_success() {
    let env = TestEnv::new();
    let password = "password";
    let permissions = VaultPermissions::default();

    create_vault(&env.vaults_dir, "test_vault", password.to_string(), permissions)
        .await
        .expect("Failed to create vault");

    let mut unlocked_vaults = HashMap::new();
    unlock_vault(
        &mut unlocked_vaults,
        &env.vaults_dir,
        "test_vault",
        password.to_string(),
        Duration::from_secs(3600),
    )
    .await
    .expect("Unlock failed");

    let result = get_unlocked_identity(&mut unlocked_vaults, "test_vault");

    assert!(result.is_ok(), "Should retrieve identity");
    let _identity = result.unwrap();
}

/// Test: Getting identity of locked vault fails.
#[tokio::test]
async fn test_get_unlocked_identity_vault_locked() {
    let mut unlocked_vaults = HashMap::new();

    let result = get_unlocked_identity(&mut unlocked_vaults, "nonexistent");

    assert!(
        matches!(result, Err(InboxCoreError::VaultLocked)),
        "Should return VaultLocked error"
    );
}

/// Test: Getting identity after unlock expiration fails.
#[tokio::test]
async fn test_get_unlocked_identity_expired() {
    let env = TestEnv::new();
    let password = "password";
    let permissions = VaultPermissions::default();

    create_vault(&env.vaults_dir, "test_vault", password.to_string(), permissions)
        .await
        .expect("Failed to create vault");

    let mut unlocked_vaults = HashMap::new();
    unlock_vault(
        &mut unlocked_vaults,
        &env.vaults_dir,
        "test_vault",
        password.to_string(),
        Duration::from_millis(100), // Very short duration
    )
    .await
    .expect("Unlock failed");

    // Wait for expiration
    tokio::time::sleep(Duration::from_millis(200)).await;

    let result = get_unlocked_identity(&mut unlocked_vaults, "test_vault");

    assert!(
        matches!(result, Err(InboxCoreError::VaultUnlockExpired)),
        "Should return VaultUnlockExpired error"
    );
    assert!(
        !unlocked_vaults.contains_key("test_vault"),
        "Expired vault should be removed from map"
    );
}

// ============================================================================
// Multiple vault lock/unlock tests
// ============================================================================

/// Test: Managing multiple vaults with different unlock times.
#[tokio::test]
async fn test_multiple_vaults_unlock_staggered() {
    let env = TestEnv::new();
    let permissions = VaultPermissions::default();

    // Create multiple vaults
    for i in 1..=3 {
        let vault_name = format!("vault{}", i);
        let password = format!("password{}", i);
        create_vault(&env.vaults_dir, &vault_name, password, permissions.clone())
            .await
            .expect("Failed to create vault");
    }

    let mut unlocked_vaults = HashMap::new();

    // Unlock with different durations
    unlock_vault(
        &mut unlocked_vaults,
        &env.vaults_dir,
        "vault1",
        "password1".to_string(),
        Duration::from_secs(3600),
    )
    .await
    .expect("Unlock failed");

    unlock_vault(
        &mut unlocked_vaults,
        &env.vaults_dir,
        "vault2",
        "password2".to_string(),
        Duration::from_secs(1800),
    )
    .await
    .expect("Unlock failed");

    unlock_vault(
        &mut unlocked_vaults,
        &env.vaults_dir,
        "vault3",
        "password3".to_string(),
        Duration::from_secs(900),
    )
    .await
    .expect("Unlock failed");

    assert_eq!(unlocked_vaults.len(), 3, "All three vaults should be unlocked");

    // Lock one
    lock_vault(&mut unlocked_vaults, &env.vaults_dir, "vault2")
        .await
        .expect("Lock failed");

    assert_eq!(unlocked_vaults.len(), 2, "Should have 2 unlocked vaults");
    assert!(unlocked_vaults.contains_key("vault1"));
    assert!(!unlocked_vaults.contains_key("vault2"));
    assert!(unlocked_vaults.contains_key("vault3"));
}

/// Test: Re-unlocking a locked vault.
#[tokio::test]
async fn test_relock_then_reunlock() {
    let env = TestEnv::new();
    let password = "password";
    let permissions = VaultPermissions::default();

    create_vault(&env.vaults_dir, "test_vault", password.to_string(), permissions)
        .await
        .expect("Failed to create vault");

    let mut unlocked_vaults = HashMap::new();

    // First unlock
    unlock_vault(
        &mut unlocked_vaults,
        &env.vaults_dir,
        "test_vault",
        password.to_string(),
        Duration::from_secs(3600),
    )
    .await
    .expect("First unlock failed");

    let first_identity = get_unlocked_identity(&mut unlocked_vaults, "test_vault")
        .expect("Failed to get first identity");
    let first_public = first_identity.to_public().to_string();

    // Lock
    lock_vault(&mut unlocked_vaults, &env.vaults_dir, "test_vault")
        .await
        .expect("Lock failed");

    // Second unlock
    unlock_vault(
        &mut unlocked_vaults,
        &env.vaults_dir,
        "test_vault",
        password.to_string(),
        Duration::from_secs(3600),
    )
    .await
    .expect("Second unlock failed");

    let second_identity = get_unlocked_identity(&mut unlocked_vaults, "test_vault")
        .expect("Failed to get second identity");
    let second_public = second_identity.to_public().to_string();

    // Public keys should be the same (deterministic derivation)
    assert_eq!(
        first_public,
        second_public,
        "Re-unlocking should produce the same identity"
    );
}

