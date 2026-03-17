mod common;

use age_inbox_core::crypto::derive_keys;

/// Test: Key derivation is deterministic for the same input pair.
#[test]
fn test_derive_keys_is_deterministic() {
    let first = derive_keys("mypassword", "vault-a").expect("First derivation failed");
    let second = derive_keys("mypassword", "vault-a").expect("Second derivation failed");

    assert_eq!(
        first.recipient.to_string(),
        second.recipient.to_string(),
        "Same password and vault name should produce identical recipient keys"
    );
}

/// Test: Different vault names produce different recipients.
#[test]
fn test_derive_keys_changes_with_vault_name() {
    let first = derive_keys("mypassword", "vault-a").expect("First derivation failed");
    let second = derive_keys("mypassword", "vault-b").expect("Second derivation failed");

    assert_ne!(
        first.recipient.to_string(),
        second.recipient.to_string(),
        "Different vault names should produce different recipient keys"
    );
}

/// Test: Different passwords produce different recipients.
#[test]
fn test_derive_keys_changes_with_password() {
    let first = derive_keys("password1", "vault-a").expect("First derivation failed");
    let second = derive_keys("password2", "vault-a").expect("Second derivation failed");

    assert_ne!(
        first.recipient.to_string(),
        second.recipient.to_string(),
        "Different passwords should produce different recipient keys"
    );
}

/// Test: Derived identity public key is in valid format.
#[test]
fn test_derive_keys_identity_format() {
    let keys = derive_keys("testpass", "testvault").expect("Key derivation failed");
    let public_key = keys.identity.to_public().to_string();

    assert!(!public_key.is_empty(), "Public key string should not be empty");
    assert!(
        public_key.starts_with("age1"),
        "Public key should start with 'age1' format"
    );
}

/// Test: Derived recipient is in valid age format.
#[test]
fn test_derive_keys_recipient_format() {
    let keys = derive_keys("testpass", "testvault").expect("Key derivation failed");
    let recipient_str = keys.recipient.to_string();

    assert!(!recipient_str.is_empty(), "Recipient string should not be empty");
    assert!(
        recipient_str.starts_with("age1"),
        "Recipient should start with 'age1' format"
    );
}

/// Test: Identity and recipient relationship is consistent.
#[test]
fn test_derive_keys_identity_recipient_relationship() {
    let keys = derive_keys("password", "vault").expect("Key derivation failed");
    let public_key = keys.identity.to_public();

    assert_eq!(
        public_key.to_string(),
        keys.recipient.to_string(),
        "Identity public key should match recipient"
    );
}

/// Test: Empty password and vault names still work.
#[test]
fn test_derive_keys_with_empty_strings() {
    let keys = derive_keys("", "").expect("Derivation with empty strings failed");

    assert!(!keys.recipient.to_string().is_empty(), "Empty strings should still produce valid keys");
}

/// Test: Very long password and vault name work correctly.
#[test]
fn test_derive_keys_with_long_inputs() {
    let long_password = "x".repeat(1000);
    let long_vault = "y".repeat(100);

    let keys = derive_keys(&long_password, &long_vault).expect("Derivation with long inputs failed");

    assert!(!keys.recipient.to_string().is_empty(), "Long inputs should produce valid keys");
}

/// Test: Special characters in vault name and password are handled.
#[test]
fn test_derive_keys_with_special_characters() {
    let keys = derive_keys("pässwörd!@#$%", "vault-ñame_123").expect("Derivation with special chars failed");

    assert!(!keys.recipient.to_string().is_empty(), "Special characters should be handled correctly");
}

