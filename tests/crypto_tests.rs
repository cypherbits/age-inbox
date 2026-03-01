use age_inbox::crypto::derive_keys;

/// Derivation is deterministic for same input pair.
#[test]
fn derive_keys_is_deterministic() {
    let first = derive_keys("mypassword", "vault-a").unwrap();
    let second = derive_keys("mypassword", "vault-a").unwrap();

    assert_eq!(first.recipient.to_string(), second.recipient.to_string());
}

/// Different vault names produce different recipients.
#[test]
fn derive_keys_changes_with_vault_name() {
    let first = derive_keys("mypassword", "vault-a").unwrap();
    let second = derive_keys("mypassword", "vault-b").unwrap();

    assert_ne!(first.recipient.to_string(), second.recipient.to_string());
}