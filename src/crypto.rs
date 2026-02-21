use age::x25519::{Identity, Recipient};
use std::str::FromStr;
use anyhow::Result;

pub struct Keys {
    pub identity: Identity,
    pub recipient: Recipient,
}

pub fn derive_keys(password: &str, vault_name: &str) -> Result<Keys> {
    // We deterministically derive a salt from the vault name using a simple sha256 or just padding.
    // Wait, let's just use the vault name directly if we pad it to 16 bytes.
    let mut salt_bytes = [0u8; 16];
    let vault_bytes = vault_name.as_bytes();
    for (i, &b) in vault_bytes.iter().take(16).enumerate() {
        salt_bytes[i] = b;
    }
    // Need a domain separator to ensure it doesn't match standard salts
    for i in vault_bytes.len()..16 {
        salt_bytes[i] = (i as u8) ^ 0xAA;
    }

    // Argon2 outputs variable length. We want 32 bytes for an x25519 key.
    let mut key_bytes = [0u8; 32];
    argon2::Argon2::default().hash_password_into(
        password.as_bytes(),
        &salt_bytes,
        &mut key_bytes,
    ).map_err(|e| anyhow::anyhow!("Argon2 error: {}", e))?;

    // Now we need to create an age::x25519::Identity from key_bytes
    // Let's use bech32 to construct the AGE-SECRET-KEY string.
use bech32::{ToBase32, Variant};
    let encoded = bech32::encode("AGE-SECRET-KEY-", key_bytes.to_base32(), Variant::Bech32).unwrap();
    
    // The age crate expects uppercase for the constant prefix.
    let identity = Identity::from_str(&encoded.to_uppercase()).map_err(|e| anyhow::anyhow!("Invalid identity: {}", e))?;
    let recipient = identity.to_public();

    Ok(Keys {
        identity,
        recipient,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_keys() {
        let keys = derive_keys("mypassword", "myvault").unwrap();
        // Just verify it doesn't crash
        let rec = keys.recipient.to_string();
        assert!(rec.starts_with("age1"));
    }
}
