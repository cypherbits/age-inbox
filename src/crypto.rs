use age::x25519::{Identity, Recipient};
use anyhow::Result;
use std::str::FromStr;
use zeroize::{Zeroize, Zeroizing};

pub struct Keys {
    pub identity: Identity,
    pub recipient: Recipient,
}

pub fn derive_keys(password: &str, vault_name: &str) -> Result<Keys> {
    // Deterministically derive a 16-byte salt from the vault name.
    let mut salt_bytes = [0u8; 16];
    let vault_bytes = vault_name.as_bytes();
    for (i, &b) in vault_bytes.iter().take(16).enumerate() {
        salt_bytes[i] = b;
    }

    // Domain separator so short names still produce a stable 16-byte salt.
    for i in vault_bytes.len()..16 {
        salt_bytes[i] = (i as u8) ^ 0xAA;
    }

    // Argon2 output for an x25519 key.
    let mut key_bytes = [0u8; 32];
    argon2::Argon2::default()
        .hash_password_into(password.as_bytes(), &salt_bytes, &mut key_bytes)
        .map_err(|e| anyhow::anyhow!("Argon2 error: {}", e))?;

    use bech32::{ToBase32, Variant};
    let encoded = Zeroizing::new(
        bech32::encode("AGE-SECRET-KEY-", key_bytes.to_base32(), Variant::Bech32)
            .map_err(|e| anyhow::anyhow!("Bech32 encode error: {}", e))?,
    );

    let encoded_upper = Zeroizing::new(encoded.to_uppercase());
    let identity = Identity::from_str(encoded_upper.as_str())
        .map_err(|e| anyhow::anyhow!("Invalid identity: {}", e))?;
    let recipient = identity.to_public();
    key_bytes.zeroize();

    Ok(Keys {
        identity,
        recipient,
    })
}
