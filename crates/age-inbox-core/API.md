# age-inbox-core API Reference

This document describes the public APIs exposed by `age-inbox-core` for integration in other Rust projects.

## Crate Overview

`age-inbox-core` provides:

- Deterministic key derivation from `(password, vault_name)`
- Vault lifecycle helpers (create, unlock, lock)
- Streaming AGE encryption/decryption for file content
- Encrypted JSON metadata helpers

`lib.rs` exports:

- `pub mod crypto;`
- `pub mod inbox_core;`

## Runtime and Integration Notes

- Async APIs require a Tokio runtime in the caller (`tokio` is **not** started by this library).
- `age-inbox-core` only depends on `tokio` for file I/O (`fs`, `io-util` features). It does **not** pull in `tokio::sync` or `tokio::time`.
- **Unlock state is owned and locked by the caller.** Functions that modify the session map (`unlock_vault`, `lock_vault`, `get_unlocked_identity`) receive a plain `&mut HashMap<String, UnlockedVault>`. The caller is responsible for acquiring the appropriate lock before calling them.
- All time types use `std::time` (`Instant`, `Duration`), not tokio equivalents.
- Paths and names should be validated before filesystem operations.

## Module: `crypto`

### Struct: `Keys`

```rust
pub struct Keys {
    pub identity: age::x25519::Identity,
    pub recipient: age::x25519::Recipient,
}
```

Represents a derived keypair:

- `identity`: private AGE identity (for decryption)
- `recipient`: public AGE recipient (for encryption)

### Function: `derive_keys`

```rust
pub fn derive_keys(password: &str, vault_name: &str) -> anyhow::Result<Keys>
```

Deterministically derives an AGE x25519 keypair from `password` + `vault_name`.

Behavior:

- Uses `vault_name` to build a stable 16-byte salt.
- Uses Argon2 to derive 32 bytes.
- Encodes as AGE secret key format and parses into `Identity`.
- Computes public `Recipient` from identity.

Important:

- Same `(password, vault_name)` always yields the same keys.
- Changing either input changes the keys.
- Derived key bytes are zeroized after use.

## Module: `inbox_core`

### Error Type: `InboxCoreError`

```rust
pub enum InboxCoreError {
    InvalidName,
    InvalidSubpath,
    VaultExists,
    VaultNotFound,
    VaultConfigMissing,
    InvalidConfig,
    InvalidPassword,
    VaultLocked,
    VaultUnlockExpired,
    Io(String),
    Crypto(String),
    Serialize(String),
}
```

Used by all high-level APIs in this module. Implements `std::error::Error` and `Display`.

## Data Types

### Struct: `VaultPermissions`

Configuration flags for vault capabilities:

- `allow_subfolders`
- `allow_upload`
- `allow_download`
- `allow_list`
- `allow_delete`
- `allow_metadata`
- `allow_lock_unlock`

`Default` values are permissive except `allow_subfolders` (`false`).

### Struct: `VaultConfig`

```rust
pub struct VaultConfig {
    pub public_key: String,
    pub permissions: VaultPermissions,
}
```

Represents parsed vault configuration from `.inbox-age.config`.

### Struct: `CreateVaultResult`

```rust
pub struct CreateVaultResult {
    pub public_key: String,
}
```

Return payload for `create_vault`.

### Struct: `UnlockedVault`

```rust
pub struct UnlockedVault {
    pub identity: age::x25519::Identity,
    pub expires_at: std::time::Instant,  // std, not tokio
}
```

Stored in the caller-owned session map. The expiration is checked by `get_unlocked_identity`.

### Struct: `FileMetadata`

```rust
pub struct FileMetadata {
    pub filename: Option<String>,
    pub origin: Option<String>,
    pub filesize: Option<u64>,
    pub extended: HashMap<String, serde_json::Value>,
}
```

JSON metadata model for sidecar files. `extended` is flattened in JSON for custom fields.

## Validation and Helpers

### `is_valid_name`

```rust
pub fn is_valid_name(name: &str) -> bool
```

Validates vault name: must not be empty, must not contain `/`, `\\`, or `..`.

### `is_valid_subpath`

```rust
pub fn is_valid_subpath(path: &str) -> bool
```

Validates relative subpath: must not contain `..`, must not start with `/`, must not contain `\\`.

### `metadata_sidecar_for`

```rust
pub fn metadata_sidecar_for(path: &Path) -> Option<PathBuf>
```

Converts `something.age` → `something.meta.age`.

Returns `None` if the name is not valid UTF-8, does not end with `.age`, or already ends with `.meta.age`.

### `generate_drop_filename`

```rust
pub fn generate_drop_filename() -> String
```

Generates a random drop filename: `drop-<32 hex chars>.age`.

## Config File APIs

### `read_vault_config_file`

```rust
pub async fn read_vault_config_file(vault_dir: &Path) -> Result<VaultConfig, InboxCoreError>
```

Reads `.inbox-age.config` from `vault_dir`.

- Returns `VaultConfigMissing` if the file cannot be read.
- Returns `InvalidConfig` if `public-key` is missing.
- `permissions` is optional; defaults apply if missing or unparseable.

### `write_vault_config_file`

```rust
pub async fn write_vault_config_file(
    vault_dir: &Path,
    inbox_name: &str,
    public_key: &str,
    allow_subfolders: bool,
) -> Result<(), InboxCoreError>
```

Writes `.inbox-age.config` with `inbox-name`, `public-key`, and serialized `permissions`.

## Vault Lifecycle APIs

### `create_vault`

```rust
pub async fn create_vault(
    vaults_dir: &Path,
    name: &str,
    password: String,
    allow_subfolders: bool,
) -> Result<CreateVaultResult, InboxCoreError>
```

Creates a new vault directory and config.

Flow: validate name → fail if exists → derive keypair → create directory → write config.

Common errors: `InvalidName`, `VaultExists`, `Crypto(_)`, `Io(_)`.

### `unlock_vault`

```rust
pub async fn unlock_vault(
    unlocked_vaults: &mut HashMap<String, UnlockedVault>,
    vaults_dir: &Path,
    name: &str,
    password: String,
    unlock_for: std::time::Duration,
) -> Result<(), InboxCoreError>
```

Validates the password against the stored public key, then inserts an `UnlockedVault` entry into the caller-provided map.

**The caller must acquire their own lock before passing `&mut map` to this function.**

Common errors: `InvalidName`, `VaultNotFound`, `VaultConfigMissing`, `InvalidConfig`, `InvalidPassword`, `Crypto("lock/unlock disabled in config")`.

### `lock_vault`

```rust
pub async fn lock_vault(
    unlocked_vaults: &mut HashMap<String, UnlockedVault>,
    vaults_dir: &Path,
    name: &str,
) -> Result<bool, InboxCoreError>
```

Removes the vault entry from the session map.

- Returns `Ok(true)` if the entry existed and was removed.
- Returns `Ok(false)` if no entry was present.

**The caller must acquire their own lock before passing `&mut map`.**

### `get_unlocked_identity`

```rust
pub fn get_unlocked_identity(
    unlocked_vaults: &mut HashMap<String, UnlockedVault>,
    name: &str,
) -> Result<age::x25519::Identity, InboxCoreError>
```

> ⚠️ This function is **synchronous** — it performs no I/O.

Looks up a vault's identity in the session map.

- If the entry has expired, removes it and returns `VaultUnlockExpired`.
- If no entry exists, returns `VaultLocked`.
- Otherwise returns a clone of the identity.

**The caller must acquire their own lock before passing `&mut map`.**

## File Encryption/Decryption APIs

### `encrypt_reader_to_age_file`

```rust
pub async fn encrypt_reader_to_age_file<R: AsyncRead + Unpin>(
    recipient: &age::x25519::Recipient,
    reader: &mut R,
    output_path: &Path,
) -> Result<u64, InboxCoreError>
```

Encrypts bytes from `reader` into an AGE file at `output_path`. Returns the plaintext byte count. Uses a 16 KiB internal buffer.

### `decrypt_age_file_to_writer`

```rust
pub async fn decrypt_age_file_to_writer<W: AsyncWrite + Unpin>(
    identity: &age::x25519::Identity,
    encrypted_path: &Path,
    writer: &mut W,
) -> Result<u64, InboxCoreError>
```

Decrypts an AGE file into `writer`. Returns the plaintext byte count.

- Rejects scrypt/passphrase AGE files with `Crypto("passphrase encryption not supported")`.

## Metadata Encryption APIs

### `encrypt_metadata_file`

```rust
pub async fn encrypt_metadata_file(
    recipient: &age::x25519::Recipient,
    metadata: &FileMetadata,
    output_path: &Path,
) -> Result<(), InboxCoreError>
```

Serializes `FileMetadata` as JSON and encrypts it into an AGE sidecar file.

### `decrypt_metadata_file`

```rust
pub async fn decrypt_metadata_file(
    identity: &age::x25519::Identity,
    encrypted_path: &Path,
) -> Result<FileMetadata, InboxCoreError>
```

Decrypts an AGE metadata sidecar and parses the JSON into `FileMetadata`.

## Recommended Usage Flow

1. `create_vault(...)` — provision the vault on disk.
2. `unlock_vault(&mut map, ...)` — caller acquires write lock, passes `&mut map`, releases lock.
3. Get recipient from `read_vault_config_file(...)` or from the `CreateVaultResult`.
4. `encrypt_reader_to_age_file(...)` — encrypt file content.
5. Optional: `metadata_sidecar_for(...)` + `encrypt_metadata_file(...)`.
6. For reads:
   - Caller acquires write lock, calls `get_unlocked_identity(&mut map, ...)` (sync), releases lock.
   - `decrypt_age_file_to_writer(...)` with the retrieved identity.
   - Optional: `decrypt_metadata_file(...)`.
7. `lock_vault(&mut map, ...)` when done — caller acquires write lock first.

## Security and Operational Notes

- Treat passwords and identities as sensitive material; avoid logging them.
- Keep `unlock_for` windows short and always call `lock_vault` after critical operations.
- Validate all user inputs with `is_valid_name` / `is_valid_subpath` before composing paths.
- Config permission parsing is lenient (invalid JSON falls back to defaults); do not rely on it for security enforcement.
- Handle all `InboxCoreError` variants explicitly at integration boundaries.

## Minimal Integration Skeleton

```rust
use age_inbox_core::inbox_core::{
    create_vault, decrypt_age_file_to_writer, encrypt_reader_to_age_file,
    get_unlocked_identity, read_vault_config_file, unlock_vault, UnlockedVault,
};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use tokio::sync::RwLock; // owned by the caller, not by the library

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let vaults_dir = Path::new("./vaults");

    // Session state is owned here, not inside age-inbox-core
    let unlocked: RwLock<HashMap<String, UnlockedVault>> = RwLock::new(HashMap::new());

    let created = create_vault(vaults_dir, "demo", "secret".to_string(), false).await?;
    println!("public key: {}", created.public_key);

    // Caller acquires the lock and passes &mut map to the library
    {
        let mut vaults = unlocked.write().await;
        unlock_vault(&mut *vaults, vaults_dir, "demo", "secret".to_string(), Duration::from_secs(60)).await?;
    }

    let cfg = read_vault_config_file(&vaults_dir.join("demo")).await?;
    let recipient: age::x25519::Recipient = cfg.public_key.parse()?;

    let mut src: &[u8] = b"hello";
    encrypt_reader_to_age_file(&recipient, &mut src, &vaults_dir.join("demo/hello.age")).await?;

    // get_unlocked_identity is synchronous — acquire lock, call, release
    let identity = {
        let mut vaults = unlocked.write().await;
        get_unlocked_identity(&mut *vaults, "demo")?
    };

    let mut out = Vec::new();
    decrypt_age_file_to_writer(&identity, &vaults_dir.join("demo/hello.age"), &mut out).await?;

    Ok(())
}
```

---

If you evolve this crate API, update this file alongside code changes to keep integration contracts explicit.

