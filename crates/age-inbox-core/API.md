# age-inbox-core API Reference

This document describes the public APIs exposed by `age-inbox-core` for integration in other Rust projects.

## Checklist

- [x] Document exported modules (`crypto`, `inbox_core`)
- [x] Document public types and errors
- [x] Document all public functions with behavior and error notes
- [x] Add practical integration notes and common pitfalls

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

- Async APIs use Tokio (`tokio` runtime required).
- Encryption/decryption APIs are stream-friendly (`AsyncRead`/`AsyncWrite`).
- Unlock state is managed externally via:
  - `RwLock<HashMap<String, UnlockedVault>>`
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

## Error Type

### Enum: `InboxCoreError`

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

Used by all high-level APIs in this module.

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
    pub expires_at: tokio::time::Instant,
}
```

Stored in shared unlock state map.

### Struct: `FileMetadata`

```rust
pub struct FileMetadata {
    pub filename: Option<String>,
    pub origin: Option<String>,
    pub filesize: Option<u64>,
    pub extended: HashMap<String, serde_json::Value>,
}
```

JSON metadata model for sidecar files.

- `extended` is flattened in JSON for custom fields.

## Validation and Helpers

### `is_valid_name`

```rust
pub fn is_valid_name(name: &str) -> bool
```

Validates vault name:

- must not be empty
- must not contain `/`, `\\`, or `..`

### `is_valid_subpath`

```rust
pub fn is_valid_subpath(path: &str) -> bool
```

Validates relative subpath:

- must not contain `..`
- must not start with `/`
- must not contain `\\`

### `metadata_sidecar_for`

```rust
pub fn metadata_sidecar_for(path: &Path) -> Option<PathBuf>
```

Converts `something.age` -> `something.meta.age`.

Returns `None` if:

- file name is not valid UTF-8
- file does not end with `.age`
- file already ends with `.meta.age`

### `generate_drop_filename`

```rust
pub fn generate_drop_filename() -> String
```

Generates a random name like:

- `drop-<32 hex chars>.age`

## Config File APIs

### `read_vault_config_file`

```rust
pub async fn read_vault_config_file(vault_dir: &Path) -> Result<VaultConfig, InboxCoreError>
```

Reads `.inbox-age.config` from `vault_dir`.

Returns:

- `VaultConfigMissing` if file cannot be read
- `InvalidConfig` if `public-key` is missing

Note:

- `permissions` line is optional; defaults apply if missing or unparseable.

### `write_vault_config_file`

```rust
pub async fn write_vault_config_file(
    vault_dir: &Path,
    inbox_name: &str,
    public_key: &str,
    allow_subfolders: bool,
) -> Result<(), InboxCoreError>
```

Writes `.inbox-age.config` with:

- `inbox-name`
- `public-key`
- serialized `permissions`

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

Flow:

1. Validate vault name.
2. Fail if directory exists.
3. Derive keypair from password + name.
4. Create directory.
5. Write config with public key.

Common errors:

- `InvalidName`
- `VaultExists`
- `Crypto(_)`
- `Io(_)`

### `unlock_vault`

```rust
pub async fn unlock_vault(
    unlocked_vaults: &RwLock<HashMap<String, UnlockedVault>>,
    vaults_dir: &Path,
    name: &str,
    password: String,
    unlock_for: tokio::time::Duration,
) -> Result<(), InboxCoreError>
```

Validates password by recomputing recipient and comparing with config public key.

On success, inserts/overwrites entry in `unlocked_vaults` with expiration time.

Common errors:

- `InvalidName`
- `VaultNotFound`
- `VaultConfigMissing` / `InvalidConfig`
- `InvalidPassword`
- `Crypto("lock/unlock disabled in config")`

### `lock_vault`

```rust
pub async fn lock_vault(
    unlocked_vaults: &RwLock<HashMap<String, UnlockedVault>>,
    vaults_dir: &Path,
    name: &str,
) -> Result<bool, InboxCoreError>
```

Removes vault from unlock map.

Returns:

- `Ok(true)` if it was unlocked and removed
- `Ok(false)` if no unlock entry existed

### `get_unlocked_identity`

```rust
pub async fn get_unlocked_identity(
    unlocked_vaults: &RwLock<HashMap<String, UnlockedVault>>,
    name: &str,
) -> Result<age::x25519::Identity, InboxCoreError>
```

Fetches current identity for a vault.

Behavior:

- If expired, removes entry and returns `VaultUnlockExpired`.
- If missing, returns `VaultLocked`.
- Otherwise returns cloned identity.

## File Encryption/Decryption APIs

### `encrypt_reader_to_age_file`

```rust
pub async fn encrypt_reader_to_age_file<R: AsyncRead + Unpin>(
    recipient: &age::x25519::Recipient,
    reader: &mut R,
    output_path: &Path,
) -> Result<u64, InboxCoreError>
```

Encrypts bytes from `reader` into an AGE file at `output_path`.

Returns plaintext byte count written.

Notes:

- Uses chunked I/O (16 KiB buffer).
- Caller controls source stream lifetime.

### `decrypt_age_file_to_writer`

```rust
pub async fn decrypt_age_file_to_writer<W: AsyncWrite + Unpin>(
    identity: &age::x25519::Identity,
    encrypted_path: &Path,
    writer: &mut W,
) -> Result<u64, InboxCoreError>
```

Decrypts AGE file into `writer`.

Returns copied plaintext byte count.

Important limitation:

- Rejects scrypt/passphrase AGE files (`Crypto("passphrase encryption not supported")`).
- Expects recipient-based AGE encryption compatible with x25519 identity.

## Metadata Encryption APIs

### `encrypt_metadata_file`

```rust
pub async fn encrypt_metadata_file(
    recipient: &age::x25519::Recipient,
    metadata: &FileMetadata,
    output_path: &Path,
) -> Result<(), InboxCoreError>
```

Serializes `FileMetadata` as JSON, then encrypts to AGE file.

### `decrypt_metadata_file`

```rust
pub async fn decrypt_metadata_file(
    identity: &age::x25519::Identity,
    encrypted_path: &Path,
) -> Result<FileMetadata, InboxCoreError>
```

Decrypts AGE metadata file and parses JSON into `FileMetadata`.

## Recommended Usage Flow

1. `create_vault(...)`
2. `unlock_vault(...)` with short `unlock_for`
3. Get recipient from vault config (`read_vault_config_file`) or prior create result
4. `encrypt_reader_to_age_file(...)`
5. Optional metadata:
   - `metadata_sidecar_for(...)`
   - `encrypt_metadata_file(...)`
6. For reads:
   - `get_unlocked_identity(...)`
   - `decrypt_age_file_to_writer(...)`
   - optional `decrypt_metadata_file(...)`
7. `lock_vault(...)` when done

## Security and Operational Notes

- Treat passwords and identities as sensitive material.
- Keep unlock windows short; rely on expiration + explicit lock.
- Validate user inputs (`is_valid_name`, `is_valid_subpath`) before path composition.
- Do not assume config parsing is strict for permissions (invalid JSON falls back to defaults).
- Handle all `InboxCoreError` variants explicitly at integration boundaries.

## Minimal Integration Skeleton

```rust
use age_inbox_core::inbox_core::{
    create_vault, decrypt_age_file_to_writer, encrypt_reader_to_age_file,
    get_unlocked_identity, read_vault_config_file, unlock_vault, UnlockedVault,
};
use std::collections::HashMap;
use std::path::Path;
use tokio::sync::RwLock;
use tokio::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let vaults_dir = Path::new("./vaults");
    let unlocked = RwLock::<HashMap<String, UnlockedVault>>::new(HashMap::new());

    let created = create_vault(vaults_dir, "demo", "secret".to_string(), false).await?;
    println!("public key: {}", created.public_key);

    unlock_vault(
        &unlocked,
        vaults_dir,
        "demo",
        "secret".to_string(),
        Duration::from_secs(60),
    )
    .await?;

    let cfg = read_vault_config_file(&vaults_dir.join("demo")).await?;
    let recipient: age::x25519::Recipient = cfg.public_key.parse()?;

    let mut src: &[u8] = b"hello";
    encrypt_reader_to_age_file(&recipient, &mut src, &vaults_dir.join("demo/hello.age")).await?;

    let identity = get_unlocked_identity(&unlocked, "demo").await?;
    let mut out = Vec::new();
    decrypt_age_file_to_writer(&identity, &vaults_dir.join("demo/hello.age"), &mut out).await?;

    Ok(())
}
```

---

If you evolve this crate API, update this file alongside code changes to keep integration contracts explicit.

