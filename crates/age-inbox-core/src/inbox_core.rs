use age::x25519::Identity;
use age::{Decryptor, Encryptor};
use futures_util::AsyncWriteExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use tokio_util::compat::{
    FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt,
};

use crate::crypto::derive_keys;

#[derive(Debug)]
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

impl Display for InboxCoreError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            InboxCoreError::InvalidName => write!(f, "Invalid vault name"),
            InboxCoreError::InvalidSubpath => write!(f, "Invalid subpath"),
            InboxCoreError::VaultExists => write!(f, "Vault already exists"),
            InboxCoreError::VaultNotFound => write!(f, "Vault not found"),
            InboxCoreError::VaultConfigMissing => write!(f, "Vault config missing"),
            InboxCoreError::InvalidConfig => write!(f, "Invalid vault config"),
            InboxCoreError::InvalidPassword => write!(f, "Invalid password"),
            InboxCoreError::VaultLocked => write!(f, "Vault is locked"),
            InboxCoreError::VaultUnlockExpired => write!(f, "Vault unlock expired"),
            InboxCoreError::Io(msg) => write!(f, "I/O error: {}", msg),
            InboxCoreError::Crypto(msg) => write!(f, "Crypto error: {}", msg),
            InboxCoreError::Serialize(msg) => write!(f, "Serialization error: {}", msg),
        }
    }
}

impl std::error::Error for InboxCoreError {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultPermissions {
    pub allow_subfolders: bool,
    pub allow_upload: bool,
    pub allow_download: bool,
    pub allow_list: bool,
    pub allow_delete: bool,
    pub allow_metadata: bool,
    pub allow_lock_unlock: bool,
}

impl Default for VaultPermissions {
    fn default() -> Self {
        Self {
            allow_subfolders: false,
            allow_upload: true,
            allow_download: true,
            allow_list: true,
            allow_delete: true,
            allow_metadata: true,
            allow_lock_unlock: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct VaultConfig {
    pub public_key: String,
    pub permissions: VaultPermissions,
}

#[derive(Debug)]
pub struct CreateVaultResult {
    pub public_key: String,
}

pub struct UnlockedVault {
    pub identity: Identity,
    pub expires_at: Instant,
}

#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct FileMetadata {
    pub filename: Option<String>,
    pub origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filesize: Option<u64>,
    #[serde(flatten)]
    pub extended: HashMap<String, serde_json::Value>,
}

pub fn is_valid_name(name: &str) -> bool {
    !name.is_empty() && !name.contains('/') && !name.contains('\\') && !name.contains("..")
}

pub fn is_valid_subpath(path: &str) -> bool {
    !path.contains("..") && !path.starts_with('/') && !path.contains('\\')
}

pub fn metadata_sidecar_for(path: &Path) -> Option<PathBuf> {
    let file_name = path.file_name()?.to_str()?;
    if !file_name.ends_with(".age") || file_name.ends_with(".meta.age") {
        return None;
    }

    let meta_name = file_name.trim_end_matches(".age").to_string() + ".meta.age";
    Some(path.with_file_name(meta_name))
}

/// Generates a unique random filename for an encrypted drop file.
/// Returns a name like `drop-<32 hex chars>.age`.
pub fn generate_drop_filename() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    format!("drop-{}.age", hex)
}

pub async fn read_vault_config_file(vault_dir: &Path) -> Result<VaultConfig, InboxCoreError> {
    let config_path = vault_dir.join(".inbox-age.config");
    let content = tokio::fs::read_to_string(&config_path)
        .await
        .map_err(|_| InboxCoreError::VaultConfigMissing)?;

    let mut public_key = String::new();
    let mut permissions = VaultPermissions::default();

    for line in content.lines() {
        if line.starts_with("public-key: ") {
            public_key = line.trim_start_matches("public-key: ").to_string();
        } else if line.starts_with("permissions: ") {
            let perm_json = line.trim_start_matches("permissions: ");
            if let Ok(perms) = serde_json::from_str::<VaultPermissions>(perm_json) {
                permissions = perms;
            }
        }
    }

    if public_key.is_empty() {
        return Err(InboxCoreError::InvalidConfig);
    }

    Ok(VaultConfig {
        public_key,
        permissions,
    })
}

pub async fn write_vault_config_file(
    vault_dir: &Path,
    inbox_name: &str,
    public_key: &str,
    allow_subfolders: bool,
) -> Result<(), InboxCoreError> {
    let config_path = vault_dir.join(".inbox-age.config");
    let mut permissions = VaultPermissions::default();
    permissions.allow_subfolders = allow_subfolders;

    let permissions_json =
        serde_json::to_string(&permissions).map_err(|e| InboxCoreError::Serialize(e.to_string()))?;

    let config_content = format!(
        "inbox-name: {}\npublic-key: {}\npermissions: {}\n",
        inbox_name, public_key, permissions_json
    );

    tokio::fs::write(config_path, config_content)
        .await
        .map_err(|e| InboxCoreError::Io(e.to_string()))?;

    Ok(())
}

pub async fn create_vault(
    vaults_dir: &Path,
    name: &str,
    password: String,
    allow_subfolders: bool,
) -> Result<CreateVaultResult, InboxCoreError> {
    if !is_valid_name(name) {
        return Err(InboxCoreError::InvalidName);
    }

    let vault_dir = vaults_dir.join(name);
    if vault_dir.exists() {
        return Err(InboxCoreError::VaultExists);
    }

    let keys = derive_keys(&password, name).map_err(|e| InboxCoreError::Crypto(e.to_string()))?;

    tokio::fs::create_dir_all(&vault_dir)
        .await
        .map_err(|e| InboxCoreError::Io(e.to_string()))?;

    let public_key = keys.recipient.to_string();
    write_vault_config_file(&vault_dir, name, &public_key, allow_subfolders).await?;

    Ok(CreateVaultResult { public_key })
}

pub async fn unlock_vault(
    unlocked_vaults: &RwLock<HashMap<String, UnlockedVault>>,
    vaults_dir: &Path,
    name: &str,
    password: String,
    unlock_for: Duration,
) -> Result<(), InboxCoreError> {
    if !is_valid_name(name) {
        return Err(InboxCoreError::InvalidName);
    }

    let vault_dir = vaults_dir.join(name);
    if !vault_dir.exists() {
        return Err(InboxCoreError::VaultNotFound);
    }

    let config = read_vault_config_file(&vault_dir).await?;
    if !config.permissions.allow_lock_unlock {
        return Err(InboxCoreError::Crypto(
            "lock/unlock disabled in config".to_string(),
        ));
    }

    let keys = derive_keys(&password, name).map_err(|e| InboxCoreError::Crypto(e.to_string()))?;

    if keys.recipient.to_string() != config.public_key {
        return Err(InboxCoreError::InvalidPassword);
    }

    let mut vaults = unlocked_vaults.write().await;
    vaults.insert(
        name.to_string(),
        UnlockedVault {
            identity: keys.identity,
            expires_at: Instant::now() + unlock_for,
        },
    );

    Ok(())
}

pub async fn lock_vault(
    unlocked_vaults: &RwLock<HashMap<String, UnlockedVault>>,
    vaults_dir: &Path,
    name: &str,
) -> Result<bool, InboxCoreError> {
    if !is_valid_name(name) {
        return Err(InboxCoreError::InvalidName);
    }

    let vault_dir = vaults_dir.join(name);
    if !vault_dir.exists() {
        return Err(InboxCoreError::VaultNotFound);
    }

    let config = read_vault_config_file(&vault_dir).await?;
    if !config.permissions.allow_lock_unlock {
        return Err(InboxCoreError::Crypto(
            "lock/unlock disabled in config".to_string(),
        ));
    }

    let mut vaults = unlocked_vaults.write().await;
    Ok(vaults.remove(name).is_some())
}

pub async fn get_unlocked_identity(
    unlocked_vaults: &RwLock<HashMap<String, UnlockedVault>>,
    name: &str,
) -> Result<Identity, InboxCoreError> {
    let mut vaults = unlocked_vaults.write().await;
    if let Some(vault) = vaults.get(name) {
        if Instant::now() > vault.expires_at {
            vaults.remove(name);
            return Err(InboxCoreError::VaultUnlockExpired);
        }
        return Ok(vault.identity.clone());
    }

    Err(InboxCoreError::VaultLocked)
}

pub async fn encrypt_reader_to_age_file<R: AsyncRead + Unpin>(
    recipient: &age::x25519::Recipient,
    reader: &mut R,
    output_path: &Path,
) -> Result<u64, InboxCoreError> {
    let file = tokio::fs::File::create(output_path)
        .await
        .map_err(|e| InboxCoreError::Io(e.to_string()))?;

    let encryptor = Encryptor::with_recipients(std::iter::once(recipient as &dyn age::Recipient))
        .expect("recipient provided");

    let mut async_writer = encryptor
        .wrap_async_output(file.compat_write())
        .await
        .map_err(|e| InboxCoreError::Crypto(e.to_string()))?;

    let mut written = 0u64;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let n = reader
            .read(&mut buffer)
            .await
            .map_err(|e| InboxCoreError::Io(e.to_string()))?;
        if n == 0 {
            break;
        }

        async_writer
            .write_all(&buffer[..n])
            .await
            .map_err(|e| InboxCoreError::Io(e.to_string()))?;
        written += n as u64;
    }

    async_writer
        .flush()
        .await
        .map_err(|e| InboxCoreError::Io(e.to_string()))?;
    async_writer
        .close()
        .await
        .map_err(|e| InboxCoreError::Io(e.to_string()))?;

    Ok(written)
}

pub async fn decrypt_age_file_to_writer<W: AsyncWrite + Unpin>(
    identity: &Identity,
    encrypted_path: &Path,
    writer: &mut W,
) -> Result<u64, InboxCoreError> {
    let fs_file = tokio::fs::File::open(encrypted_path)
        .await
        .map_err(|e| InboxCoreError::Io(e.to_string()))?;

    let decryptor = Decryptor::new_async(fs_file.compat())
        .await
        .map_err(|e| InboxCoreError::Crypto(e.to_string()))?;

    if decryptor.is_scrypt() {
        return Err(InboxCoreError::Crypto(
            "passphrase encryption not supported".to_string(),
        ));
    }

    let async_reader = decryptor
        .decrypt_async(std::iter::once(identity as &dyn age::Identity))
        .map_err(|e| InboxCoreError::Crypto(e.to_string()))?;

    let mut compat_reader = async_reader.compat();
    let copied = tokio::io::copy(&mut compat_reader, writer)
        .await
        .map_err(|e| InboxCoreError::Io(e.to_string()))?;

    Ok(copied)
}

pub async fn encrypt_metadata_file(
    recipient: &age::x25519::Recipient,
    metadata: &FileMetadata,
    output_path: &Path,
) -> Result<(), InboxCoreError> {
    let bytes =
        serde_json::to_vec(metadata).map_err(|e| InboxCoreError::Serialize(e.to_string()))?;

    let file = tokio::fs::File::create(output_path)
        .await
        .map_err(|e| InboxCoreError::Io(e.to_string()))?;
    let encryptor = Encryptor::with_recipients(std::iter::once(recipient as &dyn age::Recipient))
        .expect("recipient provided");
    let mut writer = encryptor
        .wrap_async_output(file.compat_write())
        .await
        .map_err(|e| InboxCoreError::Crypto(e.to_string()))?;

    writer
        .write_all(&bytes)
        .await
        .map_err(|e| InboxCoreError::Io(e.to_string()))?;
    writer
        .flush()
        .await
        .map_err(|e| InboxCoreError::Io(e.to_string()))?;
    writer
        .close()
        .await
        .map_err(|e| InboxCoreError::Io(e.to_string()))?;

    Ok(())
}

pub async fn decrypt_metadata_file(
    identity: &Identity,
    encrypted_path: &Path,
) -> Result<FileMetadata, InboxCoreError> {
    let mut out = Vec::new();
    let _ = decrypt_age_file_to_writer(identity, encrypted_path, &mut out).await?;
    serde_json::from_slice(&out).map_err(|e| InboxCoreError::Serialize(e.to_string()))
}
