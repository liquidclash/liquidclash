//! Credential storage abstraction (product-contract.md §2).
//!
//! The Windows production implementation is a Windows Credential Manager
//! generic credential (DPAPI-scoped, target `tono/refresh-token`) and lives
//! in the Windows app crate, not here. This crate ships the trait, an
//! in-memory implementation for tests, and a 0600 file implementation for
//! development.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use thiserror::Error;

/// Windows Credential Manager target for the refresh token (§2). The
/// Windows-side `CredentialStore` implementation uses this name.
pub const WINDOWS_CRED_TARGET_REFRESH_TOKEN: &str = "tono/refresh-token";

/// The two secrets the account session persists (§2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialKey {
    RefreshToken,
    InstallationId,
}

impl CredentialKey {
    fn file_name(self) -> &'static str {
        match self {
            CredentialKey::RefreshToken => "refresh-token",
            CredentialKey::InstallationId => "installation-id",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CredentialError {
    #[error("credential store failed: {0}")]
    Store(String),
}

/// Sync by design: Keychain and Windows Credential Manager are both
/// synchronous APIs. Implementations must be safe to call from async code
/// (operations are short and non-blocking).
pub trait CredentialStore: Send + Sync {
    fn get(&self, key: CredentialKey) -> Result<Option<String>, CredentialError>;
    fn set(&self, key: CredentialKey, value: &str) -> Result<(), CredentialError>;
    fn delete(&self, key: CredentialKey) -> Result<(), CredentialError>;

    fn refresh_token(&self) -> Result<Option<String>, CredentialError> {
        self.get(CredentialKey::RefreshToken)
    }
    fn set_refresh_token(&self, value: &str) -> Result<(), CredentialError> {
        self.set(CredentialKey::RefreshToken, value)
    }
    fn delete_refresh_token(&self) -> Result<(), CredentialError> {
        self.delete(CredentialKey::RefreshToken)
    }
    fn installation_id(&self) -> Result<Option<String>, CredentialError> {
        self.get(CredentialKey::InstallationId)
    }
    fn set_installation_id(&self, value: &str) -> Result<(), CredentialError> {
        self.set(CredentialKey::InstallationId, value)
    }
    fn delete_installation_id(&self) -> Result<(), CredentialError> {
        self.delete(CredentialKey::InstallationId)
    }
}

/// In-memory store for tests.
#[derive(Debug, Default)]
pub struct MemoryCredentialStore {
    entries: Mutex<HashMap<CredentialKey, String>>,
}

impl MemoryCredentialStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl CredentialStore for MemoryCredentialStore {
    fn get(&self, key: CredentialKey) -> Result<Option<String>, CredentialError> {
        Ok(self
            .entries
            .lock()
            .map_err(|err| CredentialError::Store(err.to_string()))?
            .get(&key)
            .cloned())
    }

    fn set(&self, key: CredentialKey, value: &str) -> Result<(), CredentialError> {
        self.entries
            .lock()
            .map_err(|err| CredentialError::Store(err.to_string()))?
            .insert(key, value.to_string());
        Ok(())
    }

    fn delete(&self, key: CredentialKey) -> Result<(), CredentialError> {
        self.entries
            .lock()
            .map_err(|err| CredentialError::Store(err.to_string()))?
            .remove(&key);
        Ok(())
    }
}

/// Development store: one 0600 file per key inside `dir`. Atomic writes
/// (temp file + rename). Not for production — production uses Windows
/// Credential Manager behind the same trait.
pub struct FileCredentialStore {
    dir: PathBuf,
}

impl FileCredentialStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn path(&self, key: CredentialKey) -> PathBuf {
        self.dir.join(key.file_name())
    }
}

impl CredentialStore for FileCredentialStore {
    fn get(&self, key: CredentialKey) -> Result<Option<String>, CredentialError> {
        match fs::read_to_string(self.path(key)) {
            Ok(value) => Ok(Some(value)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(CredentialError::Store(err.to_string())),
        }
    }

    fn set(&self, key: CredentialKey, value: &str) -> Result<(), CredentialError> {
        fs::create_dir_all(&self.dir).map_err(|err| CredentialError::Store(err.to_string()))?;
        let target = self.path(key);
        let temp = self.dir.join(format!(
            ".{}.tmp-{}-{}",
            key.file_name(),
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let result = (|| -> Result<(), CredentialError> {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            use std::io::Write as _;
            let mut file = options
                .open(&temp)
                .map_err(|err| CredentialError::Store(err.to_string()))?;
            file.write_all(value.as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|err| CredentialError::Store(err.to_string()))?;
            #[cfg(unix)]
            fs::set_permissions(&temp, std::os::unix::fs::PermissionsExt::from_mode(0o600))
                .map_err(|err| CredentialError::Store(err.to_string()))?;
            fs::rename(&temp, &target).map_err(|err| CredentialError::Store(err.to_string()))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        // Best-effort directory fsync so the rename itself is durable
        // (mirrors CatalogCache::store) (L2).
        #[cfg(unix)]
        if let Ok(dir_handle) = fs::File::open(&self.dir) {
            let _ = dir_handle.sync_all();
        }
        result
    }

    fn delete(&self, key: CredentialKey) -> Result<(), CredentialError> {
        match fs::remove_file(self.path(key)) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(CredentialError::Store(err.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exercise(store: &impl CredentialStore) {
        assert_eq!(store.refresh_token().unwrap(), None);
        store.set_refresh_token("rt-1").unwrap();
        store.set_installation_id("2f5b1f2a-0000-4c81-8d2b-3f2d0a1b2c3d").unwrap();
        assert_eq!(store.refresh_token().unwrap().as_deref(), Some("rt-1"));
        assert_eq!(
            store.installation_id().unwrap().as_deref(),
            Some("2f5b1f2a-0000-4c81-8d2b-3f2d0a1b2c3d")
        );
        // Rotation replaces atomically.
        store.set_refresh_token("rt-2").unwrap();
        assert_eq!(store.refresh_token().unwrap().as_deref(), Some("rt-2"));
        store.delete_refresh_token().unwrap();
        assert_eq!(store.refresh_token().unwrap(), None);
        // Deleting a missing key is not an error.
        store.delete_refresh_token().unwrap();
        assert_eq!(
            store.installation_id().unwrap().as_deref(),
            Some("2f5b1f2a-0000-4c81-8d2b-3f2d0a1b2c3d")
        );
    }

    #[test]
    fn memory_store_roundtrip() {
        exercise(&MemoryCredentialStore::new());
    }

    #[test]
    fn file_store_roundtrip() {
        let dir = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("tono-core-creds-{}", uuid::Uuid::new_v4()));
        let store = FileCredentialStore::new(&dir);
        exercise(&store);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn file_store_writes_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("tono-core-creds-{}", uuid::Uuid::new_v4()));
        let store = FileCredentialStore::new(&dir);
        store.set_refresh_token("rt").unwrap();
        let mode = fs::metadata(dir.join("refresh-token"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn credential_key_file_names_are_stable() {
        assert_eq!(CredentialKey::RefreshToken.file_name(), "refresh-token");
        assert_eq!(CredentialKey::InstallationId.file_name(), "installation-id");
    }
}
