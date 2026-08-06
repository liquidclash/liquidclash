//! Credential plumbing for the Tono account session (product-contract.md §2).
//!
//! Two layers, deliberately separate:
//!
//! - [`TonoCredentialStore`] — the OS vault (Windows Credential Manager in
//!   production, the macOS keychain during development). Its *synchronous*
//!   trait methods must only ever run inside `tokio::task::spawn_blocking`:
//!   a slow or prompting vault (macOS securityd ACL prompts block in
//!   `mach_msg` indefinitely) must never freeze an executor thread, and
//!   **never** the setup main thread (the startup deadlock this layering
//!   fixes).
//! - [`SessionCredentialStore`] — the store handed to tono-core's
//!   `ApiClient`: memory-first, so every sync trait call the client makes
//!   is a pure memory access; keyring persistence is a fire-and-forget
//!   `spawn_blocking` write-through that can hang a blocking-pool thread at
//!   worst, never the product logic.

use keyring::Entry;
use tono_core::credentials::{CredentialError, CredentialKey, CredentialStore, MemoryCredentialStore};

/// keyring service name; entries appear as `tono/<key>` (§2).
const SERVICE_NAME: &str = "tono";

fn account_name(key: CredentialKey) -> &'static str {
    match key {
        CredentialKey::RefreshToken => "refresh-token",
        CredentialKey::InstallationId => "installation-id",
    }
}

/// The OS credential vault behind tono-core's synchronous trait. Only call
/// inside `spawn_blocking` (or the async adapter below).
pub struct TonoCredentialStore;

impl TonoCredentialStore {
    fn entry(key: CredentialKey) -> Result<Entry, CredentialError> {
        Entry::new(SERVICE_NAME, account_name(key)).map_err(|err| CredentialError::Store(err.to_string()))
    }

    /// Async adapter: the synchronous vault call runs on the blocking pool.
    /// Join failures surface as store errors (never panic); a missing entry
    /// is `Ok(None)`, mirroring the trait.
    pub async fn get_async(key: CredentialKey) -> Result<Option<String>, CredentialError> {
        tokio::task::spawn_blocking(move || match Self::entry(key)?.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(store_error(err)),
        })
        .await
        .map_err(join_error)?
    }

    /// Async adapter for writes (user-action paths; no timeout needed).
    pub async fn set_async(key: CredentialKey, value: &str) -> Result<(), CredentialError> {
        let value = value.to_string();
        tokio::task::spawn_blocking(move || Self::entry(key)?.set_password(&value).map_err(store_error))
            .await
            .map_err(join_error)?
    }

    /// Async adapter for deletes.
    pub async fn delete_async(key: CredentialKey) -> Result<(), CredentialError> {
        tokio::task::spawn_blocking(move || match Self::entry(key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(err) => Err(store_error(err)),
        })
        .await
        .map_err(join_error)?
    }
}

fn store_error(err: keyring::Error) -> CredentialError {
    CredentialError::Store(err.to_string())
}

fn join_error(err: tokio::task::JoinError) -> CredentialError {
    CredentialError::Store(format!("credential task failed: {err}"))
}

impl CredentialStore for TonoCredentialStore {
    fn get(&self, key: CredentialKey) -> Result<Option<String>, CredentialError> {
        match Self::entry(key)?.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(store_error(err)),
        }
    }

    fn set(&self, key: CredentialKey, value: &str) -> Result<(), CredentialError> {
        Self::entry(key)?.set_password(value).map_err(store_error)
    }

    fn delete(&self, key: CredentialKey) -> Result<(), CredentialError> {
        match Self::entry(key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(err) => Err(store_error(err)),
        }
    }
}

/// The store `ApiClient` actually holds (§2): every sync trait call is a
/// pure memory access. Reads are hydrated by the startup load task;
/// writes (`adopt`, token rotation, `logout`) additionally persist to the
/// keyring via a detached `spawn_blocking` write-through — fire-and-forget,
/// so a hung vault can never stall the session it belongs to.
pub struct SessionCredentialStore {
    memory: MemoryCredentialStore,
    /// False in tests: no vault access at all.
    persist: bool,
}

impl SessionCredentialStore {
    pub fn new() -> Self {
        Self {
            memory: MemoryCredentialStore::new(),
            persist: true,
        }
    }

    /// Memory-only instance for tests (write-through disabled).
    #[cfg(test)]
    pub fn for_test() -> Self {
        Self {
            memory: MemoryCredentialStore::new(),
            persist: false,
        }
    }

    /// Memory-only write, skipping the vault write-through. Used by the
    /// startup load task to hydrate from the vault without writing the same
    /// bytes straight back.
    pub fn set_local(&self, key: CredentialKey, value: &str) -> Result<(), CredentialError> {
        self.memory.set(key, value)
    }

    /// Detached vault write; logs on failure, never blocks the caller.
    fn persist_write(&self, key: CredentialKey, value: String) {
        if !self.persist {
            return;
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                if let Err(err) = TonoCredentialStore::set_async(key, &value).await {
                    clash_verge_logging::logging!(
                        warn,
                        clash_verge_logging::Type::Service,
                        "Tono: 凭据回写系统钥匙串失败: {err}"
                    );
                }
            });
        }
    }

    /// Detached vault delete.
    fn persist_delete(&self, key: CredentialKey) {
        if !self.persist {
            return;
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = TonoCredentialStore::delete_async(key).await;
            });
        }
    }
}

impl CredentialStore for SessionCredentialStore {
    fn get(&self, key: CredentialKey) -> Result<Option<String>, CredentialError> {
        self.memory.get(key)
    }

    fn set(&self, key: CredentialKey, value: &str) -> Result<(), CredentialError> {
        self.memory.set(key, value)?;
        self.persist_write(key, value.to_string());
        Ok(())
    }

    fn delete(&self, key: CredentialKey) -> Result<(), CredentialError> {
        self.memory.delete(key)?;
        self.persist_delete(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{SERVICE_NAME, SessionCredentialStore, account_name};
    use tono_core::credentials::{CredentialKey, CredentialStore};

    #[test]
    fn account_names_are_stable() {
        // The refresh token lands at `tono/refresh-token` (§2).
        assert_eq!(
            format!("{SERVICE_NAME}/{}", account_name(CredentialKey::RefreshToken)),
            "tono/refresh-token"
        );
        assert_eq!(account_name(CredentialKey::InstallationId), "installation-id");
    }

    #[test]
    fn session_store_is_memory_first_and_vault_free_in_tests() {
        // Everything the ApiClient can do stays in memory; `for_test` never
        // reaches the OS vault (this test would otherwise hang on macOS
        // securityd prompts the same way the startup did).
        let store = SessionCredentialStore::for_test();
        assert_eq!(store.refresh_token().unwrap(), None);
        store.set_refresh_token("rt-1").unwrap();
        assert_eq!(store.refresh_token().unwrap().as_deref(), Some("rt-1"));
        // Rotation replaces the memory copy.
        store.set_refresh_token("rt-2").unwrap();
        assert_eq!(store.refresh_token().unwrap().as_deref(), Some("rt-2"));
        // set_local hydrates without any write-through.
        store
            .set_local(CredentialKey::InstallationId, "2f5b1f2a-0000-4c81-8d2b-3f2d0a1b2c3d")
            .unwrap();
        assert_eq!(
            store.installation_id().unwrap().as_deref(),
            Some("2f5b1f2a-0000-4c81-8d2b-3f2d0a1b2c3d")
        );
        store.delete_refresh_token().unwrap();
        assert_eq!(store.refresh_token().unwrap(), None);
        store.delete_refresh_token().unwrap();
    }
}
