//! Exit catalog contract (product-contract.md §3).
//!
//! Validation order, all mandatory: revision >= 0 and YAML <= 1 MiB; SHA-256
//! digest matches (base64url, no padding); YAML parses and every node passes
//! admission with at most 200 nodes; an empty catalog is accepted only as
//! the literal `proxies: []`. [`CatalogTracker`] enforces revision
//! monotonicity at install time to defeat concurrent reordering.
//! [`CatalogCache`] persists only fully verified catalogs, writes them
//! atomically, and re-checks file safety before every read.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::node::{NodeRejection, ValidatedNode, admit_nodes};

/// Maximum accepted catalog YAML size (§3).
pub const MAX_CATALOG_YAML_BYTES: usize = 1024 * 1024;
/// Maximum accepted on-disk cache size (§3).
pub const MAX_CACHE_FILE_BYTES: u64 = 2 * 1024 * 1024;
/// Cache file name inside the app data dir (§3).
pub const CACHE_FILE_NAME: &str = "managed-exit-catalog.json";

/// Wire shape of `GET exit-catalog` (§3). `updatedAt` is optional.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExitCatalogResponse {
    pub revision: i64,
    pub yaml: String,
    pub sha256: String,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,
}

/// SHA-256 of the YAML's UTF-8 bytes, base64url **without padding** (§3).
pub fn catalog_digest(yaml: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(yaml.as_bytes()))
}

/// Why a catalog (or its cache) was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CatalogError {
    /// Any contract violation that maps to the API client's
    /// `invalidResponse` (§1/§3).
    #[error("catalog response is invalid")]
    InvalidResponse,
    /// Revision lower than the installed one. Semantic difference from
    /// macOS (which silently ignores it): callers must treat this as a
    /// benign no-op caused by out-of-order delivery — never count it
    /// toward retries or error reporting (L5).
    #[error("catalog revision regressed")]
    StaleRevision,
    /// A node failed the admission contract (§4).
    #[error("node admission failed: {0}")]
    Node(#[from] NodeRejection),
    #[error("cache I/O failed: {0}")]
    Io(String),
}

/// Steps 1-3 of catalog validation (§3). Pure; revision monotonicity is
/// enforced separately by [`CatalogTracker`].
pub fn validate_catalog(catalog: &ExitCatalogResponse) -> Result<Vec<ValidatedNode>, CatalogError> {
    // 1. revision and size bounds.
    if catalog.revision < 0 || catalog.yaml.len() > MAX_CATALOG_YAML_BYTES {
        return Err(CatalogError::InvalidResponse);
    }
    // 2. Digest must match the YAML's UTF-8 bytes. The digest is not secret,
    // so a plain string compare is sufficient.
    if catalog.sha256 != catalog_digest(&catalog.yaml) {
        return Err(CatalogError::InvalidResponse);
    }
    // 3. Parse and admit every node.
    let document: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(&catalog.yaml).map_err(|_| CatalogError::InvalidResponse)?;
    let proxies = document
        .as_mapping()
        .and_then(|mapping| mapping.get(serde_yaml_ng::Value::String("proxies".to_string())));
    let nodes = match proxies {
        Some(serde_yaml_ng::Value::Sequence(entries)) => admit_nodes(entries)?,
        Some(_) => return Err(CatalogError::InvalidResponse),
        None => Vec::new(),
    };
    if nodes.is_empty() {
        // An empty catalog is accepted only as the literal `proxies: []`.
        if catalog.yaml.trim() != "proxies: []" {
            return Err(CatalogError::InvalidResponse);
        }
    }
    Ok(nodes)
}

/// Result of a [`CatalogTracker::install`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallOutcome {
    /// Newer revision: validated nodes, ready to swap in.
    Installed(Vec<ValidatedNode>),
    /// Same revision and digest as the installed catalog: idempotent accept.
    Unchanged,
}

/// Enforces catalog revision monotonicity (§3 step 4). The monotonicity
/// check runs inside `install`, after full validation, so concurrently
/// reordered downloads cannot regress the committed catalog.
#[derive(Debug, Clone)]
pub struct CatalogTracker {
    current_revision: i64,
    current_digest: Option<String>,
}

impl Default for CatalogTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl CatalogTracker {
    /// Nothing installed yet: any non-negative revision is newer.
    pub fn new() -> Self {
        Self {
            current_revision: -1,
            current_digest: None,
        }
    }

    /// Seed from a previously verified cache so a download can never roll
    /// back across restarts.
    pub fn from_installed(revision: i64, digest: String) -> Self {
        Self {
            current_revision: revision,
            current_digest: Some(digest),
        }
    }

    pub fn current_revision(&self) -> i64 {
        self.current_revision
    }

    pub fn current_digest(&self) -> Option<&str> {
        self.current_digest.as_deref()
    }

    /// Validate `catalog` (steps 1-3) and commit it if its revision is
    /// strictly newer. Equal revision with a different digest is
    /// `invalidResponse`; equal revision with the same digest is an
    /// idempotent no-op.
    pub fn install(
        &mut self,
        catalog: &ExitCatalogResponse,
    ) -> Result<InstallOutcome, CatalogError> {
        let nodes = validate_catalog(catalog)?;
        if catalog.revision < self.current_revision {
            return Err(CatalogError::StaleRevision);
        }
        if catalog.revision == self.current_revision {
            return if self.current_digest == Some(catalog.sha256.clone()) {
                Ok(InstallOutcome::Unchanged)
            } else {
                Err(CatalogError::InvalidResponse)
            };
        }
        self.current_revision = catalog.revision;
        self.current_digest = Some(catalog.sha256.clone());
        Ok(InstallOutcome::Installed(nodes))
    }
}

/// Pre-read safety policy for the on-disk cache (§3). The unix
/// implementation lives below; a Windows ACL-based implementation plugs in
/// behind this trait without touching [`CatalogCache`].
///
/// WARNING: a Windows implementation that stubs every check with `Ok(())`
/// silently voids the cache safety contract (L9) — an all-pass policy is
/// worse than none because it looks enforced.
pub trait CacheSafetyCheck {
    /// Path-level checks before opening (unix: reject symlinks via lstat).
    fn check_path(&self, path: &Path) -> Result<(), CatalogError>;
    /// Checks on the already-opened file, so the inspected inode is exactly
    /// the one being read (unix: regular file, owner, mode, size).
    fn check_open(&self, file: &fs::File) -> Result<(), CatalogError>;

    /// Hook invoked on the temporary file after its contents are written and
    /// synced, immediately before the atomic rename in [`CatalogCache::store`].
    /// Platforms use it to bring the file's protection up to what
    /// [`CacheSafetyCheck::check_open`] demands — the two must be symmetric or
    /// the cache can never be read back (Windows: a protected DACL naming
    /// exactly the owner, SYSTEM, and Administrators). Unix keeps its 0600
    /// chmod inside `store` instead, so the default here is a no-op.
    fn secure_written_file(&self, path: &Path) -> std::io::Result<()> {
        let _ = path;
        Ok(())
    }
}

/// Unix cache safety: not a symlink, a regular file, owned by the current
/// uid, `mode & 0o077 == 0`, `0 < size <= 2 MiB` (§3).
#[cfg(unix)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UnixCacheSafetyCheck;

#[cfg(unix)]
impl CacheSafetyCheck for UnixCacheSafetyCheck {
    fn check_path(&self, path: &Path) -> Result<(), CatalogError> {
        let metadata =
            fs::symlink_metadata(path).map_err(|err| CatalogError::Io(err.to_string()))?;
        if metadata.file_type().is_symlink() {
            return Err(CatalogError::Io("cache path is a symlink".to_string()));
        }
        Ok(())
    }

    fn check_open(&self, file: &fs::File) -> Result<(), CatalogError> {
        use std::os::unix::fs::MetadataExt;
        let metadata = file
            .metadata()
            .map_err(|err| CatalogError::Io(err.to_string()))?;
        if !metadata.file_type().is_file() {
            return Err(CatalogError::Io("cache is not a regular file".to_string()));
        }
        if metadata.uid() != nix::unistd::getuid().as_raw() {
            return Err(CatalogError::Io(
                "cache is owned by another uid".to_string(),
            ));
        }
        if metadata.mode() & 0o077 != 0 {
            return Err(CatalogError::Io(
                "cache permissions are too open".to_string(),
            ));
        }
        let size = metadata.size();
        if size == 0 || size > MAX_CACHE_FILE_BYTES {
            return Err(CatalogError::Io("cache size out of bounds".to_string()));
        }
        Ok(())
    }
}

/// A cache entry that survived safety checks and full re-validation.
#[derive(Debug, Clone)]
pub struct CachedCatalog {
    pub response: ExitCatalogResponse,
    pub nodes: Vec<ValidatedNode>,
}

/// On-disk catalog cache (`managed-exit-catalog.json`, §3). Only fully
/// verified catalogs are ever written; a failing or invalid download never
/// reaches `store`, and `store` re-validates defensively. Writes are atomic
/// (temp file + rename in the same directory).
pub struct CatalogCache {
    path: PathBuf,
    safety: Box<dyn CacheSafetyCheck>,
}

impl CatalogCache {
    pub fn new(dir: &Path, safety: Box<dyn CacheSafetyCheck>) -> Self {
        Self {
            path: dir.join(CACHE_FILE_NAME),
            safety,
        }
    }

    /// Cache using the platform-default safety policy (unix: owner/mode/type
    /// checks; Windows supplies an ACL implementation behind the same trait).
    #[cfg(unix)]
    pub fn platform(dir: &Path) -> Self {
        Self::new(dir, Box::new(UnixCacheSafetyCheck))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load and fully re-validate the cached catalog. Any safety or
    /// validation failure yields `None` — a corrupt cache is treated as
    /// absent, never as authoritative.
    pub fn load(&self) -> Option<CachedCatalog> {
        self.safety.check_path(&self.path).ok()?;
        let mut file = fs::File::open(&self.path).ok()?;
        self.safety.check_open(&file).ok()?;
        let mut body = String::new();
        std::io::Read::by_ref(&mut file)
            .take(MAX_CACHE_FILE_BYTES + 1)
            .read_to_string(&mut body)
            .ok()?;
        let response: ExitCatalogResponse = serde_json::from_str(&body).ok()?;
        let nodes = validate_catalog(&response).ok()?;
        Some(CachedCatalog { response, nodes })
    }

    /// Atomically persist a catalog. Re-validates before writing so the
    /// "only verified copies reach disk" invariant holds by construction.
    pub fn store(&self, catalog: &ExitCatalogResponse) -> Result<(), CatalogError> {
        validate_catalog(catalog)?;
        let body =
            serde_json::to_string(catalog).map_err(|err| CatalogError::Io(err.to_string()))?;
        // Symmetric with `load`: a body the cache would refuse to read back
        // must never be written (L1).
        if body.len() as u64 > MAX_CACHE_FILE_BYTES {
            return Err(CatalogError::Io(
                "serialized catalog exceeds the 2 MiB cache limit".to_string(),
            ));
        }
        let dir = self
            .path
            .parent()
            .ok_or_else(|| CatalogError::Io("cache path has no parent".to_string()))?;
        fs::create_dir_all(dir).map_err(|err| CatalogError::Io(err.to_string()))?;
        let temp = dir.join(format!(
            ".{CACHE_FILE_NAME}.tmp-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let write_result = (|| -> Result<(), CatalogError> {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(&temp)
                .map_err(|err| CatalogError::Io(err.to_string()))?;
            file.write_all(body.as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|err| CatalogError::Io(err.to_string()))?;
            #[cfg(unix)]
            {
                // Ensure exactly 0600 even under a restrictive umask or a
                // pre-existing temp inode.
                fs::set_permissions(&temp, std::os::unix::fs::PermissionsExt::from_mode(0o600))
                    .map_err(|err| CatalogError::Io(err.to_string()))?;
            }
            // Give the platform policy the chance to tighten the temp file
            // to exactly what `check_open` will later demand (Windows DACL),
            // before the rename publishes it.
            self.safety
                .secure_written_file(&temp)
                .map_err(|err| CatalogError::Io(err.to_string()))?;
            fs::rename(&temp, &self.path).map_err(|err| CatalogError::Io(err.to_string()))?;
            Ok(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        // Best-effort directory fsync so the rename itself is durable.
        #[cfg(unix)]
        if let Ok(dir_handle) = fs::File::open(dir) {
            let _ = dir_handle.sync_all();
        }
        write_result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODE_YAML: &str = r#"  - name: "US Reality 01"
    type: vless
    server: 8.8.8.8
    port: 443
    uuid: "9e107d9d-372b-4c81-8d2b-3f2d0a1b2c3d"
    tls: true
    sni: "www.microsoft.com"
    flow: xtls-rprx-vision
    network: tcp
    reality-opts:
      public-key: "0123456789abcdef0123456789abcdef0123456789a"
      short-id: "0123456789abcdef"
"#;

    fn catalog_with_yaml(revision: i64, yaml: &str) -> ExitCatalogResponse {
        ExitCatalogResponse {
            revision,
            yaml: yaml.to_string(),
            sha256: catalog_digest(yaml),
            updated_at: None,
        }
    }

    fn valid_catalog(revision: i64) -> ExitCatalogResponse {
        catalog_with_yaml(revision, &format!("proxies:\n{NODE_YAML}"))
    }

    /// RAII temp directory for cache tests.
    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("tono-core-test-{tag}-{}", uuid::Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    // ---- digest ----

    #[test]
    fn digest_is_base64url_without_padding() {
        // SHA-256 of "" is 32 bytes; base64url-no-pad is 43 chars.
        let digest = catalog_digest("");
        assert_eq!(digest.len(), 43);
        assert!(!digest.contains(['=', '+', '/']));
        // Known vector: SHA-256("") base64 standard is
        // 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
        assert_eq!(digest, "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU");
    }

    // ---- validate_catalog ----

    #[test]
    fn accepts_valid_catalog() {
        let nodes = validate_catalog(&valid_catalog(7)).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "US Reality 01");
    }

    #[test]
    fn rejects_negative_revision() {
        let mut catalog = valid_catalog(0);
        catalog.revision = -1;
        assert_eq!(
            validate_catalog(&catalog).unwrap_err(),
            CatalogError::InvalidResponse
        );
    }

    #[test]
    fn rejects_oversized_yaml() {
        let yaml = format!(
            "proxies:\n{NODE_YAML}#{}",
            "x".repeat(MAX_CATALOG_YAML_BYTES)
        );
        let catalog = catalog_with_yaml(0, &yaml);
        assert_eq!(
            validate_catalog(&catalog).unwrap_err(),
            CatalogError::InvalidResponse
        );
    }

    #[test]
    fn rejects_tampered_digest() {
        let mut catalog = valid_catalog(0);
        catalog.yaml = catalog.yaml.replace("8.8.8.8", "1.1.1.1"); // digest now stale
        assert_eq!(
            validate_catalog(&catalog).unwrap_err(),
            CatalogError::InvalidResponse
        );
        // Also: yaml untouched, digest replaced.
        let mut catalog = valid_catalog(0);
        catalog.sha256 = catalog_digest("something else");
        assert_eq!(
            validate_catalog(&catalog).unwrap_err(),
            CatalogError::InvalidResponse
        );
    }

    #[test]
    fn rejects_unparseable_yaml() {
        let catalog = catalog_with_yaml(0, "proxies: [not: valid: yaml: {");
        assert_eq!(
            validate_catalog(&catalog).unwrap_err(),
            CatalogError::InvalidResponse
        );
    }

    #[test]
    fn rejects_catalog_with_failing_node() {
        // A private-IP node mixed into an otherwise fine catalog.
        let yaml = format!(
            "proxies:\n{NODE_YAML}{}",
            NODE_YAML
                .replace("8.8.8.8", "10.0.0.8")
                .replace("US Reality 01", "Evil")
        );
        let catalog = catalog_with_yaml(0, &yaml);
        assert_eq!(
            validate_catalog(&catalog).unwrap_err(),
            CatalogError::Node(NodeRejection::ServerNotPublicIpv4)
        );
    }

    #[test]
    fn rejects_over_200_nodes() {
        let mut yaml = "proxies:\n".to_string();
        for index in 0..=200 {
            yaml.push_str(&NODE_YAML.replace("US Reality 01", &format!("node-{index}")));
        }
        let catalog = catalog_with_yaml(0, &yaml);
        assert_eq!(
            validate_catalog(&catalog).unwrap_err(),
            CatalogError::Node(NodeRejection::TooManyNodes)
        );
    }

    #[test]
    fn accepts_empty_catalog_literal_only() {
        let nodes = validate_catalog(&catalog_with_yaml(0, "proxies: []")).unwrap();
        assert!(nodes.is_empty());
        // Trailing whitespace/newline is tolerated by the trimmed compare.
        let nodes = validate_catalog(&catalog_with_yaml(0, "proxies: []\n")).unwrap();
        assert!(nodes.is_empty());
        for bad in [
            "proxies:",
            "proxies: null",
            "proxies: {}\n",
            "# empty\n",
            "",
        ] {
            assert_eq!(
                validate_catalog(&catalog_with_yaml(0, bad)).unwrap_err(),
                CatalogError::InvalidResponse,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn rejects_non_sequence_proxies() {
        let catalog = catalog_with_yaml(0, "proxies: 42");
        assert_eq!(
            validate_catalog(&catalog).unwrap_err(),
            CatalogError::InvalidResponse
        );
    }

    #[test]
    fn updated_at_roundtrips() {
        let json = r#"{"revision":3,"yaml":"proxies: []","sha256":"x","updatedAt":1700000000}"#;
        let parsed: ExitCatalogResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.updated_at, Some(1_700_000_000));
        let without: ExitCatalogResponse =
            serde_json::from_str(r#"{"revision":3,"yaml":"proxies: []","sha256":"x"}"#).unwrap();
        assert_eq!(without.updated_at, None);
    }

    // ---- CatalogTracker ----

    #[test]
    fn tracker_accepts_newer_revision_and_tracks_digest() {
        let mut tracker = CatalogTracker::new();
        let outcome = tracker.install(&valid_catalog(3)).unwrap();
        assert!(matches!(outcome, InstallOutcome::Installed(ref nodes) if nodes.len() == 1));
        assert_eq!(tracker.current_revision(), 3);
        assert_eq!(
            tracker.current_digest(),
            Some(valid_catalog(3).sha256.as_str())
        );
    }

    #[test]
    fn tracker_rejects_regressed_revision() {
        let mut tracker = CatalogTracker::new();
        tracker.install(&valid_catalog(5)).unwrap();
        assert_eq!(
            tracker.install(&valid_catalog(4)).unwrap_err(),
            CatalogError::StaleRevision
        );
        assert_eq!(tracker.current_revision(), 5);
    }

    #[test]
    fn tracker_same_revision_same_digest_is_idempotent() {
        let mut tracker = CatalogTracker::new();
        tracker.install(&valid_catalog(5)).unwrap();
        assert_eq!(
            tracker.install(&valid_catalog(5)).unwrap(),
            InstallOutcome::Unchanged
        );
    }

    #[test]
    fn tracker_same_revision_different_digest_is_invalid() {
        let mut tracker = CatalogTracker::new();
        tracker.install(&valid_catalog(5)).unwrap();
        let conflicting = catalog_with_yaml(
            5,
            &format!(
                "proxies:\n{}",
                NODE_YAML.replace("US Reality 01", "Other Name")
            ),
        );
        assert_eq!(
            tracker.install(&conflicting).unwrap_err(),
            CatalogError::InvalidResponse
        );
    }

    #[test]
    fn tracker_survives_concurrent_reordering() {
        // Simulate out-of-order validation completion: a stale download that
        // finishes late must not regress the committed revision, and an
        // invalid catalog must never move the tracker.
        let mut tracker = CatalogTracker::new();
        tracker.install(&valid_catalog(10)).unwrap();
        assert_eq!(
            tracker.install(&valid_catalog(9)).unwrap_err(),
            CatalogError::StaleRevision
        );
        let mut tampered = valid_catalog(11);
        tampered.sha256 = catalog_digest("forged");
        assert!(tracker.install(&tampered).is_err());
        assert_eq!(tracker.current_revision(), 10);
        tracker.install(&valid_catalog(11)).unwrap();
        assert_eq!(tracker.current_revision(), 11);
    }

    #[test]
    fn tracker_seeded_from_cache_keeps_monotonicity_across_restart() {
        let cached = valid_catalog(8);
        let mut tracker = CatalogTracker::from_installed(cached.revision, cached.sha256.clone());
        assert_eq!(
            tracker.install(&valid_catalog(7)).unwrap_err(),
            CatalogError::StaleRevision
        );
        assert_eq!(tracker.install(&cached).unwrap(), InstallOutcome::Unchanged);
    }

    // ---- CatalogCache ----

    #[cfg(unix)]
    #[test]
    fn cache_roundtrips_and_revalidates() {
        let dir = TempDir::new("roundtrip");
        let cache = CatalogCache::platform(dir.path());
        assert!(cache.load().is_none(), "no cache yet");
        let catalog = valid_catalog(12);
        cache.store(&catalog).unwrap();
        let loaded = cache.load().unwrap();
        assert_eq!(loaded.response, catalog);
        assert_eq!(loaded.nodes.len(), 1);
        // No temp files left behind.
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name() != CACHE_FILE_NAME)
            .collect();
        assert!(leftovers.is_empty(), "leftover temp files: {leftovers:?}");
    }

    #[cfg(unix)]
    #[test]
    fn cache_store_refuses_invalid_catalog() {
        let dir = TempDir::new("store-guard");
        let cache = CatalogCache::platform(dir.path());
        let mut bad = valid_catalog(1);
        bad.sha256 = catalog_digest("forged");
        assert!(cache.store(&bad).is_err());
        assert!(
            !cache.path().exists(),
            "invalid download must never reach disk"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cache_write_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("perms");
        let cache = CatalogCache::platform(dir.path());
        cache.store(&valid_catalog(1)).unwrap();
        let mode = fs::metadata(cache.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn cache_load_rejects_loosened_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("chmod");
        let cache = CatalogCache::platform(dir.path());
        cache.store(&valid_catalog(1)).unwrap();
        fs::set_permissions(cache.path(), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(cache.load().is_none(), "0644 cache must be refused");
        fs::set_permissions(cache.path(), fs::Permissions::from_mode(0o600)).unwrap();
        assert!(cache.load().is_some());
    }

    #[cfg(unix)]
    #[test]
    fn cache_load_rejects_symlink() {
        let dir = TempDir::new("symlink");
        let target = dir.path().join("real-cache.json");
        fs::write(&target, serde_json::to_string(&valid_catalog(2)).unwrap()).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, dir.path().join(CACHE_FILE_NAME)).unwrap();
        let cache = CatalogCache::platform(dir.path());
        assert!(cache.load().is_none(), "symlinked cache must be refused");
    }

    #[cfg(unix)]
    #[test]
    fn cache_load_rejects_empty_and_oversized_files() {
        let dir = TempDir::new("size");
        let cache = CatalogCache::platform(dir.path());
        // Empty.
        fs::write(cache.path(), "").unwrap();
        #[cfg(unix)]
        fs::set_permissions(
            cache.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        assert!(cache.load().is_none());
        // Oversized.
        let big = "x".repeat((MAX_CACHE_FILE_BYTES + 1) as usize);
        fs::write(cache.path(), big).unwrap();
        #[cfg(unix)]
        fs::set_permissions(
            cache.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        assert!(cache.load().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn cache_load_rejects_tampered_content() {
        let dir = TempDir::new("tamper");
        let cache = CatalogCache::platform(dir.path());
        cache.store(&valid_catalog(4)).unwrap();
        // User modifies the cached YAML but keeps the old digest.
        let mut stored: ExitCatalogResponse =
            serde_json::from_str(&fs::read_to_string(cache.path()).unwrap()).unwrap();
        stored.yaml = stored.yaml.replace("8.8.8.8", "1.1.1.1");
        fs::write(cache.path(), serde_json::to_string(&stored).unwrap()).unwrap();
        #[cfg(unix)]
        fs::set_permissions(
            cache.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        assert!(
            cache.load().is_none(),
            "tampered cache must fail revalidation"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cache_load_rejects_malformed_json() {
        let dir = TempDir::new("json");
        let cache = CatalogCache::platform(dir.path());
        fs::write(cache.path(), "{not json").unwrap();
        #[cfg(unix)]
        fs::set_permissions(
            cache.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        assert!(cache.load().is_none());
    }

    #[test]
    fn empty_catalog_literal_form_is_exact() {
        // Locked-in semantics: only the exact trimmed literal passes;
        // lookalikes are rejected (review blind-spot list).
        for bad in ["proxies: [ ]", "proxies: [] # comment"] {
            assert_eq!(
                validate_catalog(&catalog_with_yaml(0, bad)).unwrap_err(),
                CatalogError::InvalidResponse,
                "{bad:?}"
            );
        }
    }

    // ---- CacheSafetyCheck::secure_written_file ----

    /// A safety policy that accepts everything for reads and records the
    /// paths its write hook sees.
    struct HookSpy {
        seen: std::sync::Mutex<Vec<PathBuf>>,
    }

    impl CacheSafetyCheck for HookSpy {
        fn check_path(&self, _path: &Path) -> Result<(), CatalogError> {
            Ok(())
        }
        fn check_open(&self, _file: &fs::File) -> Result<(), CatalogError> {
            Ok(())
        }
        fn secure_written_file(&self, path: &Path) -> std::io::Result<()> {
            // The hook runs while the temp file still exists, before rename.
            assert!(path.exists(), "hook must run before the rename");
            self.seen.lock().unwrap().push(path.to_path_buf());
            Ok(())
        }
    }

    #[test]
    fn secure_written_file_runs_before_rename_on_every_store() {
        let dir = TempDir::new("write-hook");
        let spy = std::sync::Arc::new(HookSpy {
            seen: std::sync::Mutex::new(Vec::new()),
        });
        struct Shared(std::sync::Arc<HookSpy>);
        impl CacheSafetyCheck for Shared {
            fn check_path(&self, _path: &Path) -> Result<(), CatalogError> {
                Ok(())
            }
            fn check_open(&self, _file: &fs::File) -> Result<(), CatalogError> {
                Ok(())
            }
            fn secure_written_file(&self, path: &Path) -> std::io::Result<()> {
                self.0.secure_written_file(path)
            }
        }
        let cache = CatalogCache::new(dir.path(), Box::new(Shared(spy.clone())));
        cache.store(&valid_catalog(1)).unwrap();
        cache.store(&valid_catalog(2)).unwrap();
        let spy_seen = spy.seen.lock().unwrap().clone();
        assert_eq!(spy_seen.len(), 2, "one hook call per store");
        for path in &spy_seen {
            let name = path.file_name().unwrap().to_string_lossy();
            assert!(
                name.starts_with(&format!(".{CACHE_FILE_NAME}.tmp-")),
                "hook must see the temp file, got {name}"
            );
            assert!(!path.exists(), "temp file must be renamed away afterwards");
        }
        assert!(cache.path().exists());
    }

    #[test]
    fn secure_written_file_default_is_noop() {
        struct NoHook;
        impl CacheSafetyCheck for NoHook {
            fn check_path(&self, _path: &Path) -> Result<(), CatalogError> {
                Ok(())
            }
            fn check_open(&self, _file: &fs::File) -> Result<(), CatalogError> {
                Ok(())
            }
        }
        let dir = TempDir::new("write-hook-default");
        let cache = CatalogCache::new(dir.path(), Box::new(NoHook));
        cache
            .store(&valid_catalog(1))
            .expect("the default hook must not fail a store");
        assert!(cache.path().exists());
    }

    #[test]
    fn secure_written_file_failure_aborts_the_store() {
        struct FailingHook;
        impl CacheSafetyCheck for FailingHook {
            fn check_path(&self, _path: &Path) -> Result<(), CatalogError> {
                Ok(())
            }
            fn check_open(&self, _file: &fs::File) -> Result<(), CatalogError> {
                Ok(())
            }
            fn secure_written_file(&self, _path: &Path) -> std::io::Result<()> {
                Err(std::io::Error::other("cannot tighten protection"))
            }
        }
        let dir = TempDir::new("write-hook-fail");
        let cache = CatalogCache::new(dir.path(), Box::new(FailingHook));
        assert!(matches!(
            cache.store(&valid_catalog(1)),
            Err(CatalogError::Io(_))
        ));
        assert!(
            !cache.path().exists(),
            "a failed hook must not publish the cache"
        );
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp file must be cleaned up: {leftovers:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cache_store_refuses_when_serialized_body_exceeds_limit() {
        let dir = TempDir::new("store-size");
        let cache = CatalogCache::platform(dir.path());
        // A contract-valid empty catalog whose JSON form exceeds the 2 MiB
        // cache cap: each padding newline doubles under JSON escaping (L1).
        let padding = "\n".repeat(MAX_CATALOG_YAML_BYTES - "proxies: []".len());
        let catalog = catalog_with_yaml(0, &format!("proxies: []{padding}"));
        validate_catalog(&catalog).unwrap();
        assert!(
            serde_json::to_string(&catalog).unwrap().len() as u64 > MAX_CACHE_FILE_BYTES,
            "fixture must actually exceed the cache cap"
        );
        assert!(
            cache.store(&catalog).is_err(),
            "oversized body must not be written"
        );
        assert!(!cache.path().exists());
        // Just below the cap the same shape stores and loads fine.
        let padding = "\n".repeat(MAX_CATALOG_YAML_BYTES - "proxies: []".len() - 512);
        let catalog = catalog_with_yaml(0, &format!("proxies: []{padding}"));
        cache.store(&catalog).unwrap();
        assert!(cache.load().is_some());
    }
}
