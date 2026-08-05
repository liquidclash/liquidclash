//! Exit catalog sync (product-contract.md §3): fetch → validate → persist the
//! verified copy, immediately on login/restore and then every 300 s. Failures
//! retry at 1 s intervals, at most 3 retries. A `StaleRevision` install result
//! is a benign no-op (out-of-order delivery), never an error and never counted
//! toward retries.

use std::{sync::Arc, time::Duration};

use tauri::AppHandle;
use tono_core::{CatalogError, InstallOutcome, node::ValidatedNode};

use clash_verge_logging::{Type, logging};

use crate::{
    process::AsyncHandler,
    tono::{
        commands, connection,
        state::{TonoInner, TonoState},
    },
};

/// §3 periodic sync cadence.
pub const SYNC_INTERVAL: Duration = Duration::from_secs(300);
/// §3: failures retry at most 3 times.
const MAX_RETRIES: u32 = 3;
const RETRY_DELAY: Duration = Duration::from_secs(1);

/// Seed the tracker and node list from the last verified on-disk cache so a
/// fresh download can never roll back across restarts (§3). Safe to call
/// before any session exists; a missing or corrupt cache is simply absent.
pub fn seed_from_cache(inner: &mut TonoInner) {
    let Some(cached) = inner.catalog_cache().load() else {
        return;
    };
    inner.catalog_tracker =
        tono_core::CatalogTracker::from_installed(cached.response.revision, cached.response.sha256.clone());
    inner.nodes = cached.nodes;
    enforce_selection_survival(inner);
    let _ = ensure_usable_selection(inner);
}

/// If the selected node is not in the current catalog, flag that the user
/// must choose again; auto-reconnect stays blocked until then (§3).
fn enforce_selection_survival(inner: &mut TonoInner) {
    let Some(selected) = &inner.selected_node else {
        return;
    };
    if !inner.nodes.iter().any(|node| &node.name == selected) {
        inner.catalog_requires_choice = true;
    }
}

/// What a successful [`install_and_persist`] produced.
#[derive(Debug)]
pub struct PersistedInstall {
    pub tracker: tono_core::CatalogTracker,
    pub nodes: Vec<ValidatedNode>,
    pub installed: bool,
}

/// Clone → install → persist → commit (M2): the candidate tracker installs
/// the catalog, the verified bytes reach the disk cache, and only then does
/// the caller commit the advanced tracker and nodes. A failed `store`
/// propagates with nothing committed, so a redelivery of the same revision
/// retries the install instead of falling into the `Unchanged` hole.
pub fn install_and_persist(
    tracker: &tono_core::CatalogTracker,
    cache: &tono_core::catalog::CatalogCache,
    response: &tono_core::ExitCatalogResponse,
) -> Result<PersistedInstall, CatalogError> {
    let mut candidate = tracker.clone();
    match candidate.install(response)? {
        InstallOutcome::Installed(nodes) => {
            // Only fully verified catalogs reach disk (§3); if this fails,
            // the caller's tracker and nodes stay exactly as they were.
            cache.store(response)?;
            Ok(PersistedInstall {
                tracker: candidate,
                nodes,
                installed: true,
            })
        }
        InstallOutcome::Unchanged => Ok(PersistedInstall {
            tracker: candidate,
            nodes: Vec::new(),
            installed: false,
        }),
    }
}

/// An account-scoped fetch + install cycle. A late response from login/session restore is
/// discarded before it can persist or publish data for a session that has already signed out.
async fn sync_once_inner(state: &Arc<TonoState>, app: &AppHandle, auth_generation: u64) -> Result<(), String> {
    let client = { state.lock().await.client.clone() };
    let response = client.exit_catalog().await.map_err(|err| err.to_string())?;

    let selection_vanished = {
        let mut inner = state.lock().await;
        if inner.sign_in_generation != auth_generation {
            return Ok(());
        }
        let (installed, emit) = match install_and_persist(&inner.catalog_tracker, &inner.catalog_cache(), &response) {
            Ok(effect) if effect.installed => {
                let node_count = effect.nodes.len();
                inner.catalog_tracker = effect.tracker;
                inner.nodes = effect.nodes;
                enforce_selection_survival(&mut inner);
                let _ = ensure_usable_selection(&mut inner);
                state.audit().log(crate::tono::audit::AuditEvent::SyncOk {
                    revision: response.revision,
                    node_count,
                });
                (true, true)
            }
            Ok(_) => (false, true),
            // Benign out-of-order delivery (tono-core L5): never an error.
            Err(CatalogError::StaleRevision) => (false, false),
            Err(err) => return Err(err.to_string()),
        };
        let vanished = installed
            && inner.catalog_requires_choice
            && (inner.fsm.status().is_connected || inner.fsm.status().is_connecting);
        let snapshot = emit.then(|| commands::status_of(&inner));
        drop(inner);
        if let Some(snapshot) = snapshot {
            commands::emit_status(app, &snapshot);
        }
        vanished
    };

    if selection_vanished && state.lock().await.sign_in_generation == auth_generation {
        connection::selected_node_vanished(state.clone(), app.clone()).await;
    }
    Ok(())
}

/// Login/restore variant whose responses cannot commit across an authentication generation.
pub(crate) async fn sync_with_retries_for_auth_generation(
    state: &Arc<TonoState>,
    app: &AppHandle,
    generation: u64,
) -> Result<(), String> {
    sync_with_retries_inner(state, app, generation).await
}

async fn sync_with_retries_inner(state: &Arc<TonoState>, app: &AppHandle, auth_generation: u64) -> Result<(), String> {
    let mut last_error = String::new();
    for attempt in 0..=MAX_RETRIES {
        match sync_once_inner(state, app, auth_generation).await {
            Ok(_) => return Ok(()),
            Err(err) => {
                last_error = err;
                if attempt < MAX_RETRIES {
                    tokio::time::sleep(RETRY_DELAY).await;
                }
            }
        }
    }
    state.audit().log(crate::tono::audit::AuditEvent::SyncFail {
        error: last_error.clone(),
    });
    Err(last_error)
}

/// Start the 300 s periodic sync (§3) for one authenticated session. The task stops on sign-out
/// via the task registry and also self-terminates if its generation is superseded.
/// Callers must not hold the state lock (this registers the task handle).
pub(crate) async fn spawn_periodic_for_auth_generation(state: &Arc<TonoState>, app: &AppHandle, generation: u64) {
    spawn_periodic_inner(state, app, generation).await;
}

async fn spawn_periodic_inner(state: &Arc<TonoState>, app: &AppHandle, auth_generation: u64) {
    let task_state = state.clone();
    let task_app = app.clone();
    let handle = AsyncHandler::spawn(move || async move {
        let mut interval = tokio::time::interval(SYNC_INTERVAL);
        // The first tick fires immediately; the login/restore path already
        // synced, so skip it.
        interval.tick().await;
        loop {
            interval.tick().await;
            {
                let inner = task_state.lock().await;
                if inner.sign_in_generation != auth_generation {
                    return;
                }
                if matches!(
                    inner.account_state,
                    crate::tono::state::AccountState::SignedOut | crate::tono::state::AccountState::Restoring
                ) {
                    return;
                }
            }
            // A failing sync never replaces the last verified copy (§3) and
            // never surfaces to the UI beyond the log.
            let _ = sync_with_retries_inner(&task_state, &task_app, auth_generation).await;
            // The cloud traffic policy rides the same cadence (Build 28).
            let _ = crate::tono::policy_sync::sync_with_retries_for_auth_generation(
                &task_state,
                &task_app,
                auth_generation,
            )
            .await;
        }
    });
    let mut inner = state.lock().await;
    if inner.sign_in_generation != auth_generation {
        handle.abort();
        return;
    }
    inner.tasks.abort_catalog_sync();
    inner.tasks.catalog_sync = Some(handle);
}

/// Catalog display names that Chinese networks currently cannot reach. They stay in the
/// list (so the user sees why the previous default disappeared) but sort last and are
/// not auto-selected. Update this list when a node is unblocked or a new exit is walled.
const BLOCKED_EXIT_NAMES: &[&str] = &["US-VLESS-Reality"];

/// Preferred default when the user has no selection, or their selection is blocked.
/// First match that is present in the catalog wins.
const PREFERRED_DEFAULT_EXIT_NAMES: &[&str] = &[
    "Salt Lake City · Summit",
    "Salt Lake City - Summit",
    "Buffalo · Niagara",
    "Buffalo - Niagara",
    "Los Angeles · Harbor",
    "Los Angeles - Harbor",
    "JP-VLESS-Reality",
];

/// Whether this catalog display name is known blocked (GFW / dead exit).
pub fn is_exit_blocked(name: &str) -> bool {
    let name = name.trim();
    BLOCKED_EXIT_NAMES
        .iter()
        .any(|blocked| name.eq_ignore_ascii_case(blocked))
}

/// Pick the best usable exit: preferred list first, then first unblocked name in sort order.
pub fn default_usable_exit(nodes: &[ValidatedNode]) -> Option<String> {
    for preferred in PREFERRED_DEFAULT_EXIT_NAMES {
        if let Some(node) = nodes.iter().find(|node| {
            !is_exit_blocked(&node.name)
                && (node.name == *preferred
                    || node.name.replace('·', "-").replace('–', "-")
                        == preferred.replace('·', "-").replace('–', "-"))
        }) {
            return Some(node.name.clone());
        }
    }
    sort_server_names(nodes)
        .into_iter()
        .find(|name| !is_exit_blocked(name))
}

/// If selection is missing or points at a blocked exit, move the user to a usable default
/// and persist. Returns the name that was applied (if any).
pub fn ensure_usable_selection(inner: &mut TonoInner) -> Option<String> {
    let needs_replacement = match inner.selected_node.as_deref() {
        None => true,
        Some(name) if is_exit_blocked(name) => true,
        Some(name) if !inner.nodes.iter().any(|node| node.name == name) => true,
        Some(_) => false,
    };
    if !needs_replacement {
        return None;
    }
    let Some(replacement) = default_usable_exit(&inner.nodes) else {
        return None;
    };
    inner.selected_node = Some(replacement.clone());
    inner.catalog_requires_choice = false;
    if let Err(error) = crate::tono::state::save_selection(&inner.catalog_dir, &replacement) {
        logging!(
            warn,
            Type::Service,
            "Tono: failed to persist default exit after blocked-node migration: {error}"
        );
    }
    Some(replacement)
}

/// Region ordering for the server list: usable nodes first (US → JP → other), blocked last.
/// Within each group, name-sorted (case-insensitive, Unicode-aware).
pub fn sort_server_names(nodes: &[ValidatedNode]) -> Vec<String> {
    let mut names: Vec<String> = nodes.iter().map(|node| node.name.clone()).collect();
    names.sort_by_key(|name| {
        (
            if is_exit_blocked(name) { 1_u8 } else { 0 },
            region_rank(name),
            name.to_lowercase(),
        )
    });
    names
}

/// 0 = US, 1 = JP, 2 = other. Region tokens are matched as whole
/// alphanumeric words so "JPN"-style names do not count as JP.
pub fn region_rank(name: &str) -> u8 {
    let mut rank = 2;
    for token in name
        .split(|ch: char| !ch.is_alphanumeric())
        .filter(|token| !token.is_empty())
    {
        if token.eq_ignore_ascii_case("us") {
            return 0;
        }
        if token.eq_ignore_ascii_case("jp") {
            rank = 1;
        }
    }
    rank
}

#[cfg(test)]
mod tests {
    use super::{
        default_usable_exit, install_and_persist, is_exit_blocked, region_rank, sort_server_names,
    };
    use std::net::Ipv4Addr;
    use std::path::{Path, PathBuf};
    use tono_core::catalog::{CatalogCache, catalog_digest};
    use tono_core::node::ValidatedNode;
    use tono_core::{CatalogError, CatalogTracker, ExitCatalogResponse};

    fn node(name: &str) -> ValidatedNode {
        ValidatedNode {
            name: name.to_string(),
            server: Ipv4Addr::new(8, 8, 8, 8),
            port: 443,
            uuid: "9e107d9d-372b-4c81-8d2b-3f2d0a1b2c3d".to_string(),
            servername: "www.microsoft.com".to_string(),
            flow: None,
            client_fingerprint: None,
            reality_public_key: "0123456789abcdef0123456789abcdef0123456789a".to_string(),
            reality_short_id: "0123456789abcdef".to_string(),
        }
    }

    #[test]
    fn region_rank_matches_whole_words_only() {
        assert_eq!(region_rank("🇺🇸 US Reality 01"), 0);
        assert_eq!(region_rank("us west"), 0);
        assert_eq!(region_rank("JP Reality 02"), 1);
        assert_eq!(region_rank("jp"), 1);
        assert_eq!(region_rank("SG Reality 03"), 2);
        // Substrings do not count.
        assert_eq!(region_rank("JPN East"), 2);
        assert_eq!(region_rank("Rust Server"), 2);
    }

    #[test]
    fn servers_sort_us_then_jp_then_others() {
        let nodes = vec![
            node("SG Reality 03"),
            node("JP Reality 02"),
            node("US Reality 01"),
            node("🇯🇵 JP Reality 01"),
            node("🇺🇸 US Reality 02"),
            node("UK Reality 01"),
        ];
        let sorted = sort_server_names(&nodes);
        assert_eq!(
            sorted,
            vec![
                "US Reality 01",
                "🇺🇸 US Reality 02",
                "JP Reality 02",
                "🇯🇵 JP Reality 01",
                "SG Reality 03",
                "UK Reality 01",
            ]
        );
    }

    #[test]
    fn blocked_exit_sorts_last_and_is_not_default() {
        let nodes = vec![
            node("US-VLESS-Reality"),
            node("Salt Lake City · Summit"),
            node("JP Reality 02"),
            node("US West 01"),
        ];
        assert!(is_exit_blocked("US-VLESS-Reality"));
        assert!(!is_exit_blocked("Salt Lake City · Summit"));
        // Usable first: US token → JP token → other cities; blocked always last.
        assert_eq!(
            sort_server_names(&nodes),
            vec![
                "US West 01",
                "JP Reality 02",
                "Salt Lake City · Summit",
                "US-VLESS-Reality",
            ]
        );
        // Preferred default still picks Salt Lake even though sort rank is "other".
        assert_eq!(
            default_usable_exit(&nodes).as_deref(),
            Some("Salt Lake City · Summit")
        );
        // With only the blocked node, no usable default.
        assert_eq!(default_usable_exit(&[node("US-VLESS-Reality")]), None);
    }

    #[test]
    fn server_sort_is_case_insensitive_within_groups() {
        let nodes = vec![node("us beta"), node("US Alpha")];
        assert_eq!(sort_server_names(&nodes), vec!["US Alpha", "us beta"]);
    }

    // ---- install_and_persist (M2) ----

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

    fn catalog(revision: i64) -> ExitCatalogResponse {
        let yaml = format!("proxies:\n{NODE_YAML}");
        ExitCatalogResponse {
            revision,
            sha256: catalog_digest(&yaml),
            yaml,
            updated_at: None,
        }
    }

    /// Read-side no-op policy; write hook default (no-op). Store failures
    /// below come from the filesystem layout, not the policy.
    struct NoopCheck;
    impl tono_core::catalog::CacheSafetyCheck for NoopCheck {
        fn check_path(&self, _path: &Path) -> Result<(), CatalogError> {
            Ok(())
        }
        fn check_open(&self, _file: &std::fs::File) -> Result<(), CatalogError> {
            Ok(())
        }
    }

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let serial = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("tono-app-test-{tag}-{}-{serial}", std::process::id()));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn store_failure_commits_nothing_and_redelivery_retries() {
        let dir = TempDir::new("persist-fail");
        // A cache whose directory cannot be created: its parent is a file.
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"not a directory").unwrap();
        let bad_cache = CatalogCache::new(&blocker.join("tono"), Box::new(NoopCheck));

        let tracker = CatalogTracker::new();
        let response = catalog(7);
        let err = install_and_persist(&tracker, &bad_cache, &response).unwrap_err();
        assert!(matches!(err, CatalogError::Io(_)), "{err}");
        // Nothing committed: the caller's tracker is untouched.
        assert_eq!(tracker.current_revision(), -1);

        // Redelivery of the same revision against a working cache installs
        // fresh — no "Unchanged" black hole (M2).
        let good_dir = TempDir::new("persist-good");
        let good_cache = CatalogCache::new(good_dir.path(), Box::new(NoopCheck));
        let effect = install_and_persist(&tracker, &good_cache, &response).unwrap();
        assert!(effect.installed);
        assert_eq!(effect.tracker.current_revision(), 7);
        assert_eq!(effect.nodes.len(), 1);
    }

    #[test]
    fn successful_install_commits_and_same_revision_is_unchanged() {
        let dir = TempDir::new("persist-ok");
        let cache = CatalogCache::new(dir.path(), Box::new(NoopCheck));
        let tracker = CatalogTracker::new();

        let effect = install_and_persist(&tracker, &cache, &catalog(3)).unwrap();
        assert!(effect.installed);
        assert_eq!(effect.tracker.current_revision(), 3);
        assert_eq!(effect.nodes.len(), 1);
        assert!(cache.path().exists(), "verified bytes must reach the disk cache");

        let effect = install_and_persist(&effect.tracker, &cache, &catalog(3)).unwrap();
        assert!(!effect.installed, "same revision + digest is idempotent");
        assert_eq!(effect.tracker.current_revision(), 3);
    }

    #[test]
    fn stale_revision_is_reported_without_touching_anything() {
        let dir = TempDir::new("persist-stale");
        let cache = CatalogCache::new(dir.path(), Box::new(NoopCheck));
        let tracker = CatalogTracker::new();
        let effect = install_and_persist(&tracker, &cache, &catalog(5)).unwrap();
        assert!(effect.installed);

        let err = install_and_persist(&effect.tracker, &cache, &catalog(4)).unwrap_err();
        assert_eq!(err, CatalogError::StaleRevision);
        assert_eq!(effect.tracker.current_revision(), 5);
    }
}
