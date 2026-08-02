//! Cloud traffic-policy sync (WeChat DIRECT, Build 28 parity): fetch →
//! validate → persist the verified copy, immediately on login/restore and
//! then on the catalog's 300 s cadence. Semantics mirror the exit catalog:
//! `StaleRevision` is a benign no-op, a failing download never replaces
//! the last verified copy, and the cache seeds the tracker across
//! restarts. A *behavior change* (the validated document differs from the
//! active one) triggers a protected reconnect — never a release.

use std::{collections::BTreeSet, net::Ipv4Addr, sync::Arc, time::Duration};

use tauri::AppHandle;
use tono_core::policy::{
    PolicyError, PolicyInstallOutcome, PolicyTracker, TonoTrafficPolicy, TonoTrafficPolicyResponse,
};

use crate::tono::{
    audit::AuditEvent,
    connection,
    state::{TonoInner, TonoState},
};

/// Same retry policy as the catalog sync (§3).
const MAX_RETRIES: u32 = 3;
const RETRY_DELAY: Duration = Duration::from_secs(1);

/// Addresses protected at validation time: the permanently protected DoH
/// resolvers plus the selected node's IP (never a DIRECT target).
fn protected_addresses(inner: &TonoInner) -> BTreeSet<Ipv4Addr> {
    let mut protected = BTreeSet::new();
    if let Some(selected) = &inner.selected_node
        && let Some(node) = inner.nodes.iter().find(|node| &node.name == selected)
    {
        protected.insert(node.server);
    }
    protected
}

/// Seed the tracker and the active policy from the last verified on-disk
/// cache (restart-safe rollback protection, catalog parity).
pub fn seed_from_cache(inner: &mut TonoInner) {
    let protected = protected_addresses(inner);
    let Some(cached) = inner.policy_cache().load(&protected) else {
        return;
    };
    inner.policy_tracker = PolicyTracker::from_installed(cached.response.revision, cached.response.sha256.clone());
    inner.traffic_policy = Some(cached.policy);
}

/// Clone → install → persist → commit (M2 pattern): the tracker only
/// advances after the verified bytes are safely on disk.
fn install_and_persist(
    tracker: &PolicyTracker,
    cache: &tono_core::policy::PolicyCache,
    response: &TonoTrafficPolicyResponse,
    protected: &BTreeSet<Ipv4Addr>,
) -> Result<(PolicyTracker, Option<TonoTrafficPolicy>), PolicyError> {
    let mut candidate = tracker.clone();
    match candidate.install(response, protected)? {
        PolicyInstallOutcome::Installed(policy) => {
            cache.store(response, protected)?;
            Ok((candidate, Some(policy)))
        }
        PolicyInstallOutcome::Unchanged => Ok((candidate, None)),
    }
}

/// One account-scoped fetch + install cycle. A behavior change under an active tunnel schedules
/// the protected reconnect transaction (the barrier stays up throughout).
async fn sync_once_inner(state: &Arc<TonoState>, app: &AppHandle, auth_generation: u64) -> Result<(), String> {
    let client = { state.lock().await.client.clone() };
    let response = client.traffic_policy().await.map_err(|err| err.to_string())?;

    let behavior_changed = {
        let mut inner = state.lock().await;
        if inner.sign_in_generation != auth_generation {
            return Ok(());
        }
        let protected = protected_addresses(&inner);
        match install_and_persist(&inner.policy_tracker, &inner.policy_cache(), &response, &protected) {
            Ok((tracker, Some(policy))) => {
                let changed = inner.traffic_policy.as_ref() != Some(&policy);
                inner.policy_tracker = tracker;
                inner.traffic_policy = Some(policy.clone());
                state.audit().log(AuditEvent::PolicySyncOk {
                    revision: response.revision,
                    domains: policy.domains.len(),
                    media: policy.media_endpoints.len(),
                    web_domains: policy.web_domains.len(),
                });
                changed && (inner.fsm.status().is_connected || inner.fsm.status().is_connecting)
            }
            Ok((tracker, None)) => {
                inner.policy_tracker = tracker;
                false
            }
            // Benign out-of-order delivery: never an error.
            Err(PolicyError::StaleRevision) => false,
            Err(err) => return Err(err.to_string()),
        }
    };

    if behavior_changed && state.lock().await.sign_in_generation == auth_generation {
        connection::handle_network_change(state, app).await;
    }
    Ok(())
}

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
            Ok(()) => return Ok(()),
            Err(err) => {
                last_error = err;
                if attempt < MAX_RETRIES {
                    tokio::time::sleep(RETRY_DELAY).await;
                }
            }
        }
    }
    state.audit().log(AuditEvent::PolicySyncFail {
        error: last_error.clone(),
    });
    Err(last_error)
}

#[cfg(test)]
mod tests {
    use super::install_and_persist;
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};
    use tono_core::catalog::catalog_digest;
    use tono_core::policy::{PolicyTracker, TonoTrafficPolicyResponse};

    struct NoopCheck;
    impl tono_core::catalog::CacheSafetyCheck for NoopCheck {
        fn check_path(&self, _path: &Path) -> Result<(), tono_core::CatalogError> {
            Ok(())
        }
        fn check_open(&self, _file: &std::fs::File) -> Result<(), tono_core::CatalogError> {
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
                .join(format!("tono-policy-test-{tag}-{}-{serial}", std::process::id()));
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

    fn doc() -> String {
        r#"{"version":1,"domains":[{"host":"wxs.qq.com","ports":[80,443]}],"mediaEndpoints":[{"address":"9.0.0.9","ports":[443]}]}"#.to_string()
    }

    fn response(revision: i64) -> TonoTrafficPolicyResponse {
        let json = doc();
        TonoTrafficPolicyResponse {
            revision,
            sha256: catalog_digest(&json),
            json,
            updated_at: None,
        }
    }

    #[test]
    fn install_persists_then_commits_and_same_revision_is_unchanged() {
        let dir = TempDir::new("persist");
        let cache = tono_core::policy::PolicyCache::new(dir.path(), Box::new(NoopCheck));
        let tracker = PolicyTracker::new();
        let protected = BTreeSet::new();

        let (tracker, policy) = install_and_persist(&tracker, &cache, &response(3), &protected).unwrap();
        assert!(policy.is_some());
        assert_eq!(tracker.current_revision(), 3);
        assert!(cache.path().exists(), "verified bytes must reach the disk cache");

        let (_tracker, policy) = install_and_persist(&tracker, &cache, &response(3), &protected).unwrap();
        assert!(policy.is_none(), "same revision + digest is idempotent");
    }

    #[test]
    fn store_failure_commits_nothing_and_redelivery_retries() {
        let dir = TempDir::new("persist-fail");
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"not a directory").unwrap();
        let bad_cache = tono_core::policy::PolicyCache::new(&blocker.join("tono"), Box::new(NoopCheck));

        let tracker = PolicyTracker::new();
        let protected = BTreeSet::new();
        assert!(install_and_persist(&tracker, &bad_cache, &response(7), &protected).is_err());
        assert_eq!(tracker.current_revision(), -1, "caller-side tracker stays untouched");

        let good_dir = TempDir::new("persist-good");
        let good_cache = tono_core::policy::PolicyCache::new(good_dir.path(), Box::new(NoopCheck));
        let (tracker, policy) = install_and_persist(&tracker, &good_cache, &response(7), &protected).unwrap();
        assert!(policy.is_some(), "redelivery installs fresh — no Unchanged hole");
        assert_eq!(tracker.current_revision(), 7);
    }
}
