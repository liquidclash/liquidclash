//! Per-adapter DNS protection for the Windows kill switch.
//!
//! Snapshot every adapter's IPv4/IPv6 `NameServer`/`ProfileNameServer` → point them at the
//! loopback resolver (`127.0.0.1` / `::1`) → verify by read-back → restore from the snapshot
//! on disconnect. The snapshot (`protected-dns.json`) is written atomically to the service
//! state directory *before* any value is changed — the same discipline as the kill-switch
//! intent record.
//!
//! **DNS-before-disarm invariant (identical to the macOS helper):** the kill switch may only
//! disarm after DNS restore is *proven*; if restore cannot be proven, the disarm is refused
//! and the block stays armed. See `windows_kill_switch::disarm_unlocked`.
//!
//! **Proof covers the live resolver, not just the registry:** every CIM live-apply result is
//! recorded per adapter (in memory and in the snapshot file), and a restore is only proven
//! when the registry matches *and* no adapter has a recorded live-apply failure. A failed
//! live-apply is retried once during restore; an adapter that still fails keeps the restore
//! unproven — fail-closed for the normal disarm, while the emergency path stays the documented
//! escape hatch (it logs and proceeds).
//!
//! A registry-only match is never accepted as a normal restore. If CIM cannot prove that the
//! running resolver left loopback, normal disarm remains fail-closed and the explicit elevated
//! emergency-disarm path is the only escape hatch. Automatically opening WFP while the live
//! resolver may still point at a dead loopback server strands the machine in an ambiguous and
//! often unrecoverable network state.
//!
//! The pure snapshot/merge/restore-decision logic in this file is platform-independent and
//! unit-tested on any host; the registry/CIM engine is compiled only on Windows.

use crate::core::structure::DnsProtectionStatus;
use anyhow::{Context as _, Result, bail};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

const ENGINE_LIVE: bool = cfg!(all(windows, not(feature = "test")));

#[cfg_attr(any(not(windows), feature = "test"), allow(dead_code))]
pub(crate) const LOOPBACK_V4: &str = "127.0.0.1";
#[cfg_attr(any(not(windows), feature = "test"), allow(dead_code))]
pub(crate) const LOOPBACK_V6: &str = "::1";
const SNAPSHOT_VERSION: u32 = 1;

/// One adapter's original DNS values. `None` means the registry value was absent — the
/// typical DHCP state — and restore must delete rather than rewrite it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub(crate) struct AdapterDnsSnapshot {
    pub interface_guid: String,
    pub ipv4_name_server: Option<String>,
    pub ipv4_profile_name_server: Option<String>,
    pub ipv6_name_server: Option<String>,
    pub ipv6_profile_name_server: Option<String>,
    /// The last CIM live-apply for this adapter failed, so the running resolver cannot be
    /// trusted to match the registry until a retry succeeds. Recorded in memory and in the
    /// snapshot file; blocks any restore proof (see the module docs).
    #[serde(default)]
    pub live_apply_failed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct DnsSnapshot {
    pub version: u32,
    pub taken_at: u64,
    pub adapters: Vec<AdapterDnsSnapshot>,
}

fn snapshot_path() -> PathBuf {
    crate::service_paths()
        .persistent_state_dir()
        .join("protected-dns.json")
}

static DNS_OPERATION: Lazy<tokio::sync::Mutex<()>> = Lazy::new(|| tokio::sync::Mutex::new(()));
static DNS_LAST_ERROR: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));

// --- Pure logic (platform-independent, unit-tested below) ---

/// Registry `NameServer` values are comma-separated; tolerate spaces and empty segments.
#[cfg_attr(any(not(windows), feature = "test"), allow(dead_code))]
fn parse_name_server_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|server| !server.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// DNS servers the live CIM call should restore. `ProfileNameServer` overrides `NameServer`
/// when populated; IPv4 and IPv6 are combined because `SetDNSServerSearchOrder` accepts one
/// ordered list for the adapter. An empty list means DHCP/reset.
#[cfg_attr(any(not(windows), feature = "test"), allow(dead_code))]
fn restored_live_servers(adapter: &AdapterDnsSnapshot) -> Option<Vec<String>> {
    let mut restored = Vec::new();
    for (profile, base) in [
        (
            adapter.ipv4_profile_name_server.as_deref(),
            adapter.ipv4_name_server.as_deref(),
        ),
        (
            adapter.ipv6_profile_name_server.as_deref(),
            adapter.ipv6_name_server.as_deref(),
        ),
    ] {
        let profile = profile.map(parse_name_server_list).unwrap_or_default();
        let effective = if profile.is_empty() {
            base.map(parse_name_server_list).unwrap_or_default()
        } else {
            profile
        };
        for server in effective {
            if !restored.contains(&server) {
                restored.push(server);
            }
        }
    }
    (!restored.is_empty()).then_some(restored)
}

#[cfg_attr(not(test), allow(dead_code))]
fn format_name_server_list(servers: &[String]) -> String {
    servers.join(",")
}

/// Whether a read-back value is exactly the protected state: loopback only, nothing else.
#[cfg_attr(any(not(windows), feature = "test"), allow(dead_code))]
fn is_loopback_value(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let servers = parse_name_server_list(value);
    !servers.is_empty()
        && servers
            .iter()
            .all(|server| server == LOOPBACK_V4 || server == LOOPBACK_V6)
}

/// Idempotent enable: preserve every original already recorded, but append adapters that appeared
/// after protection started. Replacing an existing record would snapshot our loopback values and
/// destroy the way back; ignoring fresh GUIDs would leave a hot-plugged adapter unprotected.
fn merge_snapshot(existing: Option<DnsSnapshot>, fresh: DnsSnapshot) -> DnsSnapshot {
    let Some(mut existing) = existing else {
        return fresh;
    };
    for adapter in fresh.adapters {
        if !existing
            .adapters
            .iter()
            .any(|saved| saved.interface_guid == adapter.interface_guid)
        {
            existing.adapters.push(adapter);
        }
    }
    existing
}

/// Short-circuiting `enable` is only safe when a snapshot exists, the adapters are actually on
/// loopback, AND no live-apply failure is recorded (memory or snapshot). With no snapshot this is
/// the initial enable, so it must capture the originals and apply loopback. Anything else replays
/// the write — which also retries the live-apply — against the *original* snapshot.
fn needs_loopback_replay(
    snapshot_present: bool,
    all_loopback: bool,
    live_apply_failed: bool,
) -> bool {
    !snapshot_present || !all_loopback || live_apply_failed
}

/// Registry-only comparison of one adapter: the four saved values against the read-back
/// (deliberately excluding the `live_apply_failed` bookkeeping flag).
fn registry_values_match(saved: &AdapterDnsSnapshot, current: &AdapterDnsSnapshot) -> bool {
    saved.interface_guid == current.interface_guid
        && saved.ipv4_name_server == current.ipv4_name_server
        && saved.ipv4_profile_name_server == current.ipv4_profile_name_server
        && saved.ipv6_name_server == current.ipv6_name_server
        && saved.ipv6_profile_name_server == current.ipv6_profile_name_server
}

/// Whether the registry alone looks restored (the degraded-mode leg of the proof).
fn registry_restore_matches(snapshot: &DnsSnapshot, current: &[AdapterDnsSnapshot]) -> bool {
    snapshot.adapters.iter().all(|saved| {
        current
            .iter()
            .find(|adapter| adapter.interface_guid == saved.interface_guid)
            .is_none_or(|adapter| registry_values_match(saved, adapter))
    })
}

/// Restore is proven only when every snapshotted adapter reads back exactly its saved values
/// *and* no adapter carries a recorded live-apply failure — a registry match alone does not
/// prove the running resolver left loopback.
fn restore_is_proven(snapshot: &DnsSnapshot, current: &[AdapterDnsSnapshot]) -> bool {
    snapshot.adapters.iter().all(|saved| {
        current
            .iter()
            .find(|adapter| adapter.interface_guid == saved.interface_guid)
            .is_none_or(|adapter| !saved.live_apply_failed && registry_values_match(saved, adapter))
    })
}

static CONSECUTIVE_LIVE_FAILURES: AtomicU32 = AtomicU32::new(0);

/// One enable/restore round's live-apply outcome; returns the current streak of failing rounds.
fn note_apply_round(any_live_failed: bool) -> u32 {
    if any_live_failed {
        CONSECUTIVE_LIVE_FAILURES.fetch_add(1, Ordering::Relaxed) + 1
    } else {
        CONSECUTIVE_LIVE_FAILURES.swap(0, Ordering::Relaxed)
    }
}

/// Fold in-memory live-apply failures into a snapshot (the file may predate this process).
fn with_live_failures(
    snapshot: &DnsSnapshot,
    failures: &std::collections::BTreeSet<String>,
) -> DnsSnapshot {
    let mut merged = snapshot.clone();
    for adapter in &mut merged.adapters {
        adapter.live_apply_failed |= failures.contains(&adapter.interface_guid);
    }
    merged
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

async fn atomic_write(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    crate::core::paths::ensure_persistent_state_layout()?;
    crate::core::platform_security::secure_private_service_file_if_exists(path)?;
    let temporary = path.with_extension("tmp");
    if std::fs::symlink_metadata(&temporary).is_ok() {
        std::fs::remove_file(&temporary)?;
    }
    tokio::fs::write(&temporary, bytes).await?;
    crate::core::platform_security::secure_private_service_file_if_exists(&temporary)?;
    crate::core::atomic_file::replace(&temporary, path).await?;
    crate::core::platform_security::secure_private_service_file_if_exists(path)?;
    Ok(())
}

// --- Engine boundary (registry + CIM on Windows; stubs elsewhere) ---

async fn engine_collect() -> Result<Vec<AdapterDnsSnapshot>> {
    #[cfg(all(windows, not(feature = "test")))]
    {
        tokio::task::spawn_blocking(engine::collect_adapters)
            .await
            .context("DNS engine task failed")?
    }
    #[cfg(not(all(windows, not(feature = "test"))))]
    {
        Ok(Vec::new())
    }
}

async fn engine_apply_loopback(adapters: &[AdapterDnsSnapshot]) -> Result<Vec<(String, bool)>> {
    #[cfg(all(windows, not(feature = "test")))]
    {
        let guids = adapters
            .iter()
            .map(|adapter| adapter.interface_guid.clone())
            .collect::<Vec<_>>();
        return tokio::task::spawn_blocking(move || engine::apply_loopback_set(&guids))
            .await
            .context("DNS engine task failed")?;
    }
    #[cfg(not(all(windows, not(feature = "test"))))]
    {
        Ok(adapters
            .iter()
            .map(|adapter| (adapter.interface_guid.clone(), true))
            .collect())
    }
}

async fn engine_apply_snapshot(snapshot: &DnsSnapshot) -> Result<Vec<(String, bool)>> {
    #[cfg(all(windows, not(feature = "test")))]
    {
        let snapshot = snapshot.clone();
        return tokio::task::spawn_blocking(move || engine::apply_snapshot(&snapshot))
            .await
            .context("DNS engine task failed")?;
    }
    #[cfg(not(all(windows, not(feature = "test"))))]
    {
        Ok(snapshot
            .adapters
            .iter()
            .map(|adapter| (adapter.interface_guid.clone(), true))
            .collect())
    }
}

async fn engine_all_loopback(adapters: &[AdapterDnsSnapshot]) -> Result<bool> {
    #[cfg(all(windows, not(feature = "test")))]
    {
        let guids = adapters
            .iter()
            .map(|adapter| adapter.interface_guid.clone())
            .collect::<Vec<_>>();
        return tokio::task::spawn_blocking(move || engine::all_loopback(&guids))
            .await
            .context("DNS engine task failed")?;
    }
    #[cfg(not(all(windows, not(feature = "test"))))]
    {
        let _ = adapters;
        Ok(false)
    }
}

async fn engine_flush_cache() -> Result<()> {
    #[cfg(all(windows, not(feature = "test")))]
    {
        return tokio::task::spawn_blocking(engine::flush_resolver_cache)
            .await
            .context("DNS engine task failed")?;
    }
    #[cfg(not(all(windows, not(feature = "test"))))]
    {
        Ok(())
    }
}

// --- Facade ---

/// Whether the state machine runs on this build (real service on Windows; stubbed engine
/// under test builds, which is what the unit tests drive).
const SUPPORTED: bool = cfg!(any(windows, test));

static LIVE_APPLY_FAILURES: Lazy<std::sync::Mutex<std::collections::BTreeSet<String>>> =
    Lazy::new(|| std::sync::Mutex::new(std::collections::BTreeSet::new()));
/// Last committed/live-verified DNS observation. IPC reads clone this synchronously instead of
/// waiting behind a CIM mutation. The background reconciler refreshes it and repairs drift.
static DNS_STATUS_CACHE: Lazy<Mutex<DnsProtectionStatus>> =
    Lazy::new(|| Mutex::new(DnsProtectionStatus::default()));
const DNS_WATCHDOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

fn ensure_supported() -> Result<()> {
    if SUPPORTED {
        Ok(())
    } else {
        bail!("protected DNS is unsupported on this platform")
    }
}

fn record_outcome<T>(result: Result<T>) -> Result<T> {
    match result {
        Ok(value) => {
            *DNS_LAST_ERROR.lock().unwrap() = None;
            Ok(value)
        }
        Err(error) => {
            *DNS_LAST_ERROR.lock().unwrap() = Some(format!("{error:#}"));
            Err(error)
        }
    }
}

/// Record per-adapter live-apply results in memory and into the snapshot's per-adapter flags.
fn note_live_results(snapshot: &mut DnsSnapshot, results: &[(String, bool)]) {
    let mut failures = LIVE_APPLY_FAILURES.lock().unwrap();
    for (guid, ok) in results {
        if *ok {
            failures.remove(guid);
        } else {
            failures.insert(guid.clone());
        }
        if let Some(adapter) = snapshot
            .adapters
            .iter_mut()
            .find(|adapter| &adapter.interface_guid == guid)
        {
            adapter.live_apply_failed = !ok;
        }
    }
}

/// Snapshot → set loopback → verify. Idempotent: a second call while protected keeps the
/// original snapshot — but if the adapters are not actually on loopback (a previous enable
/// died mid-apply), the loopback write is replayed first.
pub(crate) async fn enable() -> Result<DnsProtectionStatus> {
    ensure_supported()?;
    let _operation = DNS_OPERATION.lock().await;
    let existing = match tokio::fs::read(snapshot_path()).await {
        Ok(bytes) => Some(
            serde_json::from_slice::<DnsSnapshot>(&bytes)
                .context("protected-dns snapshot is corrupt; restore manually or disarm")?,
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let existing = existing
        .map(|snapshot| with_live_failures(&snapshot, &LIVE_APPLY_FAILURES.lock().unwrap()));
    let snapshot_present = existing.is_some();
    // Always collect before the idempotence decision. Network-change reconnects call `enable`
    // again, and a newly installed/hot-plugged adapter must have its original DNS appended to the
    // durable snapshot before it is pointed at loopback.
    let fresh = DnsSnapshot {
        version: SNAPSHOT_VERSION,
        taken_at: now_unix(),
        adapters: engine_collect().await?,
    };
    // Health and replay decisions cover adapters that are live now, not historical snapshot
    // entries that have since been disabled or unplugged. Their originals remain in `snapshot`
    // and are still restored in the registry on disconnect.
    let active_adapters = fresh.adapters.clone();
    let mut snapshot = merge_snapshot(existing, fresh);
    let all_loopback = snapshot_present && engine_all_loopback(&active_adapters).await?;
    let live_apply_failed = snapshot
        .adapters
        .iter()
        .any(|adapter| adapter.live_apply_failed);
    // Snapshot first, even on an otherwise idempotent replay: `snapshot` may now include adapters
    // that appeared after the first enable, and any later failure must retain their originals.
    atomic_write(&snapshot_path(), &serde_json::to_vec_pretty(&snapshot)?).await?;
    if !needs_loopback_replay(snapshot_present, all_loopback, live_apply_failed) {
        return status_unlocked().await;
    }
    let outcome: Result<()> = async {
        let live = engine_apply_loopback(&snapshot.adapters).await?;
        note_apply_round(live.iter().any(|(_, ok)| !ok));
        note_live_results(&mut snapshot, &live);
        // Persist both failures and successful retries. Otherwise a recovered adapter keeps its
        // old `live_apply_failed` bit on disk and every later enable unnecessarily replays DNS.
        atomic_write(&snapshot_path(), &serde_json::to_vec_pretty(&snapshot)?).await?;
        let failed = live.iter().filter(|(_, ok)| !ok).count();
        if failed > 0 {
            bail!("live DNS apply failed on {failed} adapter(s)");
        }
        if ENGINE_LIVE {
            let active_after_apply = engine_collect().await?;
            if !engine_all_loopback(&active_after_apply).await? {
                bail!("loopback DNS could not be verified on every active adapter");
            }
        }
        Ok(())
    }
    .await;
    record_outcome(outcome)?;
    status_unlocked().await
}

/// Restore every adapter from the snapshot, prove it by read-back *and* by clean live-apply
/// records, then drop the snapshot. Failing any of that keeps the snapshot — and, via the
/// disarm invariant, the block armed.
pub(crate) async fn restore_protected() -> Result<DnsProtectionStatus> {
    if !SUPPORTED {
        return status_unlocked().await;
    }
    let _operation = DNS_OPERATION.lock().await;
    let bytes = match tokio::fs::read(snapshot_path()).await {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return status_unlocked().await;
        }
        Err(error) => return Err(error.into()),
    };
    let snapshot = serde_json::from_slice::<DnsSnapshot>(&bytes)
        .context("protected-dns snapshot is corrupt; cannot prove restore")?;
    let mut snapshot = with_live_failures(&snapshot, &LIVE_APPLY_FAILURES.lock().unwrap());
    let outcome: Result<()> = async {
        // The engine applies all adapters in one PowerShell batch and retries the failures
        // once in a second batch, reporting final per-adapter results.
        let live = engine_apply_snapshot(&snapshot).await?;
        let streak = note_apply_round(live.iter().any(|(_, ok)| !ok));
        note_live_results(&mut snapshot, &live);
        // Persist the refreshed flags either way; a refused disarm must keep accurate records.
        atomic_write(&snapshot_path(), &serde_json::to_vec_pretty(&snapshot)?).await?;
        if ENGINE_LIVE {
            let current = engine_collect().await?;
            if !restore_is_proven(&snapshot, &current) {
                let registry = registry_restore_matches(&snapshot, &current);
                bail!(
                    "DNS restore could not be proven (registry_match={registry}, consecutive_live_apply_failures={streak}); protection remains armed"
                );
            }
        } else if snapshot.adapters.iter().any(|adapter| adapter.live_apply_failed) {
            bail!("DNS restore could not be proven (recorded live-apply failure)");
        }
        Ok(())
    }
    .await;
    record_outcome(outcome)?;
    match tokio::fs::remove_file(snapshot_path()).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    // The restore is proven: flush the resolver cache unconditionally. Fake-ip (198.18/16)
    // answers and negative cache entries collected while DNS pointed at the loopback core
    // would otherwise outlive the disconnect (see `engine::flush_resolver_cache`).
    if let Err(error) = engine_flush_cache().await {
        tracing::warn!("DNS cache flush after restore failed: {error:#}");
    }
    status_unlocked().await
}

/// The disarm gate: succeed when no protection is active, or after a proven restore. An
/// error here must keep the kill switch armed (see the invariant at the top of this file).
pub(crate) async fn ensure_restored() -> Result<()> {
    if !SUPPORTED {
        return Ok(());
    }
    match tokio::fs::metadata(snapshot_path()).await {
        Ok(_) => restore_protected().await.map(|_| ()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub(crate) async fn status() -> DnsProtectionStatus {
    // Status is the recovery/diagnosis path: do not turn a past panic into permanent silence.
    DNS_STATUS_CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

fn publish_status(status: &DnsProtectionStatus) {
    *DNS_STATUS_CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = status.clone();
}

fn publish_status_error(error: &anyhow::Error) {
    let mut status = DNS_STATUS_CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    status.last_error = Some(format!("{error:#}"));
}

/// Populate the fast snapshot before IPC is opened. A corrupt recovery file is represented as a
/// status error rather than preventing the Service from starting; WFP remains independently
/// fail-closed and the GUI can still offer diagnostics/emergency recovery.
pub async fn initialize_status_cache() {
    let _operation = DNS_OPERATION.lock().await;
    match status_unlocked().await {
        Ok(status) => publish_status(&status),
        Err(error) => publish_status_error(&error),
    }
}

/// Keep the cached snapshot fresh and repair a new/drifted adapter while protection is active.
/// The expensive live read runs here, never in a request handler. `enable` preserves the original
/// snapshot and only reapplies loopback after this probe finds drift.
pub fn spawn_status_watchdog() {
    if !SUPPORTED {
        return;
    }
    tokio::spawn(async {
        loop {
            tokio::time::sleep(DNS_WATCHDOG_INTERVAL).await;
            let observed = {
                let _operation = DNS_OPERATION.lock().await;
                status_unlocked().await
            };
            match observed {
                Ok(status) => {
                    let repair = status.snapshot_present && !status.enabled;
                    publish_status(&status);
                    if repair && let Err(error) = enable().await {
                        publish_status_error(&error);
                        tracing::warn!("protected DNS reconciliation failed: {error:#}");
                    }
                }
                Err(error) => publish_status_error(&error),
            }
        }
    });
}

async fn status_unlocked() -> Result<DnsProtectionStatus> {
    let snapshot = match tokio::fs::read(snapshot_path()).await {
        Ok(bytes) => Some(
            serde_json::from_slice::<DnsSnapshot>(&bytes)
                .context("protected-dns snapshot is corrupt")?,
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let enabled = match snapshot.as_ref() {
        Some(_snapshot) if ENGINE_LIVE => {
            // Include adapters that appeared since the last enable. Checking only saved GUIDs can
            // report a false healthy state while a fresh adapter still uses an external resolver.
            let current = engine_collect().await?;
            engine_all_loopback(&current).await?
        }
        Some(snapshot) => engine_all_loopback(&snapshot.adapters).await?,
        None => false,
    };
    let status = DnsProtectionStatus {
        enabled,
        snapshot_present: snapshot.is_some(),
        adapters: snapshot
            .as_ref()
            .map_or(0, |snapshot| snapshot.adapters.len() as u32),
        last_error: DNS_LAST_ERROR.lock().unwrap().clone(),
    };
    publish_status(&status);
    Ok(status)
}

/// Only an operational IP adapter has a live resolver that can leak DNS. Registry interface keys
/// outlive disabled and removed adapters, while the software loopback has no configurable CIM DNS
/// instance; including either class makes one irrelevant `SetDNSServerSearchOrder` failure abort
/// protection for every real adapter.
#[cfg(any(all(windows, not(feature = "test")), test))]
fn is_active_dns_adapter(oper_status: i32, if_type: u32) -> bool {
    const IF_OPER_STATUS_UP: i32 = 1;
    const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
    oper_status == IF_OPER_STATUS_UP && if_type != IF_TYPE_SOFTWARE_LOOPBACK
}

// --- Windows engine: registry snapshot/set + best-effort CIM live-apply ---

#[cfg(all(windows, not(feature = "test")))]
mod engine {
    use super::{AdapterDnsSnapshot, DnsSnapshot, is_active_dns_adapter, is_loopback_value};
    use anyhow::{Context as _, Result, bail};
    use std::ffi::CStr;
    use windows_sys::Win32::Foundation::{
        ERROR_BUFFER_OVERFLOW, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_DATA,
    };
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_FRIENDLY_NAME,
        GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST, GetAdaptersAddresses,
        IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, KEY_WRITE, REG_SZ, RegCloseKey,
        RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
    };

    const TCPIP4_INTERFACES: &str =
        r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
    const TCPIP6_INTERFACES: &str =
        r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces";
    const NAME_SERVER: &str = "NameServer";
    const PROFILE_NAME_SERVER: &str = "ProfileNameServer";

    struct RegKey(HKEY);

    impl RegKey {
        fn open(subkey: &str, write: bool) -> Result<Option<Self>> {
            let wide = super_wide(subkey);
            let mut handle = std::ptr::null_mut();
            // SAFETY: valid NUL-terminated key path; `handle` is a valid out-pointer.
            let status = unsafe {
                RegOpenKeyExW(
                    HKEY_LOCAL_MACHINE,
                    wide.as_ptr(),
                    0,
                    KEY_WOW64_64KEY | if write { KEY_WRITE } else { KEY_READ },
                    &mut handle,
                )
            };
            match status {
                0 => Ok(Some(Self(handle))),
                ERROR_FILE_NOT_FOUND => Ok(None),
                _ => Err(std::io::Error::from_raw_os_error(status as i32))
                    .with_context(|| format!("failed to open registry key {subkey}")),
            }
        }
    }

    impl Drop for RegKey {
        fn drop(&mut self) {
            // SAFETY: the handle came from a successful `RegOpenKeyExW` and closes once.
            unsafe { RegCloseKey(self.0) };
        }
    }

    fn super_wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn read_sz(subkey: &str, value: &str) -> Result<Option<String>> {
        let Some(key) = RegKey::open(subkey, false)? else {
            return Ok(None);
        };
        let value_wide = super_wide(value);
        let mut size = 0_u32;
        // SAFETY: valid key handle and value name; null data pointer queries the size.
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                value_wide.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut size,
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != 0 && status != ERROR_MORE_DATA {
            return Err(std::io::Error::from_raw_os_error(status as i32))
                .with_context(|| format!("failed to size registry value {subkey}\\{value}"));
        }
        if size == 0 || size % 2 != 0 {
            return Ok(None);
        }
        let mut buffer = vec![0_u16; size as usize / 2];
        let mut actual = size;
        // SAFETY: `buffer` is `size` bytes of writable memory, as reported by the query.
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                value_wide.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
                buffer.as_mut_ptr().cast(),
                &mut actual,
            )
        };
        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status as i32))
                .with_context(|| format!("failed to read registry value {subkey}\\{value}"));
        }
        let used = actual as usize / 2;
        buffer.truncate(used);
        while buffer.last() == Some(&0) {
            buffer.pop();
        }
        Ok(Some(
            String::from_utf16(&buffer).context("registry DNS value is not valid UTF-16")?,
        ))
    }

    fn write_sz(subkey: &str, value: &str, data: &str) -> Result<()> {
        let Some(key) = RegKey::open(subkey, true)? else {
            bail!("registry key {subkey} does not exist");
        };
        let value_wide = super_wide(value);
        let wide = super_wide(data);
        // SAFETY: `wide` is a NUL-terminated UTF-16 buffer of `len * 2` bytes, alive here.
        let status = unsafe {
            RegSetValueExW(
                key.0,
                value_wide.as_ptr(),
                0,
                REG_SZ,
                wide.as_ptr().cast(),
                (wide.len() * 2) as u32,
            )
        };
        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status as i32))
                .with_context(|| format!("failed to write registry value {subkey}\\{value}"));
        }
        Ok(())
    }

    fn delete_value(subkey: &str, value: &str) -> Result<()> {
        let Some(key) = RegKey::open(subkey, true)? else {
            return Ok(());
        };
        let value_wide = super_wide(value);
        // SAFETY: valid key handle and value name.
        let status = unsafe { RegDeleteValueW(key.0, value_wide.as_ptr()) };
        if status != 0 && status != ERROR_FILE_NOT_FOUND {
            return Err(std::io::Error::from_raw_os_error(status as i32))
                .with_context(|| format!("failed to delete registry value {subkey}\\{value}"));
        }
        Ok(())
    }

    fn interface_guids() -> Result<Vec<String>> {
        // `Parameters\Interfaces` is historical state, not a list of live adapters: it commonly
        // contains disabled, unplugged, removed, and pseudo interfaces. Those either have no
        // Win32_NetworkAdapterConfiguration object or return 84 (IP not enabled), which used to
        // make the whole DNS enable fail permanently. IP Helper gives the current cheap in-process
        // view and is also what the service's network-change monitor is built on.
        const INITIAL_BUFFER_BYTES: u32 = 15 * 1024;
        const MAX_BUFFER_ATTEMPTS: usize = 4;
        let flags = GAA_FLAG_SKIP_UNICAST
            | GAA_FLAG_SKIP_ANYCAST
            | GAA_FLAG_SKIP_MULTICAST
            | GAA_FLAG_SKIP_DNS_SERVER
            | GAA_FLAG_SKIP_FRIENDLY_NAME;
        let mut bytes = INITIAL_BUFFER_BYTES;
        for _ in 0..MAX_BUFFER_ATTEMPTS {
            let entries = (bytes as usize).div_ceil(std::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>());
            // A vector of the actual structure gives the backing allocation the alignment required
            // by the linked records that `GetAdaptersAddresses` writes into the byte-sized buffer.
            let mut buffer = vec![IP_ADAPTER_ADDRESSES_LH::default(); entries.max(1)];
            // SAFETY: `buffer` is writable for at least `bytes` bytes and stays alive while the
            // returned linked list is traversed; the reserved pointer is required to be null.
            let status = unsafe {
                GetAdaptersAddresses(
                    AF_UNSPEC as u32,
                    flags,
                    std::ptr::null(),
                    buffer.as_mut_ptr(),
                    &mut bytes,
                )
            };
            if status == ERROR_BUFFER_OVERFLOW {
                continue;
            }
            if status == ERROR_NO_DATA {
                return Ok(Vec::new());
            }
            if status != 0 {
                return Err(std::io::Error::from_raw_os_error(status as i32))
                    .context("GetAdaptersAddresses failed while selecting DNS adapters");
            }

            let mut guids = Vec::new();
            let mut current = buffer.as_ptr();
            while !current.is_null() {
                // SAFETY: `current` starts inside `buffer`; each `Next` pointer belongs to the same
                // successful `GetAdaptersAddresses` result and is valid until `buffer` is dropped.
                let adapter = unsafe { &*current };
                if is_active_dns_adapter(adapter.OperStatus, adapter.IfType)
                    && !adapter.AdapterName.is_null()
                {
                    // SAFETY: Windows documents AdapterName as a NUL-terminated ANSI adapter GUID.
                    let guid = unsafe { CStr::from_ptr(adapter.AdapterName.cast()) }
                        .to_str()
                        .context("adapter GUID from GetAdaptersAddresses was not UTF-8")?;
                    if !guids
                        .iter()
                        .any(|saved: &String| saved.eq_ignore_ascii_case(guid))
                    {
                        guids.push(guid.to_owned());
                    }
                }
                current = adapter.Next;
            }
            return Ok(guids);
        }
        bail!("GetAdaptersAddresses size kept changing while selecting DNS adapters")
    }

    fn v4_key(guid: &str) -> String {
        format!(r"{TCPIP4_INTERFACES}\{guid}")
    }

    fn v6_key(guid: &str) -> String {
        format!(r"{TCPIP6_INTERFACES}\{guid}")
    }

    fn read_adapter(guid: &str) -> Result<AdapterDnsSnapshot> {
        Ok(AdapterDnsSnapshot {
            interface_guid: guid.to_owned(),
            ipv4_name_server: read_sz(&v4_key(guid), NAME_SERVER)?,
            ipv4_profile_name_server: read_sz(&v4_key(guid), PROFILE_NAME_SERVER)?,
            ipv6_name_server: read_sz(&v6_key(guid), NAME_SERVER)?,
            ipv6_profile_name_server: read_sz(&v6_key(guid), PROFILE_NAME_SERVER)?,
            live_apply_failed: false,
        })
    }

    pub(super) fn collect_adapters() -> Result<Vec<AdapterDnsSnapshot>> {
        interface_guids()?
            .iter()
            .map(|guid| read_adapter(guid))
            .collect()
    }

    /// Live application through CIM
    /// (`Win32_NetworkAdapterConfiguration.SetDNSServerSearchOrder`, the architecture doc's
    /// primary mechanism: it handles static and DHCP adapters without touching leases). The
    /// registry writes are the authoritative record this module verifies against; CIM is what
    /// makes the running resolver pick the change up without an interface bounce.
    ///
    /// All adapters are applied in ONE PowerShell process (cold start is the dominant cost),
    /// and every `Invoke-CimMethod` checks its `ReturnValue` — piping to `Out-Null` would
    /// report success for a rejected call, which is how the first version of this code could
    /// claim loopback DNS was live while the resolver still pointed at the old server. The
    /// script prints the failing GUIDs; results are recorded per adapter and required for any
    /// restore proof (see the module docs).
    ///
    /// 注意:运行时尚未实测 — wrapped so any failure is logged, never fatal.
    struct LiveApplyEntry {
        guid: String,
        /// `None` restores DHCP (SetDNSServerSearchOrder $null).
        servers: Option<Vec<String>>,
    }

    const POWERSHELL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    /// Spawn a process and collect stdout with a hard timeout. A timed-out child is killed:
    /// nothing here may ever park the facade's DNS operation lock on a hung PowerShell.
    fn run_with_timeout(
        program: &str,
        args: &[&str],
        timeout: std::time::Duration,
    ) -> Result<String> {
        let mut child = std::process::Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to start {program}"))?;
        let deadline = std::time::Instant::now() + timeout;
        loop {
            match child.try_wait()? {
                Some(_) => {
                    let output = child.wait_with_output()?;
                    if !output.status.success() {
                        bail!(
                            "{program} exited {}: {}",
                            output.status,
                            String::from_utf8_lossy(&output.stderr).trim()
                        );
                    }
                    return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
                }
                None if std::time::Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    bail!("{program} timed out after {timeout:?} and was killed");
                }
                None => std::thread::sleep(std::time::Duration::from_millis(25)),
            }
        }
    }

    /// Only these characters ever reach the generated script. GUIDs come from registry subkey
    /// names and server strings from our own snapshot writes; anything else fails closed.
    fn script_safe(value: &str, extra: &str) -> bool {
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || extra.contains(byte as char))
    }

    fn live_apply_batch(entries: &[LiveApplyEntry]) -> Vec<(String, bool)> {
        let mut script = String::from("$fails = @()\n");
        let mut skipped: std::collections::BTreeSet<String> = Default::default();
        for entry in entries {
            let servers_ok = entry
                .servers
                .as_ref()
                .is_none_or(|servers| servers.iter().all(|server| script_safe(server, ".:")));
            if !script_safe(&entry.guid, "{}-") || !servers_ok {
                skipped.insert(entry.guid.clone());
                continue;
            }
            let argument = match &entry.servers {
                Some(servers) => format!(
                    "@({})",
                    servers
                        .iter()
                        .map(|server| format!("'{server}'"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                None => "$null".to_owned(),
            };
            let guid = &entry.guid;
            script.push_str(&format!(
                "$n = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter \"SettingID='{guid}'\" -ErrorAction SilentlyContinue\n\
                 if ($n) {{ $r = Invoke-CimMethod -InputObject $n -MethodName SetDNSServerSearchOrder -Arguments @{{ DNSServerSearchOrder = {argument} }} -ErrorAction SilentlyContinue; if (-not $r -or $r.ReturnValue -ne 0) {{ $fails += '{guid}' }} }} else {{ $fails += '{guid}' }}\n"
            ));
        }
        script.push_str("[Console]::Out.Write($fails -join ',')");
        let run = run_with_timeout(
            "powershell.exe",
            &["-NoProfile", "-NonInteractive", "-Command", &script],
            POWERSHELL_TIMEOUT,
        );
        let failed: std::collections::BTreeSet<String> = match run {
            Ok(stdout) => stdout
                .split(',')
                .map(str::trim)
                .filter(|guid| !guid.is_empty())
                .map(ToOwned::to_owned)
                .collect(),
            // The whole batch failed (timeout, spawn error, non-zero exit): every entry is a
            // failure — the proof path stays closed, the DNS lock is never held hostage.
            Err(error) => {
                tracing::warn!("CIM DNS batch apply failed: {error:#}");
                entries.iter().map(|entry| entry.guid.clone()).collect()
            }
        };
        entries
            .iter()
            .map(|entry| {
                let ok = !failed.contains(&entry.guid) && !skipped.contains(&entry.guid);
                (entry.guid.clone(), ok)
            })
            .collect()
    }

    /// One batch, then one batched retry for the failures (aligned with the previous
    /// per-adapter retry semantics, without paying a PowerShell cold start per adapter).
    fn live_apply_with_retry(entries: Vec<LiveApplyEntry>) -> Vec<(String, bool)> {
        let first = live_apply_batch(&entries);
        let failed: std::collections::BTreeSet<String> = first
            .iter()
            .filter(|(_, ok)| !ok)
            .map(|(guid, _)| guid.clone())
            .collect();
        if failed.is_empty() {
            return first;
        }
        let retry_entries: Vec<LiveApplyEntry> = entries
            .into_iter()
            .filter(|entry| failed.contains(&entry.guid))
            .collect();
        let retried = live_apply_batch(&retry_entries);
        first
            .into_iter()
            .map(|(guid, ok)| {
                let ok = ok
                    || retried
                        .iter()
                        .any(|(retry_guid, retry_ok)| *retry_ok && *retry_guid == guid);
                (guid, ok)
            })
            .collect()
    }

    /// Flush the resolver cache after a restore. Fake-ip (198.18/16) answers and negative
    /// cache entries served while DNS pointed at the loopback core are the classic post-
    /// disconnect pollution; without a flush, restored resolvers keep them until TTL expiry.
    pub(super) fn flush_resolver_cache() -> Result<()> {
        use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
        // DnsFlushResolverCache (Vista+) is exported by dnsapi.dll but is not in
        // any SDK import library — it must be resolved at runtime (the same
        // approach Mullvad's winfw takes).
        type FlushFn = unsafe extern "system" fn() -> i32;
        let module_name: Vec<u16> = "dnsapi.dll\0".encode_utf16().collect();
        // SAFETY: null-terminated wide literal; the handle is validity-checked
        // before use and the module stays loaded for the process lifetime.
        let module = unsafe { LoadLibraryW(module_name.as_ptr()) };
        if !module.is_null() {
            // SAFETY: live module handle; null-terminated ANSI name literal.
            let proc = unsafe { GetProcAddress(module, c"DnsFlushResolverCache".as_ptr() as _) };
            if let Some(proc) = proc {
                let flush: FlushFn = unsafe { std::mem::transmute(proc) };
                // SAFETY: no inputs; the signature matches the documented ABI.
                if unsafe { flush() } != 0 {
                    return Ok(());
                }
            }
        }
        run_with_timeout(
            "ipconfig.exe",
            &["/flushdns"],
            std::time::Duration::from_secs(5),
        )
        .map(|_| ())
        .context("DnsFlushResolverCache failed and ipconfig /flushdns did not succeed either")
    }

    /// Whether the adapter's per-family registry subkey exists. Single-stack adapters lack one
    /// family entirely; both apply and verify must skip the absent family instead of failing.
    fn key_exists(subkey: &str) -> Result<bool> {
        Ok(RegKey::open(subkey, false)?.is_some())
    }

    fn apply_loopback(guid: &str) -> Result<LiveApplyEntry> {
        if key_exists(&v4_key(guid))? {
            write_sz(&v4_key(guid), NAME_SERVER, super::LOOPBACK_V4)?;
            write_sz(&v4_key(guid), PROFILE_NAME_SERVER, super::LOOPBACK_V4)?;
        }
        if key_exists(&v6_key(guid))? {
            write_sz(&v6_key(guid), NAME_SERVER, super::LOOPBACK_V6)?;
            write_sz(&v6_key(guid), PROFILE_NAME_SERVER, super::LOOPBACK_V6)?;
        }
        Ok(LiveApplyEntry {
            guid: guid.to_owned(),
            servers: Some(vec![
                super::LOOPBACK_V4.to_owned(),
                super::LOOPBACK_V6.to_owned(),
            ]),
        })
    }

    pub(super) fn apply_loopback_set(guids: &[String]) -> Result<Vec<(String, bool)>> {
        let active = interface_guids()?
            .into_iter()
            .map(|guid| guid.to_ascii_uppercase())
            .collect::<std::collections::BTreeSet<_>>();
        let mut skipped = guids
            .iter()
            .filter(|guid| !active.contains(&guid.to_ascii_uppercase()))
            .map(|guid| (guid.clone(), true))
            .collect::<Vec<_>>();
        let entries = guids
            .iter()
            .filter(|guid| active.contains(&guid.to_ascii_uppercase()))
            .map(|guid| apply_loopback(guid))
            .collect::<Result<Vec<_>>>()?;
        skipped.extend(live_apply_with_retry(entries));
        Ok(skipped)
    }

    fn restore_value(subkey: &str, value: &str, saved: &Option<String>) -> Result<()> {
        match saved {
            Some(data) => write_sz(subkey, value, data),
            None => delete_value(subkey, value),
        }
    }

    fn restore_entry(adapter: &AdapterDnsSnapshot) -> LiveApplyEntry {
        LiveApplyEntry {
            guid: adapter.interface_guid.clone(),
            servers: super::restored_live_servers(adapter),
        }
    }

    pub(super) fn apply_snapshot(snapshot: &DnsSnapshot) -> Result<Vec<(String, bool)>> {
        let active = interface_guids()?
            .into_iter()
            .map(|guid| guid.to_ascii_uppercase())
            .collect::<std::collections::BTreeSet<_>>();
        let mut live_results = snapshot
            .adapters
            .iter()
            .filter(|adapter| !active.contains(&adapter.interface_guid.to_ascii_uppercase()))
            .map(|adapter| (adapter.interface_guid.clone(), true))
            .collect::<Vec<_>>();
        let entries = snapshot
            .adapters
            .iter()
            .filter(|adapter| active.contains(&adapter.interface_guid.to_ascii_uppercase()))
            .map(restore_entry)
            .collect::<Vec<_>>();
        // CIM first makes the running resolver adopt the saved effective list. CIM may rewrite
        // NameServer while doing so, therefore restore all four exact registry values afterwards;
        // the facade's read-back proof then checks those originals rather than CIM's normalized
        // representation.
        live_results.extend(live_apply_with_retry(entries));
        for adapter in &snapshot.adapters {
            let guid = &adapter.interface_guid;
            if key_exists(&v4_key(guid))? {
                restore_value(&v4_key(guid), NAME_SERVER, &adapter.ipv4_name_server)?;
                restore_value(
                    &v4_key(guid),
                    PROFILE_NAME_SERVER,
                    &adapter.ipv4_profile_name_server,
                )?;
            }
            if key_exists(&v6_key(guid))? {
                restore_value(&v6_key(guid), NAME_SERVER, &adapter.ipv6_name_server)?;
                restore_value(
                    &v6_key(guid),
                    PROFILE_NAME_SERVER,
                    &adapter.ipv6_profile_name_server,
                )?;
            }
        }
        Ok(live_results)
    }

    pub(super) fn all_loopback(guids: &[String]) -> Result<bool> {
        for guid in guids {
            let adapter = read_adapter(guid)?;
            // Each present family must be fully on loopback — NameServer and, when set,
            // ProfileNameServer (which overrides NameServer for the active profile). An absent
            // family is skipped, matching the apply side.
            if key_exists(&v4_key(guid))?
                && (!is_loopback_value(adapter.ipv4_name_server.as_deref())
                    || (adapter.ipv4_profile_name_server.is_some()
                        && !is_loopback_value(adapter.ipv4_profile_name_server.as_deref())))
            {
                return Ok(false);
            }
            if key_exists(&v6_key(guid))?
                && (!is_loopback_value(adapter.ipv6_name_server.as_deref())
                    || (adapter.ipv6_profile_name_server.is_some()
                        && !is_loopback_value(adapter.ipv6_profile_name_server.as_deref())))
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter(guid: &str, v4: Option<&str>) -> AdapterDnsSnapshot {
        AdapterDnsSnapshot {
            interface_guid: guid.to_owned(),
            ipv4_name_server: v4.map(ToOwned::to_owned),
            ..Default::default()
        }
    }

    #[test]
    fn name_server_lists_tolerate_messy_registry_values() {
        assert_eq!(
            parse_name_server_list(" 1.1.1.1 , ,8.8.8.8, "),
            vec!["1.1.1.1".to_owned(), "8.8.8.8".to_owned()]
        );
        assert!(parse_name_server_list("").is_empty());
        assert_eq!(
            format_name_server_list(&["1.1.1.1".to_owned(), "8.8.8.8".to_owned()]),
            "1.1.1.1,8.8.8.8"
        );
    }

    #[test]
    fn loopback_detection_is_exact() {
        assert!(is_loopback_value(Some("127.0.0.1")));
        assert!(is_loopback_value(Some("::1")));
        assert!(is_loopback_value(Some("127.0.0.1, ::1")));
        assert!(!is_loopback_value(Some("127.0.0.1, 1.1.1.1")));
        assert!(!is_loopback_value(Some("1.1.1.1")));
        assert!(!is_loopback_value(Some("")));
        assert!(!is_loopback_value(None));
    }

    #[test]
    fn only_up_non_loopback_adapters_have_a_live_dns_resolver_to_protect() {
        assert!(is_active_dns_adapter(1, 6), "up ethernet");
        assert!(is_active_dns_adapter(1, 71), "up wi-fi");
        assert!(is_active_dns_adapter(1, 131), "up tunnel");
        assert!(!is_active_dns_adapter(2, 6), "down ethernet");
        assert!(!is_active_dns_adapter(1, 24), "software loopback");
    }

    #[test]
    fn enable_preserves_originals_and_appends_new_adapters() {
        let original = DnsSnapshot {
            version: SNAPSHOT_VERSION,
            taken_at: 1,
            adapters: vec![adapter("{A}", Some("1.1.1.1"))],
        };
        let fresh = DnsSnapshot {
            version: SNAPSHOT_VERSION,
            taken_at: 2,
            adapters: vec![
                adapter("{A}", Some(LOOPBACK_V4)),
                adapter("{NEW}", Some("9.9.9.9")),
            ],
        };
        let merged = merge_snapshot(Some(original.clone()), fresh.clone());
        assert_eq!(merged.taken_at, original.taken_at);
        assert_eq!(
            merged.adapters[0], original.adapters[0],
            "saved DNS is never overwritten"
        );
        assert_eq!(
            merged.adapters[1], fresh.adapters[1],
            "a fresh adapter keeps its original DNS"
        );
        assert_eq!(merge_snapshot(None, fresh.clone()), fresh);
    }

    #[test]
    fn restore_proof_requires_exact_saved_values() {
        let snapshot = DnsSnapshot {
            version: SNAPSHOT_VERSION,
            taken_at: 1,
            adapters: vec![
                adapter("{A}", Some("1.1.1.1")),
                adapter("{B}", None), // DHCP: restore deletes the value
            ],
        };
        let restored = vec![adapter("{A}", Some("1.1.1.1")), adapter("{B}", None)];
        assert!(restore_is_proven(&snapshot, &restored));

        let still_loopback = vec![adapter("{A}", Some(LOOPBACK_V4)), adapter("{B}", None)];
        assert!(!restore_is_proven(&snapshot, &still_loopback));

        let wrong_server = vec![adapter("{A}", Some("8.8.8.8")), adapter("{B}", None)];
        assert!(!restore_is_proven(&snapshot, &wrong_server));

        let missing_adapter = vec![adapter("{A}", Some("1.1.1.1"))];
        assert!(
            restore_is_proven(&snapshot, &missing_adapter),
            "an adapter whose registry key vanished has no live resolver left to restore"
        );
    }

    #[test]
    fn live_restore_uses_profile_overrides_and_includes_ipv6() {
        let saved = AdapterDnsSnapshot {
            interface_guid: "{DUAL}".to_owned(),
            ipv4_name_server: Some("1.1.1.1".to_owned()),
            ipv4_profile_name_server: Some("8.8.8.8, 8.8.4.4".to_owned()),
            ipv6_name_server: Some("2606:4700:4700::1111".to_owned()),
            ipv6_profile_name_server: None,
            live_apply_failed: false,
        };
        assert_eq!(
            restored_live_servers(&saved),
            Some(vec![
                "8.8.8.8".to_owned(),
                "8.8.4.4".to_owned(),
                "2606:4700:4700::1111".to_owned(),
            ])
        );

        let dhcp = AdapterDnsSnapshot {
            interface_guid: "{DHCP}".to_owned(),
            ..Default::default()
        };
        assert_eq!(restored_live_servers(&dhcp), None);
    }

    #[test]
    fn restore_proof_covers_v6_only_adapters() {
        let v6_only = AdapterDnsSnapshot {
            interface_guid: "{V6}".to_owned(),
            ipv6_name_server: Some("2606:4700:4700::1111".to_owned()),
            ..Default::default()
        };
        let snapshot = DnsSnapshot {
            version: SNAPSHOT_VERSION,
            taken_at: 1,
            adapters: vec![v6_only.clone()],
        };
        assert!(restore_is_proven(&snapshot, std::slice::from_ref(&v6_only)));

        let wrong_v6 = AdapterDnsSnapshot {
            ipv6_name_server: Some("2001:db8::53".to_owned()),
            ..v6_only.clone()
        };
        assert!(!restore_is_proven(&snapshot, &[wrong_v6]));

        let drifted_to_loopback = AdapterDnsSnapshot {
            ipv6_name_server: Some("::1".to_owned()),
            ..v6_only
        };
        assert!(
            !restore_is_proven(&snapshot, &[drifted_to_loopback]),
            "still on loopback is not a proven restore"
        );
    }

    #[test]
    fn restore_proof_ignores_adapters_added_after_the_snapshot() {
        let snapshot = DnsSnapshot {
            version: SNAPSHOT_VERSION,
            taken_at: 1,
            adapters: vec![adapter("{A}", Some("1.1.1.1"))],
        };
        let current = vec![
            adapter("{A}", Some("1.1.1.1")),
            adapter("{NEW}", Some("8.8.8.8")), // appeared later; not ours to prove
        ];
        assert!(restore_is_proven(&snapshot, &current));
    }

    #[test]
    fn restore_proof_requires_clean_live_apply_records() {
        let mut flagged = adapter("{A}", Some("1.1.1.1"));
        flagged.live_apply_failed = true;
        let snapshot = DnsSnapshot {
            version: SNAPSHOT_VERSION,
            taken_at: 1,
            adapters: vec![flagged],
        };
        let current = vec![adapter("{A}", Some("1.1.1.1"))];
        assert!(
            !restore_is_proven(&snapshot, &current),
            "a recorded live-apply failure blocks the proof even when the registry matches"
        );

        // Memory failures merge into the snapshot the same way.
        let clean = DnsSnapshot {
            version: SNAPSHOT_VERSION,
            taken_at: 1,
            adapters: vec![adapter("{A}", Some("1.1.1.1"))],
        };
        let merged = with_live_failures(&clean, &["{A}".to_owned()].into_iter().collect());
        assert!(merged.adapters[0].live_apply_failed);
        assert!(!restore_is_proven(&merged, &current));
        let unaffected = with_live_failures(&clean, &Default::default());
        assert!(restore_is_proven(&unaffected, &current));
    }

    #[test]
    fn enable_replays_loopback_only_when_protection_drifted() {
        assert!(
            needs_loopback_replay(false, false, false),
            "the first enable must snapshot adapters and apply loopback"
        );
        assert!(!needs_loopback_replay(true, true, false));
        assert!(
            needs_loopback_replay(true, false, false),
            "snapshot present but adapters off loopback: replay the write"
        );
        assert!(
            needs_loopback_replay(true, true, true),
            "a recorded live-apply failure must replay even when the registry is loopback"
        );
        assert!(needs_loopback_replay(false, false, true));
    }

    #[test]
    fn registry_match_ignores_the_live_apply_flag() {
        let mut saved = adapter("{A}", Some("1.1.1.1"));
        saved.live_apply_failed = true;
        let current = adapter("{A}", Some("1.1.1.1"));
        assert!(registry_values_match(&saved, &current));
        let drifted = adapter("{A}", Some("8.8.8.8"));
        assert!(!registry_values_match(&saved, &drifted));
    }

    #[test]
    fn snapshot_round_trips_through_json() {
        let snapshot = DnsSnapshot {
            version: SNAPSHOT_VERSION,
            taken_at: 42,
            adapters: vec![AdapterDnsSnapshot {
                interface_guid: "{GUID}".to_owned(),
                ipv4_name_server: Some("1.1.1.1,8.8.8.8".to_owned()),
                ipv4_profile_name_server: None,
                ipv6_name_server: Some("2606:4700:4700::1111".to_owned()),
                ipv6_profile_name_server: None,
                live_apply_failed: false,
            }],
        };
        let bytes = serde_json::to_vec_pretty(&snapshot).expect("snapshot should serialize");
        assert_eq!(
            serde_json::from_slice::<DnsSnapshot>(&bytes).expect("snapshot should deserialize"),
            snapshot
        );

        // Snapshots written before live-apply tracking must still load (flag defaults off).
        let legacy = serde_json::json!({
            "version": 1,
            "taken_at": 1,
            "adapters": [{
                "interface_guid": "{A}",
                "ipv4_name_server": "1.1.1.1",
                "ipv4_profile_name_server": null,
                "ipv6_name_server": null,
                "ipv6_profile_name_server": null
            }]
        });
        let decoded: DnsSnapshot =
            serde_json::from_value(legacy).expect("legacy snapshot should deserialize");
        assert!(!decoded.adapters[0].live_apply_failed);
    }
}
