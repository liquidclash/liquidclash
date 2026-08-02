//! Cross-platform facade for the Windows WFP kill switch.
//!
//! Layering mirrors `macos_kill_switch.rs`: this module owns the state machine, the persisted
//! intent record (`kill-switch.json`, written atomically *before* any WFP mutation), the
//! verify-after-write watchdog, startup recovery ("corrupt intent = armed"), and the emergency
//! disarm. The rule set itself comes from the pure model (`wfp_model.rs`); the `Fwpm*` FFI is
//! confined to `wfp.rs` and compiled only on Windows, so everything here builds and is
//! unit-exercised on any host — off Windows every mutating entry point refuses with
//! "unsupported" and status reports a never-armed switch.

use crate::core::structure::{
    KillSwitchConfig, KillSwitchStatus, KillSwitchStatusMode, ProxyEndpoint,
};
use crate::core::wfp_model::{self, RuleConfig};
use anyhow::{Context as _, Result, bail};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

/// Whether the live WFP engine is behind this build (real Windows service binary).
const ENGINE_LIVE: bool = cfg!(all(windows, not(feature = "test")));

/// The fail-closed intent record in the service state directory. Written atomically before
/// any WFP mutation, exactly like the macOS helper's `macos-kill-switch.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct IntentRecord {
    wanted: bool,
    mode: KillSwitchStatusMode,
    /// `None` is a legacy record: Locked migrated as verified, earlier phases as stale.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verified: Option<bool>,
    tunnel_interface: String,
    /// Staged core binary path the `ALE_APP_ID` permit is resolved from.
    app_path: String,
    endpoints: Vec<ProxyEndpoint>,
    /// Resolved, validated, public-only API host IPs (bounded by the model).
    api_host_ips: Vec<String>,
    updated_at: u64,
    /// Who armed the protection: the same SHA256(SID) key `authenticate_owner` derives. The
    /// machine-wide WFP policy may only be released/restricted by that owner — the pipe
    /// authenticates *a* local user, but the armed state belongs to the user who armed it.
    /// `None` for legacy/emergency-restored intents, which own no one and can be released by
    /// any authenticated owner (see `authorize_write_for`).
    #[serde(default)]
    owner_key: Option<String>,
}

impl IntentRecord {
    fn is_verified(&self) -> bool {
        self.verified
            .unwrap_or(self.mode == KillSwitchStatusMode::Locked)
    }
}

#[derive(Debug, Clone)]
struct Armed {
    intent: IntentRecord,
    tun_luid: Option<u64>,
    /// Cloud-approved DIRECT endpoints for this armed session. **omission = clear**: kept
    /// only in memory, never written to `kill-switch.json`, never restored on service start,
    /// never inherited by the next arm. While the switch stays armed (any mode), the permits
    /// stay; every restore path rebuilds with an empty set (fail-closed until the app's next
    /// connect transaction re-issues them).
    direct_endpoints: Vec<ProxyEndpoint>,
}

static ARMED: Lazy<Mutex<Option<Armed>>> = Lazy::new(|| Mutex::new(None));
static LAST_ERROR: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));
static WFP_OPERATION: Lazy<tokio::sync::Mutex<()>> = Lazy::new(|| tokio::sync::Mutex::new(()));
/// Startup recovery downgraded a `locked` intent to `blocked`; set so a successful core
/// restore can re-lock the tunnel instead of leaving the machine fail-closed until the GUI
/// returns (`relock_restored_tunnel`).
static RESTORE_WAS_LOCKED: AtomicBool = AtomicBool::new(false);
/// The watchdog's latest verify-by-key result. `/kill-switch/status` reuses it instead of
/// running a full WFP RPC sweep per request.
static LAST_VERIFY: Lazy<Mutex<Option<(std::time::Instant, bool)>>> =
    Lazy::new(|| Mutex::new(None));

/// How long a status read may trust the cached verify: the watchdog re-verifies every
/// second, so this keeps reads at most one tick stale while staying off the RPC path.
const VERIFY_CACHE_TTL: std::time::Duration = std::time::Duration::from_millis(1_500);
/// Resolution is best-effort because the App also supplies pinned literal bootstrap addresses.
/// A broken resolver must never occupy the Service lifecycle queue without a bound.
#[cfg(all(windows, not(feature = "test")))]
const API_HOST_LOOKUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

fn note_verify(ok: bool) {
    *LAST_VERIFY.lock().unwrap() = Some((std::time::Instant::now(), ok));
}

fn intent_path() -> PathBuf {
    crate::service_paths()
        .persistent_state_dir()
        .join("kill-switch.json")
}

async fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
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

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Whether the facade's state machine runs on this build: the real service on Windows, plus
/// test builds everywhere (the engine is stubbed there, the state machine is what is tested).
const SUPPORTED: bool = cfg!(any(windows, test));

fn ensure_supported() -> Result<()> {
    if SUPPORTED {
        Ok(())
    } else {
        bail!("Windows kill switch is unsupported on this platform")
    }
}

fn validate_config(config: &KillSwitchConfig) -> Result<()> {
    if config.tunnel_interface.trim().is_empty() {
        bail!("enabled kill switch requires tunnel_interface");
    }
    if config.tunnel_interface.chars().count() > 64 {
        bail!("tunnel_interface is not a plausible interface alias");
    }
    if config.proxy_endpoints.is_empty() {
        bail!("enabled kill switch requires at least one proxy endpoint");
    }
    for endpoint in &config.proxy_endpoints {
        if wfp_model::parse_endpoint(endpoint).is_none() {
            bail!("invalid proxy endpoint {}:{}", endpoint.ip, endpoint.port);
        }
    }
    validate_direct_endpoints(config)
}

/// Cloud-approved DIRECT endpoints (WeChat acceleration), mirroring the Mac helper's
/// `validateSessionDirectEndpoints`: a bounded list of exact public `IP:port` tuples on an
/// approved port — and never one of the permanently protected addresses.
fn validate_direct_endpoints(config: &KillSwitchConfig) -> Result<()> {
    const MAX_DIRECT_ENDPOINTS: usize = 256;
    if config.direct_endpoints.len() > MAX_DIRECT_ENDPOINTS {
        bail!("direct_endpoints exceeds the {MAX_DIRECT_ENDPOINTS}-entry bound");
    }
    // permanentlyProtected: a selected node address or the well-known DNS resolvers must
    // never go DIRECT.
    let node_ips = config
        .proxy_endpoints
        .iter()
        .filter_map(|endpoint| wfp_model::parse_endpoint(endpoint).map(|(ip, _, _)| ip))
        .collect::<Vec<_>>();
    for endpoint in &config.direct_endpoints {
        let Some((ip, port, protocol)) = wfp_model::parse_endpoint(endpoint) else {
            bail!("invalid direct endpoint {}:{}", endpoint.ip, endpoint.port);
        };
        let port_ok = match protocol {
            wfp_model::IpProtocol::Tcp => matches!(port, 80 | 443),
            wfp_model::IpProtocol::Udp => matches!(port, 443 | 8000),
            // parse_endpoint only yields Tcp/Udp; anything else is not an approved DIRECT port.
            _ => false,
        };
        if !port_ok {
            bail!("direct endpoint {ip}:{port}/{protocol:?} is not an approved WeChat port");
        }
        if ip == IpAddr::from([1, 1, 1, 1]) || ip == IpAddr::from([8, 8, 8, 8]) {
            bail!("direct endpoint {ip} is a permanently protected resolver");
        }
        if node_ips.contains(&ip) {
            bail!("direct endpoint {ip} duplicates a selected node address");
        }
    }
    Ok(())
}

fn intent_is_valid(intent: &IntentRecord) -> bool {
    intent.wanted
        && !intent.tunnel_interface.is_empty()
        && !intent.endpoints.is_empty()
        && intent
            .endpoints
            .iter()
            .all(|endpoint| wfp_model::parse_endpoint(endpoint).is_some())
}

fn rule_config(armed: &Armed) -> RuleConfig {
    RuleConfig {
        mode: armed.intent.mode,
        endpoints: armed.intent.endpoints.clone(),
        api_host_ips: armed
            .intent
            .api_host_ips
            .iter()
            .filter_map(|ip| ip.parse::<IpAddr>().ok())
            .collect(),
        tun_luid: armed.tun_luid,
        app_path: armed.intent.app_path.clone(),
        direct_endpoints: armed.direct_endpoints.clone(),
    }
}

/// Engine calls are synchronous WFP RPCs; run them off the (possibly single-threaded) IPC
/// runtime so a slow BFE cannot freeze request handling (the DNS engine does the same).
#[cfg(all(windows, not(feature = "test")))]
async fn engine_call<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(operation)
        .await
        .context("WFP engine task failed")?
}

async fn install_unlocked(armed: &Armed) -> Result<()> {
    let expected = wfp_model::expected_filters(&rule_config(armed));
    #[cfg(all(windows, not(feature = "test")))]
    {
        let app_path = armed.intent.app_path.clone();
        let result = engine_call(move || crate::core::wfp::install(&expected, &app_path)).await;
        // `install` ends with verify-by-key, so its outcome doubles as a verify result.
        note_verify(result.is_ok());
        result
    }
    #[cfg(not(all(windows, not(feature = "test"))))]
    {
        let _ = expected;
        Ok(())
    }
}

async fn verify_live_unlocked(armed: &Armed) -> Result<()> {
    let expected = wfp_model::expected_filters(&rule_config(armed));
    #[cfg(all(windows, not(feature = "test")))]
    {
        engine_call(move || crate::core::wfp::verify(&expected)).await
    }
    #[cfg(not(all(windows, not(feature = "test"))))]
    {
        let _ = expected;
        Ok(())
    }
}

async fn remove_all_filters_unlocked() -> Result<()> {
    #[cfg(all(windows, not(feature = "test")))]
    {
        engine_call(crate::core::wfp::remove_all_filters).await
    }
    #[cfg(not(all(windows, not(feature = "test"))))]
    {
        Ok(())
    }
}

fn record_outcome(result: Result<()>) -> Result<()> {
    match result {
        Ok(()) => {
            *LAST_ERROR.lock().unwrap() = None;
            Ok(())
        }
        Err(error) => {
            *LAST_ERROR.lock().unwrap() = Some(format!("{error:#}"));
            Err(error)
        }
    }
}

/// Literal IPs are used directly; hostnames resolve once here, before the block exists.
/// Everything is then funnelled through the model's public-only, bounded sanitizer.
async fn resolve_api_hosts(hosts: &[String]) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    for host in hosts.iter().take(16) {
        let host = host.trim();
        if host.is_empty() {
            continue;
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            ips.push(ip);
            continue;
        }
        #[cfg(all(windows, not(feature = "test")))]
        match tokio::time::timeout(
            API_HOST_LOOKUP_TIMEOUT,
            tokio::net::lookup_host(format!("{host}:443")),
        )
        .await
        {
            Ok(Ok(resolved)) => ips.extend(resolved.map(|address| address.ip())),
            Ok(Err(error)) => {
                tracing::warn!("kill-switch API host {host:?} did not resolve: {error}")
            }
            Err(_) => tracing::warn!(
                "kill-switch API host {host:?} resolution exceeded {API_HOST_LOOKUP_TIMEOUT:?}"
            ),
        }
    }
    wfp_model::sanitize_api_host_ips(ips)
}

/// First phase of the two-phase arm: floor + session rules up, API channel open, tunnel not
/// yet permitted. Called from `StartClash` before the core is started. `owner_key` is the
/// authenticated owner's key (SHA256(SID)), recorded so only that owner can later release or
/// restrict the machine-wide policy.
pub(crate) async fn arm_bootstrap(
    config: &KillSwitchConfig,
    app_path: &str,
    owner_key: &str,
) -> Result<()> {
    ensure_supported()?;
    validate_config(config)?;
    if app_path.trim().is_empty() {
        bail!("enabled kill switch requires the staged core path");
    }
    if owner_key.is_empty() {
        bail!("enabled kill switch requires the authenticated owner key");
    }
    let api_host_ips = resolve_api_hosts(&config.bootstrap_api_hosts).await;
    let _operation = WFP_OPERATION.lock().await;
    let inherited_verified = ARMED.lock().unwrap().as_ref().is_some_and(|armed| {
        armed.intent.owner_key.as_deref() == Some(owner_key) && armed.intent.is_verified()
    });
    let armed = Armed {
        intent: IntentRecord {
            wanted: true,
            mode: KillSwitchStatusMode::Bootstrap,
            verified: Some(inherited_verified),
            tunnel_interface: config.tunnel_interface.trim().to_owned(),
            app_path: app_path.to_owned(),
            endpoints: config.proxy_endpoints.clone(),
            api_host_ips: api_host_ips.iter().map(ToString::to_string).collect(),
            updated_at: now_unix(),
            owner_key: Some(owner_key.to_owned()),
        },
        tun_luid: None,
        // In memory only — the intent file deliberately never carries these (omission = clear).
        direct_endpoints: config.direct_endpoints.clone(),
    };
    // Persist fail-closed intent before touching WFP: a daemon restart installs at least the
    // floor if this process dies during the following transaction.
    atomic_write(&intent_path(), &serde_json::to_vec_pretty(&armed.intent)?).await?;
    *ARMED.lock().unwrap() = Some(armed.clone());
    record_outcome(install_unlocked(&armed).await)
}

/// Commit the full app verification barrier for the active logical session.
pub(crate) async fn mark_verified(owner_key: &str) -> Result<()> {
    ensure_supported()?;
    let _operation = WFP_OPERATION.lock().await;
    let mut armed = ARMED
        .lock()
        .unwrap()
        .clone()
        .context("kill switch is not armed")?;
    if armed.intent.owner_key.as_deref() != Some(owner_key) {
        bail!("kill switch belongs to a different owner");
    }
    if armed.intent.mode != KillSwitchStatusMode::Locked {
        bail!("kill switch must be locked before verification");
    }
    if armed.intent.is_verified() && armed.intent.verified == Some(true) {
        return Ok(());
    }
    armed.intent.verified = Some(true);
    armed.intent.updated_at = now_unix();
    atomic_write(&intent_path(), &serde_json::to_vec_pretty(&armed.intent)?).await?;
    *ARMED.lock().unwrap() = Some(armed);
    Ok(())
}

/// Whether `caller_key` may mutate the armed protection (release / restrict / DNS restore).
///
/// The pipe authenticates *a* local user; the armed WFP policy is machine-global and belongs
/// to the owner who armed it. A different local user must not release it. Intents without an
/// `owner_key` (emergency/corrupt restores, or files predating this field) own no one: they
/// can be released by any authenticated owner — that is the documented escape hatch, and it
/// cannot be abused to steal another user's protection because there is nothing to steal
/// beyond a block anybody would want gone anyway.
pub(crate) fn authorize_write_for(
    caller_key: &str,
) -> std::result::Result<(), crate::core::auth::ServiceError> {
    let recorded = { ARMED.lock().unwrap().clone() }.and_then(|armed| armed.intent.owner_key);
    let Some(recorded) = recorded else {
        return Ok(());
    };
    if recorded == caller_key {
        Ok(())
    } else {
        Err(crate::core::auth::ServiceError::not_active())
    }
}

async fn resolve_luid(name: &str) -> Result<u64> {
    #[cfg(all(windows, not(feature = "test")))]
    {
        let name = name.to_owned();
        engine_call(move || crate::core::wfp::luid_for_interface(&name)).await
    }
    #[cfg(not(all(windows, not(feature = "test"))))]
    {
        let _ = name;
        Ok(0)
    }
}

/// Second phase: permit the tunnel interface (by LUID) and retract the bootstrap API
/// channel. Runs only once the WinTUN adapter exists — until then tunnel traffic is blocked
/// too (fail-closed).
///
/// The interface name is NOT negotiable: it must equal the one recorded at arm time. A
/// client-supplied name like "Ethernet" would otherwise install a weight-8 permit for a
/// physical adapter — a fail-open primitive for every process on the machine. Rejecting a
/// mismatch has zero side effects; it guards against client bugs and same-user process abuse.
pub(crate) async fn lock(tunnel_interface: Option<&str>) -> Result<()> {
    ensure_supported()?;
    let _operation = WFP_OPERATION.lock().await;
    let mut armed = ARMED
        .lock()
        .unwrap()
        .clone()
        .context("kill switch is not armed")?;
    let recorded = armed.intent.tunnel_interface.clone();
    if recorded.is_empty() {
        bail!("armed kill switch has no tunnel interface");
    }
    if let Some(supplied) = tunnel_interface
        .map(str::trim)
        .filter(|supplied| !supplied.is_empty())
        && supplied != recorded
    {
        bail!(
            "lock interface {supplied:?} does not match the interface recorded at arm time {recorded:?}"
        );
    }
    let luid = resolve_luid(&recorded).await?;
    armed.tun_luid = Some(luid);
    armed.intent.mode = KillSwitchStatusMode::Locked;
    armed.intent.updated_at = now_unix();
    // Update live WFP first (the macOS helper's add_tunnel ordering): if this fails, the
    // previous bootstrap rules remain effective and the persisted intent restores them after
    // a crash.
    install_unlocked(&armed).await?;
    atomic_write(&intent_path(), &serde_json::to_vec_pretty(&armed.intent)?).await?;
    *ARMED.lock().unwrap() = Some(armed);
    *LAST_ERROR.lock().unwrap() = None;
    Ok(())
}

/// Disconnected-but-armed ("Protected Offline"): floor + endpoint/DNS rules stay, the API
/// recovery channel re-opens, the tunnel permit is gone.
async fn restrict_bootstrap_unlocked() -> Result<()> {
    let mut armed = ARMED
        .lock()
        .unwrap()
        .clone()
        .context("kill switch is not armed")?;
    armed.intent.mode = KillSwitchStatusMode::Blocked;
    armed.tun_luid = None;
    armed.intent.updated_at = now_unix();
    // Persist first so a crash at any later point restores the stricter block (macOS parity).
    atomic_write(&intent_path(), &serde_json::to_vec_pretty(&armed.intent)?).await?;
    *ARMED.lock().unwrap() = Some(armed.clone());
    record_outcome(install_unlocked(&armed).await)
}

pub(crate) async fn restrict_bootstrap() -> Result<()> {
    ensure_supported()?;
    let _operation = WFP_OPERATION.lock().await;
    restrict_bootstrap_unlocked().await
}

/// Normal release — only on explicit user request. See the DNS-before-disarm invariant.
async fn disarm_unlocked() -> Result<()> {
    let previous = ARMED.lock().unwrap().clone();
    let Some(previous) = previous else {
        // Not armed: still sweep possible residuals so a half-failed earlier run cannot
        // linger, then clear any stale intent file.
        remove_all_filters_unlocked().await?;
        match tokio::fs::remove_file(intent_path()).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        // A leftover DNS snapshot must not be skipped just because nothing is armed: the
        // filters are already gone, so refusing would buy no blocking — but the resolver
        // must not stay on a dead loopback. Best-effort, surfaced via last_error.
        if let Err(error) = crate::core::dns::ensure_restored().await {
            *LAST_ERROR.lock().unwrap() = Some(format!(
                "leftover DNS snapshot could not be restored: {error:#}"
            ));
        }
        return Ok(());
    };
    // DNS-before-disarm invariant (identical to the macOS helper): the network may open only
    // after the snapshotted per-adapter DNS is restored and verified. If restore cannot be
    // proven, the disarm is refused and the block stays armed — opening the network while DNS
    // still points at a dead loopback resolver would blackhole the user, and restoring after
    // opening would race leaked traffic.
    crate::core::dns::ensure_restored().await?;
    if let Err(error) = remove_all_filters_unlocked().await {
        let _ = install_unlocked(&previous).await;
        return Err(error.context("failed to remove kill-switch filters; protection restored"));
    }
    match tokio::fs::remove_file(intent_path()).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            install_unlocked(&previous).await.context(
                "network opened and persisted-state cleanup failed; failed to restore protection",
            )?;
            return Err(error).context("network opened but persisted-state cleanup failed");
        }
    }
    *ARMED.lock().unwrap() = None;
    *LAST_ERROR.lock().unwrap() = None;
    Ok(())
}

/// `POST /kill-switch/release`: the explicit user-requested disarm. Idempotent — not armed
/// is a successful no-op that still sweeps residuals — and shares the DNS-before-disarm
/// invariant via `disarm_unlocked`: when DNS restore cannot be proven the release is refused
/// and the block stays armed.
#[cfg_attr(not(windows), allow(dead_code))] // the route helper is cfg(windows); tests use it
pub(crate) async fn release() -> Result<KillSwitchStatus> {
    ensure_supported()?;
    {
        let _operation = WFP_OPERATION.lock().await;
        disarm_unlocked().await?;
    }
    Ok(status().await)
}

/// `StopClash` counterpart of the macOS helper: keep blocking (recovery channel open) unless
/// an explicit disconnect requested release.
pub(crate) async fn transition_after_stop(release_requested: bool) -> Result<()> {
    if !SUPPORTED {
        return Ok(());
    }
    let _operation = WFP_OPERATION.lock().await;
    if ARMED.lock().unwrap().is_none() {
        return Ok(());
    }
    if release_requested {
        return disarm_unlocked().await;
    }
    restrict_bootstrap_unlocked().await
}

/// Service-start recovery (design doc §3): read the intent record and reconcile.
pub async fn restore_on_service_start() -> Result<()> {
    if !SUPPORTED {
        return Ok(());
    }
    let _operation = WFP_OPERATION.lock().await;
    RESTORE_WAS_LOCKED.store(false, Ordering::Release);
    // Upgrade/migration first: remove sublayers left by older builds (filters included) so
    // the reconcile below reasons only about the current object set.
    #[cfg(all(windows, not(feature = "test")))]
    if let Err(error) = engine_call(crate::core::wfp::remove_legacy_sublayers).await {
        tracing::warn!("legacy WFP sublayer cleanup failed: {error:#}");
    }
    match tokio::fs::read(intent_path()).await {
        Ok(bytes) => match serde_json::from_slice::<IntentRecord>(&bytes) {
            Ok(intent) if intent_is_valid(&intent) => {
                if !intent.is_verified() {
                    // Do not open the machine yet. Startup reconciliation runs immediately after
                    // this function and must first prove that any previous Core is gone. It then
                    // calls `retire_unverified_on_service_start`, which durably retires the desired
                    // owner, proves DNS restoration, and only then removes WFP. Keeping a strict
                    // Blocked snapshot here closes the old Core/WFP ordering window and preserves
                    // the DNS-before-disarm invariant when recovery itself fails.
                    let mut armed = Armed {
                        intent,
                        tun_luid: None,
                        direct_endpoints: Vec::new(),
                    };
                    armed.intent.mode = KillSwitchStatusMode::Blocked;
                    armed.intent.updated_at = now_unix();
                    atomic_write(&intent_path(), &serde_json::to_vec_pretty(&armed.intent)?)
                        .await?;
                    *ARMED.lock().unwrap() = Some(armed.clone());
                    return record_outcome(install_unlocked(&armed).await);
                }
                let mut armed = Armed {
                    intent,
                    tun_luid: None,
                    // omission = clear: a restore never brings DIRECT endpoints back. The
                    // recovered session stays fail-closed for them until the app's next
                    // connect transaction re-issues the approved tuples.
                    direct_endpoints: Vec::new(),
                };
                // A persisted Locked mode is not proof this boot's tunnel exists: downgrade to
                // Blocked (fail-closed, API recovery channel open) until the tunnel is
                // re-locked — by `relock_restored_tunnel` after a core restore, or by the GUI.
                if armed.intent.mode == KillSwitchStatusMode::Locked {
                    // Materialize the legacy Locked => verified migration before changing mode.
                    // Otherwise a second service restart would reinterpret the now-Blocked
                    // field-less record as stale and incorrectly open an established session.
                    armed.intent.verified = Some(true);
                    armed.intent.mode = KillSwitchStatusMode::Blocked;
                    armed.intent.updated_at = now_unix();
                    atomic_write(&intent_path(), &serde_json::to_vec_pretty(&armed.intent)?)
                        .await?;
                    RESTORE_WAS_LOCKED.store(true, Ordering::Release);
                }
                *ARMED.lock().unwrap() = Some(armed.clone());
                record_outcome(install_unlocked(&armed).await)
            }
            Ok(intent) => {
                // wanted == false (or unwanted-but-parseable) with possible residual objects:
                // clean up, exactly the design's third recovery rule. A leftover DNS snapshot
                // (e.g. from an emergency disarm whose restore could not be proven) is swept
                // here too — protection is off, so the machine must not stay on loopback DNS.
                let _ = intent;
                remove_all_filters_unlocked().await?;
                match tokio::fs::remove_file(intent_path()).await {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                *ARMED.lock().unwrap() = None;
                if let Err(error) = crate::core::dns::ensure_restored().await {
                    tracing::warn!(
                        "service start: leftover DNS snapshot could not be restored: {error:#}"
                    );
                }
                Ok(())
            }
            Err(_) => {
                // Corrupt intent = wanted (fail-closed), exactly the macOS helper's "damaged
                // state file ⇒ install emergency block". The corrupt file is left on disk as
                // evidence; the in-memory intent below is what the watchdog reconciles.
                let emergency = Armed {
                    intent: IntentRecord {
                        wanted: true,
                        mode: KillSwitchStatusMode::Blocked,
                        verified: Some(true),
                        tunnel_interface: String::new(),
                        app_path: String::new(),
                        endpoints: Vec::new(),
                        api_host_ips: Vec::new(),
                        updated_at: now_unix(),
                        owner_key: None,
                    },
                    tun_luid: None,
                    direct_endpoints: Vec::new(),
                };
                *ARMED.lock().unwrap() = Some(emergency.clone());
                install_unlocked(&emergency)
                    .await
                    .context("corrupt kill-switch intent: failed to install emergency block")
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // Missing intent but residual objects exist → treat as wanted (fail-closed).
            #[cfg(all(windows, not(feature = "test")))]
            if engine_call(crate::core::wfp::any_filters_exist)
                .await
                .unwrap_or(true)
            {
                let emergency = Armed {
                    intent: IntentRecord {
                        wanted: true,
                        mode: KillSwitchStatusMode::Blocked,
                        verified: Some(true),
                        tunnel_interface: String::new(),
                        app_path: String::new(),
                        endpoints: Vec::new(),
                        api_host_ips: Vec::new(),
                        updated_at: now_unix(),
                        owner_key: None,
                    },
                    tun_luid: None,
                    direct_endpoints: Vec::new(),
                };
                *ARMED.lock().unwrap() = Some(emergency.clone());
                return install_unlocked(&emergency).await.context(
                    "missing intent with residual WFP objects: failed to reinstall block",
                );
            }
            // Not armed and nothing residual: still sweep a leftover DNS snapshot (see above).
            if let Err(error) = crate::core::dns::ensure_restored().await {
                tracing::warn!(
                    "service start: leftover DNS snapshot could not be restored: {error:#}"
                );
            }
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

/// Finish startup recovery for an initial attempt that never crossed the durable verification
/// barrier. This must run only *after* `reconcile_service_startup` has stopped and identified any
/// surviving Core. The order is deliberately irreversible-safe:
///
/// 1. retire the matching owner's desired run state;
/// 2. prove DNS restoration;
/// 3. remove WFP and its intent record.
///
/// Any ambiguity leaves the stricter Blocked policy installed and IPC available for recovery.
/// Returns `true` when an unverified intent was retired, `false` when there was none.
pub async fn retire_unverified_on_service_start() -> Result<bool> {
    if !SUPPORTED {
        return Ok(false);
    }
    let _operation = WFP_OPERATION.lock().await;
    let Some(armed) = ARMED.lock().unwrap().clone() else {
        return Ok(false);
    };
    if armed.intent.is_verified() {
        return Ok(false);
    }

    let result = async {
        if let Some(owner_key) = armed.intent.owner_key.as_deref() {
            if !crate::core::desired::retire_owner_if_active(owner_key)
                .await
                .context("failed to retire stale unverified owner")?
            {
                bail!(
                    "stale unverified protection owner {owner_key:?} does not match the active Core owner"
                );
            }
        } else {
            crate::core::desired::retire_legacy_active_owner()
                .await
                .context("failed to retire active owner paired with legacy unowned protection")?;
        }
        disarm_unlocked().await
    }
    .await;

    match result {
        Ok(()) => Ok(true),
        Err(error) => {
            *LAST_ERROR.lock().unwrap() = Some(format!(
                "stale unverified session remains fail-closed: {error:#}"
            ));
            Err(error)
        }
    }
}

/// Windows counterpart of the macOS helper's `add_restored_kill_switch_tunnel`: the service
/// restored a core from desired state and the recovered intent had been `locked` (startup
/// downgraded it to `blocked` because the adapter could not be proven yet). Re-run the
/// normal lock path — including the Wintun validation chain — for the recorded interface.
/// A failure keeps the stricter Blocked mode and is recorded in `last_error`.
pub async fn relock_restored_tunnel() -> Result<()> {
    if !SUPPORTED {
        return Ok(());
    }
    if !RESTORE_WAS_LOCKED.swap(false, Ordering::Acquire) {
        return Ok(());
    }
    if ARMED.lock().unwrap().is_none() {
        return Ok(());
    }
    lock(None).await.map_err(|error| {
        let message = format!("restored core could not be re-locked: {error:#}");
        *LAST_ERROR.lock().unwrap() = Some(message.clone());
        error.context(message)
    })
}

/// One-second verify-after-write watchdog (the macOS helper does the same for PF): any
/// mismatch reinstalls the full expected set transactionally. Persistent failures are
/// log-throttled — one error per minute, the rest at debug — so a broken engine cannot
/// flood the service log.
pub fn spawn_windows_kill_switch_watchdog() {
    tokio::spawn(async {
        let mut last_error_log = std::time::Instant::now() - std::time::Duration::from_secs(3_600);
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            let _operation = WFP_OPERATION.lock().await;
            let armed = { ARMED.lock().unwrap().clone() };
            if let Some(armed) = armed {
                let healthy = if ENGINE_LIVE {
                    let healthy = verify_live_unlocked(&armed).await.is_ok();
                    note_verify(healthy);
                    healthy
                } else {
                    true
                };
                if !healthy && let Err(error) = install_unlocked(&armed).await {
                    *LAST_ERROR.lock().unwrap() = Some(format!("{error:#}"));
                    if last_error_log.elapsed() >= std::time::Duration::from_secs(60) {
                        tracing::error!("Windows kill-switch reconciliation failed: {error:#}");
                        last_error_log = std::time::Instant::now();
                    } else {
                        tracing::debug!(
                            "Windows kill-switch reconciliation still failing: {error:#}"
                        );
                    }
                }
            }
        }
    });
}

/// `tono-service.exe --emergency-disarm`: restore snapshotted DNS, then delete every WFP
/// object whose provider key is Tono's (filters → legacy sublayers → sublayer → provider),
/// and remove the intent record. It touches no other provider, sublayer, or Windows Defender
/// Firewall setting.
pub async fn emergency_disarm_windows_kill_switch() -> Result<()> {
    let _operation = WFP_OPERATION.lock().await;
    // This is still the fail-open escape hatch: WFP objects are removed even if protected DNS
    // cannot be restored. The DNS failure is nevertheless returned *after* WFP and intent
    // cleanup so an uninstaller cannot report success and delete the remaining recovery files.
    // `restore_protected` preserves its snapshot on failure, making a repair + retry possible.
    let dns_restore = crate::core::dns::restore_protected().await;

    // Persist fail-open intent *before* removing WFP. If deleting the intent file later fails,
    // service-start recovery sees this tombstone and completes cleanup instead of re-arming the
    // stale wanted policy. If writing the tombstone itself fails, leave WFP untouched.
    let mut tombstone = match tokio::fs::read(intent_path()).await {
        Ok(bytes) => serde_json::from_slice::<IntentRecord>(&bytes).ok(),
        Err(_) => None,
    }
    .unwrap_or(IntentRecord {
        wanted: false,
        mode: KillSwitchStatusMode::Blocked,
        verified: Some(false),
        tunnel_interface: String::new(),
        app_path: String::new(),
        endpoints: Vec::new(),
        api_host_ips: Vec::new(),
        updated_at: now_unix(),
        owner_key: None,
    });
    tombstone.wanted = false;
    tombstone.updated_at = now_unix();
    atomic_write(&intent_path(), &serde_json::to_vec_pretty(&tombstone)?).await?;
    *ARMED.lock().unwrap() = None;
    *LAST_VERIFY.lock().unwrap() = None;

    #[cfg(all(windows, not(feature = "test")))]
    crate::core::wfp::emergency_disarm()?;
    match tokio::fs::remove_file(intent_path()).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    dns_restore.map(|_| ()).map_err(|error| {
        let snapshot = crate::service_paths()
            .persistent_state_dir()
            .join("protected-dns.json");
        anyhow::anyhow!(
            "WFP was removed, but DNS restore could not be proven: {error:#}. \
             Recovery snapshot: {snapshot:?}. Restore the affected adapter DNS (usually DHCP), \
             then rerun the uninstaller; if the snapshot is corrupt, delete it only after DNS is verified."
        )
    })
}

pub(crate) async fn status() -> KillSwitchStatus {
    // Never join the WFP writer queue. The watchdog refreshes `LAST_VERIFY`; mutations publish
    // `ARMED` only at their commit boundary, so a concurrent read gets the previous committed
    // state rather than blocking behind an RPC that may itself be the thing under diagnosis.
    let armed = { ARMED.lock().unwrap().clone() };
    let Some(armed) = armed else {
        return KillSwitchStatus {
            wanted: false,
            verified: false,
            live: false,
            mode: KillSwitchStatusMode::Blocked,
            endpoints: Vec::new(),
            last_error: LAST_ERROR.lock().unwrap().clone(),
        };
    };
    let live = if ENGINE_LIVE {
        LAST_VERIFY
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|(at, ok)| *ok && at.elapsed() < VERIFY_CACHE_TTL)
    } else {
        // No engine behind this build: report the recorded intent without claiming liveness.
        false
    };
    KillSwitchStatus {
        wanted: armed.intent.wanted,
        verified: armed.intent.is_verified(),
        live,
        mode: armed.intent.mode,
        endpoints: armed.intent.endpoints.clone(),
        last_error: LAST_ERROR.lock().unwrap().clone(),
    }
}

/// `/status` aggregate: present only where the WFP backend exists; the macOS fields stay the
/// source of truth there.
pub(crate) async fn status_snapshot() -> Option<KillSwitchStatus> {
    if cfg!(windows) {
        Some(status().await)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::structure::{KillSwitchConfig, ProxyEndpoint, ProxyProtocol};
    use serial_test::serial;

    fn test_config() -> KillSwitchConfig {
        KillSwitchConfig {
            tunnel_interface: "Tono".to_owned(),
            proxy_endpoints: vec![ProxyEndpoint {
                ip: "8.8.8.8".to_owned(),
                port: 443,
                protocol: ProxyProtocol::Tcp,
            }],
            bootstrap_api_hosts: vec!["1.1.1.1".to_owned()],
            direct_endpoints: Vec::new(),
        }
    }

    fn test_config_with_direct() -> KillSwitchConfig {
        KillSwitchConfig {
            direct_endpoints: vec![
                ProxyEndpoint {
                    ip: "203.0.113.9".to_owned(),
                    port: 443,
                    protocol: ProxyProtocol::Tcp,
                },
                ProxyEndpoint {
                    ip: "203.0.113.10".to_owned(),
                    port: 8000,
                    protocol: ProxyProtocol::Udp,
                },
            ],
            ..test_config()
        }
    }

    fn dns_snapshot_path() -> PathBuf {
        crate::service_paths()
            .persistent_state_dir()
            .join("protected-dns.json")
    }

    fn valid_intent(mode: KillSwitchStatusMode, wanted: bool) -> IntentRecord {
        IntentRecord {
            wanted,
            mode,
            // Existing tests use this as an established-session fixture; migration behavior is
            // covered separately with JSON that omits the field.
            verified: Some(true),
            tunnel_interface: "Tono".to_owned(),
            app_path: "/opt/tono/mihomo".to_owned(),
            endpoints: test_config().proxy_endpoints,
            api_host_ips: vec!["1.1.1.1".to_owned()],
            updated_at: 1,
            owner_key: None,
        }
    }

    #[test]
    fn legacy_verification_migration_depends_on_mode() {
        for (mode, expected) in [
            (KillSwitchStatusMode::Locked, true),
            (KillSwitchStatusMode::Blocked, false),
            (KillSwitchStatusMode::Bootstrap, false),
        ] {
            let mut value = serde_json::to_value(valid_intent(mode, true)).unwrap();
            value.as_object_mut().unwrap().remove("verified");
            let intent: IntentRecord = serde_json::from_value(value).unwrap();
            assert_eq!(intent.verified, None);
            assert_eq!(intent.is_verified(), expected, "{mode:?}");
        }
    }

    #[tokio::test]
    #[serial]
    async fn arm_inherits_verification_only_for_same_owner() -> Result<()> {
        cleanup().await;
        arm_bootstrap(&test_config(), "/opt/tono/mihomo", "owner-alice").await?;
        lock(None).await?;
        mark_verified("owner-alice").await?;
        arm_bootstrap(&test_config(), "/opt/tono/mihomo", "owner-alice").await?;
        assert!(ARMED.lock().unwrap().as_ref().unwrap().intent.is_verified());
        arm_bootstrap(&test_config(), "/opt/tono/mihomo", "owner-bob").await?;
        assert!(!ARMED.lock().unwrap().as_ref().unwrap().intent.is_verified());
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn mark_verified_requires_locked_matching_owner_and_is_idempotent() -> Result<()> {
        cleanup().await;
        arm_bootstrap(&test_config(), "/opt/tono/mihomo", "owner-alice").await?;
        assert!(mark_verified("owner-alice").await.is_err());
        lock(None).await?;
        assert!(mark_verified("owner-bob").await.is_err());
        mark_verified("owner-alice").await?;
        mark_verified("owner-alice").await?;
        assert!(ARMED.lock().unwrap().as_ref().unwrap().intent.is_verified());
        Ok(())
    }

    async fn cleanup() {
        *ARMED.lock().unwrap() = None;
        *LAST_ERROR.lock().unwrap() = None;
        RESTORE_WAS_LOCKED.store(false, Ordering::Release);
        for path in [intent_path(), dns_snapshot_path()] {
            match tokio::fs::remove_file(path).await {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => panic!("test cleanup failed: {error}"),
            }
        }
    }

    #[tokio::test]
    #[serial]
    async fn restore_with_valid_wanted_intent_rearms_and_downgrades_locked() -> Result<()> {
        cleanup().await;
        let intent = valid_intent(KillSwitchStatusMode::Locked, true);
        atomic_write(&intent_path(), &serde_json::to_vec_pretty(&intent)?).await?;

        restore_on_service_start().await?;

        let armed = ARMED.lock().unwrap().clone().expect("must be re-armed");
        assert_eq!(
            armed.intent.mode,
            KillSwitchStatusMode::Blocked,
            "a persisted Locked mode downgrades to Blocked until lock runs again"
        );
        assert!(armed.tun_luid.is_none());
        // The downgrade is persisted too.
        let on_disk: IntentRecord = serde_json::from_slice(&tokio::fs::read(intent_path()).await?)?;
        assert_eq!(on_disk.mode, KillSwitchStatusMode::Blocked);
        assert_eq!(on_disk.verified, Some(true));
        assert!(status().await.wanted);
        cleanup().await;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn legacy_locked_migration_stays_verified_across_a_second_restart() -> Result<()> {
        cleanup().await;
        let mut value = serde_json::to_value(valid_intent(KillSwitchStatusMode::Locked, true))?;
        value.as_object_mut().unwrap().remove("verified");
        atomic_write(&intent_path(), &serde_json::to_vec_pretty(&value)?).await?;

        restore_on_service_start().await?;
        *ARMED.lock().unwrap() = None;
        restore_on_service_start().await?;

        let armed = ARMED
            .lock()
            .unwrap()
            .clone()
            .expect("must remain fail-closed");
        assert!(armed.intent.is_verified());
        assert_eq!(armed.intent.mode, KillSwitchStatusMode::Blocked);
        cleanup().await;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn unverified_startup_intent_stays_blocked_until_core_and_dns_reconcile() -> Result<()> {
        cleanup().await;
        let mut intent = valid_intent(KillSwitchStatusMode::Blocked, true);
        intent.verified = Some(false);
        atomic_write(&intent_path(), &serde_json::to_vec_pretty(&intent)?).await?;
        atomic_write(&dns_snapshot_path(), b"{ corrupt").await?;

        restore_on_service_start().await?;

        assert!(ARMED.lock().unwrap().is_some());
        assert!(status().await.wanted);
        assert!(tokio::fs::metadata(intent_path()).await.is_ok());

        let error = retire_unverified_on_service_start()
            .await
            .expect_err("unproven DNS restoration must keep the startup barrier armed");
        assert!(format!("{error:#}").contains("corrupt"));
        assert!(ARMED.lock().unwrap().is_some());
        assert!(tokio::fs::metadata(intent_path()).await.is_ok());
        assert!(
            tokio::fs::metadata(dns_snapshot_path()).await.is_ok(),
            "failed DNS evidence must remain available for recovery"
        );

        tokio::fs::remove_file(dns_snapshot_path()).await?;
        assert!(retire_unverified_on_service_start().await?);
        assert!(ARMED.lock().unwrap().is_none());
        assert!(tokio::fs::metadata(intent_path()).await.is_err());
        cleanup().await;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn verified_startup_intent_is_never_retired_by_initial_attempt_cleanup() -> Result<()> {
        cleanup().await;
        let intent = valid_intent(KillSwitchStatusMode::Locked, true);
        atomic_write(&intent_path(), &serde_json::to_vec_pretty(&intent)?).await?;

        restore_on_service_start().await?;

        assert!(!retire_unverified_on_service_start().await?);
        assert!(ARMED.lock().unwrap().is_some());
        assert!(tokio::fs::metadata(intent_path()).await.is_ok());
        cleanup().await;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn legacy_unowned_unverified_cleanup_cannot_resurrect_desired_core() -> Result<()> {
        use crate::core::auth::AuthenticatedOwner;
        use crate::{ClashConfig, CoreConfig, OwnerIdentity};

        cleanup().await;
        crate::core::desired::clear_active_owner().await?;
        let owner = AuthenticatedOwner {
            key: "legacy-unowned-wfp-owner".to_owned(),
            identity: OwnerIdentity::Unix {
                uid: 91_001,
                gid: 20,
            },
            app_data_root: std::env::temp_dir(),
        };
        let config = ClashConfig {
            core_config: CoreConfig {
                core_path: "/tmp/legacy-unowned-core".to_owned(),
                ..Default::default()
            },
            log_config: Default::default(),
        };
        crate::core::desired::persist_owner_core_started(&owner, &config).await?;
        crate::core::desired::persist_active_owner(&owner).await?;

        let mut intent = valid_intent(KillSwitchStatusMode::Blocked, true);
        intent.verified = Some(false);
        intent.owner_key = None;
        atomic_write(&intent_path(), &serde_json::to_vec_pretty(&intent)?).await?;
        restore_on_service_start().await?;

        assert!(retire_unverified_on_service_start().await?);
        assert!(crate::core::desired::load_active_owner().await?.is_none());
        assert!(
            !crate::core::desired::load_owner_desired_state(&owner.key)
                .await?
                .core_should_be_running
        );
        cleanup().await;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn restore_with_unwanted_intent_cleans_residual_state() -> Result<()> {
        cleanup().await;
        let intent = valid_intent(KillSwitchStatusMode::Blocked, false);
        atomic_write(&intent_path(), &serde_json::to_vec_pretty(&intent)?).await?;

        restore_on_service_start().await?;

        assert!(ARMED.lock().unwrap().is_none());
        assert!(
            tokio::fs::metadata(intent_path()).await.is_err(),
            "an unwanted intent record must be removed"
        );
        assert!(!status().await.wanted);
        cleanup().await;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn restore_with_corrupt_intent_arms_emergency_block_and_keeps_evidence() -> Result<()> {
        cleanup().await;
        atomic_write(&intent_path(), b"{ not json").await?;

        restore_on_service_start().await?;

        let armed = ARMED.lock().unwrap().clone().expect("corrupt = armed");
        assert_eq!(armed.intent.mode, KillSwitchStatusMode::Blocked);
        assert!(armed.intent.endpoints.is_empty());
        assert!(
            tokio::fs::metadata(intent_path()).await.is_ok(),
            "the corrupt record is left on disk as evidence"
        );
        assert!(status().await.wanted);
        cleanup().await;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn restore_with_missing_intent_is_a_noop() -> Result<()> {
        cleanup().await;

        restore_on_service_start().await?;

        assert!(ARMED.lock().unwrap().is_none());
        assert!(!status().await.wanted);
        cleanup().await;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn transition_after_stop_without_release_restricts_to_bootstrap() -> Result<()> {
        cleanup().await;
        arm_bootstrap(&test_config(), "/opt/tono/mihomo", "owner-alice").await?;

        transition_after_stop(false).await?;

        let armed = ARMED.lock().unwrap().clone().expect("must stay armed");
        assert_eq!(armed.intent.mode, KillSwitchStatusMode::Blocked);
        assert!(armed.tun_luid.is_none());
        let on_disk: IntentRecord = serde_json::from_slice(&tokio::fs::read(intent_path()).await?)?;
        assert_eq!(on_disk.mode, KillSwitchStatusMode::Blocked);
        cleanup().await;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn disarm_is_refused_until_dns_restore_is_proven() -> Result<()> {
        cleanup().await;
        arm_bootstrap(&test_config(), "/opt/tono/mihomo", "owner-alice").await?;
        // A corrupt DNS snapshot makes the restore unprovable: the disarm must be refused and
        // the block must stay armed (the macOS DNS-before-disarm invariant).
        atomic_write(&dns_snapshot_path(), b"{ corrupt").await?;

        let error = transition_after_stop(true)
            .await
            .expect_err("disarm must be refused while DNS restore is unproven");
        assert!(format!("{error:#}").contains("corrupt"));
        assert!(
            ARMED.lock().unwrap().is_some(),
            "a refused disarm keeps the block armed"
        );
        assert!(tokio::fs::metadata(intent_path()).await.is_ok());

        // With the snapshot gone there is nothing left to restore, so the same release
        // succeeds and tears everything down.
        tokio::fs::remove_file(dns_snapshot_path()).await?;
        transition_after_stop(true).await?;
        assert!(ARMED.lock().unwrap().is_none());
        assert!(tokio::fs::metadata(intent_path()).await.is_err());
        assert!(!status().await.wanted);
        cleanup().await;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn disarm_succeeds_after_a_proven_dns_restore() -> Result<()> {
        cleanup().await;
        arm_bootstrap(&test_config(), "/opt/tono/mihomo", "owner-alice").await?;
        // A valid, empty snapshot restores trivially (the stubbed engine is a no-op).
        let snapshot = crate::core::dns::DnsSnapshot {
            version: 1,
            taken_at: 1,
            adapters: Vec::new(),
        };
        atomic_write(&dns_snapshot_path(), &serde_json::to_vec_pretty(&snapshot)?).await?;

        transition_after_stop(true).await?;

        assert!(ARMED.lock().unwrap().is_none());
        assert!(tokio::fs::metadata(dns_snapshot_path()).await.is_err());
        assert!(tokio::fs::metadata(intent_path()).await.is_err());
        cleanup().await;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn emergency_disarm_removes_wfp_intent_but_reports_unrestored_dns() -> Result<()> {
        cleanup().await;
        arm_bootstrap(&test_config(), "/opt/tono/mihomo", "owner-alice").await?;
        atomic_write(&dns_snapshot_path(), b"{ corrupt").await?;

        let error = emergency_disarm_windows_kill_switch()
            .await
            .expect_err("unproven DNS restore must fail the uninstall contract");

        let message = format!("{error:#}");
        assert!(message.contains("WFP was removed"), "{message}");
        assert!(message.contains("protected-dns.json"), "{message}");
        assert!(ARMED.lock().unwrap().is_none());
        assert!(
            tokio::fs::metadata(intent_path()).await.is_err(),
            "removed WFP must not be re-armed from a stale intent on reboot"
        );
        assert!(
            tokio::fs::metadata(dns_snapshot_path()).await.is_ok(),
            "failed DNS proof must remain available for retry"
        );
        cleanup().await;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn release_when_armed_disarms_and_reports_status() -> Result<()> {
        cleanup().await;
        arm_bootstrap(&test_config(), "/opt/tono/mihomo", "owner-alice").await?;
        assert!(status().await.wanted);

        let status = release().await?;

        assert!(!status.wanted, "released status reports wanted=false");
        assert!(ARMED.lock().unwrap().is_none());
        assert!(tokio::fs::metadata(intent_path()).await.is_err());
        cleanup().await;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn release_when_not_armed_is_an_idempotent_success() -> Result<()> {
        cleanup().await;

        // The whole point of the route: after a stop the session is gone and possibly the
        // switch was never armed — the explicit release must still succeed.
        let status = release().await?;
        assert!(!status.wanted);
        let again = release().await?;
        assert!(!again.wanted);
        cleanup().await;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn release_when_not_armed_still_attempts_dns_restore_best_effort() -> Result<()> {
        cleanup().await;
        // Nothing armed, but a previous emergency left a corrupt DNS snapshot behind: the
        // release succeeds (the filters are already gone, refusing buys nothing) and the
        // failed restore is surfaced through last_error.
        atomic_write(&dns_snapshot_path(), b"{ corrupt").await?;

        let status = release().await?;

        assert!(!status.wanted);
        let last_error = status
            .last_error
            .expect("an unrestorable snapshot must be reported");
        assert!(
            last_error.contains("could not be restored"),
            "unexpected last_error: {last_error}"
        );
        cleanup().await;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn write_authorization_follows_the_recorded_owner() -> Result<()> {
        cleanup().await;
        // Nothing armed: any authenticated owner may release (it is a no-op).
        authorize_write_for("owner-alice")?;

        arm_bootstrap(&test_config(), "/opt/tono/mihomo", "owner-alice").await?;
        authorize_write_for("owner-alice")?;
        let error = authorize_write_for("owner-bob")
            .expect_err("another local user must not release somebody else's protection");
        assert_eq!(error.code, crate::ServiceErrorCode::NotActive);
        // The intent file itself carries the owner key.
        let on_disk: IntentRecord = serde_json::from_slice(&tokio::fs::read(intent_path()).await?)?;
        assert_eq!(on_disk.owner_key.as_deref(), Some("owner-alice"));

        // A legacy/emergency intent without owner_key releases for any authenticated owner.
        *ARMED.lock().unwrap() = Some(Armed {
            intent: valid_intent(KillSwitchStatusMode::Blocked, true),
            tun_luid: None,
            direct_endpoints: Vec::new(),
        });
        authorize_write_for("owner-bob")?;
        cleanup().await;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn lock_rejects_an_interface_that_was_not_recorded_at_arm_time() -> Result<()> {
        cleanup().await;
        arm_bootstrap(&test_config(), "/opt/tono/mihomo", "owner-alice").await?;

        let error = lock(Some("Ethernet"))
            .await
            .expect_err("locking a physical adapter must be refused");
        assert!(format!("{error:#}").contains("does not match"));
        // Zero side effects: still bootstrap, no LUID recorded.
        let armed = ARMED.lock().unwrap().clone().expect("still armed");
        assert_eq!(armed.intent.mode, KillSwitchStatusMode::Bootstrap);
        assert!(armed.tun_luid.is_none());

        lock(Some("Tono")).await?;
        let armed = ARMED.lock().unwrap().clone().expect("still armed");
        assert_eq!(armed.intent.mode, KillSwitchStatusMode::Locked);
        assert_eq!(armed.tun_luid, Some(0));
        cleanup().await;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn release_is_refused_until_dns_restore_is_proven() -> Result<()> {
        cleanup().await;
        arm_bootstrap(&test_config(), "/opt/tono/mihomo", "owner-alice").await?;
        atomic_write(&dns_snapshot_path(), b"{ corrupt").await?;

        let error = release()
            .await
            .expect_err("release must be refused while DNS restore is unproven");
        assert!(format!("{error:#}").contains("corrupt"));
        assert!(
            ARMED.lock().unwrap().is_some(),
            "a refused release keeps the block armed"
        );
        assert!(tokio::fs::metadata(intent_path()).await.is_ok());

        tokio::fs::remove_file(dns_snapshot_path()).await?;
        let status = release().await?;
        assert!(!status.wanted);
        cleanup().await;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn restored_locked_intent_relocks_after_core_restore() -> Result<()> {
        cleanup().await;
        let intent = valid_intent(KillSwitchStatusMode::Locked, true);
        atomic_write(&intent_path(), &serde_json::to_vec_pretty(&intent)?).await?;

        restore_on_service_start().await?;
        // Downgraded for safety — and marked for re-lock once the core is back.
        assert_eq!(
            ARMED.lock().unwrap().as_ref().unwrap().intent.mode,
            KillSwitchStatusMode::Blocked
        );

        relock_restored_tunnel().await?;
        let armed = ARMED.lock().unwrap().clone().expect("still armed");
        assert_eq!(armed.intent.mode, KillSwitchStatusMode::Locked);
        assert_eq!(armed.tun_luid, Some(0));

        // The marker is consumed: a second call is a no-op and cannot re-lock a
        // restrict-bootstrap that happened in between.
        restrict_bootstrap().await?;
        relock_restored_tunnel().await?;
        assert_eq!(
            ARMED.lock().unwrap().as_ref().unwrap().intent.mode,
            KillSwitchStatusMode::Blocked
        );
        cleanup().await;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn direct_endpoints_are_validated_against_the_wechat_contract() -> Result<()> {
        cleanup().await;
        let base = test_config();

        // Port contract: tcp only 80/443, udp only 443/8000.
        for (port, protocol) in [(22_u16, ProxyProtocol::Tcp), (53, ProxyProtocol::Udp)] {
            let mut config = base.clone();
            config.direct_endpoints = vec![ProxyEndpoint {
                ip: "203.0.113.9".to_owned(),
                port,
                protocol,
            }];
            assert!(
                arm_bootstrap(&config, "/opt/tono/mihomo", "owner-alice")
                    .await
                    .is_err(),
                "accepted port {port}/{protocol:?}"
            );
        }
        // Permanently protected resolvers, private space, and the selected node address
        // itself must never go DIRECT.
        for ip in ["1.1.1.1", "8.8.8.8", "10.0.0.9"] {
            let mut config = base.clone();
            config.direct_endpoints = vec![ProxyEndpoint {
                ip: ip.to_owned(),
                port: 443,
                protocol: ProxyProtocol::Tcp,
            }];
            assert!(
                arm_bootstrap(&config, "/opt/tono/mihomo", "owner-alice")
                    .await
                    .is_err(),
                "accepted {ip}"
            );
        }
        let mut config = base.clone();
        config.proxy_endpoints = vec![ProxyEndpoint {
            ip: "9.9.9.9".to_owned(),
            port: 443,
            protocol: ProxyProtocol::Tcp,
        }];
        config.direct_endpoints = vec![ProxyEndpoint {
            ip: "9.9.9.9".to_owned(),
            port: 443,
            protocol: ProxyProtocol::Tcp,
        }];
        assert!(
            arm_bootstrap(&config, "/opt/tono/mihomo", "owner-alice")
                .await
                .is_err(),
            "accepted the selected node address as DIRECT"
        );

        // The 256-entry bound.
        let mut config = base.clone();
        config.direct_endpoints = (0..257_u32)
            .map(|index| ProxyEndpoint {
                ip: format!("203.0.{}.{}", 113 + index / 256, index % 256),
                port: 443,
                protocol: ProxyProtocol::Tcp,
            })
            .collect();
        assert!(
            arm_bootstrap(&config, "/opt/tono/mihomo", "owner-alice")
                .await
                .is_err(),
            "accepted more than 256 direct endpoints"
        );
        cleanup().await;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn direct_endpoints_live_only_in_the_armed_session_memory() -> Result<()> {
        cleanup().await;
        arm_bootstrap(
            &test_config_with_direct(),
            "/opt/tono/mihomo",
            "owner-alice",
        )
        .await?;
        assert_eq!(
            ARMED
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .direct_endpoints
                .len(),
            2
        );

        // Establish the logical session; while it continues (any mode), the permits stay.
        lock(None).await?;
        mark_verified("owner-alice").await?;
        restrict_bootstrap().await?;
        assert_eq!(
            ARMED
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .direct_endpoints
                .len(),
            2
        );

        // omission = clear: the intent file never carries them, so a service-start restore
        // rebuilds with an empty set (fail-closed until the app's next connect transaction).
        restore_on_service_start().await?;
        assert!(
            ARMED
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .direct_endpoints
                .is_empty()
        );

        // And a later arm that omits them inherits nothing from the previous session.
        release().await?;
        arm_bootstrap(&test_config(), "/opt/tono/mihomo", "owner-alice").await?;
        assert!(
            ARMED
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .direct_endpoints
                .is_empty()
        );
        cleanup().await;
        Ok(())
    }
}
