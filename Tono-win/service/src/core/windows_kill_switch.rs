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

/// The core process instance a tunnel permit was granted for.
///
/// A pid is not an identity — Windows recycles them — so the watchdog's monotonic restart
/// counter rides along: a respawn changes at least one of the two, always.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CoreInstance {
    pid: u32,
    restarts: u32,
}

/// The core running right now, or `None` when none is. Read from the manager's non-blocking
/// snapshot: this is on the WFP writer path (including the once-a-second watchdog tick), which
/// must never queue behind a core start or stop.
async fn current_core_instance() -> Option<CoreInstance> {
    let snapshot = crate::core::manager::status_snapshot_nonblocking().await;
    snapshot.core_pid.map(|pid| CoreInstance {
        pid,
        restarts: snapshot.restart_count,
    })
}

#[derive(Debug, Clone)]
struct Armed {
    intent: IntentRecord,
    tun_luid: Option<u64>,
    /// The core instance `tun_luid` was resolved for, recorded by `lock`. `None` means no
    /// tunnel permit may be rendered at all — see [`tunnel_permit_luid`].
    core_instance: Option<CoreInstance>,
    /// Cloud-approved DIRECT endpoints for this armed session. **omission = clear**: kept
    /// only in memory, never written to `kill-switch.json`, never restored on service start,
    /// never inherited by the next arm. The permits themselves are rendered only while
    /// `Locked` (rule G); keeping the approved set here across a mode change is what lets a
    /// re-lock re-render them without another round trip. Every restore path rebuilds with an
    /// empty set (fail-closed until the app's next connect transaction re-issues them).
    direct_endpoints: Vec<ProxyEndpoint>,
}

/// The LUID the tunnel permit may name this tick, or `None` for the pre-lock policy (no tunnel
/// permit at all — exactly the fail-closed set `lock` replaces).
///
/// The tunnel permit is the widest rule the service ever installs: weight-8, matching only
/// `IP_LOCAL_INTERFACE == luid`, with no protocol, port, or app condition. It is safe only
/// because that LUID belongs to the Wintun adapter of the core this session locked. Nothing in
/// WFP notices when that adapter goes away: a `NET_LUID` is `{NetLuidIndex, IfType}` and
/// `NetLuidIndex` is *reused*, so once the core it was granted for is gone, the next device
/// handed that index would inherit an unconditional permit for everything it carries — and the
/// verify-after-write watchdog would faithfully keep reinstalling it. So the permit lives
/// exactly as long as that core instance: a watchdog respawn, an app-driven restart, or no core
/// at all all fall back to the pre-lock policy and block tunnel traffic until the app locks
/// again, which re-resolves the LUID against the live adapter.
fn tunnel_permit_luid(armed: &Armed, current_core: Option<CoreInstance>) -> Option<u64> {
    let luid = armed.tun_luid?;
    // Fail closed on every ambiguity: an unidentified grant (`None` recorded) never matches,
    // so it can never be revived by a later tick that also cannot identify a core.
    if armed.core_instance.is_some() && armed.core_instance == current_core {
        Some(luid)
    } else {
        None
    }
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

/// The watchdog's sleep between verify-after-write ticks. Named so the staleness budget below
/// can be derived from it instead of restating it.
const WATCHDOG_PERIOD: std::time::Duration = std::time::Duration::from_secs(1);

/// How long a status read may trust the cached verify.
///
/// This is a *staleness* budget, not an optimism budget: a verify that actually fails writes
/// `note_verify(false)` and `live` goes false on the next read regardless of the TTL. What the
/// TTL decides is only whether "no fresh answer yet" reads as dead — and that has to allow for
/// how long a **successful** tick can legitimately take.
///
/// One refresh interval is `WATCHDOG_PERIOD` (1 s) plus the verify itself, which is one
/// `FwpmFilterGetByKey0` RPC to BFE per expected filter — 30-60 round trips. This module
/// already declares how slow that is allowed to get while still being a success:
/// `WFP_SLOW_CALL` (2 s) is "pathological but reportable", not "failed"; the failure budget is
/// `WFP_CALL_TIMEOUT` (25 s). At the old 1.5 s the cache expired *before* a merely slow tick
/// could refresh it, so a healthy machine reported `live: false` — which the app reads as
/// unhealthy — purely because BFE was busy.
///
/// So the floor is `WATCHDOG_PERIOD + WFP_SLOW_CALL` = 3 s, and the budget is that plus one
/// more period-and-slow-call of headroom for a tick that also had to queue behind another
/// writer on `WFP_OPERATION`: **5 s**. It stays far below `WFP_CALL_TIMEOUT`, so an engine that
/// is genuinely wedged — the case where no answer ever arrives — still reads dead within five
/// seconds, well inside the app's own reconnect budget.
const VERIFY_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(5);

/// Stable, App-mappable marker for "the WFP engine stopped answering". The App keys its i18n
/// off prefixes like `TONO_SERVICE_BUSY` by substring, and every handler wraps this message in
/// its own context ("Failed to arm Windows kill switch: …"), so the marker has to survive
/// anywhere inside the string rather than only at its start.
#[cfg_attr(not(any(all(windows, not(feature = "test")), test)), allow(dead_code))]
pub(crate) const WFP_ENGINE_WEDGED_PREFIX: &str = "TONO_WFP_ENGINE_WEDGED";
/// Stable, App-mappable marker for "the Base Filtering Engine is not running". Separate from
/// the wedge marker because the user action differs: start BFE versus reboot the machine.
#[cfg_attr(not(all(windows, not(feature = "test"))), allow(dead_code))]
pub(crate) const BFE_NOT_RUNNING_PREFIX: &str = "TONO_BFE_NOT_RUNNING";
/// Stable marker for "the DNS module did not come back", so a stalled resolver restore is
/// distinguishable in the log and in `last_error` from a DNS restore that ran and failed.
const DNS_RESTORE_STALLED_PREFIX: &str = "TONO_DNS_RESTORE_STALLED";

/// Budget for the cross-module DNS awaits taken on the WFP writer path (`bounded_dns_call`).
/// A DNS restore is two PowerShell batches (10 s each), a live read-back and a cache flush, so
/// the module's own worst case fits inside this and the bound only fires on a genuine stall. It
/// also stays under the IPC handler's 60 s budget, so the refusal still reaches the client.
const DNS_RESTORE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(40);

/// Budget for the uninstall-only DNS escalation ladder (`dns::restore_for_uninstall`), which is
/// up to two full restore rounds back to back — the exact restore, then the automatic (DHCP)
/// fallback — plus their read-backs. Reusing [`DNS_RESTORE_TIMEOUT`] would cut the ladder off
/// somewhere inside rung 2 on a merely slow machine and report "no evidence" for work that was
/// still making progress, which is the one input that lands on the blocking rung. It stays well
/// under the installer's `/TIMEOUT=180000` for the whole helper (`installer.nsi`,
/// `RemoveVergeService`), which also has to cover stopping the service.
const UNINSTALL_DNS_RESTORE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(100);

/// Environment variable by which the uninstaller opts *its own process* into the DNS escalation
/// ladder (`dns::restore_for_uninstall`).
///
/// The ladder trades exact DNS fidelity for a machine that can actually be uninstalled. That
/// trade is only correct when the product is being removed, so it must not be reachable from
/// anything else that calls this entry point — in particular not from
/// `tono-service.exe --emergency-disarm`, the Start-Menu "Restore Network" recovery, whose job
/// is to put the user's *own* servers back on a machine that is staying installed.
///
/// An in-process environment variable rather than a parameter because the uninstaller is a
/// separate binary linking this library and this is the exported entry point it has; the
/// variable is set by `uninstall_service.rs` in its own process image immediately before the
/// call, so it can never leak into a service or App process.
pub(crate) const UNINSTALL_LADDER_ENV: &str = "TONO_UNINSTALL_DNS_LADDER";

/// Whether the calling process asked for the uninstall ladder. Absent, empty or anything other
/// than `1` means no: an unrecognised value must fall back to the strict path.
fn uninstall_ladder_requested() -> bool {
    std::env::var_os(UNINSTALL_LADDER_ENV).is_some_and(|value| value == "1")
}

fn note_verify(ok: bool) {
    *LAST_VERIFY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((std::time::Instant::now(), ok));
}

/// Poison must never turn a past panic into a permanent Service freeze. These three accessors
/// recover the guard contents so status, startup restore, every mutation *and the watchdog*
/// keep working while `WFP_OPERATION` re-serializes the next write.
///
/// They are the only way this module takes these locks. A bare `.lock().unwrap()` on the
/// watchdog path would be the worst of the lot: the tick would panic inside `tokio::spawn`,
/// the task would die with its `JoinHandle` — nothing restarts it — and the verify-after-write
/// reconciliation plus the `LAST_VERIFY` refresh that `status()` reports liveness from would be
/// silently gone for the life of the process.
fn armed_guard() -> std::sync::MutexGuard<'static, Option<Armed>> {
    ARMED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Return the live tunnel identity that the current core instance is actually permitted to use.
/// DNS recovery uses this to ignore Tono's own WinTUN adapter while still treating the same
/// protected resolver on every physical adapter as an orphaned, fail-closed state. Re-validating
/// the recorded LUID against the running core is essential because Windows can reuse LUID indices.
pub(crate) async fn protected_tunnel_luid() -> Option<u64> {
    let current_core = current_core_instance().await;
    armed_guard()
        .as_ref()
        .and_then(|armed| tunnel_permit_luid(armed, current_core))
}

fn last_error_guard() -> std::sync::MutexGuard<'static, Option<String>> {
    LAST_ERROR
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn last_verify_guard() -> std::sync::MutexGuard<'static, Option<(std::time::Instant, bool)>> {
    LAST_VERIFY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// How `status()` turns the cached verify into `live`, as a pure function of the cache.
///
/// Two things it deliberately does *not* do: it never reports a verify that actually failed as
/// live (`ok` is a conjunct, not a fallback), and it never reports "no verify has ever run" as
/// live. The only thing [`VERIFY_CACHE_TTL`] buys is that a **successful but slow** tick does
/// not read as dead in the gap before it lands.
fn verify_reads_live(last_verify: Option<(std::time::Instant, bool)>) -> bool {
    last_verify.is_some_and(|(at, ok)| ok && at.elapsed() < VERIFY_CACHE_TTL)
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

/// A durable record that means an explicit release won and startup must finish removing any
/// provider-scoped WFP debris before it exposes IPC.
///
/// Keeping this record until the next Service start closes a subtle replacement race. A normal
/// release used to delete `kill-switch.json` after proving the filters absent. On this machine,
/// stopping that otherwise-clean Service during an in-place update made persistent filters
/// visible again. The replacement then saw "missing intent + filters" and correctly (but
/// disastrously for a disconnected user) installed the ownerless emergency block. `wanted:false`
/// is the existing, fail-open recovery contract; the next arm atomically replaces it with a
/// wanted record before touching WFP, and startup consumes it only after cleanup.
fn disarmed_tombstone() -> IntentRecord {
    IntentRecord {
        wanted: false,
        mode: KillSwitchStatusMode::Blocked,
        verified: Some(false),
        tunnel_interface: String::new(),
        app_path: String::new(),
        endpoints: Vec::new(),
        api_host_ips: Vec::new(),
        updated_at: now_unix(),
        owner_key: None,
    }
}

async fn persist_disarmed_tombstone() -> Result<()> {
    atomic_write(
        &intent_path(),
        &serde_json::to_vec_pretty(&disarmed_tombstone())?,
    )
    .await
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
        // The app-scoped permit is resolved from this path, and the model emits an app-id rule
        // whenever an endpoint permit exists. An empty path would therefore make every install
        // from this record fall back to "block installed, endpoint permit missing" forever; a
        // truncated record is instead an unusable *wanted* intent (emergency block below).
        && !intent.app_path.is_empty()
        && !intent.endpoints.is_empty()
        && intent
            .endpoints
            .iter()
            .all(|endpoint| wfp_model::parse_endpoint(endpoint).is_some())
}

/// The rule model's view of an armed session, given who the running core is. Pure, so the
/// tunnel-permit lifetime rule is testable without a core.
fn rule_config_for(armed: &Armed, current_core: Option<CoreInstance>) -> RuleConfig {
    RuleConfig {
        mode: armed.intent.mode,
        endpoints: armed.intent.endpoints.clone(),
        api_host_ips: armed
            .intent
            .api_host_ips
            .iter()
            .filter_map(|ip| ip.parse::<IpAddr>().ok())
            .collect(),
        tun_luid: tunnel_permit_luid(armed, current_core),
        app_path: armed.intent.app_path.clone(),
        direct_endpoints: armed.direct_endpoints.clone(),
    }
}

/// Whether the last render had to drop an orphaned tunnel permit. Only the transitions are
/// logged: the watchdog renders once a second, and a silently blocked tunnel is the one
/// outcome of this rule that needs evidence in the service log.
static TUNNEL_PERMIT_ORPHANED: AtomicBool = AtomicBool::new(false);

/// Whether the **last render** actually put the tunnel permit in the expected set.
///
/// Reported as `KillSwitchStatus::tunnel_permit_rendered`. `mode: Locked` alone cannot say
/// this: a locked session whose permit was retracted (a core respawn, or a `core_instance` that
/// could not be identified at lock time) is byte-for-byte identical on the wire to a locked
/// session that is carrying traffic, while every application on the machine has its traffic
/// dropped leaving the TUN. This is what makes the two distinguishable to the app.
static TUNNEL_PERMIT_RENDERED: AtomicBool = AtomicBool::new(false);

/// The rule model's view of an armed session for a core identity the caller has **already
/// read**.
///
/// Threading the value in is the point: `lock` records `armed.core_instance` and then renders
/// from it in the same breath, and the two must be the same read. `current_core_instance` goes
/// through `status_snapshot_nonblocking`, which falls back to a cache whenever the core manager
/// is busy, so two reads a few microseconds apart can legitimately disagree. When they did, the
/// recorded instance was the stale one (typically `None`) and the rendered one was the truth:
/// `tunnel_permit_luid` then refused the permit for ever — an unidentified grant is
/// unrevivable by design — and the machine sat at `mode: Locked, live: true, verified: true`
/// with no tunnel permit at all, dropping every application's traffic while every health check
/// passed. One read, threaded through, cannot disagree with itself.
fn rule_config_rendering(armed: &Armed, current_core: Option<CoreInstance>) -> RuleConfig {
    let config = rule_config_for(armed, current_core);
    TUNNEL_PERMIT_RENDERED.store(config.tun_luid.is_some(), Ordering::Relaxed);
    let orphaned = armed.tun_luid.is_some() && config.tun_luid.is_none();
    if orphaned != TUNNEL_PERMIT_ORPHANED.swap(orphaned, Ordering::Relaxed) {
        if orphaned {
            tracing::warn!(
                "wfp: the tunnel permit was granted for a core instance that is no longer \
                 running; falling back to the pre-lock policy, so tunnel traffic stays blocked \
                 until the app locks again"
            );
        } else {
            tracing::info!("wfp: the tunnel permit matches the running core again");
        }
    }
    config
}

/// Budget for one WFP call. A healthy transaction is milliseconds and the surrounding IPC
/// handler budget is `IPC_HANDLER_TIMEOUT` = 60 s, so 25 s is three orders of magnitude beyond
/// "slow but alive" while still leaving the handler more than half its budget to answer the
/// client. Because the first expiry latches the in-flight claim (see below), every later call
/// in the same handler fails immediately — one handler can therefore stall for at most one
/// budget, no matter how many engine calls its path makes.
#[cfg(all(windows, not(feature = "test")))]
const WFP_CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(25);
/// Anything slower than this is already pathological: report it even for the once-a-second
/// verify, so the log carries evidence of a degrading BFE before it wedges completely.
#[cfg(any(all(windows, not(feature = "test")), test))]
const WFP_SLOW_CALL: std::time::Duration = std::time::Duration::from_secs(2);
/// The BFE probe is an SCM query, not a WFP RPC: it exists only to name the cause, so it gets
/// a short budget and never delays an engine call for long.
#[cfg(all(windows, not(feature = "test")))]
const BFE_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// A WFP call that was handed to a blocking thread and has not come back yet.
///
/// Registered *before* the thread is spawned and released *only* by that thread — never by the
/// caller. That asymmetry is the whole single-writer argument: a caller that hits its deadline
/// gives up on the *answer*, not on the *ownership*.
#[cfg(any(all(windows, not(feature = "test")), test))]
#[derive(Debug, Clone, Copy)]
struct EngineCallInFlight {
    operation: &'static str,
    started_at: std::time::Instant,
    /// Epoch of this call. The releasing guard only clears its own epoch, so a call that
    /// returns very late can never erase the claim of a call that started after it.
    epoch: u64,
    /// Its caller already timed out and reported failure; the result is discarded on arrival.
    abandoned: bool,
}

#[cfg(any(all(windows, not(feature = "test")), test))]
static ENGINE_CALL_IN_FLIGHT: Lazy<Mutex<Option<EngineCallInFlight>>> =
    Lazy::new(|| Mutex::new(None));
#[cfg(any(all(windows, not(feature = "test")), test))]
static ENGINE_CALL_EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(any(all(windows, not(feature = "test")), test))]
fn engine_call_slot() -> std::sync::MutexGuard<'static, Option<EngineCallInFlight>> {
    ENGINE_CALL_IN_FLIGHT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(any(all(windows, not(feature = "test")), test))]
fn engine_call_in_flight() -> Option<EngineCallInFlight> {
    *engine_call_slot()
}

/// Refusal for a caller that wants to start an engine call while an earlier one is still
/// inside the kernel. Honest and fail-closed: nothing is installed, nothing is removed, and
/// the machine keeps whatever policy the last completed call left behind.
#[cfg(any(all(windows, not(feature = "test")), test))]
fn wedged_engine_error(operation: &str, wedged: EngineCallInFlight) -> anyhow::Error {
    anyhow::anyhow!(
        "{WFP_ENGINE_WEDGED_PREFIX}: the WFP engine has been inside {} for {:?} without \
         returning, so {operation} is refused rather than started as a second concurrent \
         writer. The Base Filtering Engine (BFE) is likely wedged or hooked by third-party \
         security software; protection stays in its last known state until that call returns \
         or the machine is restarted.",
        wedged.operation,
        wedged.started_at.elapsed(),
    )
}

/// Dropped on the blocking thread the instant the kernel call returns — on time, or hours
/// late. This is the *only* place an in-flight claim is released, and it releases only its own
/// epoch.
#[cfg(any(all(windows, not(feature = "test")), test))]
struct EngineCallClaim(u64);

#[cfg(any(all(windows, not(feature = "test")), test))]
impl Drop for EngineCallClaim {
    fn drop(&mut self) {
        let mut slot = engine_call_slot();
        let Some(current) = *slot else { return };
        if current.epoch != self.0 {
            return;
        }
        *slot = None;
        if current.abandoned {
            // The caller reported failure long ago; this is the log line that says the engine
            // is alive again. The call's own result was dropped with its `JoinHandle`, so it
            // cannot contradict what was already reported.
            tracing::error!(
                "wfp: {} finally returned after {:?}; its caller had already given up, the \
                 result is discarded, and WFP operations are accepted again",
                current.operation,
                current.started_at.elapsed(),
            );
        }
    }
}

/// The watchdog verifies once a second: only the rare, mutating operations may announce
/// themselves at info, or the service log would carry a line per second forever.
#[cfg(any(all(windows, not(feature = "test")), test))]
fn engine_call_is_periodic(operation: &str) -> bool {
    operation == "verify"
}

/// Run one engine operation on a blocking thread under a hard deadline, holding the
/// single-writer claim described on [`EngineCallInFlight`].
///
/// Engine calls are synchronous WFP RPCs, so they run off the (possibly single-threaded) IPC
/// runtime — a slow BFE must not freeze request handling (the DNS engine does the same). They
/// are also bounded, because on a real machine a wedged or hooked Base Filtering Engine can
/// make an `Fwpm*` call block forever and `spawn_blocking` cannot be cancelled: the thread
/// keeps running whatever the caller does.
///
/// Single-writer argument for the timeout path:
/// * the claim is registered *before* the thread is spawned and released only by that thread,
///   in `EngineCallClaim::drop`, when the kernel call actually returns;
/// * a caller that hits its deadline returns an error and leaves the claim standing, so every
///   later engine call — this handler's, the next handler's, the watchdog's — fails fast here
///   instead of opening a concurrent WFP transaction;
/// * the abandoned task can publish nothing: it only calls pure `wfp::*` FFI, its return value
///   dies with the `JoinHandle` the deadline dropped, and its claim release is keyed to its own
///   epoch, so it cannot clear a claim taken by a later call.
///
/// The machinery is compiled off Windows too, so those ownership rules stay unit-testable;
/// only the `Fwpm*` closures handed to it are Windows-only.
#[cfg(any(all(windows, not(feature = "test")), test))]
async fn bounded_engine_call<T: Send + 'static>(
    budget: std::time::Duration,
    operation: &'static str,
    call: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    let epoch = {
        let mut slot = engine_call_slot();
        if let Some(wedged) = *slot {
            return Err(wedged_engine_error(operation, wedged));
        }
        let epoch = ENGINE_CALL_EPOCH.fetch_add(1, Ordering::AcqRel);
        *slot = Some(EngineCallInFlight {
            operation,
            started_at: std::time::Instant::now(),
            epoch,
            abandoned: false,
        });
        epoch
    };
    let announce = !engine_call_is_periodic(operation);
    if announce {
        tracing::info!("wfp: {operation} starting");
    } else {
        tracing::debug!("wfp: {operation} starting");
    }
    let started_at = std::time::Instant::now();
    let task = tokio::task::spawn_blocking(move || {
        // Local, so it drops (releasing the claim) after `call` returns and before the result
        // reaches the awaiting caller.
        let _claim = EngineCallClaim(epoch);
        call()
    });
    match tokio::time::timeout(budget, task).await {
        Ok(joined) => {
            let elapsed = started_at.elapsed();
            if elapsed >= WFP_SLOW_CALL {
                tracing::warn!(
                    "wfp: {operation} finished in {}ms — the engine is answering, but far slower \
                     than a healthy transaction",
                    elapsed.as_millis()
                );
            } else if announce {
                tracing::info!("wfp: {operation} finished in {}ms", elapsed.as_millis());
            } else {
                tracing::debug!("wfp: {operation} finished in {}ms", elapsed.as_millis());
            }
            joined.context("WFP engine task failed")?
        }
        Err(_) => {
            // Claim the abandonment by epoch instead of writing the slot: the call may have
            // returned in the instant between the deadline and this line, in which case its
            // guard already cleared the slot and nothing is wedged.
            let still_running = {
                let mut slot = engine_call_slot();
                match slot.as_mut() {
                    Some(current) if current.epoch == epoch => {
                        current.abandoned = true;
                        true
                    }
                    _ => false,
                }
            };
            if still_running {
                tracing::error!(
                    "wfp: {operation} did not return within {budget:?} and is still inside the \
                     kernel; every further WFP operation fails fast until it returns"
                );
            } else {
                tracing::error!(
                    "wfp: {operation} returned just after its {budget:?} deadline; its result was \
                     discarded and the caller was told it failed"
                );
            }
            bail!(
                "{WFP_ENGINE_WEDGED_PREFIX}: WFP engine did not answer within {budget:?} during \
                 {operation}; the Base Filtering Engine (BFE) may be wedged or blocked by \
                 third-party security software. Protection was left in its last known state and \
                 no further WFP operation starts until the pending call returns."
            )
        }
    }
}

/// Whether the BFE probe still has anything to say. Set once it answered "Running" or proved
/// unanswerable; a conclusive "not Running" leaves it clear so the next attempt re-probes.
#[cfg(all(windows, not(feature = "test")))]
static BFE_PROBE_SETTLED: AtomicBool = AtomicBool::new(false);

/// Every `Fwpm*` call is an RPC to the Base Filtering Engine, which this service already
/// declares as a start dependency (`install_service.rs`). Probe it once before the first
/// engine open: a stopped BFE is the difference between "WFP is slow" and "WFP will never
/// answer", and naming it turns an indefinite block into an actionable error.
///
/// Only a conclusive "not Running" is fatal, and that answer is deliberately not cached, so a
/// BFE that starts late recovers on the watchdog's next tick. Everything inconclusive (SCM
/// unreachable, probe itself too slow) is diagnostics we do not have: warn once, settle, and
/// let the now-bounded engine call speak for itself.
#[cfg(all(windows, not(feature = "test")))]
async fn ensure_bfe_running() -> Result<()> {
    if BFE_PROBE_SETTLED.load(Ordering::Acquire) {
        return Ok(());
    }
    let probe = tokio::time::timeout(
        BFE_PROBE_TIMEOUT,
        tokio::task::spawn_blocking(crate::core::wfp::bfe_service_state),
    )
    .await;
    let inconclusive = match probe {
        Ok(Ok(Ok((true, state)))) => {
            tracing::info!("wfp: Base Filtering Engine reports {state}");
            BFE_PROBE_SETTLED.store(true, Ordering::Release);
            return Ok(());
        }
        Ok(Ok(Ok((false, state)))) => {
            bail!(
                "{BFE_NOT_RUNNING_PREFIX}: the Base Filtering Engine (BFE) service is {state}, \
                 not Running, so no WFP rule can be installed or removed. Start it from an \
                 elevated prompt (`sc start BFE`) or restart the machine, then retry; \
                 third-party security software is the usual reason it is stopped."
            );
        }
        Ok(Ok(Err(error))) => format!("{error:#}"),
        Ok(Err(error)) => format!("probe task failed: {error}"),
        Err(_) => format!("probe exceeded {BFE_PROBE_TIMEOUT:?}"),
    };
    tracing::warn!(
        "wfp: could not read the Base Filtering Engine service state ({inconclusive}); \
         continuing with bounded engine calls"
    );
    BFE_PROBE_SETTLED.store(true, Ordering::Release);
    Ok(())
}

/// The single door to the WFP engine: BFE diagnostics, then a bounded, single-writer call.
#[cfg(all(windows, not(feature = "test")))]
async fn engine_call<T: Send + 'static>(
    operation: &'static str,
    call: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    // The wedge check comes first: while an earlier call is still inside the kernel, nothing
    // BFE reports about itself changes the answer, and the refusal must stay instant.
    if let Some(wedged) = engine_call_in_flight() {
        return Err(wedged_engine_error(operation, wedged));
    }
    ensure_bfe_running().await?;
    bounded_engine_call(WFP_CALL_TIMEOUT, operation, call).await
}

async fn install_unlocked(armed: &Armed) -> Result<()> {
    install_unlocked_for(armed, current_core_instance().await).await
}

/// [`install_unlocked`] for a caller that has already read the core identity and must render
/// from *that* read — see [`rule_config_rendering`]. `lock` is the only such caller, and it is
/// the one where a second, disagreeing read is terminal.
async fn install_unlocked_for(armed: &Armed, current_core: Option<CoreInstance>) -> Result<()> {
    let expected = wfp_model::expected_filters(&rule_config_rendering(armed, current_core));
    #[cfg(all(windows, not(feature = "test")))]
    {
        let app_path = armed.intent.app_path.clone();
        let result = engine_call("install", move || {
            crate::core::wfp::install(&expected, &app_path)
        })
        .await;
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
    let expected =
        wfp_model::expected_filters(&rule_config_rendering(armed, current_core_instance().await));
    #[cfg(all(windows, not(feature = "test")))]
    {
        engine_call("verify", move || crate::core::wfp::verify(&expected)).await
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
        engine_call("remove all filters", crate::core::wfp::remove_all_filters).await
    }
    #[cfg(not(all(windows, not(feature = "test"))))]
    {
        Ok(())
    }
}

/// Upgrade/migration sweep: remove sublayers left by older builds (filters included). Must
/// run strictly *after* the current expected set is committed (or all filters were removed
/// on purpose): an older build's PERSISTENT block-all pair may be the only protection at
/// boot after an upgrade reboot, and deleting it before the replacement floor is live would
/// open a zero-filter window. Best-effort — a failed sweep leaves extra blocking, never less.
async fn sweep_legacy_sublayers_unlocked() {
    #[cfg(all(windows, not(feature = "test")))]
    if let Err(error) = engine_call(
        "legacy sublayer sweep",
        crate::core::wfp::remove_legacy_sublayers,
    )
    .await
    {
        tracing::warn!("legacy WFP sublayer cleanup failed: {error:#}");
    }
}

fn record_outcome(result: Result<()>) -> Result<()> {
    match result {
        Ok(()) => {
            *last_error_guard() = None;
            Ok(())
        }
        Err(error) => {
            *last_error_guard() = Some(format!("{error:#}"));
            Err(error)
        }
    }
}

/// The bootstrap API channel's destinations, admitted from what the client supplied.
///
/// **Literal IPs only — the service never resolves a name here.** Resolving one would mean the
/// answer picks the permit: the app looks the API host up through the system resolver *before*
/// the barrier arms, so a hostile DHCP resolver, a captive portal or an on-path spoofer would
/// choose up to [`wfp_model::MAX_API_HOST_IPS`] of the destinations this service then punches
/// through its own block — and "public and unreserved" is the only thing that check could ever
/// prove about the answer, because nothing here binds it to an expected host or a pin. The
/// client already pins literals for exactly this reason (its own recovery path must survive a
/// poisoned resolver), so nothing is lost: a non-literal entry is dropped, never looked up.
///
/// Order is the caller's, so the sanitizer's first-wins dedup and cap keep favouring earlier
/// hosts; everything is funnelled through the model's public-only, bounded sanitizer.
fn admit_api_host_ips(hosts: &[String]) -> Vec<IpAddr> {
    let mut literals = Vec::new();
    for host in hosts.iter().take(16) {
        let host = host.trim();
        if host.is_empty() {
            continue;
        }
        match host.parse::<IpAddr>() {
            Ok(ip) => literals.push(ip),
            Err(_) => tracing::warn!(
                "kill-switch API host {host:?} is not a literal IP and is dropped; the service \
                 does not resolve names into WFP permits"
            ),
        }
    }
    wfp_model::sanitize_api_host_ips(literals)
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
    let api_host_ips = admit_api_host_ips(&config.bootstrap_api_hosts);
    let _operation = WFP_OPERATION.lock().await;
    let inherited_verified = armed_guard().as_ref().is_some_and(|armed| {
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
        core_instance: None,
        // In memory only — the intent file deliberately never carries these (omission = clear).
        direct_endpoints: config.direct_endpoints.clone(),
    };
    // Persist fail-closed intent before touching WFP: a daemon restart installs at least the
    // floor if this process dies during the following transaction.
    atomic_write(&intent_path(), &serde_json::to_vec_pretty(&armed.intent)?).await?;
    *armed_guard() = Some(armed.clone());
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
    *armed_guard() = Some(armed);
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
    let recorded = { armed_guard().clone() }.and_then(|armed| armed.intent.owner_key);
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
        engine_call("tunnel LUID lookup", move || {
            crate::core::wfp::luid_for_interface(&name)
        })
        .await
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
///
/// The grant is recorded against the core instance running when it is made: a LUID names an
/// adapter that belongs to that core, and [`tunnel_permit_luid`] retracts the permit the moment
/// that core is replaced or gone. Locking again — the app's job — is what re-grants it.
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
    // Read the core identity *before* resolving the LUID: a core replaced in between makes the
    // recorded instance stale rather than falsely current, so the next render retracts the
    // permit instead of handing it to an adapter the new core did not create.
    //
    // Read it exactly **once**. This value is both persisted into `armed.core_instance` and
    // handed to the render below; a second read for the render could disagree with it (the
    // snapshot behind `current_core_instance` falls back to a cache while the core manager is
    // busy), and a disagreement here is terminal — see `rule_config_rendering`.
    let core_instance = current_core_instance().await;
    let luid = resolve_luid(&recorded).await?;
    armed.tun_luid = Some(luid);
    armed.core_instance = core_instance;
    if core_instance.is_none() {
        // Not fatal — the permit is simply not rendered and the tunnel stays blocked until the
        // app locks again — but it is invisible in `mode` alone, so it has to be in the log as
        // well as in `tunnel_permit_rendered`.
        tracing::warn!(
            "wfp: locking without an identifiable core instance; the tunnel permit will not be \
             rendered and tunnel traffic stays blocked until the app locks again"
        );
    }
    armed.intent.mode = KillSwitchStatusMode::Locked;
    armed.intent.updated_at = now_unix();
    // Update live WFP first (the macOS helper's add_tunnel ordering): if this fails, the
    // previous bootstrap rules remain effective and the persisted intent restores them after
    // a crash. Rendered from the same `core_instance` that was just recorded, never a re-read.
    install_unlocked_for(&armed, core_instance).await?;
    atomic_write(&intent_path(), &serde_json::to_vec_pretty(&armed.intent)?).await?;
    *armed_guard() = Some(armed);
    *last_error_guard() = None;
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
    // The grant goes with the LUID: a later lock must re-establish both.
    armed.core_instance = None;
    armed.intent.updated_at = now_unix();
    // Persist first so a crash at any later point restores the stricter block (macOS parity).
    atomic_write(&intent_path(), &serde_json::to_vec_pretty(&armed.intent)?).await?;
    *armed_guard() = Some(armed.clone());
    record_outcome(install_unlocked(&armed).await)
}

pub(crate) async fn restrict_bootstrap() -> Result<()> {
    ensure_supported()?;
    let _operation = WFP_OPERATION.lock().await;
    restrict_bootstrap_unlocked().await
}

/// Bound a cross-module DNS await taken while `WFP_OPERATION` is held.
///
/// `dns::ensure_restored` / `dns::restore_protected` are the only awaits on the WFP writer path
/// that leave this module, and the operation lock is held across them. Without a bound here a
/// stalled DNS engine holds `WFP_OPERATION` forever, so *every* WFP operation — arm, lock,
/// restrict, verify, release, emergency disarm — queues behind it and the machine stays
/// fail-closed with no way to open it short of a reboot. `dns.rs` bounds itself as well; this is
/// the defensive half, because the liveness of this module's writer lock must not depend on
/// another module's discipline.
///
/// The bound may only convert an infinite hang into a clean failure; it is never a way to skip
/// the DNS proof. Callers treat the timeout exactly like any other unprovable restore, so on the
/// disarm/release path the filters stay installed and the barrier stays armed — a timeout can
/// never open the network while DNS may still point at a dead loopback resolver. Cancelling the
/// restore (the timeout drops the future) is safe for the same reason: `restore_protected`
/// deletes its snapshot only *after* the restore is proven, so a cancelled attempt leaves the
/// evidence — and the block — exactly where a failed attempt would, ready for the next retry.
async fn bounded_dns_call<T>(
    operation: &str,
    call: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    bounded_dns_call_within(DNS_RESTORE_TIMEOUT, operation, call).await
}

/// The budget is a parameter for the same reason `bounded_engine_call` takes one: the ownership
/// and refusal rules are what matter and they must stay unit-testable without waiting out the
/// production budget.
async fn bounded_dns_call_within<T>(
    budget: std::time::Duration,
    operation: &str,
    call: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    match tokio::time::timeout(budget, call).await {
        Ok(result) => result,
        Err(_) => {
            tracing::error!(
                "dns: restore did not return within {budget:?} during {operation} while the WFP \
                 operation lock was held; the attempt is dropped so the lock is released, and \
                 {operation} is refused"
            );
            bail!(
                "{DNS_RESTORE_STALLED_PREFIX}: DNS restore did not answer within {budget:?} \
                 during {operation}, so it could not be proven. Protection stays in its last \
                 known state; retry once the resolver settles."
            )
        }
    }
}

/// Normal release — only on explicit user request. See the DNS-before-disarm invariant.
async fn disarm_unlocked() -> Result<()> {
    let previous = armed_guard().clone();
    let Some(previous) = previous else {
        // Not armed: still sweep possible residuals so a half-failed earlier run cannot
        // linger. Persist the explicit-release tombstone *after* proving the sweep so a Service
        // replacement cannot reinterpret late-visible persistent filters as a wanted session.
        remove_all_filters_unlocked().await?;
        persist_disarmed_tombstone().await?;
        // A leftover DNS snapshot must not be skipped just because nothing is armed: the
        // filters are already gone, so refusing would buy no blocking — but the resolver
        // must not stay on a dead loopback. Best-effort, surfaced via last_error.
        if let Err(error) = bounded_dns_call(
            "release without an armed switch",
            crate::core::dns::ensure_restored(),
        )
        .await
        {
            *last_error_guard() = Some(format!(
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
    //
    // The bound below does not weaken that: a timeout is an *unproven* restore, and `?` fails
    // the disarm on it exactly like a restore that ran and failed, so the filters below are
    // never reached and the barrier stays armed. It only stops another module's stall from
    // holding `WFP_OPERATION` — and therefore every future arm/lock/release — forever.
    bounded_dns_call("disarm", crate::core::dns::ensure_restored()).await?;
    if let Err(error) = remove_all_filters_unlocked().await {
        let _ = install_unlocked(&previous).await;
        return Err(error.context("failed to remove kill-switch filters; protection restored"));
    }
    if let Err(error) = persist_disarmed_tombstone().await {
        // The old wanted intent is still the only durable recovery evidence if writing the
        // replacement tombstone failed. Put it back before reinstalling the previous policy;
        // otherwise a later Service restart could open a release that this call reports failed.
        let restore_intent = atomic_write(
            &intent_path(),
            &serde_json::to_vec_pretty(&previous.intent)?,
        )
        .await;
        let restore_filters = install_unlocked(&previous).await;
        restore_intent.context(
            "network opened and the disarmed tombstone could not be written; failed to restore the wanted intent",
        )?;
        restore_filters.context(
            "network opened and the disarmed tombstone could not be written; failed to restore protection",
        )?;
        return Err(error)
            .context("network opened but the disarmed tombstone could not be written");
    }
    *armed_guard() = None;
    *last_error_guard() = None;
    TUNNEL_PERMIT_RENDERED.store(false, Ordering::Relaxed);
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
    if armed_guard().is_none() {
        return Ok(());
    }
    if release_requested {
        return disarm_unlocked().await;
    }
    restrict_bootstrap_unlocked().await
}

/// The ownerless emergency block ("damaged/unknown state = armed"): strict Blocked, no app
/// or endpoint permits, marked verified so startup recovery never retires it as stale. The
/// missing `owner_key` is the documented escape hatch — any authenticated owner may release
/// it (see `authorize_write_for`).
fn emergency_armed() -> Armed {
    Armed {
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
        core_instance: None,
        direct_endpoints: Vec::new(),
    }
}

/// Service-start recovery (design doc §3): read the intent record and reconcile.
///
/// Ordering invariant: the intent is reconciled and the current expected filter set is
/// installed *before* the legacy-sublayer upgrade sweep runs. Across an upgrade reboot an
/// older build's PERSISTENT block-all pair may be the only protection on the machine;
/// sweeping it away before the replacement floor is committed would open a zero-filter
/// window at boot — and leave the machine open for good if the reconcile then failed.
/// `install` itself swaps legacy filters for the current set in a single transaction, so
/// the sweep afterwards only clears the emptied legacy sublayer objects.
pub async fn restore_on_service_start() -> Result<()> {
    if !SUPPORTED {
        return Ok(());
    }
    let _operation = WFP_OPERATION.lock().await;
    RESTORE_WAS_LOCKED.store(false, Ordering::Release);
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
                        core_instance: None,
                        direct_endpoints: Vec::new(),
                    };
                    armed.intent.mode = KillSwitchStatusMode::Blocked;
                    armed.intent.updated_at = now_unix();
                    atomic_write(&intent_path(), &serde_json::to_vec_pretty(&armed.intent)?)
                        .await?;
                    *armed_guard() = Some(armed.clone());
                    let installed = record_outcome(install_unlocked(&armed).await);
                    if installed.is_ok() {
                        sweep_legacy_sublayers_unlocked().await;
                    }
                    return installed;
                }
                let mut armed = Armed {
                    intent,
                    tun_luid: None,
                    // A restored intent never inherits a tunnel grant: the adapter, and the core
                    // that created it, belong to a process that is gone.
                    core_instance: None,
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
                *armed_guard() = Some(armed.clone());
                let installed = record_outcome(install_unlocked(&armed).await);
                if installed.is_ok() {
                    sweep_legacy_sublayers_unlocked().await;
                }
                installed
            }
            // `wanted == false` is the *only* parseable record that may disarm the machine. The
            // guard above rejects a record for several reasons besides that one — an empty
            // interface, no endpoints, an endpoint the model no longer parses after a
            // validation tightening — and every one of those is a `wanted: true` intent whose
            // details went stale, never a request to open the network. Testing `wanted`
            // explicitly here keeps that case on the fail-closed side with the corrupt and
            // unreadable records below.
            Ok(intent) if !intent.wanted => {
                // Unwanted-but-parseable, with possible residual objects: clean up, exactly the
                // design's third recovery rule. A leftover DNS snapshot (e.g. from an emergency
                // disarm whose restore could not be proven) is swept here too — protection is
                // off, so the machine must not stay on loopback DNS.
                // `remove_all_filters` is provider-scoped, so filters in legacy sublayers go
                // with it; the sweep afterwards only clears the emptied sublayer objects.
                remove_all_filters_unlocked().await?;
                sweep_legacy_sublayers_unlocked().await;
                match tokio::fs::remove_file(intent_path()).await {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                *armed_guard() = None;
                TUNNEL_PERMIT_RENDERED.store(false, Ordering::Relaxed);
                if let Err(error) = bounded_dns_call(
                    "service start (unwanted intent)",
                    crate::core::dns::ensure_restored(),
                )
                .await
                {
                    tracing::warn!(
                        "service start: leftover DNS snapshot could not be restored: {error:#}"
                    );
                }
                Ok(())
            }
            Ok(_) => {
                // A `wanted: true` record that no longer validates: the intent to stay blocked
                // is intact, only its details are unusable. Treat it exactly like a corrupt
                // record — emergency block, file left on disk as evidence — rather than
                // disarming a machine that asked to stay closed.
                let emergency = emergency_armed();
                *armed_guard() = Some(emergency.clone());
                let installed = install_unlocked(&emergency).await.context(
                    "unusable wanted kill-switch intent: failed to install emergency block",
                );
                if installed.is_ok() {
                    sweep_legacy_sublayers_unlocked().await;
                }
                installed
            }
            Err(_) => {
                // Corrupt intent = wanted (fail-closed), exactly the macOS helper's "damaged
                // state file ⇒ install emergency block". The corrupt file is left on disk as
                // evidence; the in-memory intent below is what the watchdog reconciles.
                let emergency = emergency_armed();
                *armed_guard() = Some(emergency.clone());
                let installed = install_unlocked(&emergency)
                    .await
                    .context("corrupt kill-switch intent: failed to install emergency block");
                if installed.is_ok() {
                    sweep_legacy_sublayers_unlocked().await;
                }
                installed
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // Missing intent but residual objects exist → treat as wanted (fail-closed).
            #[cfg(all(windows, not(feature = "test")))]
            if engine_call("residual filter check", crate::core::wfp::any_filters_exist)
                .await
                .unwrap_or(true)
            {
                let emergency = emergency_armed();
                *armed_guard() = Some(emergency.clone());
                let installed = install_unlocked(&emergency)
                    .await
                    .context("missing intent with residual WFP objects: failed to reinstall block");
                if installed.is_ok() {
                    sweep_legacy_sublayers_unlocked().await;
                }
                return installed;
            }
            // Not armed and no filters anywhere (the residual check is provider-scoped, legacy
            // sublayers included): sweeping empty leftover sublayer objects cannot remove
            // protection, and on a fresh install the sweep is a read-only no-op because the
            // Tono provider does not exist.
            sweep_legacy_sublayers_unlocked().await;
            // Not armed and nothing residual: still sweep a leftover DNS snapshot (see above).
            if let Err(error) = bounded_dns_call(
                "service start (no intent)",
                crate::core::dns::ensure_restored(),
            )
            .await
            {
                tracing::warn!(
                    "service start: leftover DNS snapshot could not be restored: {error:#}"
                );
            }
            Ok(())
        }
        Err(error) => {
            // The file may exist but be unreadable (ACL damage, transient I/O). Returning the
            // error would leave `ARMED` empty and the watchdog idle — fully open even though a
            // wanted intent may sit on disk. Treat it like the corrupt case above: fail closed
            // with the emergency block. A clean NotFound never reaches here, so a fresh
            // install stays a no-op.
            tracing::warn!("kill-switch intent could not be read: {error:#}");
            let emergency = emergency_armed();
            *armed_guard() = Some(emergency.clone());
            let installed = install_unlocked(&emergency)
                .await
                .context("unreadable kill-switch intent: failed to install emergency block");
            if installed.is_ok() {
                sweep_legacy_sublayers_unlocked().await;
            }
            installed
        }
    }
}

/// Read-only WFP proof for the uninstaller's "nothing to clean" fast path.
///
/// State files are not the source of truth for persistent WFP objects: an interrupted or older
/// uninstall can leave provider-scoped filters behind after deleting `kill-switch.json` and the
/// SCM record. The next Service start deliberately treats that combination as armed. Therefore
/// an uninstaller may only skip the real disarm when this probe also proves that no Tono filter
/// exists. Errors stay on the fail-closed side and are surfaced to the caller.
#[cfg(all(windows, not(feature = "test")))]
pub async fn residual_filters_present() -> Result<bool> {
    let _operation = WFP_OPERATION.lock().await;
    engine_call(
        "uninstall residual filter check",
        crate::core::wfp::any_filters_exist,
    )
    .await
}

#[cfg(not(all(windows, not(feature = "test"))))]
pub async fn residual_filters_present() -> Result<bool> {
    Ok(false)
}

/// Prepare an in-place Service replacement without opening an active protected session.
///
/// The elevated installer calls this only after SCM reports the old Service stopped and while it
/// holds the singleton Service-owner lock. A valid wanted intent or any active owner is durable
/// evidence that protection must survive the replacement, so those cases are untouched. A
/// disconnected pre-fix build, however, has neither record: synthesize the same `wanted:false`
/// tombstone a fixed release leaves so startup removes late-visible WFP debris instead of
/// converting it into an ownerless emergency block.
///
/// Corrupt wanted-state evidence stays fail-closed. It is intentionally not "repaired" into an
/// open marker merely because an installer is running.
pub async fn prepare_for_service_replacement() -> Result<bool> {
    ensure_supported()?;

    // Do not use `load_active_owner` here: its normal runtime contract quarantines malformed
    // owner JSON and reports `None`, which is useful for an owner-gated release but too
    // permissive for an installer deciding whether it may synthesize an open marker. During a
    // replacement, unreadable or malformed owner evidence is ambiguity and ambiguity preserves
    // protection.
    let active_owner_path = crate::service_paths().active_owner_path();
    match tokio::fs::read(&active_owner_path).await {
        Ok(bytes) => {
            if serde_json::from_slice::<crate::core::desired::ActiveOwnerState>(&bytes).is_err() {
                tracing::warn!(
                    "Service replacement found corrupt active-owner evidence; preserving protection fail-closed"
                );
            }
            return Ok(false);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect active-owner evidence {active_owner_path:?} before Service replacement; refusing to change protection"
                )
            });
        }
    }

    match tokio::fs::read(intent_path()).await {
        Ok(bytes) => match serde_json::from_slice::<IntentRecord>(&bytes) {
            Ok(intent) if intent.wanted => Ok(false),
            Ok(_) => {
                persist_disarmed_tombstone().await?;
                Ok(true)
            }
            Err(error) => {
                tracing::warn!(
                    "Service replacement found a corrupt kill-switch intent; preserving it fail-closed: {error}"
                );
                Ok(false)
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            persist_disarmed_tombstone().await?;
            Ok(true)
        }
        Err(error) => Err(error).context(
            "failed to inspect kill-switch intent before Service replacement; refusing to change protection",
        ),
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
    let Some(armed) = armed_guard().clone() else {
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
            *last_error_guard() = Some(format!(
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
    if armed_guard().is_none() {
        return Ok(());
    }
    lock(None).await.map_err(|error| {
        let message = format!("restored core could not be re-locked: {error:#}");
        *last_error_guard() = Some(message.clone());
        error.context(message)
    })
}

/// One-second verify-after-write watchdog (the macOS helper does the same for PF): any
/// mismatch reinstalls the full expected set transactionally. Persistent failures are
/// log-throttled — one error per minute, the rest at debug — so a broken engine cannot
/// flood the service log.
pub fn spawn_windows_kill_switch_watchdog() {
    /// One error line per minute; the rest at debug.
    const ERROR_LOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
    tokio::spawn(async {
        // `None` = "never logged yet", *not* `Instant::now() - an hour`: `Instant` is
        // boot-relative on Windows and this service is AutoStart, so subtracting an hour
        // underflows and panics on a machine that has been up for less than that — killing the
        // watchdog task on its first statement at every boot, which would silently disable both
        // the verify-after-write reconciliation and the `LAST_VERIFY` refresh that `status()`
        // reports liveness from.
        let mut last_error_log: Option<std::time::Instant> = None;
        loop {
            tokio::time::sleep(WATCHDOG_PERIOD).await;
            let _operation = WFP_OPERATION.lock().await;
            let armed = { armed_guard().clone() };
            if let Some(armed) = armed {
                let healthy = if ENGINE_LIVE {
                    let healthy = verify_live_unlocked(&armed).await.is_ok();
                    note_verify(healthy);
                    healthy
                } else {
                    true
                };
                if !healthy && let Err(error) = install_unlocked(&armed).await {
                    *last_error_guard() = Some(format!("{error:#}"));
                    if last_error_log.is_none_or(|at| at.elapsed() >= ERROR_LOG_INTERVAL) {
                        tracing::error!("Windows kill-switch reconciliation failed: {error:#}");
                        last_error_log = Some(std::time::Instant::now());
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
///
/// **The invariant this function exists to hold, and the one the uninstall exit codes rest on:**
/// the WFP objects are removed before any DNS outcome is reported, and every `?` above the
/// removal fails *without* claiming the barrier is gone. Once WFP is deleted, every DNS outcome
/// is tagged with a continue marker (`DNS_RESTORED_AUTOMATIC_PREFIX`,
/// `DNS_UNINSTALL_STILL_ON_LOOPBACK_PREFIX`, or `WFP_REMOVED_CONTINUE_PREFIX`) so the
/// uninstaller can never treat "filters gone, DNS messy" as result 3. Removing the app while
/// leaving WFP armed is the only end state that must still block.
pub async fn emergency_disarm_windows_kill_switch() -> Result<()> {
    let _operation = WFP_OPERATION.lock().await;
    // This is still the fail-open escape hatch: WFP objects are removed even if protected DNS
    // cannot be restored. The DNS failure is nevertheless returned *after* WFP and intent
    // cleanup so an uninstaller cannot report success and delete the remaining recovery files.
    // `restore_protected` preserves its snapshot on failure, making a repair + retry possible.
    //
    // Bounded like every other cross-module await on this path, and here the bound cannot even
    // touch the ordering invariant: this path is the documented fail-open escape hatch that
    // removes WFP whether or not DNS could be restored, so a timeout only changes *how* the
    // uninstaller reports an unrestored resolver — never whether it proved one before opening.
    // An unbounded hang here would instead wedge the uninstaller while holding `WFP_OPERATION`.
    //
    // Two DNS strategies, chosen by the *calling process*, never by the machine's condition:
    //
    // * The uninstaller opts into `dns::restore_for_uninstall`, the escalation ladder. Its
    //   rung 2 resets the adapters Tono redirected to automatic (DHCP) rather than refusing —
    //   because the alternative, which is what this code used to do, was an application the
    //   user could not remove. See the block comment above `dns::uninstall_restore_rung`.
    // * Everyone else — `tono-service.exe --emergency-disarm`, the Start-Menu "Restore Network"
    //   entry — keeps `dns::restore_protected` verbatim. That path's promise is to put the
    //   user's *own* servers back on a machine that is staying installed, and a machine that is
    //   staying installed can retry. Nothing about it is made more permissive here.
    let dns_restore = if uninstall_ladder_requested() {
        bounded_dns_call_within(
            UNINSTALL_DNS_RESTORE_TIMEOUT,
            "uninstall disarm",
            crate::core::dns::restore_for_uninstall(),
        )
        .await
    } else {
        bounded_dns_call("emergency disarm", crate::core::dns::restore_protected())
            .await
            .map(|_| crate::core::dns::UninstallDnsRestore::Exact)
    };

    // Persist fail-open intent *before* removing WFP when we can. Service-start recovery sees
    // the tombstone and finishes cleanup instead of re-arming a stale wanted policy.
    //
    // **Uninstall ladder exception:** Chinese customer machines repeatedly hit
    // `ensure_private_service_directory` / ProgramData ACL failures on this write, which used to
    // return *before* WFP removal and brick install/uninstall as result 3 forever — with the
    // barrier still armed. When this process opted into the uninstall ladder, a tombstone
    // failure is logged and we still delete provider-scoped WFP objects: the alternative is an
    // application that cannot be removed. Non-uninstall callers keep the old refuse path.
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
    let tombstone_error = match atomic_write(&intent_path(), &serde_json::to_vec_pretty(&tombstone)?)
        .await
    {
        Ok(()) => None,
        Err(error) if uninstall_ladder_requested() => {
            tracing::error!(
                "uninstall disarm: kill-switch tombstone could not be written ({error:#}); \
                 still removing WFP so install/uninstall cannot dead-end as result 3"
            );
            Some(error)
        }
        Err(error) => return Err(error),
    };

    // Bounded like every other engine call: an uninstaller that hangs forever on a wedged BFE
    // is worse than one that reports why it could not finish. When the tombstone is on disk the
    // next service start completes cleanup either way; when it is not (uninstall ladder only)
    // the WFP delete itself is the safety proof the uninstaller needs.
    //
    // Ordering: prefer tombstone *before* the engine call (a crash mid-removal must still
    // complete cleanup at the next service start), but the in-memory disarmed state is
    // published *after* it. Publishing first would make `status()` report an unprotected
    // machine while the filters are demonstrably still installed — the exact inversion of what
    // the product promises. On engine failure the reported state therefore stays "armed".
    #[cfg(all(windows, not(feature = "test")))]
    engine_call("emergency disarm", crate::core::wfp::emergency_disarm).await?;
    *armed_guard() = None;
    *last_verify_guard() = None;
    TUNNEL_PERMIT_RENDERED.store(false, Ordering::Relaxed);
    // Best-effort tombstone after a skipped pre-write so a later Service start still prefers
    // cleanup over emergency re-arm when ProgramData becomes writable again.
    if tombstone_error.is_some() {
        if let Err(error) =
            atomic_write(&intent_path(), &serde_json::to_vec_pretty(&tombstone)?).await
        {
            tracing::warn!(
                "uninstall disarm: post-WFP tombstone write still failed: {error:#}"
            );
        }
    }
    // Intent deletion is best-effort once WFP is gone. The tombstone (wanted:false) is already
    // on disk, so a leftover file cannot re-arm a block; refusing uninstall here recreated the
    // "result 3 forever" deadlock for Chinese test machines whose ProgramData ACLs deny the
    // final unlink under the elevated installer token.
    match tokio::fs::remove_file(intent_path()).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            tracing::warn!(
                "kill-switch intent could not be deleted after WFP removal (continuing): {error:#}"
            );
        }
    }
    // Everything below runs only once the WFP objects are provably gone: the engine_call `?`
    // above returns before it. Every imperfect DNS outcome is therefore tagged so the
    // uninstaller continues — the barrier that could leave a brick is already down.
    match dns_restore {
        // Rung 1: the snapshot was restored and proven. Nothing to report.
        Ok(crate::core::dns::UninstallDnsRestore::Exact) => Ok(()),
        // Rung 2: reported through the error channel on purpose. This entry point's contract has
        // always been "return the DNS deviation *after* the WFP cleanup so a caller cannot
        // report unqualified success", and rung 2 is a deviation — the user's own servers were
        // not restored. The marker is what turns it into a *continue*-with-warning at the
        // uninstaller instead of a refusal; a caller that does not know the marker keeps the old,
        // conservative reading, which is the correct default for anything that is not an
        // uninstall. Reachable only when this process opted into the ladder.
        Ok(crate::core::dns::UninstallDnsRestore::Automatic { adapters }) => {
            let snapshot = crate::service_paths()
                .persistent_state_dir()
                .join("protected-dns.json");
            Err(anyhow::anyhow!(
                "{}: WFP was removed and {} adapter(s) were set back to automatic (DHCP) DNS \
                 because the saved servers could not be proven restored. The machine resolves \
                 through the network's own DNS again; this is not the exact previous \
                 configuration. The saved servers were kept next to {snapshot:?} under a \
                 `protected-dns.superseded-*.json` name if they are needed. Uninstall may \
                 continue: nothing of Tono's is left blocking or redirecting this machine.",
                crate::core::dns::DNS_RESTORED_AUTOMATIC_PREFIX,
                adapters.len(),
            ))
        }
        // Rung 3 or any other post-removal DNS failure: WFP is already gone. Tag with the
        // continue marker so install/uninstall never dead-end as result 3. The inner error
        // still names STILL_ON_LOOPBACK / snapshot paths so the detail log can tell the user
        // how to fix DNS in Windows Settings.
        Err(error) => {
            let snapshot = crate::service_paths()
                .persistent_state_dir()
                .join("protected-dns.json");
            Err(anyhow::anyhow!(
                "{}: WFP was removed, but DNS restore could not be proven: {error:#}. \
                 Recovery snapshot: {snapshot:?}. The network barrier is gone so install and \
                 uninstall may continue. If name resolution is still wrong, open Settings → \
                 Network & Internet → your adapter → DNS server assignment → Automatic (DHCP) \
                 for both IPv4 and IPv6.",
                crate::core::dns::WFP_REMOVED_CONTINUE_PREFIX,
            ))
        }
    }
}

pub(crate) async fn status() -> KillSwitchStatus {
    // Never join the WFP writer queue. The watchdog refreshes `LAST_VERIFY`; mutations publish
    // `ARMED` only at their commit boundary, so a concurrent read gets the previous committed
    // state rather than blocking behind an RPC that may itself be the thing under diagnosis.
    let armed = { armed_guard().clone() };
    let Some(armed) = armed else {
        return KillSwitchStatus {
            wanted: false,
            verified: false,
            live: false,
            mode: KillSwitchStatusMode::Blocked,
            tunnel_permit_rendered: false,
            endpoints: Vec::new(),
            last_error: last_error_guard().clone(),
        };
    };
    let live = if ENGINE_LIVE {
        verify_reads_live(*last_verify_guard())
    } else {
        // No engine behind this build: report the recorded intent without claiming liveness.
        false
    };
    KillSwitchStatus {
        wanted: armed.intent.wanted,
        verified: armed.intent.is_verified(),
        live,
        mode: armed.intent.mode,
        // What the last render decided, not what a render right now would decide: this is a
        // report on the policy that is installed, and it must not run a fresh core-manager read
        // on the status path.
        tunnel_permit_rendered: TUNNEL_PERMIT_RENDERED.load(Ordering::Relaxed),
        endpoints: armed.intent.endpoints.clone(),
        last_error: last_error_guard().clone(),
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

    /// What a watchdog tick renders for this session right now.
    async fn render(armed: &Armed) -> RuleConfig {
        rule_config_rendering(armed, current_core_instance().await)
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

    /// A corrupt snapshot only refuses a restore while the machine is still resolving through
    /// the loopback core; off Windows that answer comes from a test hook, so tests that mean
    /// "restore is unprovable" must say so explicitly.
    fn simulate_machine_still_on_loopback_dns() {
        crate::core::dns::test_hooks::set_live_dns_on_loopback(true);
    }

    async fn assert_disarmed_tombstone_present() -> Result<()> {
        let intent: IntentRecord = serde_json::from_slice(&tokio::fs::read(intent_path()).await?)?;
        assert!(
            !intent.wanted,
            "explicit release must leave wanted=false evidence"
        );
        assert!(intent.owner_key.is_none());
        assert!(intent.endpoints.is_empty());
        Ok(())
    }

    async fn cleanup() {
        crate::core::dns::test_hooks::set_live_dns_on_loopback(false);
        *ARMED.lock().unwrap() = None;
        *LAST_ERROR.lock().unwrap() = None;
        RESTORE_WAS_LOCKED.store(false, Ordering::Release);
        for path in [
            intent_path(),
            dns_snapshot_path(),
            crate::service_paths().active_owner_path(),
        ] {
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
        simulate_machine_still_on_loopback_dns();
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
        assert_disarmed_tombstone_present().await?;
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
    async fn explicit_release_tombstone_survives_until_replacement_start_consumes_it() -> Result<()>
    {
        cleanup().await;
        arm_bootstrap(&test_config(), "/opt/tono/mihomo", "owner-alice").await?;

        release().await?;
        assert_disarmed_tombstone_present().await?;

        // The in-place replacement is a fresh process; only the on-disk tombstone crosses it.
        *ARMED.lock().unwrap() = None;
        restore_on_service_start().await?;

        assert!(ARMED.lock().unwrap().is_none());
        assert!(
            tokio::fs::metadata(intent_path()).await.is_err(),
            "startup consumes the tombstone only after the residual-filter cleanup"
        );
        cleanup().await;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn replacement_marks_a_pre_fix_disconnected_install_but_preserves_wanted_intent()
    -> Result<()> {
        cleanup().await;

        assert!(prepare_for_service_replacement().await?);
        assert_disarmed_tombstone_present().await?;

        let wanted = valid_intent(KillSwitchStatusMode::Locked, true);
        atomic_write(&intent_path(), &serde_json::to_vec_pretty(&wanted)?).await?;
        assert!(
            !prepare_for_service_replacement().await?,
            "a valid wanted session must stay fail-closed across replacement"
        );
        let preserved: IntentRecord =
            serde_json::from_slice(&tokio::fs::read(intent_path()).await?)?;
        assert!(preserved.wanted);
        cleanup().await;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn replacement_never_synthesizes_an_open_marker_for_an_active_owner() -> Result<()> {
        cleanup().await;
        let active = crate::core::desired::ActiveOwnerState {
            owner_key: "owner-active".to_owned(),
            identity: crate::OwnerIdentity::Windows {
                sid: "S-1-5-21-test-owner".to_owned(),
            },
            app_data_root: std::env::temp_dir().to_string_lossy().into_owned(),
            generation: 7,
            session_token_hash: "session-hash".to_owned(),
        };
        atomic_write(
            &crate::service_paths().active_owner_path(),
            &serde_json::to_vec_pretty(&active)?,
        )
        .await?;

        assert!(!prepare_for_service_replacement().await?);
        assert!(
            tokio::fs::metadata(intent_path()).await.is_err(),
            "an active owner with missing WFP evidence is ambiguous and must not be opened"
        );
        cleanup().await;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn replacement_preserves_corrupt_active_owner_evidence_fail_closed() -> Result<()> {
        cleanup().await;
        atomic_write(
            &crate::service_paths().active_owner_path(),
            b"{ corrupt active owner evidence",
        )
        .await?;

        assert!(!prepare_for_service_replacement().await?);
        assert!(
            tokio::fs::metadata(intent_path()).await.is_err(),
            "damaged owner evidence is ambiguity, never permission to synthesize wanted=false"
        );
        assert_eq!(
            tokio::fs::read(crate::service_paths().active_owner_path()).await?,
            b"{ corrupt active owner evidence",
            "replacement preparation must retain evidence for diagnosis"
        );
        cleanup().await;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn replacement_preserves_corrupt_intent_fail_closed() -> Result<()> {
        cleanup().await;
        atomic_write(&intent_path(), b"{ corrupt wanted evidence").await?;

        assert!(!prepare_for_service_replacement().await?);
        assert_eq!(
            tokio::fs::read(intent_path()).await?,
            b"{ corrupt wanted evidence"
        );
        cleanup().await;
        Ok(())
    }

    /// The disarm path is the one place a `wanted` record may open the machine, and only
    /// `wanted == false` may do it. Every other way of failing `intent_is_valid` is a stale
    /// *wanted* intent, and must land on the emergency block with the corrupt/unreadable cases.
    #[tokio::test]
    #[serial]
    async fn a_wanted_intent_that_no_longer_validates_stays_fail_closed() -> Result<()> {
        let stale_endpoint = {
            let mut intent = valid_intent(KillSwitchStatusMode::Locked, true);
            // Parses as JSON, still says `wanted`, but the endpoint no longer satisfies the
            // model — the shape an endpoint-validation tightening leaves on disk.
            intent.endpoints = vec![ProxyEndpoint {
                ip: "not-an-ip".to_owned(),
                port: 443,
                protocol: ProxyProtocol::Tcp,
            }];
            intent
        };
        let no_app_path = {
            // A truncated record: without the staged core path every install would fall back to
            // "block installed, endpoint permit missing" forever.
            let mut intent = valid_intent(KillSwitchStatusMode::Locked, true);
            intent.app_path = String::new();
            intent
        };
        for (what, intent) in [
            ("unparseable endpoint", stale_endpoint),
            ("missing app path", no_app_path),
        ] {
            cleanup().await;
            atomic_write(&intent_path(), &serde_json::to_vec_pretty(&intent)?).await?;

            restore_on_service_start().await?;

            let armed = armed_guard().clone().expect(what);
            assert_eq!(armed.intent.mode, KillSwitchStatusMode::Blocked, "{what}");
            assert!(armed.intent.wanted, "{what}");
            assert!(armed.intent.endpoints.is_empty(), "{what}");
            assert!(status().await.wanted, "{what}");
            assert!(
                tokio::fs::metadata(intent_path()).await.is_ok(),
                "{what}: the unusable record is left on disk as evidence"
            );
        }
        cleanup().await;
        Ok(())
    }

    /// S2 in miniature: a DNS restore that never returns must not hold `WFP_OPERATION` — and
    /// the refusal must keep the disarm on the fail-closed side, never skip the proof.
    #[tokio::test]
    #[serial]
    async fn a_stalled_dns_restore_is_bounded_and_refuses_the_operation() -> Result<()> {
        let error = bounded_dns_call_within(
            std::time::Duration::from_millis(50),
            "disarm",
            std::future::pending::<Result<()>>(),
        )
        .await
        .expect_err("a DNS restore that never returns must not be awaited forever");
        let message = format!("{error:#}");
        assert!(message.contains(DNS_RESTORE_STALLED_PREFIX), "{message}");
        assert!(message.contains("disarm"), "{message}");

        // A healthy call is transparent in both directions: the bound adds no behavior of its
        // own, so every caller keeps treating a DNS failure exactly as it did before.
        let value = bounded_dns_call_within(std::time::Duration::from_secs(5), "disarm", async {
            Result::<u8>::Ok(7)
        })
        .await?;
        assert_eq!(value, 7);
        let error = bounded_dns_call_within(std::time::Duration::from_secs(5), "disarm", async {
            Result::<()>::Err(anyhow::anyhow!("snapshot is corrupt"))
        })
        .await
        .expect_err("DNS errors still propagate");
        assert!(format!("{error:#}").contains("corrupt"));
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
    async fn restore_with_unreadable_intent_arms_emergency_block() -> Result<()> {
        cleanup().await;
        // A directory at the intent path makes the read fail with a non-NotFound error on
        // every platform — the stand-in for ACL damage or transient I/O on a real service.
        tokio::fs::create_dir_all(intent_path()).await?;

        restore_on_service_start().await?;

        let armed = ARMED.lock().unwrap().clone().expect("unreadable = armed");
        assert_eq!(armed.intent.mode, KillSwitchStatusMode::Blocked);
        assert!(armed.intent.wanted);
        assert!(armed.intent.is_verified());
        assert!(armed.intent.endpoints.is_empty());
        assert!(status().await.wanted);

        tokio::fs::remove_dir(intent_path()).await?;
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

    /// The bootstrap channel's destinations are whatever the *client* pinned, never whatever a
    /// resolver answered: a hostname is dropped, not looked up, so no DHCP resolver, captive
    /// portal or on-path spoofer can nominate a destination this service permits through its
    /// own block. Order, dedup, the public-only table and the cap are unchanged.
    #[test]
    fn api_hosts_admit_public_literals_only_and_never_resolve_a_name() {
        let ips = admit_api_host_ips(&[
            " 1.1.1.1 ".to_owned(),
            "api.example.invalid".to_owned(),
            "localhost".to_owned(),
            String::new(),
            "8.8.8.8".to_owned(),
            "1.1.1.1".to_owned(),
            "10.0.0.1".to_owned(),
            "127.0.0.1".to_owned(),
        ]);
        assert_eq!(
            ips,
            vec![
                "1.1.1.1".parse::<IpAddr>().unwrap(),
                "8.8.8.8".parse::<IpAddr>().unwrap(),
            ]
        );

        // The count cap still bounds what a client can ask for, hostnames or not.
        let many = (0..32)
            .map(|index| format!("8.8.{}.{}", index / 256, index % 256 + 1))
            .collect::<Vec<_>>();
        assert!(admit_api_host_ips(&many).len() <= wfp_model::MAX_API_HOST_IPS);
        assert!(
            admit_api_host_ips(&["api.example.invalid".to_owned()]).is_empty(),
            "a hostname must yield no permit at all"
        );
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
        simulate_machine_still_on_loopback_dns();
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
        assert_disarmed_tombstone_present().await?;
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
        assert_disarmed_tombstone_present().await?;
        cleanup().await;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn emergency_disarm_removes_wfp_intent_but_reports_unrestored_dns() -> Result<()> {
        cleanup().await;
        arm_bootstrap(&test_config(), "/opt/tono/mihomo", "owner-alice").await?;
        simulate_machine_still_on_loopback_dns();
        atomic_write(&dns_snapshot_path(), b"{ corrupt").await?;

        let error = emergency_disarm_windows_kill_switch()
            .await
            .expect_err("unproven DNS restore must fail the uninstall contract");

        let message = format!("{error:#}");
        assert!(message.contains("WFP was removed"), "{message}");
        assert!(message.contains("protected-dns.json"), "{message}");
        assert!(
            message.contains(crate::core::dns::WFP_REMOVED_CONTINUE_PREFIX),
            "post-WFP DNS failure must be tagged so uninstall cannot brick as result 3: {message}"
        );
        assert!(ARMED.lock().unwrap().is_none());
        assert!(
            tokio::fs::metadata(intent_path()).await.is_err(),
            "removed WFP must not be re-armed from a stale intent on reboot"
        );
        assert!(
            tokio::fs::metadata(dns_snapshot_path()).await.is_ok(),
            "failed DNS proof must remain available for retry"
        );
        assert!(
            !message.contains(crate::core::dns::DNS_RESTORED_AUTOMATIC_PREFIX),
            "without the uninstaller's opt-in the DNS ladder must not run — the Start-Menu \
             \"Restore Network\" entry exists to put the user's own servers back on a machine \
             that is staying installed, and must not silently flatten them to DHCP: {message}"
        );
        cleanup().await;
        Ok(())
    }

    // --- The uninstall-only escalation ladder ---

    /// Opts the *process* into `dns::restore_for_uninstall`, exactly as `uninstall_service.rs`
    /// does, and takes it back out again so no other test inherits it.
    struct UninstallLadderOptIn;

    impl UninstallLadderOptIn {
        fn enter() -> Self {
            // SAFETY: every test that uses this is `#[serial]`, so no other thread in this
            // binary is reading or writing the environment while it is set.
            unsafe { std::env::set_var(UNINSTALL_LADDER_ENV, "1") };
            Self
        }
    }

    impl Drop for UninstallLadderOptIn {
        fn drop(&mut self) {
            // SAFETY: as above.
            unsafe { std::env::remove_var(UNINSTALL_LADDER_ENV) };
        }
    }

    /// A snapshot whose originals are ordinary public resolvers, so every adapter in it is one
    /// Tono redirected and is therefore a legitimate target for the DHCP reset.
    fn redirected_snapshot() -> crate::core::dns::DnsSnapshot {
        crate::core::dns::DnsSnapshot {
            version: 1,
            taken_at: 1,
            adapters: vec![
                crate::core::dns::AdapterDnsSnapshot {
                    interface_guid: "{ETHERNET}".to_owned(),
                    ipv4_name_server: Some("1.1.1.1".to_owned()),
                    ..Default::default()
                },
                crate::core::dns::AdapterDnsSnapshot {
                    interface_guid: "{WIFI}".to_owned(),
                    ipv4_name_server: Some("8.8.8.8".to_owned()),
                    ..Default::default()
                },
            ],
        }
    }

    /// Whether the ladder set the live snapshot aside under its `superseded` name instead of
    /// deleting the user's only record of their original resolvers.
    async fn superseded_snapshot_exists() -> bool {
        let paths = crate::service_paths();
        let directory = paths.persistent_state_dir();
        let Ok(mut entries) = tokio::fs::read_dir(&directory).await else {
            return false;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("protected-dns.superseded-") {
                return true;
            }
        }
        false
    }

    async fn remove_superseded_snapshots() {
        let paths = crate::service_paths();
        let directory = paths.persistent_state_dir();
        let Ok(mut entries) = tokio::fs::read_dir(&directory).await else {
            return;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("protected-dns.superseded-") {
                let _ = tokio::fs::remove_file(entry.path()).await;
            }
        }
    }

    /// Rung 1: nothing changes for a machine whose exact restore is provable. The ladder is an
    /// escalation, not a shortcut — it must never reach for DHCP while the saved servers can be
    /// put back.
    #[tokio::test]
    #[serial]
    async fn uninstall_ladder_prefers_the_exact_restore() -> Result<()> {
        cleanup().await;
        remove_superseded_snapshots().await;
        let _opt_in = UninstallLadderOptIn::enter();
        arm_bootstrap(&test_config(), "/opt/tono/mihomo", "owner-alice").await?;
        atomic_write(
            &dns_snapshot_path(),
            &serde_json::to_vec_pretty(&crate::core::dns::DnsSnapshot {
                version: 1,
                taken_at: 1,
                adapters: Vec::new(),
            })?,
        )
        .await?;

        emergency_disarm_windows_kill_switch()
            .await
            .expect("a provable restore reports plain success");

        assert!(ARMED.lock().unwrap().is_none());
        assert!(tokio::fs::metadata(dns_snapshot_path()).await.is_err());
        assert!(
            !superseded_snapshot_exists().await,
            "rung 1 must not leave a superseded snapshot behind"
        );
        cleanup().await;
        Ok(())
    }

    /// Rung 2 — the regression this ladder exists for. The machine is still resolving through
    /// the loopback core when the exact restore is attempted, so the old code returned an
    /// unqualified failure, `uninstall_service.rs` exited 3 and `installer.nsi` aborted: the
    /// application could not be uninstalled at all. Now the adapters are reset to automatic
    /// (DHCP), verified off the loopback resolver, and the failure carries the marker that lets
    /// the uninstall continue.
    #[tokio::test]
    #[serial]
    async fn uninstall_ladder_falls_back_to_automatic_dns_instead_of_becoming_unremovable()
    -> Result<()> {
        cleanup().await;
        remove_superseded_snapshots().await;
        let _opt_in = UninstallLadderOptIn::enter();
        arm_bootstrap(&test_config(), "/opt/tono/mihomo", "owner-alice").await?;
        atomic_write(
            &dns_snapshot_path(),
            &serde_json::to_vec_pretty(&redirected_snapshot())?,
        )
        .await?;
        // The reported machine: the exact restore cannot be proven because adapters still read
        // as the loopback redirect. The DHCP reset is what clears that.
        simulate_machine_still_on_loopback_dns();

        let error = emergency_disarm_windows_kill_switch()
            .await
            .expect_err("an inexact restore is still reported, but as a continuable one");
        let message = format!("{error:#}");

        assert!(
            message.contains(crate::core::dns::DNS_RESTORED_AUTOMATIC_PREFIX),
            "the fallback must be reported with the marker the uninstaller keys its \
             continue-with-warning exit code off: {message}"
        );
        assert!(
            !message.contains(crate::core::dns::DNS_UNINSTALL_STILL_ON_LOOPBACK_PREFIX),
            "{message}"
        );
        // The invariant: the marker may only ever be produced once the barrier is gone.
        assert!(
            ARMED.lock().unwrap().is_none(),
            "the continuing outcome must never be reported while the kill switch is armed"
        );
        assert!(
            tokio::fs::metadata(intent_path()).await.is_err(),
            "a continuing uninstall must not leave an intent record that re-arms on reboot"
        );
        assert!(
            tokio::fs::metadata(dns_snapshot_path()).await.is_err(),
            "the redirect is gone, so the live snapshot must not survive to be replayed"
        );
        assert!(
            superseded_snapshot_exists().await,
            "the user's original servers must be retained under the superseded name, not deleted"
        );

        remove_superseded_snapshots().await;
        cleanup().await;
        Ok(())
    }

    /// Rung 3: DNS may still be stuck on Tono's resolver, but WFP is already gone. The error is
    /// still reported (so the detail log can tell the user to flip DNS to Automatic), and it is
    /// tagged with the continue marker so install/uninstall never dead-end as result 3.
    #[tokio::test]
    #[serial]
    async fn uninstall_ladder_reports_stuck_dns_but_lets_uninstall_continue_after_wfp_is_gone()
    -> Result<()> {
        cleanup().await;
        remove_superseded_snapshots().await;
        let _opt_in = UninstallLadderOptIn::enter();
        arm_bootstrap(&test_config(), "/opt/tono/mihomo", "owner-alice").await?;
        atomic_write(
            &dns_snapshot_path(),
            &serde_json::to_vec_pretty(&redirected_snapshot())?,
        )
        .await?;
        simulate_machine_still_on_loopback_dns();
        // Neither the exact restore nor the DHCP reset lands, so nothing takes the machine off
        // the loopback resolver.
        crate::core::dns::test_hooks::set_live_apply_fails(true);

        let error = emergency_disarm_windows_kill_switch()
            .await
            .expect_err("stuck DNS is still reported, but as a continuable outcome");
        let message = format!("{error:#}");

        assert!(
            message.contains(crate::core::dns::DNS_UNINSTALL_STILL_ON_LOOPBACK_PREFIX),
            "{message}"
        );
        assert!(
            message.contains(crate::core::dns::WFP_REMOVED_CONTINUE_PREFIX),
            "post-WFP DNS failure must carry the continue marker so result 3 cannot fire: \
             {message}"
        );
        assert!(
            message.contains("Automatic (DHCP)"),
            "the report has to tell the user what to do about DNS: {message}"
        );
        // The barrier is removed: being unable to remove the app *and* being blocked offline is
        // the worse end state, and the barrier is the half that makes them offline.
        assert!(ARMED.lock().unwrap().is_none());
        assert!(tokio::fs::metadata(intent_path()).await.is_err());
        assert!(
            tokio::fs::metadata(dns_snapshot_path()).await.is_ok(),
            "imperfect DNS restore preserves the snapshot so the user can recover originals"
        );
        assert!(!superseded_snapshot_exists().await);

        crate::core::dns::test_hooks::set_live_apply_fails(false);
        remove_superseded_snapshots().await;
        cleanup().await;
        Ok(())
    }

    /// The opt-in is the whole boundary between the two behaviours: an unset or unrecognised
    /// value must leave the strict path in force, because everything that is not an uninstall
    /// still wants the user's exact servers back.
    #[test]
    #[serial]
    fn only_an_explicit_opt_in_enables_the_uninstall_ladder() {
        // SAFETY: `#[serial]` peers; this test touches the variable alone.
        unsafe { std::env::remove_var(UNINSTALL_LADDER_ENV) };
        assert!(!uninstall_ladder_requested());
        for value in ["", "0", "true", "yes", "2"] {
            unsafe { std::env::set_var(UNINSTALL_LADDER_ENV, value) };
            assert!(
                !uninstall_ladder_requested(),
                "{value:?} must not be read as an opt-in"
            );
        }
        unsafe { std::env::set_var(UNINSTALL_LADDER_ENV, "1") };
        assert!(uninstall_ladder_requested());
        unsafe { std::env::remove_var(UNINSTALL_LADDER_ENV) };
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
        assert_disarmed_tombstone_present().await?;
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
        assert_disarmed_tombstone_present().await?;
        let again = release().await?;
        assert!(!again.wanted);
        assert_disarmed_tombstone_present().await?;
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
        simulate_machine_still_on_loopback_dns();
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
            core_instance: None,
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

    /// The tunnel permit is the widest rule this service installs: weight 8, `LocalInterface`
    /// only — no protocol, port, or app condition. WFP does not notice when the adapter behind
    /// that LUID dies, and `NetLuidIndex` is reused, so a permit that outlives the core it was
    /// granted for can end up naming whatever device receives that index next. It therefore
    /// expires with that core instance, and expiring must fail closed.
    #[test]
    fn a_tunnel_permit_expires_with_the_core_instance_it_was_granted_for() {
        let granted = CoreInstance {
            pid: 4242,
            restarts: 0,
        };
        let mut armed = Armed {
            intent: valid_intent(KillSwitchStatusMode::Locked, true),
            tun_luid: Some(0x1234_5678),
            core_instance: Some(granted),
            direct_endpoints: Vec::new(),
        };

        assert_eq!(
            rule_config_for(&armed, Some(granted)).tun_luid,
            Some(0x1234_5678),
            "the core that locked is still running"
        );

        for (label, current) in [
            (
                "watchdog respawn onto a recycled pid",
                Some(CoreInstance {
                    pid: 4242,
                    restarts: 1,
                }),
            ),
            (
                "watchdog respawn onto a new pid",
                Some(CoreInstance {
                    pid: 5150,
                    restarts: 1,
                }),
            ),
            (
                "the core was replaced without the watchdog",
                Some(CoreInstance {
                    pid: 5150,
                    restarts: 0,
                }),
            ),
            ("no core at all", None),
        ] {
            let config = rule_config_for(&armed, current);
            assert_eq!(config.tun_luid, None, "{label}");
            // Closed, not open: the fallback is exactly the pre-lock policy. The mode, the
            // app-scoped endpoint permit and the DNS block are untouched — only the tunnel
            // permit is gone — so losing the grant widens nothing.
            assert_eq!(config.mode, KillSwitchStatusMode::Locked, "{label}");
            let filters = wfp_model::expected_filters(&config);
            assert!(
                !filters
                    .iter()
                    .flat_map(|filter| filter.conditions.iter())
                    .any(|condition| matches!(condition, wfp_model::Condition::LocalInterface(_))),
                "{label}: a stale LUID must not stay installed"
            );
            assert!(
                filters
                    .iter()
                    .any(|filter| filter.conditions.contains(&wfp_model::Condition::AleAppId)),
                "{label}: the rest of the locked policy still stands"
            );
        }

        // An unidentified grant is never revived by a tick that also cannot identify a core.
        armed.core_instance = None;
        assert_eq!(rule_config_for(&armed, None).tun_luid, None);
    }

    /// P2: `lock` records the core instance and renders the permit from it. Reading the core
    /// twice let the two disagree — `status_snapshot_nonblocking` serves a cache whenever the
    /// core manager is busy — and a disagreement is permanent, because `tunnel_permit_luid`
    /// refuses to revive an unidentified grant. One read, threaded through, cannot disagree.
    #[test]
    fn locking_renders_the_permit_from_the_very_instance_it_recorded() {
        let running = CoreInstance {
            pid: 4242,
            restarts: 3,
        };
        for recorded in [
            None,
            Some(running),
            Some(CoreInstance {
                pid: 1,
                restarts: 0,
            }),
        ] {
            let armed = Armed {
                intent: valid_intent(KillSwitchStatusMode::Locked, true),
                tun_luid: Some(0x7777),
                core_instance: recorded,
                direct_endpoints: Vec::new(),
            };
            // This is exactly what `lock` now does: `armed.core_instance` and the render's
            // `current_core` are the same value.
            assert_eq!(
                rule_config_for(&armed, armed.core_instance).tun_luid,
                recorded.map(|_| 0x7777),
                "a render from the recorded instance agrees with it by construction"
            );
        }

        // The defect this replaces: read #1 missed the core, read #2 saw it. The permit is
        // retracted at the instant it is granted — and `None` can never match again, so the
        // machine stays Locked, verified and live with every application's traffic dropped
        // leaving the TUN.
        let stale = Armed {
            intent: valid_intent(KillSwitchStatusMode::Locked, true),
            tun_luid: Some(0x7777),
            core_instance: None,
            direct_endpoints: Vec::new(),
        };
        assert_eq!(rule_config_for(&stale, Some(running)).tun_luid, None);
        assert_eq!(
            rule_config_for(&stale, None).tun_luid,
            None,
            "and no later tick can revive it"
        );
    }

    /// The observability half: `mode` alone cannot tell "Locked and carrying traffic" from
    /// "Locked with the permit retracted". `tunnel_permit_rendered` reports what the last
    /// render actually installed.
    #[test]
    fn the_status_flag_tracks_what_the_last_render_installed() {
        let running = CoreInstance {
            pid: 90,
            restarts: 0,
        };
        let armed = Armed {
            intent: valid_intent(KillSwitchStatusMode::Locked, true),
            tun_luid: Some(0x99),
            core_instance: Some(running),
            direct_endpoints: Vec::new(),
        };

        let config = rule_config_rendering(&armed, Some(running));
        assert!(config.tun_luid.is_some());
        assert!(TUNNEL_PERMIT_RENDERED.load(Ordering::Relaxed));

        // Same mode, same `wanted`/`verified`/`live` — only this flag changes.
        let config = rule_config_rendering(&armed, None);
        assert_eq!(config.mode, KillSwitchStatusMode::Locked);
        assert!(config.tun_luid.is_none());
        assert!(!TUNNEL_PERMIT_RENDERED.load(Ordering::Relaxed));
    }

    /// P1: `live` is a staleness cache, and its budget has to cover a **successful** but slow
    /// watchdog tick. At 1.5 s it did not: one sleep (1 s) plus a verify that this module
    /// itself calls merely "pathological but reportable" at `WFP_SLOW_CALL` (2 s) already
    /// exceeds it, so a healthy machine reported `live: false` and the app read it as unhealthy.
    #[test]
    fn the_verify_cache_survives_a_slow_but_successful_watchdog_tick() {
        assert!(
            VERIFY_CACHE_TTL > WATCHDOG_PERIOD + WFP_SLOW_CALL,
            "the budget must cover a whole slow-but-successful refresh interval"
        );
        assert!(
            VERIFY_CACHE_TTL <= std::time::Duration::from_secs(10),
            "and stay far below the 25 s call timeout, so a wedged engine still reads dead"
        );

        let slow_tick = std::time::Instant::now()
            .checked_sub(WATCHDOG_PERIOD + WFP_SLOW_CALL)
            .expect("the test host has been up for more than three seconds");
        assert!(
            verify_reads_live(Some((slow_tick, true))),
            "a successful verify that merely took a long time is still alive"
        );

        // What the TTL must never soften.
        assert!(
            !verify_reads_live(Some((std::time::Instant::now(), false))),
            "a verify that actually failed is dead immediately, TTL or no TTL"
        );
        assert!(!verify_reads_live(None), "no verify has ever run");
        let expired = std::time::Instant::now()
            .checked_sub(VERIFY_CACHE_TTL + std::time::Duration::from_millis(1))
            .expect("the test host has been up for more than the TTL");
        assert!(
            !verify_reads_live(Some((expired, true))),
            "an answer older than the budget is stale, not live"
        );
    }

    #[tokio::test]
    #[serial]
    async fn lock_grants_the_tunnel_permit_against_the_running_core_and_restrict_revokes_it()
    -> Result<()> {
        cleanup().await;
        arm_bootstrap(&test_config(), "/opt/tono/mihomo", "owner-alice").await?;
        assert!(armed_guard().as_ref().unwrap().core_instance.is_none());

        lock(None).await?;
        let armed = armed_guard().clone().expect("armed");
        assert_eq!(armed.tun_luid, Some(0));
        assert_eq!(
            armed.core_instance,
            current_core_instance().await,
            "the grant names the core that was running when lock ran"
        );
        // No core runs behind a test build, so the grant is unidentified — and an unidentified
        // grant renders no tunnel permit, which is the fail-closed direction.
        assert!(armed.core_instance.is_none());
        assert!(render(&armed).await.tun_luid.is_none());

        restrict_bootstrap().await?;
        let armed = armed_guard().clone().expect("still armed");
        assert!(armed.tun_luid.is_none());
        assert!(
            armed.core_instance.is_none(),
            "the grant is given back with the LUID"
        );
        cleanup().await;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn release_is_refused_until_dns_restore_is_proven() -> Result<()> {
        cleanup().await;
        arm_bootstrap(&test_config(), "/opt/tono/mihomo", "owner-alice").await?;
        simulate_machine_still_on_loopback_dns();
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

    /// The S1 residual risk in miniature: a WFP call that never returns must produce a
    /// mappable error, and the abandoned blocking thread must keep the single-writer claim
    /// until the kernel call really comes back. The FFI is mock-gated off Windows, so the
    /// closure stands in for a wedged `Fwpm*` call — the ownership rules under test are the
    /// engine-independent part.
    #[tokio::test]
    #[serial]
    async fn a_wedged_engine_call_times_out_and_blocks_a_second_wfp_writer() -> Result<()> {
        let (release, blocked) = std::sync::mpsc::channel::<()>();
        let wedged = move || -> Result<()> {
            // Returns only when the test says so — the stand-in for a BFE that never answers.
            let _ = blocked.recv_timeout(std::time::Duration::from_secs(30));
            Ok(())
        };

        let timed_out =
            bounded_engine_call(std::time::Duration::from_millis(50), "install", wedged)
                .await
                .expect_err("a call that never returns must not be awaited forever");
        let message = format!("{timed_out:#}");
        assert!(message.contains(WFP_ENGINE_WEDGED_PREFIX), "{message}");
        assert!(message.contains("install"), "{message}");

        // The claim is still held by the running thread, so nothing may start a second WFP
        // transaction — the refusal names the operation that is stuck.
        let refused = bounded_engine_call(std::time::Duration::from_secs(5), "verify", || Ok(()))
            .await
            .expect_err("a second writer must be refused while the first is inside the kernel");
        let message = format!("{refused:#}");
        assert!(message.contains(WFP_ENGINE_WEDGED_PREFIX), "{message}");
        assert!(message.contains("install"), "{message}");

        // Only the abandoned call itself releases the claim, and it does so on its own thread.
        release.send(()).expect("the wedged call is still running");
        for _ in 0..300 {
            if engine_call_in_flight().is_none() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            engine_call_in_flight().is_none(),
            "the blocking thread must release the claim when the call finally returns"
        );
        bounded_engine_call(std::time::Duration::from_secs(5), "install", || Ok(())).await?;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn a_healthy_engine_call_leaves_no_claim_behind() -> Result<()> {
        bounded_engine_call(std::time::Duration::from_secs(5), "install", || Ok(())).await?;
        assert!(
            engine_call_in_flight().is_none(),
            "a completed call must not keep the next operation out"
        );
        let error = bounded_engine_call(
            std::time::Duration::from_secs(5),
            "verify",
            || -> Result<()> { bail!("engine said no") },
        )
        .await
        .expect_err("engine errors still propagate");
        assert!(format!("{error:#}").contains("engine said no"));
        assert!(engine_call_in_flight().is_none());
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

        // Establish the logical session. The approved set survives a mode change in memory so
        // a re-lock can re-render it, but the *permits* exist only while locked: dropping back
        // to Blocked renders none, so the mode change removes them by key rather than leaving
        // un-app-scoped holes open on a machine with no tunnel (see rule G).
        lock(None).await?;
        mark_verified("owner-alice").await?;
        let armed = armed_guard().clone().expect("still armed");
        assert_eq!(
            wfp_model::expected_filters(&render(&armed).await)
                .iter()
                .filter(|filter| filter.name.contains("DIRECT"))
                .count(),
            4,
            "each approved tuple must exist at ALE and outbound transport"
        );

        restrict_bootstrap().await?;
        let armed = armed_guard().clone().expect("still armed");
        assert_eq!(armed.direct_endpoints.len(), 2);
        assert!(
            !wfp_model::expected_filters(&render(&armed).await)
                .iter()
                .any(|filter| filter.name.contains("DIRECT")),
            "Protected Offline must not keep DIRECT permits installed"
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
