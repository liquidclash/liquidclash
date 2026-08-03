//! Connect orchestration (product-contract.md §6).
//!
//! Every privileged step goes through the Service IPC wrappers in
//! `core::service` — the owner/session machinery is never bypassed. The
//! fail-closed invariant: once the WFP policy exists, only Disconnect,
//! Sign Out, or Quit release it; everything else keeps blocking behind
//! `Protected Offline` plus the 2/5/10/20/30 s reconnect backoff.
//!
//! Concurrency: `connect_generation` (in `TonoInner`) is bumped by
//! disconnect, sign-out, node switches, and catalog-driven teardowns. An
//! in-flight attempt re-checks it at every stage boundary and exits with no
//! side effects — no `fail_connect`, no emit, no core action — when it
//! moved (H1).

use std::{future::Future, net::IpAddr, sync::Arc, time::Duration};

use clash_verge_logging::{Type, logging};
use clash_verge_service_ipc::{
    DnsProtectionStatus, KillSwitchConfig, KillSwitchStatus, KillSwitchStatusMode, ProxyEndpoint, ProxyProtocol,
    RuntimeBundle,
};
use tauri::AppHandle;
use tokio_util::sync::CancellationToken;
use tono_core::{
    EXIT_GROUP_NAME,
    config::{self, RuntimePorts, build_owned_runtime_with_ports, generate_controller_secret},
    connection::{ConnectStage, ConnectionStatus},
    node::ValidatedNode,
};

#[cfg(not(windows))]
use crate::core::{CoreManager, manager::RunningMode};
use crate::{
    core::service,
    process::AsyncHandler,
    tono::{
        audit::AuditEvent,
        bootstrap, commands,
        state::{AccountState, TonoState},
    },
};

/// §6.8 exit probe target.
const EXIT_PROBE_URL: &str = "https://www.gstatic.com/generate_204";
/// §6.8: the probe also proves fake-ip DNS via this lookup.
const FAKE_IP_LOOKUP: &str = "www.gstatic.com:443";
/// §6.4: controller readiness poll budget. Mihomo's controller is usually up within a few
/// hundred milliseconds, so the first polls run on a tight 50 ms grid before falling back to
/// the coarse 250 ms interval — the fixed grid alone overshot a typical readiness by ~200 ms.
/// The attempt count is sized so the 15 s deadline, not the counter, is the effective budget.
const VERSION_POLL_ATTEMPTS: u32 = 64;
const VERSION_POLL_FAST_ATTEMPTS: u32 = 8;
const VERSION_POLL_FAST_INTERVAL: Duration = Duration::from_millis(50);
const VERSION_POLL_INTERVAL: Duration = Duration::from_millis(250);
/// A localhost controller poll must never inherit the general 6 s HTTP timeout. Forty such
/// timeouts would turn the documented ~10 s readiness window into a multi-minute apparent hang.
const CONTROLLER_POLL_TIMEOUT: Duration = Duration::from_millis(750);
const CONTROLLER_READY_TIMEOUT: Duration = Duration::from_secs(15);
/// §6.5: TUN adapter / lock retry budget. The first WinTUN driver install
/// plus interface-alias propagation is slow (~10 s on real hardware, P0-12).
const LOCK_ATTEMPTS: u32 = 50;
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(200);
/// §6.7/§6.8 retry counts.
const VERIFY_ATTEMPTS: u32 = 3;
const VERIFY_RETRY_INTERVAL: Duration = Duration::from_millis(500);
/// `lookup_host` delegates to the OS resolver and has no Tokio timeout of its own. Bound every
/// lookup so a broken adapter/resolver cannot strand Connecting forever.
const DNS_LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);
/// One absolute budget covers service readiness, both possible Core starts (cold WinTUN + WFP),
/// controller/DNS verification, cloud-policy re-arm, and locking. Per-stage retries never reset
/// this clock. 45 s was too tight on real Windows: a first StartClash alone can approach the
/// Service's 60 s handler budget, and a cloud-policy second StartClash plus DNS would then race
/// the absolute deadline and look like a hang/failure even when the backend was still making
/// progress. 120 s keeps UI bounded while matching cold first-connect reality.
const CONNECT_TRANSACTION_TIMEOUT: Duration = Duration::from_secs(120);
/// UI budget for an explicit release. The ordered DNS → Core → WFP sequence runs in a detached
/// reconciliation task, so reaching this budget stops waiting but never cancels a safety step.
const EXPLICIT_RELEASE_TIMEOUT: Duration = Duration::from_secs(30);
/// The WFP model has a hard endpoint budget. The runtime DIRECT plan and its permits must be
/// generated from the same complete set; silently truncating only the permits creates selective
/// blackholes that look like random application hangs.
const MAX_DIRECT_ENDPOINTS: usize = 256;
/// network_events poll cadence while Connected.
const NETWORK_MONITOR_INTERVAL: Duration = Duration::from_secs(2);
/// P0-13: bursts of network events inside this window merge into a single
/// invalidation (interface-level filtering — GetBestRoute2 — is the
/// documented follow-up; the debounce covers the common route-flap storm).
const NETWORK_EVENT_DEBOUNCE: Duration = Duration::from_secs(2);
/// F2: exit-probe cadence while Connected (the Mac "9.17 h fake-green"
/// lesson — a silent tunnel must be caught by probing, not by watching).
const EXIT_PROBE_INTERVAL: Duration = Duration::from_secs(120);
/// F2: consecutive failures before the tunnel is declared dead.
pub const HEALTH_FAILURE_THRESHOLD: u32 = 2;

/// F2: while Connected, the barrier must be wanted, live, and fully
/// locked; anything else (or no answer) is unhealthy.
pub fn kill_switch_unhealthy(status: Option<&KillSwitchStatus>) -> bool {
    match status {
        Some(status) => !(status.wanted && status.live && status.mode == KillSwitchStatusMode::Locked),
        None => true,
    }
}

/// Connected is not healthy unless every currently known adapter is proven to use loopback DNS.
/// The Service status deliberately includes adapters that appeared after the original snapshot,
/// closing the first-netmon-sample race and covering a failed Windows notification registration.
pub fn protected_dns_unhealthy(status: Option<&DnsProtectionStatus>) -> bool {
    match status {
        Some(status) => {
            !(status.enabled && status.snapshot_present && status.adapters > 0 && status.last_error.is_none())
        }
        None => true,
    }
}

/// F2: threshold test shared by the kill-switch and exit-probe legs.
pub fn health_threshold_reached(consecutive_failures: u32) -> bool {
    consecutive_failures >= HEALTH_FAILURE_THRESHOLD
}

/// Spawned task futures are boxed into this trait object so a spawner's
/// async opaque type never embeds the spawned task's (the tasks re-enter
/// `attempt`, which would otherwise make the types infinitely recursive).
type BoxedTask = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

/// `attempt` returns a boxed future rather than being an `async fn`: the
/// network monitor and the reconnect loop re-enter it, and a concrete return
/// type keeps the async opaque-type graph finite.
type BoxedAttempt<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = Attempt> + Send + 'a>>;

/// Outcome of one connect attempt, distinguishing "never started" from
/// "started and failed" — only the latter runs the failure decision table.
enum Attempt {
    Connected,
    /// Guards rejected the attempt before any state changed (busy, no
    /// selection, suspended). No failure handling applies.
    GuardRejected(String),
    /// The transaction ran (or reached the service checks) and failed.
    Failed(String),
    /// The connect generation moved under us (disconnect / sign-out / node
    /// switch / catalog teardown). Exit without touching the FSM, the core,
    /// or the UI: the flow that bumped the generation owns the cleanup.
    Stale,
}

/// Why `run_stages` ended.
enum StageFailure {
    /// Generation moved; see [`Attempt::Stale`].
    Stale,
    /// The shared transaction deadline elapsed. The generation is retired before failure
    /// handling so any detached privileged IPC completion performs the stale-commit repair.
    TimedOut(String),
    Error(String),
}

impl StageFailure {
    /// Every stage funnels its errors through here, so the Service's stable WFP markers are
    /// translated once — whichever stage (arm, lock, release) surfaced them.
    fn error(err: impl std::fmt::Display) -> Self {
        let text = err.to_string();
        StageFailure::Error(map_wfp_engine_error(&text).unwrap_or(text))
    }
}

#[derive(Clone)]
struct ConnectTransaction {
    deadline: tokio::time::Instant,
    cancellation: CancellationToken,
}

impl ConnectTransaction {
    fn new(cancellation: CancellationToken) -> Self {
        Self {
            deadline: tokio::time::Instant::now() + CONNECT_TRANSACTION_TIMEOUT,
            cancellation,
        }
    }

    fn check(&self, stage: &'static str) -> Result<(), StageFailure> {
        if self.cancellation.is_cancelled() {
            return Err(StageFailure::Stale);
        }
        if tokio::time::Instant::now() >= self.deadline {
            return Err(StageFailure::TimedOut(format!(
                "connection transaction exceeded {CONNECT_TRANSACTION_TIMEOUT:?} during {stage}"
            )));
        }
        Ok(())
    }

    async fn wait<T>(&self, stage: &'static str, future: impl Future<Output = T>) -> Result<T, StageFailure> {
        self.check(stage)?;
        tokio::select! {
            biased;
            _ = self.cancellation.cancelled() => Err(StageFailure::Stale),
            result = tokio::time::timeout_at(self.deadline, future) => result.map_err(|_| {
                StageFailure::TimedOut(format!(
                    "connection transaction exceeded {CONNECT_TRANSACTION_TIMEOUT:?} during {stage}"
                ))
            }),
        }
    }
}

/// `tono_connect`: guard, then the full §6 transaction; any failure after
/// arm keeps blocking and schedules the protected reconnect.
pub async fn connect(state: Arc<TonoState>, app: AppHandle) -> Result<(), String> {
    {
        let inner = state.lock().await;
        match &inner.account_state {
            AccountState::Ready => {}
            AccountState::Suspended => return Err("account is suspended".to_string()),
            _ => return Err("not signed in".to_string()),
        }
        if inner.fsm.status().is_connected {
            return Err("already connected".to_string());
        }
        if inner.fsm.status().is_connecting {
            return Err("already connecting".to_string());
        }
    }
    match attempt(&state, &app).await {
        Attempt::Connected => Ok(()),
        Attempt::GuardRejected(err) => Err(err),
        Attempt::Stale => Err("connection superseded by a newer transition".to_string()),
        Attempt::Failed(err) => {
            let err = fail_connect(&state, &app, err).await;
            schedule_reconnect(&state, &app).await;
            Err(err)
        }
    }
}

/// One full connect attempt: guards → service checks → begin → stages.
/// Returns a boxed future (see [`BoxedAttempt`]); call sites `await` it as
/// before.
fn attempt<'a>(state: &'a Arc<TonoState>, app: &'a AppHandle) -> BoxedAttempt<'a> {
    Box::pin(attempt_inner(state, app))
}

async fn attempt_inner(state: &Arc<TonoState>, app: &AppHandle) -> Attempt {
    let (node, nodes, generation, cancellation) = match guard_snapshot(state).await {
        Ok(snapshot) => snapshot,
        Err(err) => return Attempt::GuardRejected(err),
    };
    let transaction = ConnectTransaction::new(cancellation);
    // L5: the clock starts at the top of the attempt, so even a
    // service-readiness failure leaves no orphan ConnectFail.
    let started = std::time::Instant::now();
    // F5 single-flight, latched BEFORE any service I/O: rapid repeated
    // clicks admit exactly one attempt to the service probe; the rest exit
    // here with no side effects (the real-machine double-probe this kills).
    {
        let mut inner = state.lock().await;
        let current_generation = inner.connect_generation;
        if !single_flight_begin(&mut inner.fsm, current_generation, generation) {
            if inner.connect_generation != generation {
                return Attempt::Stale;
            }
            return Attempt::GuardRejected("a connection transition is already in flight".to_string());
        }
        // F3: a fresh attempt resets the step record and clears the last
        // failure details (retry bookkeeping persists across attempts).
        inner.connect_steps = crate::tono::steps::initial_steps();
        inner.step_started_at = Some(started);
        inner.failed_stage = None;
        inner.connect_error = None;
        inner.connect_error_at_ms = None;
        inner.next_retry_at_ms = None;
        commands::emit_status(app, &commands::status_of(&inner));
    }

    state.audit().log(AuditEvent::ConnectBegin {
        node: node.name.clone(),
    });
    match transaction.wait("service readiness", ensure_service_ready()).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            // The kill switch may already be armed from a previous session, so this is a
            // transaction failure, not a guard rejection. `fail_connect` runs the decision
            // table and (pre-arm) releases the FSM cleanly.
            return Attempt::Failed(err);
        }
        Err(failure) => return attempt_from_stage_failure(state, generation, failure).await,
    }

    match run_stages(state, app, &node, &nodes, generation, started, &transaction).await {
        Ok(()) => Attempt::Connected,
        Err(StageFailure::Stale) => Attempt::Stale,
        Err(StageFailure::TimedOut(err)) => {
            retire_timed_out_generation(state, generation).await;
            Attempt::Failed(err)
        }
        Err(StageFailure::Error(err)) => Attempt::Failed(err),
    }
}

async fn attempt_from_stage_failure(state: &Arc<TonoState>, generation: u64, failure: StageFailure) -> Attempt {
    match failure {
        StageFailure::Stale => Attempt::Stale,
        StageFailure::TimedOut(error) => {
            retire_timed_out_generation(state, generation).await;
            Attempt::Failed(error)
        }
        StageFailure::Error(error) => Attempt::Failed(error),
    }
}

async fn retire_timed_out_generation(state: &Arc<TonoState>, generation: u64) {
    let mut inner = state.lock().await;
    if inner.connect_generation != generation {
        return;
    }
    // A first attempt may release a late unverified arm. A previously verified protected
    // reconnect keeps the barrier, matching the normal failure decision table.
    let release_late_commit = !inner.fsm.session_verified();
    // The abort-free variant: this handler frequently runs *inside* a registered connection
    // task (reconnect loop / monitor re-entry / switch), and aborting the registry here would
    // kill the caller before `fail_connect` + `schedule_reconnect` run, stranding Connecting.
    inner.retire_connection_generation(release_late_commit);
}

/// §6.1 guards: forced values live in the owned runtime; here we check the
/// account is ready (H2a — the reconnect path's only account gate), the
/// catalog is usable, the selection exists and passed admission, and no
/// transaction is in flight. Pure read — no state changes.
async fn guard_snapshot(
    state: &Arc<TonoState>,
) -> Result<(ValidatedNode, Vec<ValidatedNode>, u64, CancellationToken), String> {
    if state.release_in_progress().await {
        return Err(format!(
            "{RELEASE_RECONCILING_PREFIX}: network protection release is still reconciling; wait before reconnecting"
        ));
    }
    let inner = state.lock().await;
    match &inner.account_state {
        AccountState::Ready => {}
        AccountState::Suspended => return Err("account is suspended".to_string()),
        _ => return Err("not signed in".to_string()),
    }
    let status = inner.fsm.status();
    if status.is_connecting || status.is_connected || status.is_disconnecting {
        return Err("a connection transition is already in flight".to_string());
    }
    if inner.catalog_requires_choice {
        return Err("the selected node left the catalog; pick a server again".to_string());
    }
    if inner.nodes.is_empty() {
        return Err("the exit catalog is not available yet".to_string());
    }
    let selected = inner
        .selected_node
        .clone()
        .ok_or_else(|| "select a server first".to_string())?;
    let node = inner
        .nodes
        .iter()
        .find(|node| node.name == selected)
        .cloned()
        .ok_or_else(|| "the selected server is not in the catalog".to_string())?;
    Ok((
        node,
        inner.nodes.clone(),
        inner.connect_generation,
        inner.connect_cancellation.clone(),
    ))
}

/// Stable error-code prefix the frontend's i18n keys off: the Service has
/// a privileged operation in flight (install/repair pending, possibly a
/// UAC prompt nobody approved).
pub const SERVICE_BUSY_PREFIX: &str = "TONO_SERVICE_BUSY";
/// Disconnect/Sign-out/Quit release is still finishing. Connect must wait — racing would let
/// a late release tear down a fresh StartClash (the P0 fixed in the final review).
pub const RELEASE_RECONCILING_PREFIX: &str = "TONO_RELEASE_RECONCILING";
/// Installed Service is below protocol revision 9 (Test 5 or older).
pub const SERVICE_TOO_OLD_PREFIX: &str = "TONO_SERVICE_TOO_OLD";
/// The Service's WFP engine call did not return inside its budget — the Base Filtering Engine
/// is wedged, typically behind a third-party security product's filter hooks. Distinct from
/// [`BFE_NOT_RUNNING_PREFIX`] because the user action differs (reboot / remove the hook versus
/// simply starting the service). The Service nests these inside its own context string, so
/// they are matched by `contains`, not `starts_with`.
pub const WFP_ENGINE_WEDGED_PREFIX: &str = "TONO_WFP_ENGINE_WEDGED";
/// Windows' Base Filtering Engine service is not running, so no kill switch can be installed.
pub const BFE_NOT_RUNNING_PREFIX: &str = "TONO_BFE_NOT_RUNNING";

/// Translate the Service's stable WFP markers into an actionable message. Returns `None` for
/// every other error so callers keep the original diagnostic text.
pub fn map_wfp_engine_error(text: &str) -> Option<String> {
    if text.contains(BFE_NOT_RUNNING_PREFIX) {
        return Some(format!(
            "{BFE_NOT_RUNNING_PREFIX}: Windows 基础筛选引擎 (BFE) 未运行，无法安装网络保护；请以管理员身份运行 `sc start BFE` 后重试"
        ));
    }
    if text.contains(WFP_ENGINE_WEDGED_PREFIX) {
        return Some(format!(
            "{WFP_ENGINE_WEDGED_PREFIX}: Windows 防火墙引擎无响应（常见于第三方安全软件挂钩 WFP）；请重启电脑，若仍然如此请暂时退出杀毒/防火墙软件后重试"
        ));
    }
    None
}

/// Layer the Run State's raw English onto a stable, actionable message.
/// Everything else keeps the original detail for diagnostics.
pub fn map_service_ready_error(err: &anyhow::Error) -> String {
    let text = format!("{err:#}");
    if text.contains("service operation already running")
        || text.contains("previous privileged service operation may still be running")
    {
        return format!(
            "{SERVICE_BUSY_PREFIX}: Tono Service 正在安装/修复中，请检查是否有待授权的管理员提示；若无反应请重启 Tono"
        );
    }
    format!("Tono Service is not ready: {text}")
}

/// Whether a lock failure is the expected "WinTUN still coming up" class that must be
/// retried, versus a permanent failure that would only burn the connect budget if looped.
///
/// Permanent errors (owner mismatch, not armed, WFP engine failure, auth) must not be
/// retried: each attempt is a full Service lifecycle IPC (up to 65 s), and blind retries
/// after a transport timeout can also race a still-running lock on the Service side.
pub fn is_retryable_lock_error(message: &str) -> bool {
    let lower = message.to_lowercase();
    // Primary: ConvertInterfaceAliasToLuid failed because the adapter is not registered yet.
    if lower.contains("did not resolve to a luid") {
        return true;
    }
    // validate_tunnel_luid refuses a non-tunnel LUID while WinTUN is still renaming/initializing.
    if lower.contains("is not a tunnel device") {
        return true;
    }
    // Transient service lifecycle contention while StartClash is still materializing.
    if lower.contains("service unavailable")
        || lower.contains("operation already")
        || lower.contains("busy")
    {
        return true;
    }
    false
}

/// Tono has no sidecar: the Service must be Ready and speak the kill switch
/// protocol (rev 5 arm/lock + rev 6 release, C1).
async fn ensure_service_ready() -> Result<(), String> {
    service::tono_service_ready()
        .await
        .map_err(|err| map_service_ready_error(&err))?;
    match service::tono_probe_kill_switch_release_support().await {
        Ok(true) => Ok(()),
        Ok(false) => Err(format!(
            "{SERVICE_TOO_OLD_PREFIX}: Tono Service is too old for this App (protocol revision below the system-safety floor); reinstall/repair the Tono Service from this installer"
        )),
        Err(err) => Err(format!("cannot query the Tono Service protocol: {err}")),
    }
}

/// The §6 stage sequence, from endpoint computation to `Connected`. The
/// generation is re-checked at every stage boundary; a moved generation
/// ends the transaction with no side effects.
async fn run_stages(
    state: &Arc<TonoState>,
    app: &AppHandle,
    node: &ValidatedNode,
    nodes: &[ValidatedNode],
    generation: u64,
    started: std::time::Instant,
    transaction: &ConnectTransaction,
) -> Result<(), StageFailure> {
    // §6.2: proxy endpoints (public IPv4/port/TCP) from the selected node;
    // the bootstrap API hosts are the only control-plane recovery channel.
    let proxy_endpoints = vec![proxy_endpoint_of(node)];

    transaction.check("preparing service")?;
    set_stage(state, app, ConnectStage::PreparingService, generation, false, started).await?;

    // Capture both the policy and its physical egress before WinTUN changes the default route.
    // Re-reading either after the first Core start can select the Tono adapter itself and makes
    // the runtime plan disagree with the WFP preflight that was actually performed.
    let traffic_policy = { state.lock().await.traffic_policy.clone() };
    let needs_physical_interface = traffic_policy.as_ref().is_some_and(|policy| {
        !policy.domains.is_empty() || !policy.media_endpoints.is_empty() || !policy.web_domains.is_empty()
    });

    // The five preparation probes are independent of each other and all read-only /
    // cancellation-safe (the two port binds are released immediately; the core-path query is a
    // read IPC), so they run concurrently under one transaction wait instead of paying their
    // worst cases back to back (the bootstrap DNS lookup alone budgets 2 s):
    //  - F1: pinned bootstrap IPs merged with the live resolution — the WFP bootstrap permit
    //    must not depend on the system resolver once blocking starts, and the app's own API
    //    client is pinned to the same addresses (see `tono::bootstrap` / `tono::transport`).
    //  - The physical egress interface, still strictly before the first Core start (above).
    //  - Tono is TUN-only, so it does not expose Mihomo's legacy mixed listener. A fresh
    //    controller port eliminates collisions with another proxy or a stale 9090 listener.
    //  - DNS stays fixed at loopback:53 because Windows adapter protection points resolvers
    //    there, therefore prove both TCP and UDP are available before installing WFP rather
    //    than timing out after the arm.
    //  - The Service-side core binary path validation.
    let (bootstrap_api_hosts, physical_interface_probe, controller_port, dns_preflight, core_path) = transaction
        .wait("preparing service", async {
            tokio::join!(
                bootstrap_hosts(),
                async {
                    if needs_physical_interface {
                        Some(detect_physical_interface().await)
                    } else {
                        None
                    }
                },
                allocate_controller_port(),
                preflight_dns_listener(),
                service::tono_core_binary_path(),
            )
        })
        .await?;
    let controller_port = controller_port.map_err(StageFailure::error)?;
    dns_preflight.map_err(StageFailure::error)?;
    let core_path = core_path.map_err(StageFailure::error)?;
    let physical_interface = match physical_interface_probe {
        Some(interface) => {
            let interface = interface.map_err(StageFailure::error)?;
            tono_core::config::DirectPlan::validate_physical_interface(&interface).map_err(StageFailure::error)?;
            Some(interface)
        }
        None => None,
    };
    let runtime_ports = RuntimePorts {
        mixed_port: 0,
        controller_port,
    };

    // §5: the owned runtime carries a fresh random controller secret; only
    // the redacted copy may touch disk.
    let secret = generate_controller_secret();
    let runtime =
        build_owned_runtime_with_ports(nodes, &node.name, &secret, None, runtime_ports).map_err(StageFailure::error)?;
    write_redacted_copy(state, &runtime.redacted_yaml()).await;
    let bundle = RuntimeBundle {
        yaml: runtime.yaml().to_string(),
        assets: Vec::new(),
        remote_providers: Vec::new(),
        core_path: core_path.to_string_lossy().into_owned(),
    };
    let kill_switch = KillSwitchConfig {
        tunnel_interface: config::TUN_DEVICE_NAME.to_string(),
        proxy_endpoints: proxy_endpoints.clone(),
        bootstrap_api_hosts: bootstrap_api_hosts.clone(),
        // Omission = clear (service-side): the first start never carries
        // direct permits; the cloud-policy stage adds them later if needed.
        direct_endpoints: Vec::new(),
    };

    // §6.3: startingKillSwitch — the Service persists intent, installs the
    // bootstrap WFP policy, writes the runtime copy, and starts the core;
    // a failure inside is fail-closed on the Service side.
    set_stage(state, app, ConnectStage::StartingKillSwitch, generation, false, started).await?;
    ensure_fresh(state, generation).await?;
    transaction
        .wait(
            "starting kill switch and core",
            start_core_cancellation_safe(state, bundle, kill_switch, generation),
        )
        .await??;

    // The WFP policy exists from here on: the machine is fail-closed.
    {
        let mut inner = state.lock().await;
        if inner.connect_generation != generation {
            // A disconnect/switch bumped us while the StartClash IPC was in
            // flight; it cannot be retracted. Patch the late arm (H-1).
            drop(inner);
            return Err(stale_after_arm(state).await);
        }
        inner.fsm.mark_kill_switch_armed();
        inner.controller_secret = Some(secret.clone());
        inner.controller_port = Some(controller_port);
        commands::emit_status(app, &commands::status_of(&inner));
    }

    // §6.4: startingTunnel — poll the controller (≤ 40 × 250 ms).
    set_stage(state, app, ConnectStage::StartingTunnel, generation, true, started).await?;
    transaction
        .wait("controller readiness", wait_controller(&secret, controller_port))
        .await?
        .map_err(StageFailure::error)?;

    // §6.5+§6.6: lockingTraffic — the lock call doubles as the TUN adapter
    // existence check and is idempotent on the Service side (≤ 20 × 100 ms).
    set_stage(state, app, ConnectStage::LockingTraffic, generation, true, started).await?;
    transaction
        .wait("locking traffic", lock_kill_switch_with_retries())
        .await?
        .map_err(StageFailure::error)?;

    // Build 28: applyingCloudPolicy — resolve the cloud WeChat-DIRECT
    // policy through the now-running controller and, when a plan exists,
    // re-arm with its endpoint permits before the DIRECT-capable runtime
    // starts (permit strictly before selector, via a second StartClash).
    set_stage(state, app, ConnectStage::ApplyingCloudPolicy, generation, true, started).await?;
    let secret = transaction
        .wait(
            "cloud traffic policy",
            apply_cloud_policy(
                state,
                app,
                &node,
                nodes,
                generation,
                &secret,
                controller_port,
                &proxy_endpoints,
                &bootstrap_api_hosts,
                traffic_policy,
                physical_interface,
            ),
        )
        .await??;

    // §6.7: securingDNS — snapshot + point resolvers at loopback, then prove
    // an ordinary lookup returns a fake-ip address.
    set_stage(state, app, ConnectStage::SecuringDns, generation, true, started).await?;
    transaction
        .wait(
            "enabling protected DNS",
            enable_dns_cancellation_safe(state, generation),
        )
        .await??;
    if state.lock().await.connect_generation != generation {
        return Err(stale_after_dns(state).await);
    }
    transaction
        .wait("fake-IP verification", verify_fake_ip())
        .await?
        .map_err(StageFailure::error)?;

    // §6.8: checkingExit — probe generate_204 through the Tono-Exit group.
    set_stage(state, app, ConnectStage::CheckingExit, generation, true, started).await?;
    transaction
        .wait("exit verification", probe_exit(&secret, controller_port))
        .await?
        .map_err(StageFailure::error)?;

    // §6.9: verifyingTraffic — the barrier must be wanted, live, and locked.
    set_stage(state, app, ConnectStage::VerifyingTraffic, generation, true, started).await?;
    let mut kill_status = transaction
        .wait("kill-switch verification", verify_locked())
        .await?
        .map_err(StageFailure::error)?;

    // The durable logical-session latch is committed only after every existing check and a
    // final generation guard. A failure remains an ordinary connect failure.
    ensure_fresh(state, generation).await?;
    transaction
        .wait("committing verified session", service::tono_mark_kill_switch_verified())
        .await?
        .map_err(StageFailure::error)?;
    kill_status.verified = true;

    // §6.10: only now Connected; monitors start.
    {
        let mut inner = state.lock().await;
        if inner.connect_generation != generation {
            drop(inner);
            return Err(stale_after_arm(state).await);
        }
        inner.kill_switch = Some(kill_status);
        inner.fsm.mark_session_verified();
        inner.fsm.connect_succeeded().map_err(StageFailure::error)?;
        // M4 seeds must reset on *every* success, not only on disconnect: a
        // reconnect's own StartClash always changes the core pid and bumps
        // the netmon counter, so comparing against pre-reconnect values made
        // the fresh monitor's first poll re-invalidate immediately — a
        // self-sustaining connect/teardown loop. Clearing them re-enters the
        // documented "first sample seeds without firing" path.
        inner.network_events_counter = None;
        inner.last_core_pid = None;
        inner.last_restart_count = None;
        // F3: every step completed; retry bookkeeping resets.
        let elapsed = inner
            .step_started_at
            .map(|at| at.elapsed().as_millis() as u64)
            .unwrap_or(0);
        crate::tono::steps::complete_all(&mut inner.connect_steps, elapsed);
        inner.retry_attempt = 0;
        inner.next_retry_at_ms = None;
        commands::emit_status(app, &commands::status_of(&inner));
    }
    state.audit().log(AuditEvent::ConnectOk {
        node: node.name.clone(),
        elapsed_ms: started.elapsed().as_millis() as u64,
    });
    spawn_network_monitor(state, app).await;
    Ok(())
}

/// The generation guard used between the long I/O steps.
async fn ensure_fresh(state: &Arc<TonoState>, generation: u64) -> Result<(), StageFailure> {
    if state.lock().await.connect_generation != generation {
        return Err(StageFailure::Stale);
    }
    Ok(())
}

/// Keep a mutating StartClash request alive if its reconnect/switch parent is aborted. Dropping a
/// direct IPC future can discard the response while the Service still commits; this detached child
/// always reaches the generation check and patches a late arm for releasing transitions.
async fn start_core_cancellation_safe(
    state: &Arc<TonoState>,
    bundle: RuntimeBundle,
    kill_switch: KillSwitchConfig,
    generation: u64,
) -> Result<(), StageFailure> {
    let mutation_guard = state.begin_connect_mutation().await;
    if state.lock().await.connect_generation != generation {
        drop(mutation_guard);
        return Err(StageFailure::Stale);
    }
    let task_state = Arc::clone(state);
    let task = tokio::spawn(async move {
        let _mutation_guard = mutation_guard;
        service::tono_start_core_with_kill_switch(bundle, kill_switch)
            .await
            .map_err(StageFailure::error)?;
        if task_state.lock().await.connect_generation != generation {
            return Err(stale_after_arm(&task_state).await);
        }
        Ok(())
    });
    task.await
        .map_err(|error| StageFailure::error(format!("StartClash reconciliation task failed: {error}")))?
}

/// Cancellation-safe counterpart for DNS enable. A disconnect may restore and release while an
/// old enable is still in flight; the detached child restores again after that late commit.
async fn enable_dns_cancellation_safe(state: &Arc<TonoState>, generation: u64) -> Result<(), StageFailure> {
    let mutation_guard = state.begin_connect_mutation().await;
    if state.lock().await.connect_generation != generation {
        drop(mutation_guard);
        return Err(StageFailure::Stale);
    }
    let task_state = Arc::clone(state);
    let task = tokio::spawn(async move {
        let _mutation_guard = mutation_guard;
        service::tono_enable_protected_dns()
            .await
            .map_err(StageFailure::error)?;
        if task_state.lock().await.connect_generation != generation {
            return Err(stale_after_dns(&task_state).await);
        }
        Ok(())
    });
    task.await
        .map_err(|error| StageFailure::error(format!("DNS reconciliation task failed: {error}")))?
}

/// H-1 decision: a stale exit only patches the late arm when the StartClash
/// IPC actually returned success (a failed IPC never armed anything) *and*
/// the generation bump came from a releasing flow (disconnect / sign-out /
/// quit) — a node switch or catalog teardown re-arms or keeps the barrier,
/// so releasing here would tear down their protection instead.
pub fn stale_exit_needs_release(start_clash_committed: bool, release_intent: bool) -> bool {
    start_clash_committed && release_intent
}

/// A stale exit past a committed StartClash (H-1): the IPC cannot be
/// retracted and the bumper's release may have run before the Service
/// committed, so patch the late arm with one best-effort owner-gated
/// release (idempotent, no session needed).
///
/// Chosen over join-waiting the in-flight attempt inside disconnect /
/// sign-out: the join would serialize the user's release behind a
/// StartClash lifecycle IPC of up to ~30 s, while this patch is bounded and
/// order-safe by construction — it runs strictly after the arm commit it
/// patches, and is idempotent against the bumper's own release.
async fn stale_after_arm(state: &Arc<TonoState>) -> StageFailure {
    let release_intent = { state.lock().await.release_on_stale };
    if stale_exit_needs_release(true, release_intent) {
        logging!(
            warn,
            Type::Service,
            "Tono: 连接代际失效于 StartClash 之后，补一次 stop + owner-gated release 拆除迟到 core/arm"
        );
        // A late StartClash starts both WFP and the Core. The original releasing flow may have
        // completed before that commit, so releasing WFP alone would leave the TUN Core running.
        // Stop is best-effort, matching `release_explicit`; release remains owner-gated and
        // idempotent even if the session was already cleared.
        let _ = service::tono_stop_core(false).await;
        let _ = service::tono_release_kill_switch().await;
    }
    StageFailure::Stale
}

/// A stale DNS enable needs one extra rollback before WFP may be released. A disconnect can
/// restore DNS while the old enable IPC is still in flight; if that enable commits afterwards,
/// releasing WFP alone strands the machine on loopback DNS with no resolver. Node-switch
/// invalidations deliberately keep DNS protected because their replacement transaction owns it.
async fn stale_after_dns(state: &Arc<TonoState>) -> StageFailure {
    let release_intent = { state.lock().await.release_on_stale };
    if release_intent {
        if let Err(error) = service::tono_restore_protected_dns().await {
            logging!(
                error,
                Type::Service,
                "Tono: 连接代际失效于 DNS 启用之后，但 DNS 恢复失败；保留 WFP 保护: {error:#}"
            );
            return StageFailure::Stale;
        }
        return stale_after_arm(state).await;
    }
    StageFailure::Stale
}

/// What a connect failure does, decided purely (§6 decision table + the
/// raced-disconnect rule). Exhaustively unit-tested; `fail_connect` only
/// executes the plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailurePlan {
    /// Latch the FSM armed flag before the decision table runs.
    pub mark_armed: bool,
    /// Stop the core: `Some(false)` keeps WFP armed, `Some(true)` releases,
    /// `None` leaves the core alone entirely.
    pub stop_core: Option<bool>,
    /// Restrict to the bootstrap recovery channel after the stop.
    pub restrict_bootstrap: bool,
}

pub fn plan_failure(armed: bool, session_verified: bool, was_disconnecting: bool) -> FailurePlan {
    if was_disconnecting {
        // A disconnect is in flight and owns the release sequence end to
        // end; the failing transaction must not double it.
        FailurePlan {
            mark_armed: false,
            stop_core: None,
            restrict_bootstrap: false,
        }
    } else if armed && session_verified {
        FailurePlan {
            mark_armed: true,
            stop_core: Some(false),
            restrict_bootstrap: true,
        }
    } else {
        // §6: failure before the WFP policy exists is a full release.
        FailurePlan {
            mark_armed: false,
            stop_core: Some(true),
            restrict_bootstrap: false,
        }
    }
}

/// Whether the explicit-release sequence may attempt a session-gated core
/// stop before the owner-gated release. Only a live session can stop; the
/// release itself never depends on one (C1: Protected Offline's session is
/// long gone).
#[cfg(any(not(windows), test))]
pub fn stop_core_before_release(core_active: bool, session_active: bool) -> bool {
    core_active && session_active
}

/// The §6 failure decision table, executing [`plan_failure`]. After arm:
/// stop the core, keep blocking (restrict to the bootstrap channel),
/// Protected Offline. Before arm: full release.
async fn fail_connect(state: &Arc<TonoState>, app: &AppHandle, err: String) -> String {
    logging!(error, Type::Service, "Tono: 连接事务失败: {err}");
    let observed = service::tono_kill_switch_status().await.ok();
    let (plan, stage, action, armed) = {
        let mut inner = state.lock().await;
        if let Some(status) = &observed {
            inner.kill_switch = Some(status.clone());
        }
        let stage = inner.fsm.status().stage;
        let armed = observed
            .as_ref()
            .map(|status| status.wanted)
            .unwrap_or(inner.fsm.kill_switch_armed());
        let was_disconnecting = inner.fsm.status().is_disconnecting;
        let session_verified = observed
            .as_ref()
            .map(|status| status.verified)
            .unwrap_or(inner.fsm.session_verified());
        if session_verified {
            inner.fsm.mark_session_verified();
        }
        let plan = plan_failure(armed, session_verified, was_disconnecting);
        let action: &'static str = if was_disconnecting {
            "racedDisconnect"
        } else if armed && session_verified {
            "keepBlockingAndReconnect"
        } else {
            "fullRelease"
        };
        if plan.mark_armed {
            inner.fsm.mark_kill_switch_armed();
        } else if armed && !session_verified && !was_disconnecting {
            // Keep reality visible until the required full release actually succeeds.
            inner.fsm.mark_kill_switch_armed();
        }
        if !was_disconnecting && (session_verified || !armed) {
            // Drives the FSM to Protected Offline (armed) or releases it
            // (pre-arm), mirroring the plan.
            inner.fsm.connect_failed();
        }
        inner.controller_secret = None;
        inner.controller_port = None;
        // F3: the in-flight step is failed (never completed); the error is
        // sanitized before it is stored for the UI.
        let step_elapsed = inner
            .step_started_at
            .map(|at| at.elapsed().as_millis() as u64)
            .unwrap_or(0);
        crate::tono::steps::fail_current(&mut inner.connect_steps, step_elapsed);
        inner.failed_stage = stage.map(commands::stage_key);
        inner.connect_error = Some(crate::tono::audit::redact(&err));
        inner.connect_error_at_ms = Some(commands::epoch_millis());
        if plan.mark_armed {
            inner.retry_attempt += 1;
        }
        (plan, stage, action, armed)
    };
    state.audit().log(AuditEvent::ConnectFail {
        stage: stage.map(commands::stage_key),
        error: err.clone(),
        action,
    });
    if plan.mark_armed {
        state
            .audit()
            .log(AuditEvent::ProtectedOffline { reason: "connectFail" });
    }

    if plan.stop_core == Some(true) && armed {
        match release_explicit(state, app).await {
            Ok(()) => {
                state.lock().await.fsm.connect_failed();
            }
            Err(release_error) => {
                let mut inner = state.lock().await;
                inner.fsm.initial_release_failed();
                inner.connect_error = Some(crate::tono::audit::redact(&format!("{err}; {release_error}")));
            }
        }
    } else if let Some(release) = plan.stop_core {
        let _ = service::tono_stop_core(release).await;
    }
    if plan.restrict_bootstrap {
        let _ = service::tono_restrict_bootstrap().await;
    }

    let inner = state.lock().await;
    commands::emit_status(app, &commands::status_of(&inner));
    err
}

/// Explicit user release (Disconnect / Sign Out / Quit, §6; C1).
///
/// Windows executes DNS restore → matching Core stop/retire → WFP removal inside one owner-gated
/// Service handler, including from Protected Offline where the arming session is gone. Every
/// caller joins one App-side operation; its UI deadline never cancels the worker. A failed release
/// keeps the system armed and surfaces an error.
pub async fn release_explicit(state: &Arc<TonoState>, app: &AppHandle) -> Result<(), String> {
    let (operation, is_new) = state.begin_release().await;
    if is_new {
        let task_state = Arc::clone(state);
        let task_app = app.clone();
        let worker_state = Arc::clone(state);
        let worker_app = app.clone();
        let worker =
            tauri::async_runtime::spawn(async move { run_explicit_release_sequence(&worker_state, &worker_app).await });
        let supervised_operation = Arc::clone(&operation);
        AsyncHandler::spawn(move || async move {
            let result = worker
                .await
                .map_err(|error| format!("release reconciliation task failed: {error}"))
                .and_then(|result| result);
            if let Err(message) = &result {
                task_state
                    .audit()
                    .log(AuditEvent::ReleaseFail { error: message.clone() });
                logging!(error, Type::Service, "Tono: 安全释放对账失败: {message}");
            }
            supervised_operation.complete(result);
            task_state.finish_release(supervised_operation.id()).await;
            // A timed-out caller may no longer be present to repaint. Publish the final state (or
            // the still-protected failure state) after the coordinator has settled.
            let inner = task_state.lock().await;
            commands::emit_status(&task_app, &commands::status_of(&inner));
        });
    }

    match tokio::time::timeout(EXPLICIT_RELEASE_TIMEOUT, operation.wait()).await {
        Ok(result) => result,
        Err(_) => Err(format!(
            "release exceeded {EXPLICIT_RELEASE_TIMEOUT:?}; ordered background reconciliation continues and protection is assumed on until proven otherwise"
        )),
    }
}

/// The release worker is never owned by one UI call. On Windows the owner-gated Service route is
/// already the transaction boundary: under one lifecycle lock it proves DNS restoration, stops
/// and retires the matching Core, then removes WFP. Calling those as three App-owned IPCs would
/// recreate a cancellation window between the steps. Other platforms retain their existing
/// helper sequence until their Service route provides the same complete stop semantics.
async fn run_explicit_release_sequence(state: &Arc<TonoState>, app: &AppHandle) -> Result<(), String> {
    // Wait for detached StartClash/DNS commits that began before the release generation bump.
    // Keeping this guard through the Service call also prevents a stale mutation from starting
    // between the wait and the atomic DNS/Core/WFP transaction.
    let _release_guard = state.begin_privileged_release().await;

    #[cfg(windows)]
    let status = service::tono_release_kill_switch()
        .await
        .map_err(|error| format!("kill switch release failed; protection stays on: {error}"))?;

    #[cfg(not(windows))]
    let status = {
        service::tono_restore_protected_dns()
            .await
            .map_err(|error| format!("DNS restore failed; protection stays on: {error}"))?;
        let core_active = matches!(*CoreManager::global().get_running_mode(), RunningMode::Service);
        if stop_core_before_release(core_active, service::tono_session_live()) {
            let _ = service::tono_stop_core(false).await;
        }
        service::tono_release_kill_switch()
            .await
            .map_err(|error| format!("kill switch release failed; protection stays on: {error}"))?
    };

    if status.wanted || status.live {
        return Err(format!(
            "kill switch release returned an armed state (wanted={}, live={})",
            status.wanted, status.live
        ));
    }

    let mut inner = state.lock().await;
    inner.kill_switch = Some(status);
    inner.controller_secret = None;
    inner.controller_port = None;
    inner.network_events_counter = None;
    inner.last_core_pid = None;
    inner.last_restart_count = None;
    // Also closes a caller that reached its UI budget and temporarily surfaced Protected
    // Offline; this transition is allowed only after the Service proved WFP is gone. A new
    // connect cannot race this commit because `guard_snapshot` rejects while the coordinator is
    // populated.
    inner.fsm.sign_out_or_quit();
    commands::emit_status(app, &commands::status_of(&inner));
    Ok(())
}

/// Schedule the protected auto-reconnect (2/5/10/20/30 s, §6). The delay is
/// handed out only while idle in Protected Offline, and never when the
/// catalog is waiting for a fresh user choice.
pub async fn schedule_reconnect(state: &Arc<TonoState>, app: &AppHandle) {
    let mut inner = state.lock().await;
    if !reconnect_allowed(
        inner.catalog_requires_choice,
        inner.fsm.status(),
        inner.fsm.kill_switch_armed(),
    ) {
        return;
    }
    if inner
        .tasks
        .reconnect
        .as_ref()
        .is_some_and(|handle| !handle.inner().is_finished())
    {
        return;
    }
    let Some(delay) = inner.fsm.next_reconnect_delay() else {
        return;
    };
    let task_state = state.clone();
    let task_app = app.clone();
    // The task future is boxed into a trait object so this function's opaque
    // type never embeds the reconnect loop's (which re-enters `attempt`).
    let handle = AsyncHandler::spawn(move || Box::pin(reconnect_loop(task_state, task_app, delay)) as BoxedTask);
    inner.tasks.reconnect = Some(handle);
    // F3: expose the scheduled deadline to the UI.
    inner.next_retry_at_ms = Some(commands::epoch_millis() + delay.as_millis() as i64);
    state.audit().log(AuditEvent::ReconnectScheduled {
        delay_ms: delay.as_millis() as u64,
    });
}

/// Whether a protected reconnect may run: the barrier is up, the machine is
/// idle in Protected Offline, and the catalog is not waiting for the user.
pub fn reconnect_allowed(requires_choice: bool, status: &ConnectionStatus, kill_switch_armed: bool) -> bool {
    kill_switch_armed
        && !requires_choice
        && status.is_protection_blocked
        && !status.is_connected
        && !status.is_connecting
        && !status.is_disconnecting
}

/// Whether sign-out must run the explicit-release sequence before clearing
/// account state (§2/§6): anything that could hold protection counts —
/// including an in-flight connect (M-1: disconnect's guard and quit_release
/// already include it; sign-out must not be the exception).
pub fn sign_out_needs_release(status: &ConnectionStatus, kill_switch_armed: bool) -> bool {
    kill_switch_armed
        || status.is_connected
        || status.is_connecting
        || status.is_protection_blocked
        || status.is_disconnecting
}

/// F3: `tono_retry_now` is a success-no-op in these states; anything else
/// falls through to the normal reconnect predicate (`reconnect_allowed`).
pub fn retry_now_is_noop(status: &ConnectionStatus) -> bool {
    status.is_connected || status.is_connecting
}

/// F5 single-flight predicate (called with the state lock already held):
/// begin the transaction only when the generation matches *and* no tunnel
/// or transaction exists. Two racing attempts calling this back-to-back
/// produce exactly one `true` — the observable proof that only one of them
/// enters `run_stages`.
pub fn single_flight_begin(
    fsm: &mut tono_core::connection::ConnectionFsm,
    current_generation: u64,
    captured_generation: u64,
) -> bool {
    if current_generation != captured_generation {
        return false;
    }
    if fsm.status().is_connecting || fsm.status().is_connected {
        return false;
    }
    fsm.begin_connect();
    true
}

/// What selecting a server does to the connection machinery (H1/M2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectAction {
    /// Same node, no pending catalog choice: the command is a pure no-op —
    /// generation, tasks, and the H-1 intent bit stay untouched.
    Noop,
    /// Selection state updates only (new pick while idle); no transaction,
    /// no generation bump, no intent write.
    UpdateOnly,
    /// Derive the §6 node-switch transaction.
    Switch,
    /// Schedule a protected reconnect (M5: also when a vanished node's
    /// replacement was just picked, i.e. `requires_choice` cleared).
    Reconnect,
}

pub fn select_action(
    changed: bool,
    requires_choice: bool,
    status: &ConnectionStatus,
    kill_switch_armed: bool,
) -> SelectAction {
    if !changed && !requires_choice {
        return SelectAction::Noop;
    }
    if changed && (status.is_connected || status.is_connecting) {
        return SelectAction::Switch;
    }
    if (changed || requires_choice) && reconnect_allowed(false, status, kill_switch_armed) {
        return SelectAction::Reconnect;
    }
    SelectAction::UpdateOnly
}

async fn reconnect_loop(state: Arc<TonoState>, app: AppHandle, first_delay: Duration) {
    let mut delay = first_delay;
    loop {
        tokio::time::sleep(delay).await;
        {
            let inner = state.lock().await;
            if !reconnect_allowed(
                inner.catalog_requires_choice,
                inner.fsm.status(),
                inner.fsm.kill_switch_armed(),
            ) {
                return;
            }
        }
        match attempt(&state, &app).await {
            Attempt::Connected | Attempt::GuardRejected(_) | Attempt::Stale => return,
            Attempt::Failed(err) => {
                let _ = fail_connect(&state, &app, err).await;
                let next = {
                    let mut inner = state.lock().await;
                    if inner.catalog_requires_choice {
                        None
                    } else {
                        inner.fsm.next_reconnect_delay()
                    }
                };
                match next {
                    Some(next_delay) => delay = next_delay,
                    None => return,
                }
            }
        }
    }
}

/// `tono_disconnect`: cancel the reconnect, then the explicit-release
/// sequence (DNS restore → core stop → owner-gated release, §6/C1).
/// Idempotent while a disconnect is already in flight (L6).
pub async fn disconnect(state: Arc<TonoState>, app: AppHandle) -> Result<(), String> {
    {
        let mut inner = state.lock().await;
        if inner.fsm.status().is_disconnecting {
            return Ok(());
        }
        inner.invalidate_connection(true);
        let status = inner.fsm.status();
        if !status.is_connected && !status.is_connecting && !status.is_protection_blocked {
            return Ok(());
        }
        inner.fsm.begin_disconnect();
        commands::emit_status(&app, &commands::status_of(&inner));
    }
    state.audit().log(AuditEvent::DisconnectBegin { cause: "user" });

    if let Err(err) = release_explicit(&state, &app).await {
        stay_armed_after_failed_release(&state, &app).await;
        return Err(err);
    }

    let mut inner = state.lock().await;
    inner.fsm.finish_disconnect();
    inner.controller_secret = None;
    inner.controller_port = None;
    inner.kill_switch = None;
    inner.network_events_counter = None;
    inner.last_core_pid = None;
    inner.last_restart_count = None;
    // F3: a user disconnect supersedes the backoff state.
    inner.retry_attempt = 0;
    inner.next_retry_at_ms = None;
    commands::emit_status(&app, &commands::status_of(&inner));
    state.audit().log(AuditEvent::DisconnectOk);
    Ok(())
}

/// A releasing step failed mid-disconnect: fall back to Protected Offline
/// without ever disarming (§6). `initial_release_failed`, not
/// `connect_failed`: for an armed-but-unverified session the latter's
/// decision table resolves to FullRelease and clears the armed latch even
/// though the Service release just failed — the UI would show notConnected
/// over a still-blocking WFP barrier and `quit_release` would then skip the
/// release entirely. `initial_release_failed` keeps the real armed state
/// visible in every combination (and also clears a stuck `is_disconnecting`
/// when the release failed before any arm existed).
async fn stay_armed_after_failed_release(state: &Arc<TonoState>, app: &AppHandle) {
    let mut inner = state.lock().await;
    inner.fsm.initial_release_failed();
    commands::emit_status(app, &commands::status_of(&inner));
}

/// §3: the selected node vanished from a new catalog while a tunnel was up —
/// stop the core, keep the kill switch armed, and wait for the user to pick
/// a surviving node (no auto-reconnect).
pub async fn selected_node_vanished(state: Arc<TonoState>, app: AppHandle) {
    let active = {
        let mut inner = state.lock().await;
        let active = inner.fsm.status().is_connected || inner.fsm.status().is_connecting;
        // M2: only touch the generation, the intent bit, and the tasks when
        // a teardown actually follows — an idle catalog shrink must not
        // stomp a releaser's intent.
        if active {
            // The teardown keeps blocking, so a stale attempt must not
            // release the barrier (H-1 intent).
            inner.invalidate_connection(false);
        }
        active
    };
    if !active {
        return;
    }
    logging!(warn, Type::Service, "Tono: 选中节点从新目录中消失，停止核心但保持封锁");
    let _ = service::tono_stop_core(false).await;
    let _ = service::tono_restrict_bootstrap().await;

    let mut inner = state.lock().await;
    inner.controller_secret = None;
    inner.controller_port = None;
    let vanished_node = inner.selected_node.clone();
    if inner.fsm.status().is_connected {
        inner.fsm.tunnel_died();
    } else {
        inner.fsm.connect_failed();
    }
    commands::emit_status(&app, &commands::status_of(&inner));
    drop(inner);
    if let Some(node) = vanished_node {
        state.audit().log(AuditEvent::SelectionVanished { node });
    }
    state.audit().log(AuditEvent::ProtectedOffline {
        reason: "catalogSelectionVanished",
    });
}

/// §6 node switch while a tunnel is up. The WFP endpoint permit can only
/// move through `StartClash` (runtime staging carries no kill-switch
/// config), so the switch is a keep-blocking teardown followed by the full
/// transaction: the new permit is armed before the new selector starts. On
/// failure the core stays down and blocking — never a fall back (§6).
///
/// `generation` is the connect generation the switch was spawned under; a
/// newer bump (another switch, disconnect, sign-out) retires it silently.
pub async fn switch_selected_node(state: Arc<TonoState>, app: AppHandle, generation: u64) {
    {
        let mut inner = state.lock().await;
        if inner.connect_generation != generation {
            return;
        }
        if !inner.fsm.status().is_connected && !inner.fsm.status().is_connecting {
            return;
        }
        inner.controller_secret = None;
        inner.controller_port = None;
        if inner.fsm.status().is_connected {
            inner.fsm.tunnel_died();
        } else {
            inner.fsm.connect_failed();
        }
        commands::emit_status(&app, &commands::status_of(&inner));
    }
    // Keep the barrier up between the old and the new tunnel.
    let _ = service::tono_stop_core(false).await;
    if let Attempt::Failed(err) = attempt(&state, &app).await {
        let _ = fail_connect(&state, &app, err).await;
        schedule_reconnect(&state, &app).await;
    }
}

/// Poll the Service network-event feed while Connected. Any counter change
/// (adapter change, sleep/wake) or core identity change (crash / TUN
/// rebuild, M4) invalidates Connected and reruns the full transaction
/// behind the still-armed barrier (§6).
async fn spawn_network_monitor(state: &Arc<TonoState>, app: &AppHandle) {
    let task_state = state.clone();
    let task_app = app.clone();
    // Boxed trait object: the monitor loop re-enters `attempt`, so embedding
    // its opaque type here would make the async types infinitely recursive.
    let handle = AsyncHandler::spawn(move || Box::pin(network_monitor_loop(task_state, task_app)) as BoxedTask);
    let mut inner = state.lock().await;
    inner.tasks.abort_network_monitor();
    inner.tasks.network_monitor = Some(handle);
}

async fn network_monitor_loop(state: Arc<TonoState>, app: AppHandle) {
    let mut interval = tokio::time::interval(NETWORK_MONITOR_INTERVAL);
    interval.tick().await;
    let mut kill_switch_abnormal = 0_u32;
    let mut protected_dns_abnormal = 0_u32;
    let mut probe_failures = 0_u32;
    let mut last_probe = std::time::Instant::now();
    loop {
        interval.tick().await;
        {
            let inner = state.lock().await;
            if !inner.fsm.status().is_connected {
                return;
            }
        }
        let snapshot = match service::tono_service_status_snapshot().await {
            Ok(snapshot) => snapshot,
            Err(error) => {
                // A dead/unreachable Service is not a neutral sample. Treat it as a failed
                // protection probe so two consecutive IPC failures invalidate Connected and
                // enter the normal fail-closed reconnect path; `continue` here used to leave a
                // permanently stale green state and also skipped every later health leg.
                kill_switch_abnormal += 1;
                protected_dns_abnormal += 1;
                state.audit().log(AuditEvent::HealthProbeFail {
                    probe: "service",
                    error: error.to_string(),
                });
                if health_threshold_reached(kill_switch_abnormal) || health_threshold_reached(protected_dns_abnormal) {
                    handle_network_change(&state, &app).await;
                    return;
                }
                continue;
            }
        };

        // F2 leg 1: kill-switch completeness every tick.
        if kill_switch_unhealthy(snapshot.kill_switch.as_ref()) {
            kill_switch_abnormal += 1;
        } else {
            kill_switch_abnormal = 0;
        }

        // DNS health is checked independently of netmon. The first network event is used only
        // to seed the counter (to ignore our own connect-time interface churn), so an adapter
        // arriving in that narrow window would otherwise remain external-DNS until another event.
        let protected_dns = service::tono_protected_dns_status().await.ok();
        if protected_dns_unhealthy(protected_dns.as_ref()) {
            protected_dns_abnormal += 1;
        } else {
            protected_dns_abnormal = 0;
        }

        // F2 leg 2: periodic single-shot exit probe through the tunnel.
        if last_probe.elapsed() >= EXIT_PROBE_INTERVAL {
            last_probe = std::time::Instant::now();
            let controller = {
                let inner = state.lock().await;
                inner.controller_secret.clone().zip(inner.controller_port)
            };
            let failed = match controller {
                Some((secret, port)) => match probe_exit_once(&secret, port).await {
                    Ok(_) => false,
                    Err(err) => {
                        state.audit().log(AuditEvent::HealthProbeFail {
                            probe: "exit",
                            error: err,
                        });
                        true
                    }
                },
                // Connected without an authenticated controller endpoint is itself abnormal.
                None => true,
            };
            if failed {
                probe_failures += 1;
            } else {
                probe_failures = 0;
            }
        }
        let health_invalid = health_threshold_reached(kill_switch_abnormal)
            || health_threshold_reached(protected_dns_abnormal)
            || health_threshold_reached(probe_failures);

        let (invalidate, kill_switch_snapshot, service_events) = {
            let mut inner = state.lock().await;

            // L3: surface kill switch changes as they are observed.
            let kill_switch_changed = snapshot.kill_switch.is_some() && inner.kill_switch != snapshot.kill_switch;
            if let Some(kill_switch) = &snapshot.kill_switch {
                inner.kill_switch = Some(kill_switch.clone());
            }

            // The first sample seeds every leg without firing (unchanged
            // first-seed semantics); afterwards the legs compare whole
            // Options so a seeded-None → Some transition is caught too (L-1).
            let first_sample = inner.network_events_counter.is_none();
            let counter = snapshot.network_events.counter;
            let network_changed = !first_sample && inner.network_events_counter != Some(counter);
            inner.network_events_counter = Some(counter);

            // M4: a core crash/restart shows up as a new pid or a bumped
            // restart counter; the TUN LUID is re-resolved by the fresh
            // transaction's lock phase.
            let old_pid = inner.last_core_pid;
            let core_changed = !first_sample
                && (inner.last_core_pid != snapshot.core_pid
                    || inner.last_restart_count != Some(snapshot.restart_count));
            inner.last_core_pid = snapshot.core_pid;
            inner.last_restart_count = Some(snapshot.restart_count);

            // P0-13: merge event bursts — only the first change inside the
            // debounce window invalidates Connected.
            let invalidated = (network_changed || core_changed)
                && inner
                    .last_network_event_at
                    .is_none_or(|at| at.elapsed() >= NETWORK_EVENT_DEBOUNCE);
            if invalidated {
                inner.last_network_event_at = Some(std::time::Instant::now());
            }

            let snapshot_for_emit = kill_switch_changed.then(|| commands::status_of(&inner));
            let mut events: Vec<AuditEvent> = Vec::new();
            if kill_switch_changed && let Some(kill_switch) = &snapshot.kill_switch {
                events.push(AuditEvent::KillSwitchSnapshot {
                    wanted: kill_switch.wanted,
                    live: kill_switch.live,
                    mode: kill_switch_mode_key(kill_switch.mode),
                    endpoints: kill_switch.endpoints.len(),
                });
            }
            if network_changed {
                events.push(AuditEvent::NetworkChange { counter });
            }
            if core_changed {
                events.push(AuditEvent::CoreRestart {
                    old_pid,
                    new_pid: snapshot.core_pid,
                    restart_count: snapshot.restart_count,
                });
            }
            (invalidated, snapshot_for_emit, events)
        };
        for event in service_events {
            state.audit().log(event);
        }
        if let Some(status) = kill_switch_snapshot {
            commands::emit_status(&app, &status);
        }
        if invalidate || health_invalid {
            handle_network_change(&state, &app).await;
            return;
        }
    }
}

/// Network adapter change / sleep-wake / core restart / policy behavior
/// change (§6, M4, Build 28): invalidate Connected first, keep WFP armed
/// (restrict to bootstrap), rerun the full transaction.
pub(crate) async fn handle_network_change(state: &Arc<TonoState>, app: &AppHandle) {
    logging!(warn, Type::Service, "Tono: 检测到网络或核心变化，失效 Connected 并重连");
    {
        let mut inner = state.lock().await;
        if !inner.fsm.status().is_connected {
            return;
        }
        inner.fsm.tunnel_died();
        commands::emit_status(&app, &commands::status_of(&inner));
    }
    state.audit().log(AuditEvent::ProtectedOffline {
        reason: "networkChange",
    });
    let _ = service::tono_restrict_bootstrap().await;
    if let Attempt::Failed(err) = attempt(state, app).await {
        let _ = fail_connect(state, app, err).await;
        schedule_reconnect(state, app).await;
    }
}

/// §6.2 endpoint derivation: the selected node's public IPv4/port over TCP.
pub fn proxy_endpoint_of(node: &ValidatedNode) -> ProxyEndpoint {
    ProxyEndpoint {
        ip: node.server.to_string(),
        port: node.port,
        protocol: ProxyProtocol::Tcp,
    }
}

/// F1: merge the pinned bootstrap IPs with the live resolution of the API
/// host (best-effort — a failed lookup just yields the pins alone).
async fn bootstrap_hosts() -> Vec<String> {
    let dynamic: Vec<String> =
        match tokio::time::timeout(DNS_LOOKUP_TIMEOUT, tokio::net::lookup_host((bootstrap::API_HOST, 443))).await {
            Ok(Ok(addrs)) => addrs.map(|addr| addr.ip().to_string()).collect(),
            Ok(Err(_)) | Err(_) => Vec::new(),
        };
    bootstrap::merge_bootstrap_hosts(&dynamic)
}

/// Wire key for the kill switch mode in audit records.
fn kill_switch_mode_key(mode: KillSwitchStatusMode) -> &'static str {
    match mode {
        KillSwitchStatusMode::Bootstrap => "bootstrap",
        KillSwitchStatusMode::Locked => "locked",
        KillSwitchStatusMode::Blocked => "blocked",
    }
}

/// fake-ip range check (§5: 198.18.0.0/16).
pub fn is_fake_ip(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.octets()[0] == 198 && v4.octets()[1] == 18,
        IpAddr::V6(_) => false,
    }
}

async fn set_stage(
    state: &Arc<TonoState>,
    app: &AppHandle,
    stage: ConnectStage,
    generation: u64,
    armed: bool,
    started: std::time::Instant,
) -> Result<(), StageFailure> {
    let fresh = {
        let mut inner = state.lock().await;
        if inner.connect_generation != generation {
            false
        } else {
            if inner.fsm.status().is_connecting {
                inner.fsm.advance_stage(stage);
                // F3: complete the previous step with its wall time and
                // mark the new one current.
                let now = std::time::Instant::now();
                let elapsed = inner
                    .step_started_at
                    .map(|at| now.saturating_duration_since(at).as_millis() as u64)
                    .unwrap_or(0);
                crate::tono::steps::advance(&mut inner.connect_steps, stage, elapsed);
                inner.step_started_at = Some(now);
                commands::emit_status(app, &commands::status_of(&inner));
                state.audit().log(AuditEvent::Stage {
                    stage: commands::stage_key(stage),
                    elapsed_ms: started.elapsed().as_millis() as u64,
                });
            }
            true
        }
    };
    if fresh {
        return Ok(());
    }
    // `armed` marks stage boundaries past a committed StartClash: a stale
    // exit there patches the late arm (H-1).
    if armed {
        Err(stale_after_arm(state).await)
    } else {
        Err(StageFailure::Stale)
    }
}

fn controller_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_millis(500))
        .timeout(Duration::from_secs(6))
        .build()
        .map_err(|err| err.to_string())
}

fn controller_url(port: u16, path: &str) -> String {
    format!("http://127.0.0.1:{port}{path}")
}

/// Pick an unused loopback port for this connection generation. The bind is intentionally released
/// before Mihomo starts; a second process can theoretically win that narrow race, but Mihomo then
/// fails immediately and the absolute connection deadline handles it. Keeping a listener open would
/// prevent the child from binding on Windows.
async fn allocate_controller_port() -> Result<u16, String> {
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|error| format!("cannot allocate loopback controller port: {error}"))?;
    let port = listener
        .local_addr()
        .map_err(|error| format!("cannot inspect loopback controller port: {error}"))?
        .port();
    drop(listener);
    if port == 0 {
        return Err("operating system returned an invalid controller port".to_string());
    }
    Ok(port)
}

/// Protected DNS requires Mihomo to own both TCP and UDP loopback:53. Fail before WFP is installed
/// when another resolver already owns either socket, avoiding a 45-second protected-offline mystery.
#[cfg(windows)]
async fn preflight_dns_listener() -> Result<(), String> {
    let tcp = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 53))
        .await
        .map_err(|error| format!("DNS TCP 127.0.0.1:53 is unavailable: {error}"))?;
    let udp = tokio::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 53))
        .await
        .map_err(|error| format!("DNS UDP 127.0.0.1:53 is unavailable: {error}"))?;
    drop((tcp, udp));
    Ok(())
}

#[cfg(not(windows))]
async fn preflight_dns_listener() -> Result<(), String> {
    Ok(())
}

/// §6.4: poll the mihomo controller `/version` for at most 15 seconds. Each localhost request is
/// independently bounded as well, so a half-open socket cannot multiply the whole-stage budget.
async fn wait_controller(secret: &str, controller_port: u16) -> Result<(), String> {
    let client = controller_client()?;
    let url = controller_url(controller_port, "/version");
    let mut last = String::from("no response");
    let deadline = tokio::time::Instant::now() + CONTROLLER_READY_TIMEOUT;
    for attempt in 0..VERSION_POLL_ATTEMPTS {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(
            remaining.min(CONTROLLER_POLL_TIMEOUT),
            client.get(&url).bearer_auth(secret).send(),
        )
        .await
        {
            Ok(Ok(response)) if response.status().is_success() => return Ok(()),
            Ok(Ok(response)) => last = format!("controller answered {}", response.status()),
            Ok(Err(err)) => last = err.to_string(),
            Err(_) => last = format!("controller poll exceeded {CONTROLLER_POLL_TIMEOUT:?}"),
        }
        if attempt + 1 == VERSION_POLL_ATTEMPTS {
            break;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let interval = if attempt < VERSION_POLL_FAST_ATTEMPTS {
            VERSION_POLL_FAST_INTERVAL
        } else {
            VERSION_POLL_INTERVAL
        };
        tokio::time::sleep(remaining.min(interval)).await;
    }
    Err(format!("mihomo controller not ready: {last}"))
}

/// §6.5+§6.6: lock, retrying only while the TUN adapter comes up (≤ 50 × 200 ms between
/// retryable failures). Permanent lock errors fail immediately so a bad owner/WFP state does
/// not burn the 120 s connect budget on 50 full lifecycle IPCs.
async fn lock_kill_switch_with_retries() -> Result<(), String> {
    let mut last = String::from("no response");
    for attempt in 0..LOCK_ATTEMPTS {
        match service::tono_lock_kill_switch().await {
            Ok(()) => return Ok(()),
            Err(err) => {
                last = err.to_string();
                if !is_retryable_lock_error(&last) {
                    return Err(format!("kill switch lock failed: {last}"));
                }
                if attempt + 1 == LOCK_ATTEMPTS {
                    break;
                }
                tokio::time::sleep(LOCK_RETRY_INTERVAL).await;
            }
        }
    }
    Err(format!("kill switch lock failed (TUN adapter not ready?): {last}"))
}

/// §6.7: an ordinary system lookup must return a fake-ip address (3 tries).
async fn verify_fake_ip() -> Result<(), String> {
    let mut last = String::from("no answer");
    for attempt in 0..VERIFY_ATTEMPTS {
        match tokio::time::timeout(DNS_LOOKUP_TIMEOUT, tokio::net::lookup_host(FAKE_IP_LOOKUP)).await {
            Ok(Ok(addrs)) => {
                let addrs: Vec<_> = addrs.collect();
                if addrs.iter().any(|addr| is_fake_ip(addr.ip())) {
                    return Ok(());
                }
                last = format!("no fake-ip in {addrs:?}");
            }
            Ok(Err(err)) => last = err.to_string(),
            Err(_) => last = format!("system DNS lookup exceeded {DNS_LOOKUP_TIMEOUT:?}"),
        }
        if attempt + 1 < VERIFY_ATTEMPTS {
            tokio::time::sleep(VERIFY_RETRY_INTERVAL).await;
        }
    }
    Err(format!("fake-ip verification failed: {last}"))
}

/// §6.8: delay-probe the exit group through the selected node (3 tries; no
/// sleep after the last failure — it only delayed the error).
async fn probe_exit(secret: &str, controller_port: u16) -> Result<(), String> {
    let mut last = String::from("no response");
    for attempt in 0..VERIFY_ATTEMPTS {
        match probe_exit_once(secret, controller_port).await {
            Ok(_) => return Ok(()),
            Err(err) => {
                last = err;
                if attempt + 1 < VERIFY_ATTEMPTS {
                    tokio::time::sleep(VERIFY_RETRY_INTERVAL).await;
                }
            }
        }
    }
    Err(format!("exit check failed: {last}"))
}

/// One exit probe: `GET /proxies/Tono-Exit/delay` against the generate_204
/// target with a 5 s core-side timeout; a positive delay proves egress.
async fn probe_exit_once(secret: &str, controller_port: u16) -> Result<u64, String> {
    let client = controller_client()?;
    let mut url = reqwest::Url::parse(&controller_url(
        controller_port,
        &format!("/proxies/{EXIT_GROUP_NAME}/delay"),
    ))
    .map_err(|err| err.to_string())?;
    url.query_pairs_mut()
        .append_pair("url", EXIT_PROBE_URL)
        .append_pair("timeout", "5000");

    match client.get(url).bearer_auth(secret).send().await {
        Ok(response) if response.status().is_success() => match response.json::<serde_json::Value>().await {
            Ok(value) => {
                let delay = value.get("delay").and_then(serde_json::Value::as_u64).unwrap_or(0);
                if delay > 0 {
                    Ok(delay)
                } else {
                    Err("exit delay was 0".to_string())
                }
            }
            Err(err) => Err(err.to_string()),
        },
        Ok(response) => Err(format!("delay probe answered {}", response.status())),
        Err(err) => Err(err.to_string()),
    }
}

/// Run one real, bounded egress measurement for the currently connected server. The authenticated
/// in-memory controller endpoint is never exposed to the WebView; only the measured milliseconds
/// cross the Tauri command boundary.
pub async fn test_current_server(state: &Arc<TonoState>) -> Result<u64, String> {
    let (secret, controller_port) = {
        let inner = state.lock().await;
        if !inner.fsm.status().is_connected {
            return Err("connect before testing the current server".to_string());
        }
        inner
            .controller_secret
            .clone()
            .zip(inner.controller_port)
            .ok_or_else(|| "connected controller endpoint is unavailable".to_string())?
    };
    probe_exit_once(&secret, controller_port)
        .await
        .map_err(|error| format!("current server test failed: {error}"))
}

/// §6.9: the kill switch must be wanted, verified live, and fully locked.
async fn verify_locked() -> Result<KillSwitchStatus, String> {
    let status = service::tono_kill_switch_status()
        .await
        .map_err(|err| err.to_string())?;
    if status.wanted && status.live && status.mode == KillSwitchStatusMode::Locked {
        Ok(status)
    } else {
        Err(format!(
            "kill switch not locked (wanted={}, live={}, mode={:?})",
            status.wanted, status.live, status.mode
        ))
    }
}

// ---- WeChat-DIRECT cloud policy (Build 28) ----

/// Maximum resolved addresses kept per policy domain (Mac parity).
const MAX_ADDRESSES_PER_DOMAIN: usize = 8;

/// The applyingCloudPolicy stage: when a validated cloud policy exists,
/// resolve its domains through the now-running controller, build the
/// DIRECT plan, and re-arm with the endpoint permits + the direct-enabled
/// runtime. Returns the controller secret the remaining stages must use
/// (a second start rotates it). `Ok(original)` when there is no policy or
/// the policy is empty — byte-identical behavior to a plan-less connect.
async fn apply_cloud_policy(
    state: &Arc<TonoState>,
    app: &AppHandle,
    node: &ValidatedNode,
    nodes: &[ValidatedNode],
    generation: u64,
    original_secret: &str,
    controller_port: u16,
    proxy_endpoints: &[ProxyEndpoint],
    bootstrap_api_hosts: &[String],
    policy: Option<tono_core::policy::TonoTrafficPolicy>,
    physical_interface: Option<String>,
) -> Result<String, StageFailure> {
    let Some(policy) = policy else {
        return Ok(original_secret.to_string());
    };
    if policy.domains.is_empty() && policy.media_endpoints.is_empty() && policy.web_domains.is_empty() {
        return Ok(original_secret.to_string());
    }

    let interface = physical_interface
        .ok_or_else(|| StageFailure::error("cloud DIRECT policy has no pre-TUN physical interface snapshot"))?;

    // Resolve every policy domain through the controller (parallel; a
    // failed query fails the stage = a connect failure behind the barrier).
    let (wechat_pins, web_pins) = tokio::try_join!(
        resolve_direct_domains(original_secret, controller_port, &policy.domains, node),
        resolve_direct_domains(original_secret, controller_port, &policy.web_domains, node),
    )
    .map_err(StageFailure::error)?;
    let (plan, direct_endpoints) = build_direct_plan(interface, &wechat_pins, &web_pins, &policy.media_endpoints, node)
        .map_err(StageFailure::error)?;
    if plan.hosts.is_empty()
        && plan.tcp_wechat_rules.is_empty()
        && plan.tcp_web_rules.is_empty()
        && plan.udp_wechat_rules.is_empty()
    {
        return Ok(original_secret.to_string());
    }

    // Domain/interface discovery can take seconds. Do not let an invalidated transaction rotate
    // the runtime or widen WFP permits after Disconnect or a node switch has taken ownership.
    ensure_fresh(state, generation).await?;

    // Permit before selector: a second StartClash carries the same barrier
    // plus the exact DIRECT endpoint tuples and the direct-enabled runtime
    // (fresh controller secret per start, §5).
    let secret = generate_controller_secret();
    let runtime = build_owned_runtime_with_ports(
        nodes,
        &node.name,
        &secret,
        Some(&plan),
        RuntimePorts {
            mixed_port: 0,
            controller_port,
        },
    )
    .map_err(StageFailure::error)?;
    write_redacted_copy(state, &runtime.redacted_yaml()).await;
    ensure_fresh(state, generation).await?;
    let core_path = service::tono_core_binary_path().await.map_err(StageFailure::error)?;
    let bundle = RuntimeBundle {
        yaml: runtime.yaml().to_string(),
        assets: Vec::new(),
        remote_providers: Vec::new(),
        core_path: core_path.to_string_lossy().into_owned(),
    };
    let kill_switch = KillSwitchConfig {
        tunnel_interface: config::TUN_DEVICE_NAME.to_string(),
        proxy_endpoints: proxy_endpoints.to_vec(),
        bootstrap_api_hosts: bootstrap_api_hosts.to_vec(),
        direct_endpoints,
    };
    start_core_cancellation_safe(state, bundle, kill_switch, generation).await?;

    {
        let mut inner = state.lock().await;
        if inner.connect_generation != generation {
            drop(inner);
            return Err(stale_after_arm(state).await);
        }
        inner.controller_secret = Some(secret.clone());
        inner.controller_port = Some(controller_port);
    }
    // The restarted core re-creates the TUN adapter: wait for the new
    // controller, then re-lock (idempotent, re-asserts the adapter).
    wait_controller(&secret, controller_port)
        .await
        .map_err(StageFailure::error)?;
    if state.lock().await.connect_generation != generation {
        return Err(stale_after_arm(state).await);
    }
    lock_kill_switch_with_retries().await.map_err(StageFailure::error)?;
    if state.lock().await.connect_generation != generation {
        return Err(stale_after_arm(state).await);
    }

    state.audit().log(AuditEvent::PolicyActivated {
        wechat_tcp: plan.tcp_wechat_rules.len(),
        web_tcp: plan.tcp_web_rules.len(),
        udp: plan.udp_wechat_rules.len(),
    });
    let _ = app;
    Ok(secret)
}

/// One (host, usable addresses, ports) pin per policy domain, resolved via
/// the mihomo controller's `/dns/query` (fail-closed on any query error).
async fn resolve_direct_domains(
    secret: &str,
    controller_port: u16,
    domains: &[tono_core::policy::PolicyDomain],
    node: &ValidatedNode,
) -> Result<Vec<(String, Vec<std::net::Ipv4Addr>, Vec<u16>)>, String> {
    let queries: Vec<_> = domains
        .iter()
        .map(|domain| {
            let host = domain.host.clone();
            let ports = domain.ports.clone();
            let server = node.server;
            let secret = secret.to_string();
            async move {
                let addresses = dns_query_a(&secret, controller_port, &host).await?;
                let usable: Vec<std::net::Ipv4Addr> = addresses
                    .into_iter()
                    .filter(|ip| tono_core::node::is_public_ipv4(*ip))
                    .filter(|ip| *ip != server)
                    .filter(|ip| !tono_core::policy::is_permanently_protected(*ip))
                    .take(MAX_ADDRESSES_PER_DOMAIN)
                    .collect();
                Ok::<_, String>((host, usable, ports))
            }
        })
        .collect();
    let mut pins = Vec::with_capacity(queries.len());
    for result in futures::future::join_all(queries).await {
        pins.push(result?);
    }
    Ok(pins)
}

/// `GET /dns/query?name=<host>&type=A` through the controller; the response
/// shape is tolerated by collecting every IPv4 literal in the JSON tree.
async fn dns_query_a(secret: &str, controller_port: u16, host: &str) -> Result<Vec<std::net::Ipv4Addr>, String> {
    let client = controller_client()?;
    let mut url = reqwest::Url::parse(&controller_url(controller_port, "/dns/query")).map_err(|err| err.to_string())?;
    url.query_pairs_mut().append_pair("name", host).append_pair("type", "A");
    let response = client
        .get(url)
        .bearer_auth(secret)
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if !response.status().is_success() {
        return Err(format!("dns query for {host} answered {}", response.status()));
    }
    let value: serde_json::Value = response.json().await.map_err(|err| err.to_string())?;
    Ok(collect_ipv4_literals(&value))
}

/// Collect every IPv4 literal from a JSON tree (mihomo's dns.Msg JSON nests
/// answers under Header/A fields; shape drift must not break resolution).
pub fn collect_ipv4_literals(value: &serde_json::Value) -> Vec<std::net::Ipv4Addr> {
    fn walk(value: &serde_json::Value, out: &mut Vec<std::net::Ipv4Addr>) {
        match value {
            serde_json::Value::String(text) => {
                if let Ok(ip) = text.parse::<std::net::Ipv4Addr>() {
                    out.push(ip);
                }
            }
            serde_json::Value::Array(items) => items.iter().for_each(|item| walk(item, out)),
            serde_json::Value::Object(map) => map.values().for_each(|item| walk(item, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(value, &mut out);
    out.sort_unstable();
    out.dedup();
    out
}

/// Assemble the runtime plan and the WFP permit tuples. Media addresses are
/// re-checked against the node IP and the permanently protected resolvers
/// (defense in depth on top of sync-time validation).
pub fn build_direct_plan(
    interface: String,
    wechat_pins: &[(String, Vec<std::net::Ipv4Addr>, Vec<u16>)],
    web_pins: &[(String, Vec<std::net::Ipv4Addr>, Vec<u16>)],
    media: &[tono_core::policy::PolicyMedia],
    node: &ValidatedNode,
) -> Result<(tono_core::config::DirectPlan, Vec<ProxyEndpoint>), String> {
    let mut hosts: Vec<(String, String)> = Vec::new();
    let mut wechat_tcp = Vec::new();
    let mut web_tcp = Vec::new();
    for (is_web, pins) in [(false, wechat_pins), (true, web_pins)] {
        for (host, addresses, ports) in pins {
            for ip in addresses {
                // The selected node's own IP must never become a DIRECT target
                // (resolution already filters it; the plan builder re-checks).
                if *ip == node.server || tono_core::policy::is_permanently_protected(*ip) {
                    continue;
                }
                hosts.push((host.clone(), ip.to_string()));
                for port in ports {
                    if is_web {
                        web_tcp.push((host.clone(), *ip, *port));
                    } else {
                        wechat_tcp.push((host.clone(), *ip, *port));
                    }
                }
            }
        }
    }
    let mut udp: Vec<(std::net::Ipv4Addr, u16)> = Vec::new();
    for entry in media {
        let Ok(ip) = entry.address.parse::<std::net::Ipv4Addr>() else {
            continue;
        };
        if ip == node.server || tono_core::policy::is_permanently_protected(ip) {
            continue;
        }
        for port in &entry.ports {
            udp.push((ip, *port));
        }
    }
    wechat_tcp.sort_unstable();
    wechat_tcp.dedup();
    web_tcp.sort_unstable();
    web_tcp.dedup();
    udp.sort_unstable();
    udp.dedup();

    let mut endpoint_keys: std::collections::BTreeSet<(std::net::Ipv4Addr, u16, bool)> = wechat_tcp
        .iter()
        .chain(web_tcp.iter())
        .map(|(_, ip, port)| (*ip, *port, false))
        .collect();
    endpoint_keys.extend(udp.iter().map(|(ip, port)| (*ip, *port, true)));
    if endpoint_keys.len() > MAX_DIRECT_ENDPOINTS {
        return Err(format!(
            "cloud DIRECT policy resolved to {} unique endpoints; maximum is {MAX_DIRECT_ENDPOINTS}",
            endpoint_keys.len()
        ));
    }
    let endpoints = endpoint_keys
        .into_iter()
        .map(|(ip, port, is_udp)| ProxyEndpoint {
            ip: ip.to_string(),
            port,
            protocol: if is_udp { ProxyProtocol::Udp } else { ProxyProtocol::Tcp },
        })
        .collect();

    let plan = tono_core::config::DirectPlan {
        physical_interface: interface,
        hosts,
        tcp_wechat_rules: wechat_tcp,
        tcp_web_rules: web_tcp,
        udp_wechat_rules: udp,
    };
    Ok((plan, endpoints))
}

/// The physical interface carrying the default route. Windows uses
/// `GetBestRoute2` (runtime-unverified here; covered by the xwin check and
/// on-device smoke); other dev machines parse `route get default`.
async fn detect_physical_interface() -> Result<String, String> {
    #[cfg(windows)]
    {
        // GetBestRoute2/GetIfEntry2 are synchronous OS calls. Keep them off the Tauri async
        // workers so a slow IP helper stack cannot starve UI / status / release tasks.
        tokio::task::spawn_blocking(detect_physical_interface_windows)
            .await
            .map_err(|error| format!("physical interface discovery worker failed: {error}"))?
    }
    #[cfg(not(windows))]
    {
        detect_physical_interface_route_command().await
    }
}

/// macOS/Linux dev path: parse `interface: en0` out of `route get default`.
#[cfg(not(windows))]
async fn detect_physical_interface_route_command() -> Result<String, String> {
    let output = tokio::process::Command::new("route")
        .args(["get", "default"])
        .output()
        .await
        .map_err(|err| format!("route get default failed: {err}"))?;
    if !output.status.success() {
        return Err("route get default returned an error".to_string());
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if let Some(interface) = line.trim().strip_prefix("interface:") {
            let interface = interface.trim();
            if !interface.is_empty() {
                return Ok(interface.to_string());
            }
        }
    }
    Err("no default route interface found".to_string())
}

/// Windows path: `GetBestRoute2` for a public destination, then `GetIfEntry2` for the interface
/// alias (`"Ethernet 2"`, `"以太网"`, etc.). This runs before WinTUN starts, so the best route
/// cannot resolve back to Tono. The Service deliberately resolves aliases to LUIDs as well; using
/// `ConvertInterfaceLuidToNameW` here would produce the adapter's internal name and recreate the
/// alias/name mismatch behind Windows error 123.
#[cfg(windows)]
fn detect_physical_interface_windows() -> Result<String, String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetBestRoute2, GetIfEntry2, MIB_IF_ROW2, MIB_IPFORWARD_ROW2,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, IN_ADDR, SOCKADDR_INET};

    // 8.8.8.8 — byte-symmetric, so the S_addr value needs no byte swapping.
    let mut destination = SOCKADDR_INET::default();
    destination.Ipv4.sin_family = AF_INET;
    destination.Ipv4.sin_addr = IN_ADDR {
        S_un: windows_sys::Win32::Networking::WinSock::IN_ADDR_0 { S_addr: 0x0808_0808 },
    };

    let mut best_route = MIB_IPFORWARD_ROW2::default();
    let mut best_source = SOCKADDR_INET::default();
    let status = unsafe {
        GetBestRoute2(
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
            &destination,
            0,
            &mut best_route,
            &mut best_source,
        )
    };
    if status != 0 {
        return Err(format!("GetBestRoute2 failed: {status}"));
    }

    let mut interface = MIB_IF_ROW2 {
        InterfaceLuid: best_route.InterfaceLuid,
        ..Default::default()
    };
    // SAFETY: `interface` is initialized and its LUID came from a successful `GetBestRoute2`.
    let status = unsafe { GetIfEntry2(&mut interface) };
    if status != 0 {
        return Err(format!("GetIfEntry2 failed: {status}"));
    }
    let end = interface
        .Alias
        .iter()
        .position(|ch| *ch == 0)
        .unwrap_or(interface.Alias.len());
    let alias = String::from_utf16(&interface.Alias[..end]).map_err(|err| err.to_string())?;
    if alias.is_empty() {
        return Err("GetIfEntry2 returned an empty interface alias".to_string());
    }
    Ok(alias)
}

/// Persist the redacted runtime copy (§5: the secret never touches disk).
async fn write_redacted_copy(state: &Arc<TonoState>, redacted: &str) {
    let path = { state.lock().await.catalog_dir.join("owned-runtime.redacted.yaml") };
    let result = tokio::task::spawn_blocking({
        let redacted = redacted.to_string();
        move || -> std::io::Result<()> {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            let mut file = options.open(&path)?;
            use std::io::Write as _;
            file.write_all(redacted.as_bytes())
        }
    })
    .await;
    if let Err(err) = result {
        logging!(warn, Type::Service, "Tono: 写入 redacted 运行时副本失败: {err}");
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FailurePlan, MAX_DIRECT_ENDPOINTS, RELEASE_RECONCILING_PREFIX, SERVICE_BUSY_PREFIX,
        SERVICE_TOO_OLD_PREFIX, SelectAction, build_direct_plan, collect_ipv4_literals,
        health_threshold_reached, is_fake_ip, is_retryable_lock_error, kill_switch_unhealthy,
        BFE_NOT_RUNNING_PREFIX, WFP_ENGINE_WEDGED_PREFIX, map_service_ready_error,
        map_wfp_engine_error, plan_failure, protected_dns_unhealthy, proxy_endpoint_of,
        reconnect_allowed, retry_now_is_noop, select_action, sign_out_needs_release,
        single_flight_begin, stale_exit_needs_release, stop_core_before_release,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use tono_core::{connection::ConnectionStatus, node::ValidatedNode};

    fn node() -> ValidatedNode {
        ValidatedNode {
            name: "US Reality 01".to_string(),
            server: Ipv4Addr::new(203, 0, 113, 7),
            port: 8443,
            uuid: "9e107d9d-372b-4c81-8d2b-3f2d0a1b2c3d".to_string(),
            servername: "www.microsoft.com".to_string(),
            flow: None,
            client_fingerprint: None,
            reality_public_key: "0123456789abcdef0123456789abcdef0123456789a".to_string(),
            reality_short_id: "0123456789abcdef".to_string(),
        }
    }

    #[test]
    fn wfp_engine_markers_map_to_actionable_messages() {
        // The Service nests its marker inside its own context string, so matching must be
        // by `contains`, and BFE-not-running must win over the generic wedge message.
        let wedged = map_wfp_engine_error(&format!(
            "Failed to arm Windows kill switch: {WFP_ENGINE_WEDGED_PREFIX}: install did not answer"
        ))
        .expect("wedged engine is mapped");
        assert!(wedged.starts_with(WFP_ENGINE_WEDGED_PREFIX));
        assert!(wedged.contains("重启"));

        let bfe = map_wfp_engine_error(&format!(
            "Failed to arm Windows kill switch: {BFE_NOT_RUNNING_PREFIX}: state Stopped"
        ))
        .expect("stopped BFE is mapped");
        assert!(bfe.starts_with(BFE_NOT_RUNNING_PREFIX));
        assert!(bfe.contains("sc start BFE"));

        assert!(map_wfp_engine_error("kill switch lock failed: owner mismatch").is_none());
    }

    #[test]
    fn proxy_endpoint_is_public_ipv4_port_tcp() {
        let endpoint = proxy_endpoint_of(&node());
        assert_eq!(endpoint.ip, "203.0.113.7");
        assert_eq!(endpoint.port, 8443);
        assert_eq!(endpoint.protocol, clash_verge_service_ipc::ProxyProtocol::Tcp);
    }

    #[test]
    fn fake_ip_range_is_198_18_slash_16() {
        assert!(is_fake_ip(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))));
        assert!(is_fake_ip(IpAddr::V4(Ipv4Addr::new(198, 18, 255, 254))));
        assert!(!is_fake_ip(IpAddr::V4(Ipv4Addr::new(198, 19, 0, 1))));
        assert!(!is_fake_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_fake_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn reconnect_only_in_armed_idle_protected_offline_without_choice() {
        let idle_blocked = ConnectionStatus {
            is_connected: false,
            is_connecting: false,
            is_disconnecting: false,
            is_protection_blocked: true,
            stage: None,
        };
        assert!(reconnect_allowed(false, &idle_blocked, true));
        // The catalog waiting for the user blocks auto-reconnect (§3).
        assert!(!reconnect_allowed(true, &idle_blocked, true));
        // Never reconnect without the barrier.
        assert!(!reconnect_allowed(false, &idle_blocked, false));

        let connected = ConnectionStatus {
            is_connected: true,
            ..idle_blocked.clone()
        };
        assert!(!reconnect_allowed(false, &connected, true));
        let connecting = ConnectionStatus {
            is_connecting: true,
            ..idle_blocked.clone()
        };
        assert!(!reconnect_allowed(false, &connecting, true));
        let disconnecting = ConnectionStatus {
            is_disconnecting: true,
            ..idle_blocked.clone()
        };
        assert!(!reconnect_allowed(false, &disconnecting, true));
        let plain_idle = ConnectionStatus::default();
        assert!(!reconnect_allowed(false, &plain_idle, true));
    }

    #[test]
    fn failure_plan_is_exhaustive() {
        // Armed, no disconnect in flight: keep blocking (stop, never
        // release), restrict to bootstrap, latch the armed flag.
        assert_eq!(
            plan_failure(true, true, false),
            FailurePlan {
                mark_armed: true,
                stop_core: Some(false),
                restrict_bootstrap: true,
            }
        );
        // Pre-arm failure: full release.
        assert_eq!(
            plan_failure(false, false, false),
            FailurePlan {
                mark_armed: false,
                stop_core: Some(true),
                restrict_bootstrap: false,
            }
        );
        // Initial post-arm failure has not crossed the verification barrier: full release.
        assert_eq!(
            plan_failure(true, false, false),
            FailurePlan {
                mark_armed: false,
                stop_core: Some(true),
                restrict_bootstrap: false,
            }
        );
        // A raced disconnect owns the release end to end; the failing
        // transaction does nothing, whatever the arm state.
        for armed in [true, false] {
            assert_eq!(
                plan_failure(armed, false, true),
                FailurePlan {
                    mark_armed: false,
                    stop_core: None,
                    restrict_bootstrap: false,
                },
                "armed={armed}"
            );
        }
    }

    #[test]
    fn stop_before_release_only_with_a_live_session() {
        // The owner-gated release works without a session (C1); the
        // session-gated stop is attempted only when one exists.
        assert!(stop_core_before_release(true, true));
        assert!(!stop_core_before_release(true, false));
        assert!(!stop_core_before_release(false, true));
        assert!(!stop_core_before_release(false, false));
    }

    #[test]
    fn stale_exit_release_requires_commit_and_release_intent() {
        // H-1: only a committed StartClash can leave a late arm, and only a
        // releasing bump (disconnect/sign-out/quit) may be patched — a
        // switch or catalog teardown owns the barrier it is re-arming.
        assert!(stale_exit_needs_release(true, true));
        assert!(!stale_exit_needs_release(true, false));
        assert!(!stale_exit_needs_release(false, true));
        assert!(!stale_exit_needs_release(false, false));
    }

    #[test]
    fn sign_out_release_covers_every_protected_shape() {
        let idle = ConnectionStatus::default();
        assert!(!sign_out_needs_release(&idle, false));
        // The armed latch alone is enough.
        assert!(sign_out_needs_release(&idle, true));
        let connecting = ConnectionStatus {
            is_connecting: true,
            ..ConnectionStatus::default()
        };
        // M-1: an in-flight connect must not skip the release.
        assert!(sign_out_needs_release(&connecting, false));
        let connected = ConnectionStatus {
            is_connected: true,
            ..ConnectionStatus::default()
        };
        assert!(sign_out_needs_release(&connected, false));
        let blocked = ConnectionStatus {
            is_protection_blocked: true,
            ..ConnectionStatus::default()
        };
        assert!(sign_out_needs_release(&blocked, false));
        let disconnecting = ConnectionStatus {
            is_disconnecting: true,
            ..ConnectionStatus::default()
        };
        assert!(sign_out_needs_release(&disconnecting, false));
    }

    #[test]
    fn select_action_same_node_reselect_is_a_noop_in_every_state() {
        // H1: reselecting the current node with no pending choice must not
        // touch the generation, the tasks, or the intent bit.
        for status in [
            ConnectionStatus::default(),
            ConnectionStatus {
                is_connecting: true,
                ..ConnectionStatus::default()
            },
            ConnectionStatus {
                is_connected: true,
                ..ConnectionStatus::default()
            },
            ConnectionStatus {
                is_protection_blocked: true,
                ..ConnectionStatus::default()
            },
        ] {
            for armed in [true, false] {
                assert_eq!(
                    select_action(false, false, &status, armed),
                    SelectAction::Noop,
                    "{status:?} armed={armed}"
                );
            }
        }
    }

    #[test]
    fn select_action_switch_only_when_changed_and_active() {
        let connected = ConnectionStatus {
            is_connected: true,
            ..ConnectionStatus::default()
        };
        assert_eq!(select_action(true, false, &connected, true), SelectAction::Switch);
        let connecting = ConnectionStatus {
            is_connecting: true,
            ..ConnectionStatus::default()
        };
        assert_eq!(select_action(true, false, &connecting, true), SelectAction::Switch);
        // Changed while idle: no transaction at all.
        assert_eq!(
            select_action(true, false, &ConnectionStatus::default(), false),
            SelectAction::UpdateOnly
        );
    }

    #[test]
    fn select_action_reconnects_after_choice_cleared_in_blocked_state() {
        // M5/H1 variant: the vanished node's replacement picked in armed
        // Protected Offline must schedule the reconnect even when the name
        // is unchanged (`changed == false`, `requires_choice == true`).
        let blocked = ConnectionStatus {
            is_protection_blocked: true,
            ..ConnectionStatus::default()
        };
        assert_eq!(select_action(false, true, &blocked, true), SelectAction::Reconnect);
        assert_eq!(select_action(true, true, &blocked, true), SelectAction::Reconnect);
        // Without the barrier there is nothing to protect: update only.
        assert_eq!(select_action(false, true, &blocked, false), SelectAction::UpdateOnly);
    }

    #[test]
    fn retry_now_noop_only_when_connected_or_connecting() {
        let connected = ConnectionStatus {
            is_connected: true,
            ..ConnectionStatus::default()
        };
        let connecting = ConnectionStatus {
            is_connecting: true,
            ..ConnectionStatus::default()
        };
        let blocked = ConnectionStatus {
            is_protection_blocked: true,
            ..ConnectionStatus::default()
        };
        assert!(retry_now_is_noop(&connected));
        assert!(retry_now_is_noop(&connecting));
        assert!(!retry_now_is_noop(&blocked));
        assert!(!retry_now_is_noop(&ConnectionStatus::default()));
    }

    #[test]
    fn single_flight_admits_exactly_one_of_two_racing_attempts() {
        use tono_core::connection::ConnectionFsm;
        let mut fsm = ConnectionFsm::new();
        // The two racing attempts, evaluated back-to-back under one lock:
        // the first begins, the second sees it and is refused.
        assert!(single_flight_begin(&mut fsm, 7, 7), "first attempt enters run_stages");
        assert!(
            !single_flight_begin(&mut fsm, 7, 7),
            "second attempt must not double-start"
        );
        // A stale generation is refused without touching the machine.
        assert!(!single_flight_begin(&mut fsm, 8, 7));
        // After a failure the machine is idle again and a retry may begin.
        fsm.mark_kill_switch_armed();
        fsm.connect_failed();
        assert!(single_flight_begin(&mut fsm, 7, 7));
        // While connected, nothing may start a parallel transaction.
        fsm.mark_kill_switch_armed();
        fsm.mark_session_verified();
        fsm.connect_succeeded().unwrap();
        assert!(!single_flight_begin(&mut fsm, 7, 7));
    }

    #[test]
    fn service_busy_maps_to_a_stable_prefixed_message() {
        for detail in [
            "service operation already running",
            "the previous privileged service operation may still be running; restart Tono before retrying",
        ] {
            let busy = anyhow::anyhow!(detail);
            let mapped = map_service_ready_error(&busy);
            assert!(mapped.starts_with(SERVICE_BUSY_PREFIX), "{mapped}");
            assert!(mapped.contains("重启 Tono"), "{mapped}");
            assert!(!mapped.contains(detail), "{mapped}");
        }

        // Anything else keeps its detail for diagnostics.
        let other = anyhow::anyhow!("ipc transport refused");
        let mapped = map_service_ready_error(&other);
        assert!(mapped.contains("Tono Service is not ready"), "{mapped}");
        assert!(mapped.contains("ipc transport refused"), "{mapped}");
        assert!(!mapped.starts_with(SERVICE_BUSY_PREFIX), "{mapped}");
    }

    #[test]
    fn lock_retries_only_tun_not_ready_errors() {
        assert!(is_retryable_lock_error(
            r#"interface alias "Tono" did not resolve to a LUID: Windows error 87"#
        ));
        assert!(is_retryable_lock_error(
            "interface LUID 123 is not a tunnel device (type 6, description \"Ethernet\"); refusing to lock"
        ));
        assert!(is_retryable_lock_error("Service unavailable: busy"));
        // Permanent failures must fail the stage, not loop for 50 lifecycle IPCs.
        assert!(!is_retryable_lock_error("kill switch is not armed"));
        assert!(!is_retryable_lock_error("kill switch belongs to a different owner"));
        assert!(!is_retryable_lock_error("WFP error 0x80320009"));
        assert!(!is_retryable_lock_error("authentication failed"));
        // Stable prefixes used by the UI for release/protocol gates.
        assert!(RELEASE_RECONCILING_PREFIX.starts_with("TONO_"));
        assert!(SERVICE_TOO_OLD_PREFIX.starts_with("TONO_"));
    }

    #[test]
    fn health_probes_require_two_consecutive_failures() {
        assert!(!health_threshold_reached(0));
        assert!(!health_threshold_reached(1));
        assert!(health_threshold_reached(2));
        assert!(health_threshold_reached(5));
    }

    #[test]
    fn kill_switch_health_requires_wanted_live_locked() {
        use clash_verge_service_ipc::{KillSwitchStatus, KillSwitchStatusMode, ProxyEndpoint, ProxyProtocol};
        let endpoint = ProxyEndpoint {
            ip: "203.0.113.7".to_string(),
            port: 443,
            protocol: ProxyProtocol::Tcp,
        };
        let healthy = KillSwitchStatus {
            wanted: true,
            verified: true,
            live: true,
            mode: KillSwitchStatusMode::Locked,
            endpoints: vec![endpoint.clone()],
            last_error: None,
        };
        assert!(!kill_switch_unhealthy(Some(&healthy)));
        assert!(kill_switch_unhealthy(None));
        for (wanted, live, mode) in [
            (false, true, KillSwitchStatusMode::Locked),
            (true, false, KillSwitchStatusMode::Locked),
            (true, true, KillSwitchStatusMode::Bootstrap),
            (true, true, KillSwitchStatusMode::Blocked),
        ] {
            let status = KillSwitchStatus {
                wanted,
                verified: false,
                live,
                mode,
                endpoints: vec![endpoint.clone()],
                last_error: None,
            };
            assert!(kill_switch_unhealthy(Some(&status)), "{wanted} {live} {mode:?}");
        }
    }

    #[test]
    fn protected_dns_health_requires_a_clean_nonempty_snapshot() {
        use clash_verge_service_ipc::DnsProtectionStatus;

        let healthy = DnsProtectionStatus {
            enabled: true,
            snapshot_present: true,
            adapters: 2,
            last_error: None,
        };
        assert!(!protected_dns_unhealthy(Some(&healthy)));
        assert!(protected_dns_unhealthy(None));
        for status in [
            DnsProtectionStatus {
                enabled: false,
                ..healthy.clone()
            },
            DnsProtectionStatus {
                snapshot_present: false,
                ..healthy.clone()
            },
            DnsProtectionStatus {
                adapters: 0,
                ..healthy.clone()
            },
            DnsProtectionStatus {
                last_error: Some("live apply failed".to_string()),
                ..healthy.clone()
            },
        ] {
            assert!(protected_dns_unhealthy(Some(&status)), "{status:?}");
        }
    }

    #[test]
    fn collect_ipv4_literals_walks_nested_dns_answers() {
        let value = serde_json::json!({
            "Answer": [
                {"Header": {"Name": "wxs.qq.com.", "RRtype": 5}, "CNAME": "cdn.wxs.qq.com."},
                {"Header": {"Name": "cdn.wxs.qq.com.", "RRtype": 1}, "A": "9.0.0.10"},
                {"Header": {"Name": "cdn.wxs.qq.com.", "RRtype": 1}, "A": "9.0.0.10"},
                {"Header": {"Name": "cdn.wxs.qq.com.", "RRtype": 1}, "A": "9.0.0.11"}
            ],
            "Question": [{"Name": "wxs.qq.com.", "Qtype": 1}]
        });
        let ips = collect_ipv4_literals(&value);
        assert_eq!(
            ips,
            vec![
                std::net::Ipv4Addr::new(9, 0, 0, 10),
                std::net::Ipv4Addr::new(9, 0, 0, 11)
            ]
        );
        // Non-IP strings and bare scalars never leak through.
        let garbage = serde_json::json!({"A": "not-an-ip", "B": ["9.0.0.9", 42, null, true]});
        assert_eq!(
            collect_ipv4_literals(&garbage),
            vec![std::net::Ipv4Addr::new(9, 0, 0, 9)]
        );
    }

    #[test]
    fn direct_plan_builds_deduped_rules_and_matching_endpoints() {
        use tono_core::policy::PolicyMedia;
        let node = node();
        // The fixture node is 203.0.113.7; pins include it to prove the
        // node IP never becomes a rule or a permit.
        let pins = vec![
            (
                "wxs.qq.com".to_string(),
                vec![
                    std::net::Ipv4Addr::new(9, 0, 0, 10),
                    std::net::Ipv4Addr::new(9, 0, 0, 10),
                    std::net::Ipv4Addr::new(9, 0, 0, 11),
                ],
                vec![80, 443],
            ),
            (
                "qpic.cn".to_string(),
                vec![std::net::Ipv4Addr::new(203, 0, 113, 7)],
                vec![443],
            ),
        ];
        let media = vec![
            PolicyMedia {
                address: "9.0.0.20".to_string(),
                ports: vec![443, 8000],
            },
            PolicyMedia {
                address: "1.1.1.1".to_string(), // permanently protected: dropped
                ports: vec![443],
            },
            PolicyMedia {
                address: "203.0.113.7".to_string(), // the node itself: dropped
                ports: vec![443],
            },
        ];
        let web_pins = vec![
            (
                "www.bilibili.com".to_string(),
                vec![std::net::Ipv4Addr::new(9, 0, 0, 30)],
                vec![443],
            ),
            (
                "api.bilibili.com".to_string(),
                // Shared CDN tuple must not consume a second WFP slot.
                vec![std::net::Ipv4Addr::new(9, 0, 0, 10)],
                vec![443],
            ),
        ];
        let (plan, endpoints) = build_direct_plan("Ethernet 2".to_string(), &pins, &web_pins, &media, &node).unwrap();
        // WeChat TCP tuples deduped: (9.0.0.10, 80|443) +
        // (9.0.0.11, 80|443) = 4; exact web remains separate by host.
        assert_eq!(plan.tcp_wechat_rules.len(), 4);
        assert_eq!(
            plan.tcp_web_rules,
            vec![
                (
                    "api.bilibili.com".to_string(),
                    std::net::Ipv4Addr::new(9, 0, 0, 10),
                    443,
                ),
                (
                    "www.bilibili.com".to_string(),
                    std::net::Ipv4Addr::new(9, 0, 0, 30),
                    443,
                ),
            ]
        );
        // UDP: only (9.0.0.20, 443|8000).
        assert_eq!(plan.udp_wechat_rules.len(), 2);
        // hosts carry both WeChat domains and the exact web domain.
        assert_eq!(plan.hosts.len(), 5);
        assert!(plan.hosts.iter().all(|(_, ip)| ip != "203.0.113.7"));
        // Endpoints: 4 WeChat TCP + 1 distinct web TCP + 2 UDP. The shared
        // 9.0.0.10:443 tuple consumes only one WFP permit.
        assert_eq!(endpoints.len(), 7);
        assert!(endpoints.iter().all(|endpoint| endpoint.ip != "203.0.113.7"));
        assert_eq!(
            endpoints
                .iter()
                .filter(|endpoint| endpoint.protocol == clash_verge_service_ipc::ProxyProtocol::Udp)
                .count(),
            2
        );
        assert!(
            plan.tcp_wechat_rules
                .iter()
                .all(|(_host, _ip, port)| [80, 443].contains(port))
        );
        assert!(
            plan.udp_wechat_rules
                .iter()
                .all(|(_ip, port)| [443, 8000].contains(port))
        );
    }

    #[test]
    fn direct_plan_rejects_more_endpoints_than_wfp_can_permit() {
        let node = node();
        let pins = (0..=MAX_DIRECT_ENDPOINTS)
            .map(|index| {
                (
                    format!("edge-{index}.example"),
                    vec![std::net::Ipv4Addr::new(11, 1, (index / 256) as u8, (index % 256) as u8)],
                    vec![443],
                )
            })
            .collect::<Vec<_>>();

        let error = build_direct_plan("Ethernet 2".to_string(), &pins, &[], &[], &node)
            .expect_err("a partial WFP permit set must never be emitted");

        assert!(error.contains("257 unique endpoints"));
    }
}
