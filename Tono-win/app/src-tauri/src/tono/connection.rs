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

use std::{net::IpAddr, sync::Arc, time::Duration};

use clash_verge_logging::{Type, logging};
use clash_verge_service_ipc::{
    DnsProtectionStatus, KillSwitchConfig, KillSwitchStatus, KillSwitchStatusMode, ProxyEndpoint, ProxyProtocol,
    RuntimeBundle,
};
use tauri::AppHandle;
use tono_core::{
    EXIT_GROUP_NAME,
    config::{self, build_owned_runtime, generate_controller_secret},
    connection::{ConnectStage, ConnectionStatus},
    node::ValidatedNode,
};

use crate::{
    core::{CoreManager, manager::RunningMode, service},
    process::AsyncHandler,
    tono::{
        audit::AuditEvent,
        bootstrap, commands,
        state::{AccountState, TonoState},
    },
};

/// Owned runtime controller (§5).
const CONTROLLER_BASE: &str = "http://127.0.0.1:9090";
/// §6.8 exit probe target.
const EXIT_PROBE_URL: &str = "https://www.gstatic.com/generate_204";
/// §6.8: the probe also proves fake-ip DNS via this lookup.
const FAKE_IP_LOOKUP: &str = "www.gstatic.com:443";
/// §6.4: controller readiness poll budget.
const VERSION_POLL_ATTEMPTS: u32 = 40;
const VERSION_POLL_INTERVAL: Duration = Duration::from_millis(250);
/// §6.5: TUN adapter / lock retry budget. The first WinTUN driver install
/// plus interface-alias propagation is slow (~10 s on real hardware, P0-12).
const LOCK_ATTEMPTS: u32 = 50;
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(200);
/// §6.7/§6.8 retry counts.
const VERIFY_ATTEMPTS: u32 = 3;
const VERIFY_RETRY_INTERVAL: Duration = Duration::from_millis(500);
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
    Error(String),
}

impl StageFailure {
    fn error(err: impl std::fmt::Display) -> Self {
        StageFailure::Error(err.to_string())
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
    let (node, nodes, generation) = match guard_snapshot(state).await {
        Ok(snapshot) => snapshot,
        Err(err) => return Attempt::GuardRejected(err),
    };
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
    if let Err(err) = ensure_service_ready().await {
        // The kill switch may already be armed from a previous session, so
        // this is a transaction failure, not a guard rejection. fail_connect
        // runs the decision table and (pre-arm) releases the FSM cleanly.
        return Attempt::Failed(err);
    }

    match run_stages(state, app, &node, &nodes, generation, started).await {
        Ok(()) => Attempt::Connected,
        Err(StageFailure::Stale) => Attempt::Stale,
        Err(StageFailure::Error(err)) => Attempt::Failed(err),
    }
}

/// §6.1 guards: forced values live in the owned runtime; here we check the
/// account is ready (H2a — the reconnect path's only account gate), the
/// catalog is usable, the selection exists and passed admission, and no
/// transaction is in flight. Pure read — no state changes.
async fn guard_snapshot(state: &Arc<TonoState>) -> Result<(ValidatedNode, Vec<ValidatedNode>, u64), String> {
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
    Ok((node, inner.nodes.clone(), inner.connect_generation))
}

/// Stable error-code prefix the frontend's i18n keys off: the Service has
/// a privileged operation in flight (install/repair pending, possibly a
/// UAC prompt nobody approved).
pub const SERVICE_BUSY_PREFIX: &str = "TONO_SERVICE_BUSY";

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

/// Tono has no sidecar: the Service must be Ready and speak the kill switch
/// protocol (rev 5 arm/lock + rev 6 release, C1).
async fn ensure_service_ready() -> Result<(), String> {
    service::tono_service_ready()
        .await
        .map_err(|err| map_service_ready_error(&err))?;
    match service::tono_probe_kill_switch_release_support().await {
        Ok(true) => Ok(()),
        Ok(false) => Err("Tono Service is too old for the kill switch; reinstall the service".to_string()),
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
) -> Result<(), StageFailure> {
    // §6.2: proxy endpoints (public IPv4/port/TCP) from the selected node;
    // the bootstrap API hosts are the only control-plane recovery channel.
    let proxy_endpoints = vec![proxy_endpoint_of(node)];
    // F1: pinned bootstrap IPs merged with the live resolution — the WFP
    // bootstrap permit must not depend on the system resolver once
    // blocking starts, and the app's own API client is pinned to the same
    // addresses (see `tono::bootstrap` / `tono::transport`).
    let bootstrap_api_hosts = bootstrap_hosts().await;

    set_stage(state, app, ConnectStage::PreparingService, generation, false, started).await?;

    // §5: the owned runtime carries a fresh random controller secret; only
    // the redacted copy may touch disk.
    let secret = generate_controller_secret();
    let runtime = build_owned_runtime(nodes, &node.name, &secret, None).map_err(StageFailure::error)?;
    write_redacted_copy(state, &runtime.redacted_yaml()).await;
    let core_path = service::tono_core_binary_path().await.map_err(StageFailure::error)?;
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
    start_core_cancellation_safe(state, bundle, kill_switch, generation).await?;

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
        commands::emit_status(app, &commands::status_of(&inner));
    }

    // §6.4: startingTunnel — poll the controller (≤ 40 × 250 ms).
    set_stage(state, app, ConnectStage::StartingTunnel, generation, true, started).await?;
    wait_controller(&secret).await.map_err(StageFailure::error)?;

    // §6.5+§6.6: lockingTraffic — the lock call doubles as the TUN adapter
    // existence check and is idempotent on the Service side (≤ 20 × 100 ms).
    set_stage(state, app, ConnectStage::LockingTraffic, generation, true, started).await?;
    lock_kill_switch_with_retries().await.map_err(StageFailure::error)?;

    // Build 28: applyingCloudPolicy — resolve the cloud WeChat-DIRECT
    // policy through the now-running controller and, when a plan exists,
    // re-arm with its endpoint permits before the DIRECT-capable runtime
    // starts (permit strictly before selector, via a second StartClash).
    set_stage(state, app, ConnectStage::ApplyingCloudPolicy, generation, true, started).await?;
    let secret = apply_cloud_policy(
        state,
        app,
        &node,
        nodes,
        generation,
        &secret,
        &proxy_endpoints,
        &bootstrap_api_hosts,
    )
    .await?;

    // §6.7: securingDNS — snapshot + point resolvers at loopback, then prove
    // an ordinary lookup returns a fake-ip address.
    set_stage(state, app, ConnectStage::SecuringDns, generation, true, started).await?;
    enable_dns_cancellation_safe(state, generation).await?;
    if state.lock().await.connect_generation != generation {
        return Err(stale_after_dns(state).await);
    }
    verify_fake_ip().await.map_err(StageFailure::error)?;

    // §6.8: checkingExit — probe generate_204 through the Tono-Exit group.
    set_stage(state, app, ConnectStage::CheckingExit, generation, true, started).await?;
    probe_exit(&secret).await.map_err(StageFailure::error)?;

    // §6.9: verifyingTraffic — the barrier must be wanted, live, and locked.
    set_stage(state, app, ConnectStage::VerifyingTraffic, generation, true, started).await?;
    let kill_status = verify_locked().await.map_err(StageFailure::error)?;

    // §6.10: only now Connected; monitors start.
    {
        let mut inner = state.lock().await;
        if inner.connect_generation != generation {
            drop(inner);
            return Err(stale_after_arm(state).await);
        }
        inner.kill_switch = Some(kill_status);
        inner.fsm.connect_succeeded().map_err(StageFailure::error)?;
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
    let task_state = Arc::clone(state);
    let task = tokio::spawn(async move {
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
    let task_state = Arc::clone(state);
    let task = tokio::spawn(async move {
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

pub fn plan_failure(armed: bool, was_disconnecting: bool) -> FailurePlan {
    if was_disconnecting {
        // A disconnect is in flight and owns the release sequence end to
        // end; the failing transaction must not double it.
        FailurePlan {
            mark_armed: false,
            stop_core: None,
            restrict_bootstrap: false,
        }
    } else if armed {
        // §6: anything after arm keeps blocking and reconnects.
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
pub fn stop_core_before_release(core_active: bool, session_active: bool) -> bool {
    core_active && session_active
}

/// The §6 failure decision table, executing [`plan_failure`]. After arm:
/// stop the core, keep blocking (restrict to the bootstrap channel),
/// Protected Offline. Before arm: full release.
async fn fail_connect(state: &Arc<TonoState>, app: &AppHandle, err: String) -> String {
    logging!(error, Type::Service, "Tono: 连接事务失败: {err}");
    let observed = service::tono_kill_switch_status().await.ok();
    let (plan, stage, action) = {
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
        let plan = plan_failure(armed, was_disconnecting);
        let action: &'static str = if was_disconnecting {
            "racedDisconnect"
        } else if armed {
            "keepBlockingAndReconnect"
        } else {
            "fullRelease"
        };
        if plan.mark_armed {
            inner.fsm.mark_kill_switch_armed();
        }
        if !was_disconnecting {
            // Drives the FSM to Protected Offline (armed) or releases it
            // (pre-arm), mirroring the plan.
            inner.fsm.connect_failed();
        }
        inner.controller_secret = None;
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
        (plan, stage, action)
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

    if let Some(release) = plan.stop_core {
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
/// Order: DNS restore — proven, or the whole release aborts and the system
/// stays armed (M3) → best-effort session-gated core stop while a session
/// is live → owner-gated kill switch release, which works from Protected
/// Offline where the arming session is long gone. A failed release keeps
/// the system armed and surfaces an error.
pub async fn release_explicit(state: &Arc<TonoState>, app: &AppHandle) -> Result<(), String> {
    let _ = app;
    // 1. DNS is always restored before the kill switch is disarmed (§6);
    //    a missing snapshot is a proven no-op on the Service side.
    if let Err(err) = service::tono_restore_protected_dns().await {
        let message = format!("DNS restore failed; protection stays on: {err}");
        state.audit().log(AuditEvent::ReleaseFail { error: message.clone() });
        return Err(message);
    }

    // 2. Best-effort core stop; its failure never blocks the release.
    let core_active = matches!(*CoreManager::global().get_running_mode(), RunningMode::Service);
    if stop_core_before_release(core_active, service::tono_session_live()) {
        let _ = service::tono_stop_core(false).await;
    }

    // 3. The actual disarm (owner-gated, idempotent, DNS-before-disarm is
    //    re-enforced Service-side).
    let status = match service::tono_release_kill_switch().await {
        Ok(status) => status,
        Err(err) => {
            let message = format!("kill switch release failed; protection stays on: {err}");
            state.audit().log(AuditEvent::ReleaseFail { error: message.clone() });
            return Err(message);
        }
    };

    let mut inner = state.lock().await;
    inner.kill_switch = Some(status);
    inner.controller_secret = None;
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
        inner.connect_generation += 1;
        inner.release_on_stale = true;
        inner.tasks.abort_connection_tasks();
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
/// without ever disarming (§6).
async fn stay_armed_after_failed_release(state: &Arc<TonoState>, app: &AppHandle) {
    let mut inner = state.lock().await;
    if inner.fsm.kill_switch_armed() {
        inner.fsm.connect_failed();
    }
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
            inner.connect_generation += 1;
            // The teardown keeps blocking, so a stale attempt must not
            // release the barrier (H-1 intent).
            inner.release_on_stale = false;
            inner.tasks.abort_connection_tasks();
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
            let secret = { state.lock().await.controller_secret.clone() };
            let failed = match secret {
                Some(secret) => match probe_exit_once(&secret).await {
                    Ok(()) => false,
                    Err(err) => {
                        state.audit().log(AuditEvent::HealthProbeFail {
                            probe: "exit",
                            error: err,
                        });
                        true
                    }
                },
                // Connected without a controller secret is itself abnormal.
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
    let dynamic: Vec<String> = match tokio::net::lookup_host((bootstrap::API_HOST, 443)).await {
        Ok(addrs) => addrs.map(|addr| addr.ip().to_string()).collect(),
        Err(_) => Vec::new(),
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
        .timeout(Duration::from_secs(6))
        .build()
        .map_err(|err| err.to_string())
}

/// §6.4: poll the mihomo controller `/version` (≤ 40 × 250 ms).
async fn wait_controller(secret: &str) -> Result<(), String> {
    let client = controller_client()?;
    let url = format!("{CONTROLLER_BASE}/version");
    let mut last = String::from("no response");
    for _ in 0..VERSION_POLL_ATTEMPTS {
        match client.get(&url).bearer_auth(secret).send().await {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(response) => last = format!("controller answered {}", response.status()),
            Err(err) => last = err.to_string(),
        }
        tokio::time::sleep(VERSION_POLL_INTERVAL).await;
    }
    Err(format!("mihomo controller not ready: {last}"))
}

/// §6.5+§6.6: lock, retrying while the TUN adapter comes up (≤ 20 × 100 ms).
async fn lock_kill_switch_with_retries() -> Result<(), String> {
    let mut last = String::from("no response");
    for _ in 0..LOCK_ATTEMPTS {
        match service::tono_lock_kill_switch().await {
            Ok(()) => return Ok(()),
            Err(err) => {
                last = err.to_string();
                tokio::time::sleep(LOCK_RETRY_INTERVAL).await;
            }
        }
    }
    Err(format!("kill switch lock failed (TUN adapter not ready?): {last}"))
}

/// §6.7: an ordinary system lookup must return a fake-ip address (3 tries).
async fn verify_fake_ip() -> Result<(), String> {
    let mut last = String::from("no answer");
    for _ in 0..VERIFY_ATTEMPTS {
        match tokio::net::lookup_host(FAKE_IP_LOOKUP).await {
            Ok(addrs) => {
                let addrs: Vec<_> = addrs.collect();
                if addrs.iter().any(|addr| is_fake_ip(addr.ip())) {
                    return Ok(());
                }
                last = format!("no fake-ip in {addrs:?}");
            }
            Err(err) => last = err.to_string(),
        }
        tokio::time::sleep(VERIFY_RETRY_INTERVAL).await;
    }
    Err(format!("fake-ip verification failed: {last}"))
}

/// §6.8: delay-probe the exit group through the selected node (3 tries).
async fn probe_exit(secret: &str) -> Result<(), String> {
    let mut last = String::from("no response");
    for _ in 0..VERIFY_ATTEMPTS {
        match probe_exit_once(secret).await {
            Ok(()) => return Ok(()),
            Err(err) => {
                last = err;
                tokio::time::sleep(VERIFY_RETRY_INTERVAL).await;
            }
        }
    }
    Err(format!("exit check failed: {last}"))
}

/// One exit probe: `GET /proxies/Tono-Exit/delay` against the generate_204
/// target with a 5 s core-side timeout; a positive delay proves egress.
async fn probe_exit_once(secret: &str) -> Result<(), String> {
    let client = controller_client()?;
    let mut url = reqwest::Url::parse(&format!("{CONTROLLER_BASE}/proxies/{EXIT_GROUP_NAME}/delay"))
        .map_err(|err| err.to_string())?;
    url.query_pairs_mut()
        .append_pair("url", EXIT_PROBE_URL)
        .append_pair("timeout", "5000");

    match client.get(url).bearer_auth(secret).send().await {
        Ok(response) if response.status().is_success() => match response.json::<serde_json::Value>().await {
            Ok(value) => {
                let delay = value.get("delay").and_then(serde_json::Value::as_u64).unwrap_or(0);
                if delay > 0 {
                    Ok(())
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
    proxy_endpoints: &[ProxyEndpoint],
    bootstrap_api_hosts: &[String],
) -> Result<String, StageFailure> {
    let policy = { state.lock().await.traffic_policy.clone() };
    let Some(policy) = policy else {
        return Ok(original_secret.to_string());
    };
    if policy.domains.is_empty() && policy.media_endpoints.is_empty() {
        return Ok(original_secret.to_string());
    }

    // The DIRECT group binds the physical egress interface; resolving it
    // fail-closed (a DIRECT path with no valid interface must not exist).
    let interface = detect_physical_interface().await.map_err(StageFailure::error)?;
    tono_core::config::DirectPlan::validate_physical_interface(&interface).map_err(StageFailure::error)?;

    // Resolve every policy domain through the controller (parallel; a
    // failed query fails the stage = a connect failure behind the barrier).
    let pins = resolve_direct_domains(original_secret, &policy.domains, node)
        .await
        .map_err(StageFailure::error)?;
    let (plan, direct_endpoints) = build_direct_plan(interface, &pins, &policy.media_endpoints, node);
    if plan.hosts.is_empty() && plan.tcp_rules.is_empty() && plan.udp_wechat_rules.is_empty() {
        return Ok(original_secret.to_string());
    }

    // Domain/interface discovery can take seconds. Do not let an invalidated transaction rotate
    // the runtime or widen WFP permits after Disconnect or a node switch has taken ownership.
    ensure_fresh(state, generation).await?;

    // Permit before selector: a second StartClash carries the same barrier
    // plus the exact DIRECT endpoint tuples and the direct-enabled runtime
    // (fresh controller secret per start, §5).
    let secret = generate_controller_secret();
    let runtime = build_owned_runtime(nodes, &node.name, &secret, Some(&plan)).map_err(StageFailure::error)?;
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
    }
    // The restarted core re-creates the TUN adapter: wait for the new
    // controller, then re-lock (idempotent, re-asserts the adapter).
    wait_controller(&secret).await.map_err(StageFailure::error)?;
    if state.lock().await.connect_generation != generation {
        return Err(stale_after_arm(state).await);
    }
    lock_kill_switch_with_retries().await.map_err(StageFailure::error)?;
    if state.lock().await.connect_generation != generation {
        return Err(stale_after_arm(state).await);
    }

    state.audit().log(AuditEvent::PolicyActivated {
        tcp: plan.tcp_rules.len(),
        udp: plan.udp_wechat_rules.len(),
    });
    let _ = app;
    Ok(secret)
}

/// One (host, usable addresses, ports) pin per policy domain, resolved via
/// the mihomo controller's `/dns/query` (fail-closed on any query error).
async fn resolve_direct_domains(
    secret: &str,
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
                let addresses = dns_query_a(&secret, &host).await?;
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
async fn dns_query_a(secret: &str, host: &str) -> Result<Vec<std::net::Ipv4Addr>, String> {
    let client = controller_client()?;
    let mut url = reqwest::Url::parse(&format!("{CONTROLLER_BASE}/dns/query")).map_err(|err| err.to_string())?;
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
    pins: &[(String, Vec<std::net::Ipv4Addr>, Vec<u16>)],
    media: &[tono_core::policy::PolicyMedia],
    node: &ValidatedNode,
) -> (tono_core::config::DirectPlan, Vec<ProxyEndpoint>) {
    let mut hosts: Vec<(String, String)> = Vec::new();
    let mut tcp: Vec<(std::net::Ipv4Addr, u16)> = Vec::new();
    for (host, addresses, ports) in pins {
        for ip in addresses {
            // The selected node's own IP must never become a DIRECT target
            // (resolution already filters it; the plan builder re-checks).
            if *ip == node.server || tono_core::policy::is_permanently_protected(*ip) {
                continue;
            }
            hosts.push((host.clone(), ip.to_string()));
            for port in ports {
                tcp.push((*ip, *port));
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
    tcp.sort_unstable();
    tcp.dedup();
    udp.sort_unstable();
    udp.dedup();

    let mut endpoints: Vec<ProxyEndpoint> = tcp
        .iter()
        .map(|(ip, port)| ProxyEndpoint {
            ip: ip.to_string(),
            port: *port,
            protocol: ProxyProtocol::Tcp,
        })
        .collect();
    endpoints.extend(udp.iter().map(|(ip, port)| ProxyEndpoint {
        ip: ip.to_string(),
        port: *port,
        protocol: ProxyProtocol::Udp,
    }));
    // Service-side cap for direct permits.
    endpoints.truncate(256);

    let plan = tono_core::config::DirectPlan {
        physical_interface: interface,
        hosts,
        tcp_rules: tcp,
        udp_wechat_rules: udp,
    };
    (plan, endpoints)
}

/// The physical interface carrying the default route. Windows uses
/// `GetBestRoute2` (runtime-unverified here; covered by the xwin check and
/// on-device smoke); other dev machines parse `route get default`.
async fn detect_physical_interface() -> Result<String, String> {
    #[cfg(windows)]
    {
        detect_physical_interface_windows()
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

/// Windows path: `GetBestRoute2` for a public destination, then
/// `ConvertInterfaceLuidToNameW` for the interface's friendly name
/// (`"Ethernet 2"` etc.). Runtime-unverified on this dev host; the shapes
/// mirror the documented windows-sys signatures.
#[cfg(windows)]
fn detect_physical_interface_windows() -> Result<String, String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceLuidToNameW, GetBestRoute2, MIB_IPFORWARD_ROW2,
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

    let mut name = [0u16; 256];
    let status = unsafe { ConvertInterfaceLuidToNameW(&best_route.InterfaceLuid, name.as_mut_ptr(), name.len()) };
    if status != 0 {
        return Err(format!("ConvertInterfaceLuidToNameW failed: {status}"));
    }
    let end = name.iter().position(|ch| *ch == 0).unwrap_or(name.len());
    String::from_utf16(&name[..end]).map_err(|err| err.to_string())
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
        FailurePlan, SERVICE_BUSY_PREFIX, SelectAction, build_direct_plan, collect_ipv4_literals,
        health_threshold_reached, is_fake_ip, kill_switch_unhealthy, map_service_ready_error, plan_failure,
        protected_dns_unhealthy, proxy_endpoint_of, reconnect_allowed, retry_now_is_noop, select_action,
        sign_out_needs_release, single_flight_begin, stale_exit_needs_release, stop_core_before_release,
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
            plan_failure(true, false),
            FailurePlan {
                mark_armed: true,
                stop_core: Some(false),
                restrict_bootstrap: true,
            }
        );
        // Pre-arm failure: full release.
        assert_eq!(
            plan_failure(false, false),
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
                plan_failure(armed, true),
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
    fn direct_plan_builds_deduped_rules_and_capped_endpoints() {
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
        let (plan, endpoints) = build_direct_plan("Ethernet 2".to_string(), &pins, &media, &node);
        // TCP tuples deduped: (9.0.0.10, 80|443) + (9.0.0.11, 80|443) = 4.
        assert_eq!(plan.tcp_rules.len(), 4);
        // UDP: only (9.0.0.20, 443|8000).
        assert_eq!(plan.udp_wechat_rules.len(), 2);
        // hosts carry both domains' addresses.
        assert_eq!(plan.hosts.len(), 3);
        assert!(plan.hosts.iter().all(|(_, ip)| ip != "203.0.113.7"));
        // Endpoints: 4 TCP + 2 UDP, protocols mapped, none for the node IP.
        assert_eq!(endpoints.len(), 6);
        assert!(endpoints.iter().all(|endpoint| endpoint.ip != "203.0.113.7"));
        assert_eq!(
            endpoints
                .iter()
                .filter(|endpoint| endpoint.protocol == clash_verge_service_ipc::ProxyProtocol::Udp)
                .count(),
            2
        );
        assert!(plan.tcp_rules.iter().all(|(_ip, port)| [80, 443].contains(port)));
        assert!(
            plan.udp_wechat_rules
                .iter()
                .all(|(_ip, port)| [443, 8000].contains(port))
        );
    }
}
