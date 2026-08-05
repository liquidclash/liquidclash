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

use std::{error::Error as _, future::Future, net::IpAddr, sync::Arc, time::Duration};

use clash_verge_logging::{Type, logging};
use clash_verge_service_ipc::{
    DnsProtectionStatus, KillSwitchConfig, KillSwitchStatus, KillSwitchStatusMode, ProxyEndpoint, ProxyProtocol,
    RuntimeBundle,
};
use futures::{StreamExt as _, stream::FuturesUnordered};
use tauri::AppHandle;
use tauri_plugin_mihomo::{MihomoExt as _, models::Protocol};
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
        audit::{self, AuditEvent},
        bootstrap, commands,
        state::{AccountState, TonoState},
    },
};

/// §6.8 exit probe target.
const EXIT_PROBE_URL: &str = "https://www.gstatic.com/generate_204";
/// §6.8: the probe also proves fake-ip DNS via this lookup.
const FAKE_IP_LOOKUP_HOST: &str = "www.gstatic.com";
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
/// §6.7 DNS verification retry count.
const VERIFY_ATTEMPTS: u32 = 3;
const VERIFY_RETRY_INTERVAL: Duration = Duration::from_millis(500);
/// C2 — §6.8 exit-probe budgets. The generated runtime sets `unified-delay: true`
/// (`crates/tono-core/src/config.rs`), under which mihomo performs the measured request **twice**
/// inside the single `timeout` the delay endpoint is handed. On a distant REALITY exit one
/// request is realistically 1.5–3.5 s, so the old 5 s core budget was marginal for the pair and
/// routinely lost to the client's own 6 s ceiling — which discarded mihomo's diagnosis and
/// reported a transport timeout instead. 8 s gives the doubled request room.
const EXIT_PROBE_CORE_TIMEOUT_MS: u64 = 8_000;
/// The HTTP client must always outlast the core budget by a real margin, so the *core* decides
/// the verdict of an exit probe. 3 s over the core budget covers the loopback round trip, the
/// core's scheduling, and the JSON reply.
const EXIT_PROBE_CLIENT_TIMEOUT: Duration = Duration::from_secs(11);
/// The controller delay request is advisory during Connect. Its reqwest timeout plus the
/// integration profile's maximum synthetic delay bounds the single attempt; retrying a doubled
/// `unified-delay` request made a harmless 504 consume 38 seconds before the authoritative real
/// App data-plane check was even allowed to run.
#[cfg(test)]
const EXIT_PROBE_ADVISORY_BUDGET: Duration = Duration::from_secs(16);
/// Every other controller call keeps the original general budget: `/version` polls are bounded
/// far tighter by `CONTROLLER_POLL_TIMEOUT`, and a cloud-policy `/dns/query` must not be able to
/// spend an exit-probe-sized slice of the transaction.
const CONTROLLER_HTTP_TIMEOUT: Duration = Duration::from_secs(6);
/// One attempt through the Windows DNS Client. The Windows path uses cancellable `DnsQueryEx`,
/// so a slow adapter transition can consume this budget without leaving stale `getaddrinfo`
/// workers behind; all bounded attempts remain available on high-latency machines.
const FAKE_IP_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
/// §6.9 must prove traffic from the App itself, not merely ask Mihomo whether Mihomo can reach
/// the Internet. The client is fresh, ignores all explicit proxy settings, resolves through the
/// protected system DNS, and therefore has only one permitted path while WFP is locked: WinTUN.
// A 4 s connect ceiling passed the local 1 s synthetic-latency profile but failed on real
// mainland-to-US paths: that profile delays *before* the request and therefore does not consume
// reqwest's DNS + proxy handshake + TLS connect budget. The Buffalo reports show the independent
// controller request completing in 2.5 s while every real App request exhausts exactly this 4 s
// connect ceiling. Twelve seconds covers several cross-border handshakes without weakening the
// verdict; the whole request remains absolutely bounded and still has to return the exact TLS
// origin status.
const TUN_DATA_PLANE_CONNECT_TIMEOUT: Duration = Duration::from_secs(12);
const TUN_DATA_PLANE_TIMEOUT: Duration = Duration::from_secs(18);
/// A single public origin is not a data plane. The controller probe and 0.0.7's App probe both
/// targeted Google, so one node-to-Google failure made two nominally independent checks fail
/// together on a mainland tester. Race independent TLS origins and accept the first exact,
/// authenticated response. Because WFP is already verified Locked, any such fresh App flow can
/// only leave through WinTUN; an ordinary physical-interface fallback remains impossible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TunDataPlaneProbe {
    label: &'static str,
    url: &'static str,
    expected_status: u16,
}

const TUN_DATA_PLANE_PROBES: [TunDataPlaneProbe; 3] = [
    TunDataPlaneProbe {
        label: "Google",
        url: EXIT_PROBE_URL,
        expected_status: 204,
    },
    TunDataPlaneProbe {
        label: "Cloudflare",
        url: "https://cp.cloudflare.com/generate_204",
        expected_status: 204,
    },
    TunDataPlaneProbe {
        label: "Apple",
        url: "https://www.apple.com/library/test/success.html",
        expected_status: 200,
    },
];
/// Controller failures are useful only when they remain bounded and safe to persist in the
/// connect progress/audit trail. Mihomo's local API normally returns a tiny JSON error; cap the
/// extracted message in case that shape changes.
const CONTROLLER_ERROR_DETAIL_LIMIT: usize = 384;
/// V1/H1 — §6.9 kill-switch verification retries. `KillSwitchStatus.live` on Windows is not a
/// live query: it is a ~1.5 s-decaying cache refreshed by a 1 s loop, so one slow-but-successful
/// verify reads `live: false` and fails a healthy tunnel. Every other stage retries (`lock` 50×,
/// `verify_fake_ip` 3×, `wait_controller` 64×); the only stage reading a
/// time-decayed field retried zero times. The window deliberately spans more than one full
/// refresh period, so the verdict is never decided by a single sample of a decaying value.
const VERIFY_LOCK_ATTEMPTS: u32 = 4;
const VERIFY_LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(700);
/// C3 — `checkingExit` + `verifyingTraffic` form one retryable *verification* group.
///
/// At that point the barrier is locked and the tunnel is proven up, but `session_verified` is
/// still false (it is committed only after both stages pass), so `plan_failure(armed = true,
/// session_verified = false, ..)` resolves to `FullRelease` — and `next_reconnect_delay()`
/// then requires `is_protection_blocked && session_verified`, both false, so nothing retries.
/// A controller delay result is only advisory; the real App data-plane request below owns the
/// verdict. A transient failure of that authoritative check still gets one full in-place retry.
///
/// The retry therefore belongs **before** the full release, inside the still-live transaction:
/// the decision table, the verification latch, and the release rules are untouched, and an
/// exhausted group still falls through to exactly the old `FullRelease`.
const POST_LOCK_VERIFY_ROUNDS: u32 = 2;
const POST_LOCK_VERIFY_ROUND_DELAY: Duration = Duration::from_secs(1);
/// `lookup_host` delegates to the OS resolver and has no Tokio timeout of its own. Bound every
/// lookup so a broken adapter/resolver cannot strand Connecting forever.
const DNS_LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);
/// One absolute budget covers service readiness, both possible Core starts (cold WinTUN + WFP),
/// controller/DNS verification, cloud-policy re-arm, locking, and the post-lock verification
/// group. Per-stage retries never reset this clock.
///
/// C4 — 120 s did not cover a real cold first connect. It was sized while the DNS stage still
/// failed fast; once DNS starts *succeeding* (10–30 s of PowerShell) the sum crosses 120 s right
/// at the exit check, and a timeout there lands on the same no-retry path C3 describes. The
/// accounting below is per-leg worst case, machine-checked by `CONNECT_BUDGET_LEGS`:
///
/// | leg                                                    | worst |
/// |--------------------------------------------------------|-------|
/// | service readiness probe                                  |   3 s |
/// | StartClash #1 — cold WinTUN install + WFP arm             |  60 s | Service handler budget
/// | controller readiness (`CONTROLLER_READY_TIMEOUT`)         |  15 s |
/// | lock ladder (`LOCK_ATTEMPTS` × `LOCK_RETRY_INTERVAL`)     |  10 s |
/// | cloud policy — DNS 35 s + StartClash #2 60 s + ready/lock| 120 s |
/// | securingDNS — PowerShell batches + read-back              |  30 s |
/// | fake-ip verification (3 × (5 s + 0.5 s), cancellable)     |  16 s |
/// | checkingExit (one advisory controller delay request)      |  16 s |
/// | verifyingTraffic (WFP status + mainland App HTTP over TUN) |  26 s |
/// | C3 second TUN round + concurrent proxy check + delay       |  27 s |
/// | MarkVerified commit IPC                                   |   5 s |
/// | **total**                                                 | 328 s |
///
/// 360 s leaves margin over that sum. It is a backstop for a wedged stage, not an expected
/// duration: every leg above has its own tighter budget, so a real hang surfaces as that stage's
/// error long before this deadline — whose own expiry is the one failure with no retry left.
const CONNECT_TRANSACTION_TIMEOUT: Duration = Duration::from_secs(360);
/// The accounting table above, machine-checked by `connect_budget_covers_a_cold_first_connect`.
#[cfg(test)]
const CONNECT_BUDGET_LEGS: [(&str, u64); 11] = [
    ("service readiness", 3),
    ("StartClash #1 (cold WinTUN + WFP arm)", 60),
    ("controller readiness", 15),
    ("lock ladder", 10),
    ("cloud policy (DNS + StartClash #2 + ready/relock)", 120),
    ("securingDNS", 30),
    ("fake-ip verification", 16),
    ("checkingExit", 16),
    ("verifyingTraffic", 26),
    ("C3 second verification round", 27),
    ("MarkVerified commit", 5),
];
/// The redacted runtime copy is a diagnostics convenience, but it lands under `%APPDATA%`,
/// which enterprise policy can redirect to a UNC share or a sync-provider placeholder folder.
/// `OpenOptions::open`/`write_all` then have no timeout of their own, so an offline share can
/// park the write for minutes. Bound it well under the transaction budget: a diagnostics file
/// must never be the reason a connect spends its clock.
const REDACTED_COPY_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// UI budget for an explicit release. The ordered DNS → Core → WFP sequence runs in a detached
/// reconciliation task, so reaching this budget stops waiting but never cancels a safety step.
///
/// D1 — 30 s was below the Service's own reality, so the user was told the disconnect had failed
/// while the detached worker completed fine seconds later. One Service-side release runs a DNS
/// restore (two 10 s PowerShell batches plus two 25 s-budgeted engine reads, Service-side leg
/// budget 40 s — `service/src/core/dns.rs` / `windows_kill_switch::DNS_RESTORE_TIMEOUT`), a core
/// stop (≤ 3 s plus a watchdog join) and a WFP transaction. 40 + 3 + ~12 of stop/WFP/IPC
/// overhead ⇒ 55 s, which must stay strictly under the IPC client's own 65 s
/// (`service/src/client/mod.rs` `LIFECYCLE_TIMEOUT`) so a genuine hang is reported by the client
/// with its real cause rather than by this UI deadline.
const EXPLICIT_RELEASE_TIMEOUT: Duration = Duration::from_secs(55);
/// The IPC client's own lifecycle budget. Mirrored here only so the invariant
/// `EXPLICIT_RELEASE_TIMEOUT < LIFECYCLE_TIMEOUT` is asserted rather than assumed.
#[cfg(test)]
const SERVICE_LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(65);
/// The WFP model has a hard endpoint budget. The runtime DIRECT plan and its permits must be
/// generated from the same complete set; silently truncating only the permits creates selective
/// blackholes that look like random application hangs.
const MAX_DIRECT_ENDPOINTS: usize = 256;
/// network_events poll cadence while Connected.
const NETWORK_MONITOR_INTERVAL: Duration = Duration::from_secs(2);
/// H4: consecutive *quiet* missing-core samples before a core change is believed. The Service's
/// `/status` reports `core_pid: None, restart_count: 0` on a non-error path — whenever its
/// per-poll `is_active` check reads `Ok(None)` it considers the session inactive — so a single
/// such sample must not be able to tear a healthy tunnel down. Same treatment as `core_is_gone`
/// in `core/runstate/owner.rs`.
const CORE_MISSING_SUSTAINED_SAMPLES: u32 = 2;
/// P0-13: bursts of network events inside this window merge into a single
/// invalidation (interface-level filtering — GetBestRoute2 — is the
/// documented follow-up; the debounce covers the common route-flap storm).
const NETWORK_EVENT_DEBOUNCE: Duration = Duration::from_secs(2);
/// F2: exit-probe cadence while Connected (the Mac "9.17 h fake-green"
/// lesson — a silent tunnel must be caught by probing, not by watching).
const EXIT_PROBE_INTERVAL: Duration = Duration::from_secs(120);
/// F2: consecutive failures before the tunnel is declared dead.
///
/// H7 — the threshold's premise ("two consecutive failures ≈ 4 s of sustained failure") holds
/// only because the monitor's interval uses [`MissedTickBehavior::Delay`]. Under the default
/// `Burst`, a tick that overran (each tick makes two named-pipe round trips, and the Windows pipe
/// connect is synchronous and bounded only by a 30 s guard) is followed by the next tick ~0 ms
/// later, so two samples milliseconds apart could read the *same* stale value and tear down a
/// healthy tunnel. Never build the monitor's interval anywhere but [`monitor_interval`].
pub const HEALTH_FAILURE_THRESHOLD: u32 = 2;

/// The connected-lifetime monitor's tick source (H7). `Delay` re-bases the schedule after a slow
/// tick, so every threshold in [`HealthLegs`] counts genuinely *separate* observations spaced by
/// at least [`NETWORK_MONITOR_INTERVAL`]. `app/src-tauri/src/lib.rs` sets the same behaviour on
/// the main-thread pump watchdog for the same reason.
fn monitor_interval() -> tokio::time::Interval {
    let mut interval = tokio::time::interval(NETWORK_MONITOR_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    interval
}

/// The independent health legs of the connected-lifetime monitor (F2).
///
/// H8 — a failing `tono_service_status_snapshot()` used to increment *both* the kill-switch and
/// the protected-DNS counters against an `||` threshold test, so a single failed observation
/// counted as two failures and two failing polls guaranteed a teardown (with H7, two polls 0 ms
/// apart). It now has its own leg: one failed observation is one failure, on one counter.
/// Fail-closed is preserved — a dead Service still reaches `HEALTH_FAILURE_THRESHOLD` on that
/// leg and invalidates Connected — but at the honest rate of one failure per tick, and the
/// unobserved legs are never *reset* by a failed poll either.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HealthLegs {
    /// Consecutive unhealthy kill-switch snapshots.
    pub kill_switch: u32,
    /// Consecutive unhealthy protected-DNS snapshots.
    pub protected_dns: u32,
    /// Consecutive failed periodic exit probes.
    pub probe: u32,
    /// Consecutive failed Service status IPCs.
    pub service: u32,
}

impl HealthLegs {
    /// One failed Service observation: exactly one failure, on the Service leg. The other legs
    /// were not observed at all, so they are neither incremented nor cleared.
    pub const fn observe_service_failure(&mut self) {
        self.service = self.service.saturating_add(1);
    }

    /// A Service snapshot arrived; the Service leg is healthy again.
    pub const fn observe_service_ok(&mut self) {
        self.service = 0;
    }

    pub const fn observe_kill_switch(&mut self, unhealthy: bool) {
        self.kill_switch = if unhealthy {
            self.kill_switch.saturating_add(1)
        } else {
            0
        };
    }

    pub const fn observe_protected_dns(&mut self, unhealthy: bool) {
        self.protected_dns = if unhealthy {
            self.protected_dns.saturating_add(1)
        } else {
            0
        };
    }

    pub const fn observe_probe(&mut self, failed: bool) {
        self.probe = if failed { self.probe.saturating_add(1) } else { 0 };
    }

    /// Any leg that reached the threshold invalidates Connected.
    pub const fn invalid(&self) -> bool {
        health_threshold_reached(self.kill_switch)
            || health_threshold_reached(self.protected_dns)
            || health_threshold_reached(self.probe)
            || health_threshold_reached(self.service)
    }
}

/// One core-identity observation against the recorded baseline (H4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreSample {
    /// Same pid, no restart-counter bump.
    Unchanged,
    /// The Service reports no core while we recorded one. This is the *quiet* path — a
    /// `core_pid: None, restart_count: 0` payload the Service emits whenever its per-poll
    /// `is_active` check reads `Ok(None)`, with no error anywhere — so it must be sustained
    /// before it counts as a change.
    Missing,
    /// A different live pid, or a strictly increased restart counter: the Service is explicitly
    /// reporting a crash/restart, which still fires on the first sample.
    Restarted,
}

/// Classify one `/status` core-identity sample (M4/H4). `restart_count` counts only as an
/// *increase*: the quiet inactive payload resets it to 0, and a decrease is that artefact, never
/// a restart.
pub fn classify_core_sample(
    last_pid: Option<u32>,
    last_restart_count: Option<u32>,
    observed_pid: Option<u32>,
    observed_restart_count: u32,
) -> CoreSample {
    if observed_pid.is_none() && last_pid.is_some() {
        return CoreSample::Missing;
    }
    if last_pid != observed_pid {
        return CoreSample::Restarted;
    }
    match last_restart_count {
        Some(previous) if observed_restart_count > previous => CoreSample::Restarted,
        _ => CoreSample::Unchanged,
    }
}

/// Whether a classified sample invalidates Connected, given how many consecutive `Missing`
/// samples (this one included) have been seen. `Missing` needs
/// [`CORE_MISSING_SUSTAINED_SAMPLES`]; an explicit restart report does not.
pub const fn core_change_fires(sample: CoreSample, missing_samples: u32) -> bool {
    match sample {
        CoreSample::Unchanged => false,
        CoreSample::Restarted => true,
        CoreSample::Missing => missing_samples >= CORE_MISSING_SUSTAINED_SAMPLES,
    }
}

/// P0-13 debounce: only the first change inside the window invalidates Connected.
///
/// H5 — `last_network_event_at` must be cleared on connect success along with the other monitor
/// seeds. It was not, so a reconnect completing in under [`NETWORK_EVENT_DEBOUNCE`] silently
/// *discarded* its first genuine event (the counter seed still advanced, so the event was lost,
/// not deferred). `None` — the post-reset state — always fires.
pub fn network_event_fires(changed: bool, since_last_event: Option<Duration>) -> bool {
    changed && since_last_event.is_none_or(|elapsed| elapsed >= NETWORK_EVENT_DEBOUNCE)
}

/// A Windows route/interface notification is only a hint: WinTUN creation, protected-DNS
/// reconciliation, and their delayed IP Helper callbacks can all arrive after Connect has
/// already committed. Keep the fail-closed response for a changed Core identity or a failed
/// health leg, but require a fresh locked data-plane failure before a notification by itself
/// tears down a tunnel that is still carrying authenticated HTTPS traffic.
pub fn monitor_requires_reconnect(
    event_invalidated: bool,
    core_changed: bool,
    health_invalid: bool,
    event_probe_failed: bool,
) -> bool {
    health_invalid || (event_invalidated && (core_changed || event_probe_failed))
}

/// F2: while Connected, the barrier must be wanted, live, and fully
/// locked; anything else (or no answer) is unhealthy.
pub fn kill_switch_unhealthy(status: Option<&KillSwitchStatus>) -> bool {
    match status {
        Some(status) => !(status.wanted && status.live && status.mode == KillSwitchStatusMode::Locked),
        None => true,
    }
}

/// Stable Service markers that ride in `last_error` on an operation that SUCCEEDED. They are
/// warnings about what could not be proven, not reports of a broken tunnel, and the health
/// monitor must not tear a live connection down for them.
///
/// `TONO_DNS_UNVERIFIED`: DNS was applied but the read-back could not confirm every adapter.
/// `TONO_DNS_RESTORE_DEGRADED`: a restore was accepted on registry evidence alone.
///
/// Treating these as unhealthy is not a cosmetic mistake: two consecutive samples invalidate
/// Connected, and a machine that can never verify would then reconnect forever.
const DNS_WARNING_MARKERS: [&str; 2] = ["TONO_DNS_UNVERIFIED", "TONO_DNS_RESTORE_DEGRADED"];

/// Whether a `last_error` string reports an actual failure rather than an unproven-but-applied
/// state. Substring, not prefix: the Service nests these markers inside its own context.
fn dns_error_is_a_failure(last_error: Option<&str>) -> bool {
    match last_error {
        None => false,
        Some(text) => !DNS_WARNING_MARKERS.iter().any(|marker| text.contains(marker)),
    }
}

/// Connected is not healthy unless every currently known adapter is proven to use Tono's
/// protected DNS endpoint.
/// The Service status deliberately includes adapters that appeared after the original snapshot,
/// closing the first-netmon-sample race and covering a failed Windows notification registration.
pub fn protected_dns_unhealthy(status: Option<&DnsProtectionStatus>) -> bool {
    match status {
        Some(status) => {
            !(status.enabled
                && status.snapshot_present
                && status.adapters > 0
                && !dns_error_is_a_failure(status.last_error.as_deref()))
        }
        None => true,
    }
}

/// F2: threshold test shared by the kill-switch and exit-probe legs.
pub const fn health_threshold_reached(consecutive_failures: u32) -> bool {
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
            return Attempt::GuardRejected(TRANSITION_IN_FLIGHT_REJECTION.to_string());
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
        return Err(TRANSITION_IN_FLIGHT_REJECTION.to_string());
    }
    if inner.catalog_requires_choice {
        return Err("the selected node left the catalog; pick a server again".to_string());
    }
    if inner.nodes.is_empty() {
        return Err(CATALOG_NOT_READY_REJECTION.to_string());
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
/// The two guard rejections that clear on their own; see [`guard_rejection_is_transient`].
/// Named so the classifier and the sites that produce them cannot drift apart.
const TRANSITION_IN_FLIGHT_REJECTION: &str = "a connection transition is already in flight";
const CATALOG_NOT_READY_REJECTION: &str = "the exit catalog is not available yet";
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
/// Stable post-lock classifications. The loopback-proxy cross-check distinguishes a selected
/// node/Core path that works without WinTUN from a failure shared by every Mihomo ingress path.
/// None of these markers relaxes the real TUN proof required for Connected.
pub const TUN_DATA_PLANE_BROKEN_PREFIX: &str = "TONO_TUN_DATA_PLANE_BROKEN";
pub const TUN_INGRESS_BROKEN_PREFIX: &str = "TONO_TUN_INGRESS_BROKEN";
pub const NODE_OR_CORE_UNREACHABLE_PREFIX: &str = "TONO_NODE_OR_CORE_UNREACHABLE";

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
    if lower.contains("service unavailable") || lower.contains("operation already") || lower.contains("busy") {
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
        Ok(None) => Ok(()),
        // The detail carries both sides' epoch/revision. The old wording asserted "too old",
        // which `supports_client` cannot actually distinguish — it rejects a *newer* Service
        // just as flatly — so a mismatched pair used to be told to reinstall the wrong half.
        Ok(Some(detail)) => Err(format!(
            "{SERVICE_TOO_OLD_PREFIX}: Tono Service protocol does not match this App ({detail}); reinstall/repair the Tono Service from this installer"
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
    let needs_physical_interface = WINDOWS_OPTIONAL_DIRECT_ENABLED
        && traffic_policy.as_ref().is_some_and(|policy| {
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
    //  - Fresh loopback controller and diagnostic mixed-proxy ports eliminate collisions with
    //    another proxy or stale fixed listeners. The mixed listener is never a connection proof
    //    or product proxy: it is used only after a real TUN failure to distinguish node/Core
    //    egress from the Windows TUN path, and the runtime binds it explicitly to 127.0.0.1.
    //  - Mihomo's DNS listener still owns loopback:53 and publishes that resolver through the
    //    TUN endpoint at 198.18.0.2. Prove both listener sockets are available before installing
    //    WFP rather than timing out after the arm.
    //  - The Service-side core binary path validation.
    let (bootstrap_api_hosts, physical_interface_probe, runtime_ports, dns_preflight, core_path) = transaction
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
                allocate_runtime_ports(),
                preflight_dns_listener(),
                service::tono_core_binary_path(),
            )
        })
        .await?;
    let runtime_ports = runtime_ports.map_err(StageFailure::error)?;
    let controller_port = runtime_ports.controller_port;
    let mixed_port = runtime_ports.mixed_port;
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
    // §5: the owned runtime carries a fresh random controller secret; only
    // the redacted copy may touch disk.
    let secret = generate_controller_secret();
    let runtime =
        build_owned_runtime_with_ports(nodes, &node.name, &secret, None, runtime_ports).map_err(StageFailure::error)?;
    // Under the transaction like every other stage on this path. `apply_cloud_policy`'s copy is
    // already covered because that whole stage runs inside a `wait`; this one was the only
    // uncovered await in `run_stages`, and an %APPDATA% redirected to an offline share parks it
    // where the `CONNECT_TRANSACTION_TIMEOUT` budget cannot reach — Connecting forever, every retry then rejected as
    // "already connecting". The write itself never fails the connect (see `write_redacted_copy`),
    // so this wait only trips when the budget was already spent.
    transaction
        .wait(
            "writing redacted runtime copy",
            write_redacted_copy(state, &runtime.redacted_yaml()),
        )
        .await?;
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
            return Err(stale_after_arm(state, generation).await);
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
                mixed_port,
                &proxy_endpoints,
                &bootstrap_api_hosts,
                traffic_policy,
                physical_interface,
            ),
        )
        .await??;

    // §6.7: securingDNS — snapshot + point resolvers at the protected TUN endpoint, then prove
    // an ordinary lookup returns a fake-ip address.
    set_stage(state, app, ConnectStage::SecuringDns, generation, true, started).await?;
    transaction
        .wait(
            "enabling protected DNS",
            enable_dns_cancellation_safe(state, generation),
        )
        .await??;
    if state.lock().await.connect_generation != generation {
        return Err(stale_after_dns(state, generation).await);
    }
    transaction
        .wait("fake-IP verification", verify_fake_ip())
        .await?
        .map_err(StageFailure::error)?;

    // §6.8 + §6.9: checkingExit → verifyingTraffic, as one retryable verification group (C3).
    let mut kill_status = verify_post_lock(
        state,
        app,
        &secret,
        controller_port,
        mixed_port,
        generation,
        started,
        transaction,
    )
    .await?;

    // The durable logical-session latch is committed only after every existing check and a
    // final generation guard. A failure remains an ordinary connect failure.
    ensure_fresh(state, generation).await?;
    transaction
        .wait("committing verified session", service::tono_mark_kill_switch_verified())
        .await?
        .map_err(StageFailure::error)?;
    kill_status.verified = true;

    // The Tono runtime owns a fresh HTTP controller port and secret on every connection. The
    // dashboard reuses the Mihomo plugin's traffic WebSocket, so point that plugin at this
    // generation before publishing Connected. Updating the protocol last prevents a subscriber
    // from observing a half-configured HTTP context.
    configure_owned_controller_for_ui(app, &secret, controller_port);

    // §6.10: only now Connected; monitors start.
    {
        let mut inner = state.lock().await;
        if inner.connect_generation != generation {
            drop(inner);
            return Err(stale_after_arm(state, generation).await);
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
        // H5: the debounce timestamp is a monitor seed too. Leaving the previous session's
        // stamp behind meant a reconnect that completed inside NETWORK_EVENT_DEBOUNCE silently
        // *discarded* its first genuine event — the counter seed advanced past it, so the event
        // was lost rather than deferred, and the tunnel stayed green over a changed network.
        inner.last_network_event_at = None;
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

/// C3 — the post-lock verification group: an advisory controller delay check followed by the
/// authoritative real App data-plane check, retried up to [`POST_LOCK_VERIFY_ROUNDS`] times
/// inside the still-live transaction.
///
/// Why here and not in the failure path: by this point WFP is armed *and* locked and the tunnel
/// is proven up, but `session_verified` is committed only after both stages pass. A failure
/// therefore reaches `plan_failure(armed = true, session_verified = false, ..)` → `FullRelease`,
/// which destroys the tunnel — and `next_reconnect_delay()` then requires
/// `is_protection_blocked && session_verified`, both false afterwards, so nothing retries. A
/// single transient 504 on the exit probe took a working tunnel to NotConnected with no recovery.
///
/// Fail-closed is untouched: a controller `/delay` 504 is tolerated only if a fresh HTTPS request
/// from this App succeeds while WFP is locked and system DNS points into WinTUN. That is stronger
/// proof of user traffic than Mihomo's doubled synthetic measurement. Nothing here marks a
/// session verified until that proof passes, releases or weakens the barrier, or shortens any
/// release; an exhausted real-data-plane check still reaches the same `FullRelease`.
#[allow(clippy::too_many_arguments, reason = "stage helper mirrors run_stages' own context")]
async fn verify_post_lock(
    state: &Arc<TonoState>,
    app: &AppHandle,
    secret: &str,
    controller_port: u16,
    mixed_port: u16,
    generation: u64,
    started: std::time::Instant,
    transaction: &ConnectTransaction,
) -> Result<KillSwitchStatus, StageFailure> {
    // §6.8 is deliberately one advisory measurement for the whole verification group. Repeating
    // Mihomo's doubled `unified-delay` request on every TUN retry used to spend another full
    // cross-border round without adding any connection proof.
    set_stage(state, app, ConnectStage::CheckingExit, generation, true, started).await?;
    let controller_probe = transaction
        .wait("advisory exit measurement", probe_exit_once(secret, controller_port))
        .await?
        .map(|_| ());

    // §6.9 owns the verdict: first prove the barrier is wanted/live/locked, then make a fresh
    // request from this App through system DNS and WinTUN.
    set_stage(state, app, ConnectStage::VerifyingTraffic, generation, true, started).await?;
    let mut last = String::from("post-lock verification did not run");
    for round in 0..POST_LOCK_VERIFY_ROUNDS {
        if round > 0 && state.lock().await.connect_generation != generation {
            return Err(stale_after_arm(state, generation).await);
        }
        let final_round = round + 1 == POST_LOCK_VERIFY_ROUNDS;
        let (data_plane, proxy_cross_check) = if final_round {
            // Only an exhausted TUN path needs diagnosis. Run the loopback proxy check beside the
            // last mandatory TUN attempt so a broken machine does not pay another serial network
            // timeout. Success here remains diagnostic only and can never mark Connected.
            let (data_plane, proxy) = transaction
                .wait("real TUN verification with proxy cross-check", async {
                    tokio::join!(verify_locked_data_plane(), verify_mixed_proxy_data_plane(mixed_port))
                })
                .await?;
            (data_plane, Some(proxy))
        } else {
            (
                transaction
                    .wait("real TUN data-plane verification", verify_locked_data_plane())
                    .await?,
                None,
            )
        };
        let data_plane_error = data_plane.as_ref().err().cloned();

        match classify_post_lock_verification(controller_probe.clone(), data_plane) {
            PostLockVerification::Verified {
                status,
                controller_warning,
            } => {
                if let Some(error) = controller_warning {
                    let error = audit::redact(&error);
                    logging!(
                        warn,
                        Type::Service,
                        "Tono: controller exit measurement degraded; real TUN data plane passed: {error}"
                    );
                    state.audit().log(AuditEvent::HealthProbeFail {
                        probe: "controllerExitAdvisory",
                        error,
                    });
                }
                return Ok(status);
            }
            PostLockVerification::Retry { error } => {
                last = match (proxy_cross_check, data_plane_error) {
                    (Some(proxy), Some(data_plane)) => {
                        classify_exhausted_data_plane(controller_probe.clone(), data_plane, proxy)
                    }
                    _ => error,
                };
            }
        }
        if final_round {
            break;
        }
        logging!(
            warn,
            Type::Service,
            "Tono: 隧道已锁定但验证未通过，重试验证阶段 ({}/{}): {last}",
            round + 1,
            POST_LOCK_VERIFY_ROUNDS
        );
        transaction
            .wait(
                "post-lock verification retry",
                tokio::time::sleep(POST_LOCK_VERIFY_ROUND_DELAY),
            )
            .await?;
    }
    Err(StageFailure::error(last))
}

#[derive(Debug, PartialEq, Eq)]
enum PostLockVerification<T> {
    Verified {
        status: T,
        controller_warning: Option<String>,
    },
    Retry {
        error: String,
    },
}

fn classify_post_lock_verification<T>(
    controller_probe: Result<(), String>,
    data_plane: Result<T, String>,
) -> PostLockVerification<T> {
    match (controller_probe, data_plane) {
        (Ok(()), Ok(status)) => PostLockVerification::Verified {
            status,
            controller_warning: None,
        },
        (Err(error), Ok(status)) => PostLockVerification::Verified {
            status,
            controller_warning: Some(error),
        },
        (Ok(()), Err(error)) => PostLockVerification::Retry { error },
        (Err(controller), Err(data_plane)) => PostLockVerification::Retry {
            error: format!(
                "controller exit measurement failed: {controller}; real TUN data plane failed: {data_plane}"
            ),
        },
    }
}

fn classify_exhausted_data_plane(
    controller_probe: Result<(), String>,
    data_plane: String,
    proxy_cross_check: Result<(), String>,
) -> String {
    match (controller_probe, proxy_cross_check) {
        (Ok(()), Ok(())) => format!(
            "{TUN_DATA_PLANE_BROKEN_PREFIX}: selected node and Mihomo proxy egress passed, but the Windows TUN data plane failed: {data_plane}"
        ),
        (Err(controller), Ok(())) => format!(
            "{TUN_DATA_PLANE_BROKEN_PREFIX}: loopback proxy egress passed despite controller warning ({controller}), but the Windows TUN data plane failed: {data_plane}"
        ),
        (Ok(()), Err(proxy)) => format!(
            "{TUN_INGRESS_BROKEN_PREFIX}: controller node egress passed, but both App ingress paths failed; TUN: {data_plane}; loopback proxy: {proxy}"
        ),
        (Err(controller), Err(proxy)) => format!(
            "{NODE_OR_CORE_UNREACHABLE_PREFIX}: controller, Windows TUN, and loopback proxy checks all failed; controller: {controller}; TUN: {data_plane}; loopback proxy: {proxy}"
        ),
    }
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
            return Err(stale_after_arm(&task_state, generation).await);
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
            return Err(stale_after_dns(&task_state, generation).await);
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
async fn stale_after_arm(state: &Arc<TonoState>, generation: u64) -> StageFailure {
    // Asks for the intent of the bump that retired *this* generation, not the latest one: a
    // later non-releasing bump must not downgrade a pending release into "keep blocking".
    let release_intent = { state.lock().await.release_intent_for(generation) };
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
/// releasing WFP alone strands the machine on Tono's protected DNS with no answering core. Node-switch
/// invalidations deliberately keep DNS protected because their replacement transaction owns it.
async fn stale_after_dns(state: &Arc<TonoState>, generation: u64) -> StageFailure {
    let release_intent = { state.lock().await.release_intent_for(generation) };
    if release_intent {
        if let Err(error) = service::tono_restore_protected_dns().await {
            logging!(
                error,
                Type::Service,
                "Tono: 连接代际失效于 DNS 启用之后，但 DNS 恢复失败；保留 WFP 保护: {error:#}"
            );
            return StageFailure::Stale;
        }
        return stale_after_arm(state, generation).await;
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
            // ...and stop claiming Connecting while it runs. The predicate below deliberately
            // skips `connect_failed` in this case (it would resolve to FullRelease and disarm
            // before the release had actually run), which left `is_connecting` true alongside
            // `is_protection_blocked` for the whole of `release_explicit` — a full
            // `EXPLICIT_RELEASE_TIMEOUT` of a UI reading "Connecting" with no transaction in
            // flight, during which `guard_snapshot`
            // rejected every new connect. This is the state both exit branches below converge
            // on anyway, minus the release verdict.
            inner.fsm.initial_release_failed();
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
/// Guard rejections that describe a moment rather than a decision.
///
/// `guard_snapshot`'s first check is `release_in_progress`, which is transient by construction,
/// and its transition check clears as soon as the in-flight attempt ends. Treating either as a
/// verdict ends the reconnect chain for good, and the machine then sits blocked in Protected
/// Offline with no scheduled retry and nothing shown to the user. Everything else — suspended,
/// signed out, no selection, a vanished node — needs a person, so it correctly stops the chain.
pub fn guard_rejection_is_transient(reason: &str) -> bool {
    reason.contains(RELEASE_RECONCILING_PREFIX)
        || reason == TRANSITION_IN_FLIGHT_REJECTION
        || reason == CATALOG_NOT_READY_REJECTION
}

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
            Attempt::Connected | Attempt::Stale => return,
            Attempt::GuardRejected(reason) => {
                if !guard_rejection_is_transient(&reason) {
                    return;
                }
                // The attempt never started, so this is not a connect failure: no `fail_connect`,
                // no error shown, no retry_attempt bump. It only earns the next delay, because
                // ending the loop here would strand the machine blocked with nothing scheduled.
                logging!(info, Type::Service, "Tono: 自动重连被暂态守卫拒绝，稍后重试: {reason}");
                let next = {
                    let mut inner = state.lock().await;
                    inner.fsm.next_reconnect_delay()
                };
                match next {
                    Some(next_delay) => delay = next_delay,
                    None => return,
                }
            }
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
    let generation = {
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
        active.then_some(inner.connect_generation)
    };
    let Some(generation) = generation else {
        return;
    };
    logging!(warn, Type::Service, "Tono: 选中节点从新目录中消失，停止核心但保持封锁");
    let _ = service::tono_stop_core(false).await;
    let _ = service::tono_restrict_bootstrap().await;

    let mut inner = state.lock().await;
    // Two IPCs ran with the lock released. If a disconnect / sign-out / quit took ownership in
    // that window, its FSM state is the truth and must not be overwritten here: the
    // `connect_failed()` below runs the failure decision table, and for an armed-but-unverified
    // session — exactly what a *failed* release leaves behind — it resolves to FullRelease and
    // calls `release()`, clearing `kill_switch_armed` and showing NotConnected over a barrier
    // that is still blocking. `quit_release` would then compute `protected == false` and skip
    // the release entirely. Leaving `stay_armed_after_failed_release`'s state alone is the same
    // "keep the real armed state visible" treatment.
    if inner.connect_generation != generation {
        logging!(
            info,
            Type::Service,
            "Tono: 目录消失清理已被更新的连接代际取代，保留其可见状态"
        );
        return;
    }
    inner.controller_secret = None;
    inner.controller_port = None;
    let vanished_node = inner.selected_node.clone();
    if inner.fsm.status().is_connected {
        inner.fsm.tunnel_died();
    } else {
        // `initial_release_failed`, not `connect_failed`: this teardown deliberately keeps
        // blocking (stop_core(false) + restrict_bootstrap), but for an attempt that armed and
        // has not yet been verified the decision table resolves `connect_failed` to a full
        // release, which clears the armed latch while the Service is still blocking. The UI
        // would then read notConnected over a live barrier, and Disconnect / Sign out / Quit
        // would each compute "nothing to release" and skip it — a silent total blackout that
        // survives app exit.
        inner.fsm.initial_release_failed();
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
            // Keep-blocking teardown: see the note in `selected_node_vanished`. A switch that
            // interrupts an armed-but-unverified attempt must not let the decision table
            // release the latch the Service is still enforcing.
            inner.fsm.initial_release_failed();
        }
        commands::emit_status(&app, &commands::status_of(&inner));
    }
    // Keep the barrier up between the old and the new tunnel.
    let _ = service::tono_stop_core(false).await;
    // The entry check above is not enough: that stop is an IPC that can take seconds, and a
    // disconnect landing inside it owns the machine from that point on. Without this the switch
    // would re-arm WFP and start a core after the user's release had already completed.
    if state.lock().await.connect_generation != generation {
        return;
    }
    match attempt(&state, &app).await {
        Attempt::Failed(err) => {
            let _ = fail_connect(&state, &app, err).await;
            schedule_reconnect(&state, &app).await;
        }
        // Same reason as in `reconnect_loop`: a guard that clears on its own must leave a retry
        // behind, or the switch ends with the machine blocked and idle.
        Attempt::GuardRejected(reason) if guard_rejection_is_transient(&reason) => {
            logging!(info, Type::Service, "Tono: 节点切换被暂态守卫拒绝，稍后重试: {reason}");
            schedule_reconnect(&state, &app).await;
        }
        Attempt::Connected | Attempt::GuardRejected(_) | Attempt::Stale => {}
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

/// F2 leg 2: periodically repeat the same authoritative multi-origin real App request used at
/// Connect. The controller delay API is deliberately excluded: under `unified-delay` it is a
/// doubled measurement and persistent 504s on distant Reality exits do not prove user traffic is
/// dead. A single public origin is likewise insufficient: every independent TLS target must fail
/// before this leg reports failure.
async fn periodic_data_plane_probe_failed(state: &Arc<TonoState>) -> bool {
    match verify_tun_data_plane().await {
        Ok(()) => false,
        Err(err) => {
            state.audit().log(AuditEvent::HealthProbeFail {
                probe: "tunDataPlane",
                error: err,
            });
            true
        }
    }
}

async fn network_monitor_loop(state: Arc<TonoState>, app: AppHandle) {
    // H7: `Delay`, never the default `Burst` — see `HEALTH_FAILURE_THRESHOLD`.
    let mut interval = monitor_interval();
    interval.tick().await;
    let mut legs = HealthLegs::default();
    let mut missing_core_samples = 0_u32;
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
                // A dead/unreachable Service is not a neutral sample: it is one failed
                // observation on the Service leg (H8 — it used to be counted on the kill-switch
                // *and* the protected-DNS leg against an `||` test, which made a single failing
                // poll worth two failures). Fail-closed is unchanged: consecutive failures still
                // reach the threshold and invalidate Connected. The other legs keep their
                // counters — a failed poll observed nothing, so it clears nothing either.
                legs.observe_service_failure();
                state.audit().log(AuditEvent::HealthProbeFail {
                    probe: "service",
                    error: error.to_string(),
                });
                if legs.invalid() {
                    handle_network_change(&state, &app).await;
                    return;
                }
                continue;
            }
        };
        legs.observe_service_ok();

        // F2 leg 1: kill-switch completeness every tick.
        legs.observe_kill_switch(kill_switch_unhealthy(snapshot.kill_switch.as_ref()));

        // DNS health is checked independently of netmon. The first network event is used only
        // to seed the counter (to ignore our own connect-time interface churn), so an adapter
        // arriving in that narrow window would otherwise remain external-DNS until another event.
        let protected_dns = service::tono_protected_dns_status().await.ok();
        legs.observe_protected_dns(protected_dns_unhealthy(protected_dns.as_ref()));

        // F2 leg 2: periodic real App data-plane probe through the tunnel.
        if last_probe.elapsed() >= EXIT_PROBE_INTERVAL {
            last_probe = std::time::Instant::now();
            legs.observe_probe(periodic_data_plane_probe_failed(&state).await);
        }
        let health_invalid = legs.invalid();

        let (invalidate, network_changed, core_changed, kill_switch_snapshot, service_events) = {
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

            // M4: a core crash/restart shows up as a new pid or a bumped restart counter; the
            // TUN LUID is re-resolved by the fresh transaction's lock phase.
            //
            // H4: a *quiet* `core_pid: None` is not proof of a crash — the Service emits it
            // (with `restart_count: 0`, no error) whenever its per-poll `is_active` check reads
            // `Ok(None)` — so it must be sustained before it fires, and the baseline pid is kept
            // until it does. Overwriting the baseline with the quiet `None` would make the very
            // next healthy sample look like a pid change and tear the tunnel down anyway.
            let old_pid = inner.last_core_pid;
            let sample = classify_core_sample(
                inner.last_core_pid,
                inner.last_restart_count,
                snapshot.core_pid,
                snapshot.restart_count,
            );
            missing_core_samples = if sample == CoreSample::Missing {
                missing_core_samples.saturating_add(1)
            } else {
                0
            };
            let core_changed = !first_sample && core_change_fires(sample, missing_core_samples);
            if sample != CoreSample::Missing || core_changed {
                inner.last_core_pid = snapshot.core_pid;
                inner.last_restart_count = Some(snapshot.restart_count);
            }

            // P0-13: merge event bursts — only the first change inside the
            // debounce window invalidates Connected.
            let invalidated = network_event_fires(
                network_changed || core_changed,
                inner.last_network_event_at.map(|at| at.elapsed()),
            );
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
            (invalidated, network_changed, core_changed, snapshot_for_emit, events)
        };
        for event in service_events {
            state.audit().log(event);
        }
        if let Some(status) = kill_switch_snapshot {
            commands::emit_status(&app, &status);
        }

        // IP Helper delivers Tono's own WinTUN/route and DNS-reconciliation callbacks
        // asynchronously. A callback can therefore land after the Service write window and
        // after this monitor seeded its counter, producing the old connectOk -> networkChange ->
        // reconnect loop. Do not trust the event either way: under the still-locked barrier,
        // repeat the same multi-origin HTTPS proof that admitted Connected. Success proves the
        // current tunnel still carries user traffic; failure corroborates the event and keeps the
        // existing fail-closed reconnect. Core identity and health failures remain unconditional.
        let event_probe_failed = if invalidate && network_changed && !core_changed && !health_invalid {
            periodic_data_plane_probe_failed(&state).await
        } else {
            false
        };
        if invalidate && network_changed && !core_changed && !health_invalid && !event_probe_failed {
            logging!(
                info,
                Type::Service,
                "Tono: Windows reported a network change, but the locked TUN data plane remains healthy; keeping Connected"
            );
            legs.observe_probe(false);
        }
        if monitor_requires_reconnect(invalidate, core_changed, health_invalid, event_probe_failed) {
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
    // Captured under the same guard as the `is_connected` check, because that check is the
    // *entry* condition and everything below it runs across awaits. This helper is reached from
    // two callers and only one of them is connection-scoped: the cloud-policy sync runs inside
    // `tasks.catalog_sync`, which is account-scoped and deliberately survives a disconnect, so
    // `invalidate_connection` never aborts it. Without a generation, a policy revision arriving
    // while Connected would tear the tunnel down, the user would press Disconnect during the
    // resulting Protected Offline flash, the release would complete — and this task would then
    // walk into `attempt` and silently re-arm WFP and restart the core with no user action.
    // The netmon caller was protected only by accident, by `abort_network_monitor()` landing at
    // its next await; now both are protected on purpose.
    let generation = {
        let mut inner = state.lock().await;
        if !inner.fsm.status().is_connected {
            return;
        }
        inner.fsm.tunnel_died();
        commands::emit_status(&app, &commands::status_of(&inner));
        inner.connect_generation
    };
    state.audit().log(AuditEvent::ProtectedOffline {
        reason: "networkChange",
    });
    let _ = service::tono_restrict_bootstrap().await;
    // Stop the core before re-attempting, like both sibling teardowns (`switch_selected_node`,
    // `selected_node_vanished`). `restrict_bootstrap` only rewrites WFP; it leaves mihomo
    // running, and mihomo owns loopback:53 for the whole session — the very port `run_stages`'
    // DNS preflight binds. Without this, every sleep/wake and Wi-Fi flap burned attempt #1 on a
    // guaranteed "DNS UDP 127.0.0.1:53 is unavailable", recorded a ConnectFail, bumped the retry
    // counter and showed a DNS error, and only then stopped the core on the way out.
    // `false` = keep blocking: the core goes down, the barrier stays armed.
    let _ = service::tono_stop_core(false).await;
    // Immediately before re-entering the transaction, and deliberately not earlier: a disconnect
    // bumps the generation as its very first act (`invalidate_connection(true)`, before any
    // IPC), so any release that will complete has already bumped by the time this reads. A moved
    // generation means someone else owns the machine — exit without touching the FSM, the core
    // or the UI, exactly like `StageFailure::Stale`.
    {
        let inner = state.lock().await;
        if inner.connect_generation != generation || inner.fsm.status().is_disconnecting {
            logging!(
                info,
                Type::Service,
                "Tono: 网络变化重连已被更新的连接代际取代，交由其所有者处理"
            );
            return;
        }
    }
    match attempt(state, app).await {
        Attempt::Failed(err) => {
            let _ = fail_connect(state, app, err).await;
            schedule_reconnect(state, app).await;
        }
        // A transient guard (a release still reconciling, a transition still finishing) is not a
        // verdict — without a reschedule the machine sits blocked with nothing left to retry.
        Attempt::GuardRejected(reason) if guard_rejection_is_transient(&reason) => {
            logging!(info, Type::Service, "Tono: 重连被暂态守卫拒绝，稍后重试: {reason}");
            schedule_reconnect(state, app).await;
        }
        Attempt::Connected | Attempt::GuardRejected(_) | Attempt::Stale => {}
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
        Err(stale_after_arm(state, generation).await)
    } else {
        Err(StageFailure::Stale)
    }
}

/// The controller HTTP client. C2: the total timeout is per call site, because one of them (the
/// exit probe) hands the *core* a budget of its own and must always outlast it — a client that
/// times out first throws away mihomo's diagnosis and reports a transport error instead.
fn controller_client(timeout: Duration) -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_millis(500))
        .timeout(timeout)
        .build()
        .map_err(|err| err.to_string())
}

fn controller_url(port: u16, path: &str) -> String {
    format!("http://127.0.0.1:{port}{path}")
}

fn configure_owned_controller_for_ui(app: &AppHandle, secret: &str, controller_port: u16) {
    let mihomo = app.mihomo();
    mihomo.update_external_host(Some("127.0.0.1"));
    mihomo.update_external_port(Some(controller_port));
    mihomo.update_secret(Some(secret));
    if let Err(error) = mihomo.update_protocol(Protocol::Http) {
        // Telemetry must never turn a fully verified tunnel into a failed connection. Keep the
        // product online and make the missing dashboard data diagnosable instead.
        logging!(
            warn,
            Type::Frontend,
            "Tono: failed to configure dashboard traffic telemetry: {error:#}"
        );
    }
}

/// Pick two distinct unused loopback ports for this connection generation. Both binds stay live
/// until both port numbers have been observed, so the OS cannot hand the same ephemeral port to
/// the controller and the diagnostic proxy. They are intentionally released before Mihomo starts;
/// another process can theoretically win that narrow race, but Mihomo then fails immediately and
/// the absolute connection deadline handles it. Keeping either listener open would prevent the
/// child from binding on Windows.
async fn allocate_runtime_ports() -> Result<RuntimePorts, String> {
    let controller = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|error| format!("cannot allocate loopback controller port: {error}"))?;
    let mixed = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|error| format!("cannot allocate loopback diagnostic proxy port: {error}"))?;
    let controller_port = controller
        .local_addr()
        .map_err(|error| format!("cannot inspect loopback controller port: {error}"))?
        .port();
    let mixed_port = mixed
        .local_addr()
        .map_err(|error| format!("cannot inspect loopback diagnostic proxy port: {error}"))?
        .port();
    drop((controller, mixed));
    if controller_port == 0 || mixed_port == 0 || controller_port == mixed_port {
        return Err("operating system returned an invalid runtime listener plan".to_string());
    }
    Ok(RuntimePorts {
        mixed_port,
        controller_port,
    })
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
    let client = controller_client(CONTROLLER_HTTP_TIMEOUT)?;
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
/// not burn the connect transaction budget on 50 full lifecycle IPCs.
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

/// §6.7: an ordinary system lookup must return a fake-ip address. On Windows, use the DNS Client
/// API directly with cache bypass and true cancellation; this keeps all three propagation retries
/// useful instead of accumulating uncancellable `getaddrinfo` work.
async fn verify_fake_ip() -> Result<(), String> {
    let mut last = String::from("no answer");
    for attempt in 0..VERIFY_ATTEMPTS {
        #[cfg(windows)]
        let lookup = crate::tono::windows_dns::query_a(FAKE_IP_LOOKUP_HOST, FAKE_IP_LOOKUP_TIMEOUT)
            .await
            .map(|addrs| addrs.into_iter().map(IpAddr::V4).collect::<Vec<_>>());
        #[cfg(not(windows))]
        let lookup = tokio::time::timeout(
            FAKE_IP_LOOKUP_TIMEOUT,
            tokio::net::lookup_host((FAKE_IP_LOOKUP_HOST, 443)),
        )
        .await
        .map_err(|_| format!("system DNS lookup exceeded {FAKE_IP_LOOKUP_TIMEOUT:?}"))
        .and_then(|result| {
            result
                .map(|addrs| addrs.map(|addr| addr.ip()).collect::<Vec<_>>())
                .map_err(|e| e.to_string())
        });

        match lookup {
            Ok(addrs) => {
                if addrs.iter().copied().any(is_fake_ip) {
                    return Ok(());
                }
                last = format!("no fake-ip in {addrs:?}");
            }
            Err(err) => last = err,
        }
        if attempt + 1 < VERIFY_ATTEMPTS {
            tokio::time::sleep(VERIFY_RETRY_INTERVAL).await;
        }
    }
    Err(format!("fake-ip verification failed: {last}"))
}

/// One exit probe: `GET /proxies/Tono-Exit/delay` against the generate_204 target with an
/// [`EXIT_PROBE_CORE_TIMEOUT_MS`] core-side budget; a positive delay proves egress. The client
/// budget ([`EXIT_PROBE_CLIENT_TIMEOUT`]) is strictly larger, so the verdict — including a
/// mihomo-reported failure — always comes from the core (C2).
async fn probe_exit_once(secret: &str, controller_port: u16) -> Result<u64, String> {
    let client = controller_client(EXIT_PROBE_CLIENT_TIMEOUT)?;
    let mut url = reqwest::Url::parse(&controller_url(
        controller_port,
        &format!("/proxies/{EXIT_GROUP_NAME}/delay"),
    ))
    .map_err(|err| err.to_string())?;
    url.query_pairs_mut()
        .append_pair("url", EXIT_PROBE_URL)
        .append_pair("timeout", &EXIT_PROBE_CORE_TIMEOUT_MS.to_string());

    crate::tono::integration_profile::delay_remote_operation().await;
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

/// V1/H1 — the retry window `verify_locked` spends before it calls a tunnel unverified. Must
/// exceed the Service-side liveness cache TTL, or the verdict is one sample of a decaying value.
pub fn verify_lock_retry_window() -> Duration {
    VERIFY_LOCK_RETRY_INTERVAL * (VERIFY_LOCK_ATTEMPTS.saturating_sub(1))
}

/// §6.9: the kill switch must be wanted, verified live, and fully locked.
///
/// V1/H1: bounded retry, never a single shot. `live` is not a live query on Windows — it is a
/// ~1.5 s-decaying cache refreshed by a 1 s loop — so a slow-but-successful verify reads
/// `live: false`. Retrying only re-*reads*: nothing but a `wanted && live && Locked` answer
/// passes, so the fail-closed verdict is unchanged, it is merely no longer decided by one sample.
async fn verify_locked() -> Result<KillSwitchStatus, String> {
    let mut last = String::from("no answer");
    for attempt in 0..VERIFY_LOCK_ATTEMPTS {
        match service::tono_kill_switch_status().await {
            Ok(status) => {
                if status.wanted && status.live && status.mode == KillSwitchStatusMode::Locked {
                    return Ok(status);
                }
                last = format!(
                    "kill switch not locked (wanted={}, live={}, mode={:?})",
                    status.wanted, status.live, status.mode
                );
            }
            Err(err) => last = err.to_string(),
        }
        if attempt + 1 < VERIFY_LOCK_ATTEMPTS {
            tokio::time::sleep(VERIFY_LOCK_RETRY_INTERVAL).await;
        }
    }
    Err(format!(
        "{last} (after {VERIFY_LOCK_ATTEMPTS} samples over {:?})",
        verify_lock_retry_window()
    ))
}

/// The authoritative connection verdict: an ordinary fresh App flow must traverse the protected
/// Windows data plane. With WFP locked, a physical-interface fallback is blocked and only the
/// recorded WinTUN LUID is permitted, so a valid HTTPS 204 is positive evidence of tunnel traffic.
async fn verify_locked_data_plane() -> Result<KillSwitchStatus, String> {
    let status = verify_locked().await?;
    verify_tun_data_plane().await?;
    Ok(status)
}

async fn verify_tun_data_plane() -> Result<(), String> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(TUN_DATA_PLANE_CONNECT_TIMEOUT)
        .timeout(TUN_DATA_PLANE_TIMEOUT)
        .build()
        .map_err(|error| format!("cannot create TUN data-plane probe: {error}"))?;
    crate::tono::integration_profile::delay_remote_operation().await;

    race_data_plane_probes(&client)
        .await
        .map_err(|failures| format_tun_probe_failures(&failures))
}

/// Diagnostic-only App ingress through Mihomo's ephemeral loopback mixed listener. This bypasses
/// WinTUN but still uses the exact owned runtime, selected exit group, staged core, WFP endpoint
/// permit, and remote node. A success therefore isolates a Windows TUN/route failure; it is never
/// returned as a successful connection verdict.
async fn verify_mixed_proxy_data_plane(mixed_port: u16) -> Result<(), String> {
    let proxy_url = format!("http://127.0.0.1:{mixed_port}");
    let proxy = reqwest::Proxy::all(&proxy_url)
        .map_err(|error| format!("cannot configure loopback diagnostic proxy: {error}"))?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .proxy(proxy)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(TUN_DATA_PLANE_CONNECT_TIMEOUT)
        .timeout(TUN_DATA_PLANE_TIMEOUT)
        .build()
        .map_err(|error| format!("cannot create loopback diagnostic proxy probe: {error}"))?;
    crate::tono::integration_profile::delay_remote_operation().await;

    race_data_plane_probes(&client).await.map_err(|failures| {
        format!(
            "all {} independent loopback-proxy probes failed: {}",
            TUN_DATA_PLANE_PROBES.len(),
            failures.join(" | ")
        )
    })
}

async fn race_data_plane_probes(client: &reqwest::Client) -> Result<(), Vec<String>> {
    let mut in_flight = FuturesUnordered::new();
    for probe in TUN_DATA_PLANE_PROBES {
        in_flight.push(probe_tun_endpoint(&client, probe));
    }

    let mut failures = Vec::with_capacity(TUN_DATA_PLANE_PROBES.len());
    while let Some(result) = in_flight.next().await {
        match result {
            Ok(()) => return Ok(()),
            Err(error) => failures.push(error),
        }
    }
    Err(failures)
}

async fn probe_tun_endpoint(client: &reqwest::Client, probe: TunDataPlaneProbe) -> Result<(), String> {
    let response = client
        .get(probe.url)
        .send()
        .await
        .map_err(|error| format!("{} ({}): {}", probe.label, probe.url, describe_reqwest_error(&error)))?;
    let actual = response.status().as_u16();
    if actual == probe.expected_status {
        Ok(())
    } else {
        Err(format!(
            "{} ({}) answered {}, expected {}",
            probe.label, probe.url, actual, probe.expected_status
        ))
    }
}

fn describe_reqwest_error(error: &reqwest::Error) -> String {
    let category = if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect"
    } else {
        "request"
    };
    let mut parts = vec![format!("{category}: {error}")];
    let mut source = error.source();
    while let Some(cause) = source {
        let detail = cause.to_string();
        if !detail.is_empty() && parts.last().is_none_or(|last| last != &detail) {
            parts.push(detail);
        }
        if parts.len() == 5 {
            break;
        }
        source = cause.source();
    }
    let joined = parts.join(" -> ");
    controller_error_detail(&joined).unwrap_or_else(|| category.to_string())
}

fn format_tun_probe_failures(failures: &[String]) -> String {
    format!(
        "all {} independent real TUN data-plane probes failed: {}",
        TUN_DATA_PLANE_PROBES.len(),
        failures.join(" | ")
    )
}

// ---- WeChat-DIRECT cloud policy (Build 28) ----

/// Optional physical-interface DIRECT acceleration currently requires a destructive second Core
/// start. Mainland reports proved the first full-tunnel runtime could resolve the policy through
/// the selected node, then the replacement runtime lost controller, TUN, and loopback-proxy
/// egress together. Retain the already-working full-tunnel runtime until policy activation can be
/// made transactional with a proven rollback. This removes physical DIRECT permits and therefore
/// narrows, rather than weakens, the fail-closed policy.
const WINDOWS_OPTIONAL_DIRECT_ENABLED: bool = false;
/// Maximum resolved addresses kept per policy domain (Mac parity).
const MAX_ADDRESSES_PER_DOMAIN: usize = 8;
/// A cloud policy can currently carry dozens of names. Launching all DoH
/// lookups at once overloaded otherwise healthy distant Reality exits on
/// real mainland-like links, so keep a small, deterministic in-flight cap.
const CLOUD_DNS_QUERY_CONCURRENCY: usize = 4;
/// One transient controller/DoH failure must not tear down a protected
/// connection. Permanent controller errors still fail immediately.
const CLOUD_DNS_QUERY_ATTEMPTS: u32 = 3;
const CLOUD_DNS_QUERY_RETRY_DELAY: Duration = Duration::from_millis(350);
/// Both WeChat and web-domain sets share this one deadline. The enclosing
/// connect transaction remains the final fail-closed ceiling.
const CLOUD_POLICY_RESOLUTION_TIMEOUT: Duration = Duration::from_secs(35);

/// The applyingCloudPolicy stage: when a validated cloud policy exists,
/// resolve its domains through the now-running controller, build the
/// DIRECT plan, and re-arm with the endpoint permits + the direct-enabled
/// runtime. Returns the controller secret the remaining stages must use
/// (a second start rotates it). `Ok(original)` when there is no policy or
/// the policy is empty. DIRECT is optional acceleration: if its interface
/// snapshot or DNS discovery is unavailable, no DIRECT permits are added
/// and the byte-identical plan-less tunnel continues instead.
async fn apply_cloud_policy(
    state: &Arc<TonoState>,
    app: &AppHandle,
    node: &ValidatedNode,
    nodes: &[ValidatedNode],
    generation: u64,
    original_secret: &str,
    controller_port: u16,
    mixed_port: u16,
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
    if !WINDOWS_OPTIONAL_DIRECT_ENABLED {
        return Ok(skip_optional_direct_policy(
            state,
            original_secret,
            "optional Windows DIRECT policy is disabled; retaining the proven full-tunnel runtime".to_string(),
        ));
    }

    let Some(interface) = physical_interface else {
        return Ok(skip_optional_direct_policy(
            state,
            original_secret,
            "cloud DIRECT policy has no pre-TUN physical interface snapshot".to_string(),
        ));
    };

    // Resolve through a small bounded pool. WeChat and web sets run in
    // sequence so their separate batches cannot double the global cap.
    let resolution = tokio::time::timeout(CLOUD_POLICY_RESOLUTION_TIMEOUT, async {
        let wechat = resolve_direct_domains(original_secret, controller_port, &policy.domains, node).await?;
        let web = resolve_direct_domains(original_secret, controller_port, &policy.web_domains, node).await?;
        Ok::<_, String>((wechat, web))
    })
    .await
    .map_err(|_| {
        format!(
            "cloud DIRECT DNS resolution exceeded {}s",
            CLOUD_POLICY_RESOLUTION_TIMEOUT.as_secs()
        )
    })
    .and_then(|result| result);
    let (wechat_pins, web_pins) = match classify_optional_direct_resolution(resolution) {
        OptionalDirectResolution::Ready(pins) => pins,
        OptionalDirectResolution::Skip(reason) => {
            return Ok(skip_optional_direct_policy(state, original_secret, reason));
        }
    };
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
            mixed_port,
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
            return Err(stale_after_arm(state, generation).await);
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
        return Err(stale_after_arm(state, generation).await);
    }
    lock_kill_switch_with_retries().await.map_err(StageFailure::error)?;
    if state.lock().await.connect_generation != generation {
        return Err(stale_after_arm(state, generation).await);
    }

    state.audit().log(AuditEvent::PolicyActivated {
        wechat_tcp: plan.tcp_wechat_rules.len(),
        web_tcp: plan.tcp_web_rules.len(),
        udp: plan.udp_wechat_rules.len(),
    });
    let _ = app;
    Ok(secret)
}

/// Resolution failures only disable the optional DIRECT optimization. Keeping
/// the original runtime and its zero-DIRECT WFP policy is the fail-closed
/// outcome: every packet still has to traverse the protected tunnel.
#[derive(Debug, PartialEq, Eq)]
enum OptionalDirectResolution<T> {
    Ready(T),
    Skip(String),
}

fn classify_optional_direct_resolution<T>(result: Result<T, String>) -> OptionalDirectResolution<T> {
    match result {
        Ok(value) => OptionalDirectResolution::Ready(value),
        Err(reason) => OptionalDirectResolution::Skip(reason),
    }
}

fn skip_optional_direct_policy(state: &Arc<TonoState>, original_secret: &str, reason: String) -> String {
    let reason = audit::redact(&reason);
    logging!(
        warn,
        Type::Service,
        "Tono: optional cloud DIRECT policy skipped; all traffic remains tunneled: {reason}"
    );
    state.audit().log(AuditEvent::PolicyActivationSkipped { reason });
    original_secret.to_string()
}

/// One (host, usable addresses, ports) pin per policy domain, resolved via
/// the mihomo controller's `/dns/query`. An error rejects the entire DIRECT
/// plan; the caller then continues with zero DIRECT permits.
async fn resolve_direct_domains(
    secret: &str,
    controller_port: u16,
    domains: &[tono_core::policy::PolicyDomain],
    node: &ValidatedNode,
) -> Result<Vec<(String, Vec<std::net::Ipv4Addr>, Vec<u16>)>, String> {
    let client = controller_client(CONTROLLER_HTTP_TIMEOUT)?;
    let mut pins = Vec::with_capacity(domains.len());
    for batch in domains.chunks(CLOUD_DNS_QUERY_CONCURRENCY) {
        let queries = batch.iter().map(|domain| {
            let host = domain.host.clone();
            let ports = domain.ports.clone();
            let server = node.server;
            let secret = secret.to_string();
            let client = client.clone();
            async move {
                let addresses = dns_query_a_with_retry(&client, &secret, controller_port, &host).await?;
                let usable: Vec<std::net::Ipv4Addr> = addresses
                    .into_iter()
                    .filter(|ip| tono_core::node::is_public_ipv4(*ip))
                    .filter(|ip| *ip != server)
                    .filter(|ip| !tono_core::policy::is_permanently_protected(*ip))
                    .take(MAX_ADDRESSES_PER_DOMAIN)
                    .collect();
                Ok::<_, String>((host, usable, ports))
            }
        });
        for result in futures::future::join_all(queries).await {
            pins.push(result?);
        }
    }
    Ok(pins)
}

#[derive(Debug)]
struct ControllerDnsFailure {
    message: String,
    retryable: bool,
}

fn controller_dns_status_is_retryable(status: reqwest::StatusCode) -> bool {
    status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS
}

async fn dns_query_a_with_retry(
    client: &reqwest::Client,
    secret: &str,
    controller_port: u16,
    host: &str,
) -> Result<Vec<std::net::Ipv4Addr>, String> {
    let mut last = String::from("no response");
    for attempt in 1..=CLOUD_DNS_QUERY_ATTEMPTS {
        match dns_query_a(client, secret, controller_port, host).await {
            Ok(addresses) => return Ok(addresses),
            Err(error) => {
                last = error.message;
                if !error.retryable {
                    return Err(last);
                }
            }
        }
        if attempt < CLOUD_DNS_QUERY_ATTEMPTS {
            tokio::time::sleep(CLOUD_DNS_QUERY_RETRY_DELAY).await;
        }
    }
    Err(format!(
        "dns query for {host} failed after {CLOUD_DNS_QUERY_ATTEMPTS} attempts: {last}"
    ))
}

/// `GET /dns/query?name=<host>&type=A` through the controller; the response
/// shape is tolerated by collecting every IPv4 literal in the JSON tree.
async fn dns_query_a(
    client: &reqwest::Client,
    secret: &str,
    controller_port: u16,
    host: &str,
) -> Result<Vec<std::net::Ipv4Addr>, ControllerDnsFailure> {
    let mut url =
        reqwest::Url::parse(&controller_url(controller_port, "/dns/query")).map_err(|err| ControllerDnsFailure {
            message: err.to_string(),
            retryable: false,
        })?;
    url.query_pairs_mut().append_pair("name", host).append_pair("type", "A");
    crate::tono::integration_profile::delay_remote_operation().await;
    let response = client
        .get(url)
        .bearer_auth(secret)
        .send()
        .await
        .map_err(|err| ControllerDnsFailure {
            message: err.to_string(),
            retryable: true,
        })?;
    if !response.status().is_success() {
        let status = response.status();
        let retryable = controller_dns_status_is_retryable(status);
        let detail = response
            .text()
            .await
            .ok()
            .and_then(|body| controller_error_detail(&body));
        let message = match detail {
            Some(detail) => format!("dns query for {host} answered {status}: {detail}"),
            None => format!("dns query for {host} answered {status}"),
        };
        return Err(ControllerDnsFailure { message, retryable });
    }
    let value: serde_json::Value = response.json().await.map_err(|err| ControllerDnsFailure {
        message: format!("dns query for {host} returned invalid JSON: {err}"),
        retryable: false,
    })?;
    Ok(collect_ipv4_literals(&value))
}

/// Extract the human-readable part of a Mihomo controller error without carrying credentials,
/// query strings, arbitrary control characters, or an unbounded response into logs/UI state.
pub fn controller_error_detail(body: &str) -> Option<String> {
    const MAX_JSON_INPUT: usize = 4 * 1024;
    let json_detail = (body.len() <= MAX_JSON_INPUT)
        .then(|| serde_json::from_str::<serde_json::Value>(body).ok())
        .flatten()
        .and_then(|value| {
            ["message", "error", "detail"]
                .into_iter()
                .find_map(|key| value.get(key).and_then(serde_json::Value::as_str).map(str::to_owned))
        });
    let source = json_detail.as_deref().unwrap_or(body);

    let mut normalized = String::with_capacity(CONTROLLER_ERROR_DETAIL_LIMIT.min(source.len()));
    let mut pending_space = false;
    let mut truncated = false;
    for character in source.chars() {
        if character.is_whitespace() || character.is_control() {
            pending_space = !normalized.is_empty();
            continue;
        }
        if pending_space {
            if normalized.chars().count() >= CONTROLLER_ERROR_DETAIL_LIMIT {
                truncated = true;
                break;
            }
            normalized.push(' ');
            pending_space = false;
        }
        if normalized.chars().count() >= CONTROLLER_ERROR_DETAIL_LIMIT {
            truncated = true;
            break;
        }
        normalized.push(character);
    }
    let mut normalized = audit::redact(normalized.trim());
    if normalized.is_empty() {
        return None;
    }
    if truncated {
        normalized.push('…');
    }
    Some(normalized)
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

/// Open the redacted copy with the per-user DACL the rest of Tono's private files get.
///
/// It was the one file in the set written through plain `OpenOptions`, so it inherited whatever
/// the parent directory grants while `selection.json` and the owner token did not — and it is
/// the file that describes the selected node. A copy left by an earlier build fails the
/// private-file validation on its inherited ACL; replacing it once is how those converge.
#[cfg(windows)]
fn open_private_redacted_copy(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let open = || crate::core::owner_identity::open_or_create_private_current_user_file(path);
    let file = match open() {
        Ok(file) => file,
        Err(error) => {
            if !path.exists() {
                // Nothing to converge — the create itself failed, so report that.
                return Err(std::io::Error::other(error));
            }
            std::fs::remove_file(path)?;
            open().map_err(std::io::Error::other)?
        }
    };
    // The helper opens without truncating; this file is always rewritten whole.
    file.set_len(0)?;
    Ok(file)
}

/// Persist the redacted runtime copy (§5: the secret never touches disk).
///
/// Never fails the connect. The copy is a diagnostics convenience — the runtime the core
/// actually receives travels over IPC and never through this file — so refusing an otherwise
/// healthy connect because a support artefact could not be written trades availability for
/// nothing. Skipping is also the safe direction for §5: not writing cannot leak. It is loud in
/// the log instead, and the timeout is reported separately from a write error so a stalled
/// redirected AppData is diagnosable rather than looking like a permissions problem.
async fn write_redacted_copy(state: &Arc<TonoState>, redacted: &str) {
    let path = { state.lock().await.catalog_dir.join("owned-runtime.redacted.yaml") };
    let write = tokio::task::spawn_blocking({
        let redacted = redacted.to_string();
        move || -> std::io::Result<()> {
            #[cfg(windows)]
            let mut file = open_private_redacted_copy(&path)?;
            #[cfg(not(windows))]
            let mut file = {
                let mut options = std::fs::OpenOptions::new();
                options.write(true).create(true).truncate(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt as _;
                    options.mode(0o600);
                }
                options.open(&path)?
            };
            use std::io::Write as _;
            file.write_all(redacted.as_bytes())
        }
    });
    // Abandoning the JoinHandle cannot stop the blocking thread — a thread parked inside a UNC
    // `open` stays parked until the redirector gives up. It commits nothing the connect depends
    // on, so leaving it behind is safe; what matters is that this future returns.
    match tokio::time::timeout(REDACTED_COPY_WRITE_TIMEOUT, write).await {
        Ok(Ok(Ok(()))) => {}
        // Previously dropped on the floor: only the JoinError was reported, so a failed write
        // was silent.
        Ok(Ok(Err(err))) => logging!(warn, Type::Service, "Tono: 写入 redacted 运行时副本失败: {err}"),
        Ok(Err(err)) => logging!(warn, Type::Service, "Tono: 写入 redacted 运行时副本失败: {err}"),
        Err(_elapsed) => logging!(
            warn,
            Type::Service,
            "Tono: 写入 redacted 运行时副本超时 ({REDACTED_COPY_WRITE_TIMEOUT:?})，跳过；连接继续"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BFE_NOT_RUNNING_PREFIX, CATALOG_NOT_READY_REJECTION, CLOUD_POLICY_RESOLUTION_TIMEOUT, CONNECT_BUDGET_LEGS,
        CONNECT_TRANSACTION_TIMEOUT, CONTROLLER_READY_TIMEOUT, CORE_MISSING_SUSTAINED_SAMPLES, CoreSample,
        EXIT_PROBE_ADVISORY_BUDGET, EXIT_PROBE_CLIENT_TIMEOUT, EXIT_PROBE_CORE_TIMEOUT_MS, EXPLICIT_RELEASE_TIMEOUT,
        FailurePlan, HEALTH_FAILURE_THRESHOLD, HealthLegs, LOCK_ATTEMPTS, LOCK_RETRY_INTERVAL, MAX_DIRECT_ENDPOINTS,
        NETWORK_EVENT_DEBOUNCE, NETWORK_MONITOR_INTERVAL, POST_LOCK_VERIFY_ROUND_DELAY, POST_LOCK_VERIFY_ROUNDS,
        RELEASE_RECONCILING_PREFIX, SERVICE_BUSY_PREFIX, SERVICE_LIFECYCLE_TIMEOUT, SERVICE_TOO_OLD_PREFIX,
        SelectAction, TRANSITION_IN_FLIGHT_REJECTION, TUN_DATA_PLANE_CONNECT_TIMEOUT, TUN_DATA_PLANE_PROBES,
        TUN_DATA_PLANE_TIMEOUT, VERIFY_LOCK_ATTEMPTS, WFP_ENGINE_WEDGED_PREFIX, WINDOWS_OPTIONAL_DIRECT_ENABLED,
        build_direct_plan, classify_core_sample, collect_ipv4_literals, controller_error_detail, core_change_fires,
        format_tun_probe_failures, guard_rejection_is_transient, health_threshold_reached, is_fake_ip,
        is_retryable_lock_error, kill_switch_unhealthy, map_service_ready_error, map_wfp_engine_error,
        monitor_interval, monitor_requires_reconnect, network_event_fires, plan_failure, protected_dns_unhealthy,
        proxy_endpoint_of, reconnect_allowed, retry_now_is_noop, select_action, sign_out_needs_release,
        single_flight_begin, stale_exit_needs_release, stop_core_before_release, verify_lock_retry_window,
    };
    use clash_verge_service_ipc::DnsProtectionStatus;
    use std::time::Duration;
    use std::{
        collections::BTreeSet,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
    };
    use tono_core::{connection::ConnectionStatus, node::ValidatedNode};

    // ---- H7: the monitor's tick source must never collapse its thresholds ----

    /// The default `MissedTickBehavior::Burst` fires the tick after a slow one ~0 ms later, so
    /// two "consecutive" samples can be milliseconds apart and read the same stale value — the
    /// premise of every threshold below ("2 failures ≈ 4 s of sustained failure") is then false.
    #[tokio::test]
    async fn monitor_interval_delays_missed_ticks_instead_of_bursting() {
        let interval = monitor_interval();
        assert_eq!(interval.missed_tick_behavior(), tokio::time::MissedTickBehavior::Delay);
        assert_eq!(interval.period(), NETWORK_MONITOR_INTERVAL);
    }

    /// The documented meaning of the threshold, restated as an assertion: reaching it must cost
    /// at least `(threshold - 1)` real monitor periods of sustained failure.
    #[test]
    #[allow(clippy::assertions_on_constants, reason = "these tests exist to pin the constants")]
    fn health_threshold_spans_real_time() {
        assert!(HEALTH_FAILURE_THRESHOLD >= 2);
        let sustained = NETWORK_MONITOR_INTERVAL * (HEALTH_FAILURE_THRESHOLD - 1);
        assert!(sustained >= Duration::from_secs(2));
    }

    // ---- H8: one failed observation is one failure ----

    #[test]
    fn a_failed_service_poll_counts_as_one_failure_not_two() {
        let mut legs = HealthLegs::default();
        legs.observe_service_failure();
        assert_eq!(legs.service, 1);
        // The legs that were not observed are untouched — neither incremented (the old bug,
        // which made a single failing poll worth two failures against an `||` test) nor cleared.
        assert_eq!(legs.kill_switch, 0);
        assert_eq!(legs.protected_dns, 0);
        assert_eq!(legs.probe, 0);
        assert!(!legs.invalid());
    }

    /// Fail-closed is preserved: a Service that stays dead still invalidates Connected, just at
    /// the honest rate of one failure per monitor tick.
    #[test]
    fn a_dead_service_still_invalidates_connected() {
        let mut legs = HealthLegs::default();
        for _ in 0..HEALTH_FAILURE_THRESHOLD {
            legs.observe_service_failure();
        }
        assert!(legs.invalid());
    }

    #[test]
    fn a_failed_poll_never_clears_another_leg() {
        let mut legs = HealthLegs::default();
        legs.observe_kill_switch(true);
        legs.observe_service_failure();
        assert_eq!(legs.kill_switch, 1, "an unobserved leg keeps its history");
        legs.observe_service_ok();
        legs.observe_kill_switch(false);
        assert!(!legs.invalid());
        assert_eq!(legs.service, 0);
    }

    #[test]
    fn each_health_leg_thresholds_independently() {
        for (name, apply) in [
            (
                "kill switch",
                (|legs: &mut HealthLegs| legs.observe_kill_switch(true)) as fn(&mut HealthLegs),
            ),
            ("protected dns", |legs: &mut HealthLegs| {
                legs.observe_protected_dns(true)
            }),
            ("probe", |legs: &mut HealthLegs| legs.observe_probe(true)),
            ("service", |legs: &mut HealthLegs| legs.observe_service_failure()),
        ] {
            let mut legs = HealthLegs::default();
            apply(&mut legs);
            assert!(!legs.invalid(), "{name}: one failure must not invalidate");
            apply(&mut legs);
            assert!(legs.invalid(), "{name}: a sustained failure must invalidate");
        }
    }

    // ---- H4: a quiet `core_pid: None` cannot tear down a healthy tunnel ----

    #[test]
    fn a_missing_core_pid_is_a_quiet_sample() {
        assert_eq!(classify_core_sample(Some(42), Some(3), None, 0), CoreSample::Missing);
        assert!(
            !core_change_fires(CoreSample::Missing, 1),
            "the Service reports core_pid: None on its non-error inactive path"
        );
        assert!(core_change_fires(CoreSample::Missing, CORE_MISSING_SUSTAINED_SAMPLES));
    }

    #[test]
    fn an_explicit_restart_report_still_fires_on_the_first_sample() {
        // A different live pid.
        assert_eq!(
            classify_core_sample(Some(42), Some(3), Some(77), 3),
            CoreSample::Restarted
        );
        // A bumped restart counter under the same pid.
        assert_eq!(
            classify_core_sample(Some(42), Some(3), Some(42), 4),
            CoreSample::Restarted
        );
        assert!(core_change_fires(CoreSample::Restarted, 0));
    }

    #[test]
    fn a_steady_core_is_unchanged() {
        assert_eq!(
            classify_core_sample(Some(42), Some(3), Some(42), 3),
            CoreSample::Unchanged
        );
        assert!(!core_change_fires(CoreSample::Unchanged, 9));
    }

    /// The quiet payload also resets `restart_count` to 0. A *decrease* is that artefact, never
    /// a restart — treating it as one would make the missing-sample threshold pointless.
    #[test]
    fn a_reset_restart_counter_is_not_a_restart() {
        assert_eq!(classify_core_sample(Some(42), Some(3), None, 0), CoreSample::Missing);
        assert_eq!(
            classify_core_sample(Some(42), Some(3), Some(42), 0),
            CoreSample::Unchanged
        );
    }

    // ---- H5: the debounce stamp is a monitor seed ----

    #[test]
    fn a_reconnect_inside_the_debounce_window_keeps_its_first_event() {
        // The bug: a stale stamp from the previous session swallowed the first genuine event.
        assert!(!network_event_fires(true, Some(Duration::from_millis(500))));
        // After the connect-success reset the first event of the new session always fires.
        assert!(network_event_fires(true, None));
        assert!(network_event_fires(true, Some(NETWORK_EVENT_DEBOUNCE)));
        assert!(!network_event_fires(false, None), "no change, no invalidation");
    }

    #[test]
    fn a_network_notification_needs_data_plane_corroboration() {
        assert!(
            !monitor_requires_reconnect(true, false, false, false),
            "a healthy locked tunnel must survive a delayed notification from its own setup"
        );
        assert!(
            monitor_requires_reconnect(true, false, false, true),
            "a failed real data-plane probe corroborates the network event"
        );
        assert!(
            monitor_requires_reconnect(true, true, false, false),
            "a changed Core identity always rebuilds the connection"
        );
        assert!(
            monitor_requires_reconnect(false, false, true, false),
            "independent health failure remains fail-closed without a network event"
        );
        assert!(
            !monitor_requires_reconnect(false, false, false, true),
            "an event-only probe result has no meaning when debounce did not emit an event"
        );
    }

    // ---- V1/H1: verify_locked must not decide on one sample of a decaying cache ----

    #[test]
    #[allow(clippy::assertions_on_constants, reason = "these tests exist to pin the constants")]
    fn kill_switch_verification_outlives_the_liveness_cache() {
        assert!(VERIFY_LOCK_ATTEMPTS > 1, "single-shot verification is the bug");
        // The Service caches `live` for ~1.5 s and refreshes it on a 1 s loop; the retry window
        // must span more than one full refresh so a slow sample is re-read, not believed.
        assert!(
            verify_lock_retry_window() > Duration::from_millis(1_500),
            "retry window {:?} must exceed the liveness cache TTL",
            verify_lock_retry_window()
        );
    }

    // ---- C2: the client must outlast the core, and the stage must stay sane ----

    #[test]
    fn exit_probe_client_budget_outlasts_the_core_budget() {
        let core = Duration::from_millis(EXIT_PROBE_CORE_TIMEOUT_MS);
        assert!(
            EXIT_PROBE_CLIENT_TIMEOUT >= core + Duration::from_secs(2),
            "the client must lose to the core by a real margin, or mihomo's diagnosis is discarded"
        );
    }

    /// `unified-delay: true` in the generated runtime makes mihomo run the measured request
    /// twice inside the single core budget, so that budget must hold a *doubled* request.
    #[test]
    #[allow(clippy::assertions_on_constants, reason = "these tests exist to pin the constants")]
    fn exit_probe_core_budget_holds_a_doubled_request() {
        const SLOW_REALITY_REQUEST_MS: u64 = 3_500;
        assert!(EXIT_PROBE_CORE_TIMEOUT_MS >= 2 * SLOW_REALITY_REQUEST_MS);
    }

    #[test]
    fn advisory_exit_probe_is_one_bounded_attempt() {
        // 11 s of HTTP + at most 5 s from the mainland integration profile. Connect performs
        // exactly one such advisory request before the authoritative data-plane check.
        assert_eq!(
            EXIT_PROBE_ADVISORY_BUDGET,
            EXIT_PROBE_CLIENT_TIMEOUT + Duration::from_secs(5)
        );
    }

    // ---- C3: a transient verification failure is not "the tunnel never came up" ----

    /// Why the retry has to live inside the transaction: at `checkingExit`/`verifyingTraffic`
    /// the barrier is armed and locked but `session_verified` is still false, so the failure
    /// decision table resolves to a full release — and the reconnect gate then refuses to hand
    /// out a delay, because it requires the very latch the release just cleared.
    #[test]
    fn a_post_lock_failure_would_otherwise_be_a_dead_end() {
        assert_eq!(
            plan_failure(true, false, false),
            FailurePlan {
                mark_armed: false,
                stop_core: Some(true),
                restrict_bootstrap: false,
            }
        );
        // ...and the FSM confirms the dead end: after that release neither
        // `is_protection_blocked` nor `session_verified` holds, and `next_reconnect_delay`
        // requires both — so the user lands on NotConnected with nothing scheduled.
        let mut fsm = tono_core::connection::ConnectionFsm::new();
        fsm.begin_connect();
        fsm.mark_kill_switch_armed();
        assert!(!fsm.session_verified(), "the latch is committed after these stages");
        fsm.connect_failed();
        assert!(!fsm.status().is_protection_blocked);
        assert_eq!(
            fsm.next_reconnect_delay(),
            None,
            "nothing retries after a post-lock failure — so the retry must happen before it"
        );
    }

    #[test]
    #[allow(clippy::assertions_on_constants, reason = "these tests exist to pin the constants")]
    fn the_post_lock_group_retries_before_giving_up() {
        assert!(
            POST_LOCK_VERIFY_ROUNDS >= 2,
            "one transient real TUN failure must not destroy a working tunnel"
        );
        // ...but the group stays bounded: it can never outlive the transaction budget.
        let real_data_plane_budget = verify_lock_retry_window() + TUN_DATA_PLANE_TIMEOUT + Duration::from_secs(5);
        let worst = EXIT_PROBE_ADVISORY_BUDGET
            + real_data_plane_budget * POST_LOCK_VERIFY_ROUNDS
            + POST_LOCK_VERIFY_ROUND_DELAY;
        assert!(worst < CONNECT_TRANSACTION_TIMEOUT);
    }

    #[test]
    fn exhausted_tun_failure_uses_the_independent_proxy_cross_check() {
        use super::{
            NODE_OR_CORE_UNREACHABLE_PREFIX, TUN_DATA_PLANE_BROKEN_PREFIX, TUN_INGRESS_BROKEN_PREFIX,
            classify_exhausted_data_plane,
        };

        let tun = "all real TUN probes timed out".to_string();
        let isolated = classify_exhausted_data_plane(Ok(()), tun.clone(), Ok(()));
        assert!(isolated.starts_with(TUN_DATA_PLANE_BROKEN_PREFIX));
        assert!(isolated.contains("node and Mihomo proxy egress passed"));

        let advisory_degraded = classify_exhausted_data_plane(Err("delay probe 504".to_string()), tun.clone(), Ok(()));
        assert!(advisory_degraded.starts_with(TUN_DATA_PLANE_BROKEN_PREFIX));
        assert!(advisory_degraded.contains("loopback proxy egress passed"));

        let ingress = classify_exhausted_data_plane(Ok(()), tun.clone(), Err("proxy CONNECT timeout".to_string()));
        assert!(ingress.starts_with(TUN_INGRESS_BROKEN_PREFIX));

        let unreachable = classify_exhausted_data_plane(
            Err("delay probe 504".to_string()),
            tun,
            Err("proxy CONNECT timeout".to_string()),
        );
        assert!(unreachable.starts_with(NODE_OR_CORE_UNREACHABLE_PREFIX));
    }

    #[test]
    fn controller_504_is_advisory_but_real_data_plane_remains_mandatory() {
        use super::{PostLockVerification, classify_post_lock_verification};

        assert_eq!(
            classify_post_lock_verification(Err("delay probe answered 504 Gateway Timeout".to_string()), Ok(7_u8)),
            PostLockVerification::Verified {
                status: 7,
                controller_warning: Some("delay probe answered 504 Gateway Timeout".to_string()),
            }
        );
        assert_eq!(
            classify_post_lock_verification::<u8>(Ok(()), Err("real request timed out".to_string())),
            PostLockVerification::Retry {
                error: "real request timed out".to_string(),
            }
        );
        let both_failed = classify_post_lock_verification::<u8>(
            Err("delay probe answered 504 Gateway Timeout".to_string()),
            Err("HTTPS 204 failed".to_string()),
        );
        assert_eq!(
            both_failed,
            PostLockVerification::Retry {
                error: "controller exit measurement failed: delay probe answered 504 Gateway Timeout; real TUN data plane failed: HTTPS 204 failed".to_string(),
            }
        );
    }

    #[test]
    fn real_data_plane_probes_independent_https_origins() {
        assert!(
            TUN_DATA_PLANE_PROBES.len() >= 3,
            "one provider failure must not decide whether a locked tunnel works"
        );
        let mut hosts = BTreeSet::new();
        for probe in TUN_DATA_PLANE_PROBES {
            let url = reqwest::Url::parse(probe.url).expect("probe URL must parse");
            assert_eq!(url.scheme(), "https", "{} must be authenticated TLS", probe.label);
            hosts.insert(url.host_str().expect("probe URL must carry a host").to_string());
            assert!(
                (200..300).contains(&probe.expected_status),
                "{} must require an exact success status",
                probe.label
            );
        }
        assert_eq!(
            hosts.len(),
            TUN_DATA_PLANE_PROBES.len(),
            "nominally separate probes must not share an origin"
        );
    }

    #[test]
    fn real_data_plane_failure_names_every_failed_origin() {
        let failures = vec![
            "Google: timeout".to_string(),
            "Cloudflare: connect reset".to_string(),
            "Apple: status 503".to_string(),
        ];
        let error = format_tun_probe_failures(&failures);
        assert!(error.contains("all 3 independent"));
        for failure in failures {
            assert!(error.contains(&failure));
        }
    }

    /// Fail-closed: retrying the checks changes nothing about the decision table. An exhausted
    /// group still resolves to the same full release an unverified session always did, and a
    /// verified session still keeps blocking and reconnects.
    #[test]
    fn post_lock_retry_does_not_weaken_the_failure_table() {
        assert_eq!(
            plan_failure(true, false, false).stop_core,
            Some(true),
            "an unverified session is still fully released once the retries are exhausted"
        );
        assert_eq!(
            plan_failure(true, true, false),
            FailurePlan {
                mark_armed: true,
                stop_core: Some(false),
                restrict_bootstrap: true,
            }
        );
    }

    // ---- C4: the transaction budget must cover a cold first connect ----

    #[test]
    fn connect_budget_covers_a_cold_first_connect() {
        let accounted: u64 = CONNECT_BUDGET_LEGS.iter().map(|(_, secs)| secs).sum();
        assert_eq!(accounted, 328, "the table in the doc comment must stay in sync");
        assert!(
            Duration::from_secs(accounted) <= CONNECT_TRANSACTION_TIMEOUT,
            "the accounted cold-connect worst case ({accounted} s) must fit the budget"
        );
        // The legs whose budgets are constants here must match those constants.
        let leg = |name: &str| {
            CONNECT_BUDGET_LEGS
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, secs)| Duration::from_secs(*secs))
                .unwrap_or_default()
        };
        assert!(leg("controller readiness") >= CONTROLLER_READY_TIMEOUT);
        assert!(leg("lock ladder") >= LOCK_RETRY_INTERVAL * LOCK_ATTEMPTS);
        assert!(
            leg("cloud policy (DNS + StartClash #2 + ready/relock)")
                >= CLOUD_POLICY_RESOLUTION_TIMEOUT
                    + Duration::from_secs(60)
                    + CONTROLLER_READY_TIMEOUT
                    + LOCK_RETRY_INTERVAL * LOCK_ATTEMPTS,
            "the cloud-policy leg must cover its DNS deadline, second Service start, controller readiness, and relock"
        );
        assert!(leg("checkingExit") >= EXIT_PROBE_ADVISORY_BUDGET);
        assert!(
            leg("verifyingTraffic") >= verify_lock_retry_window() + TUN_DATA_PLANE_TIMEOUT,
            "the final stage must budget both WFP status and one real App data-plane request"
        );
    }

    #[test]
    #[allow(clippy::assertions_on_constants, reason = "these tests exist to pin the constants")]
    fn tun_data_plane_probe_is_bounded_and_cannot_outlive_its_connect() {
        assert!(TUN_DATA_PLANE_CONNECT_TIMEOUT < TUN_DATA_PLANE_TIMEOUT);
        assert!(TUN_DATA_PLANE_TIMEOUT < CONNECT_TRANSACTION_TIMEOUT);
    }

    // ---- D1: the release UI budget must match the Service's reality ----

    #[test]
    fn release_budget_matches_the_service_reality() {
        // DNS restore leg (Service-side budget) + core stop + WFP/IPC overhead.
        const SERVICE_DNS_RESTORE: Duration = Duration::from_secs(40);
        const SERVICE_CORE_STOP: Duration = Duration::from_secs(3);
        assert!(
            EXPLICIT_RELEASE_TIMEOUT >= SERVICE_DNS_RESTORE + SERVICE_CORE_STOP,
            "telling the user the disconnect failed while the worker is still inside its own \
             budget is the D1 defect"
        );
        assert!(
            EXPLICIT_RELEASE_TIMEOUT < SERVICE_LIFECYCLE_TIMEOUT,
            "the IPC client must be the one that reports a genuine hang"
        );
    }

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
    fn dns_warnings_do_not_tear_down_a_live_tunnel() {
        // The Service reports these on operations that SUCCEEDED. Judging them unhealthy costs
        // two samples and then a full teardown, so a machine that can never verify its DNS
        // would reconnect forever — which is the failure this predicate exists to prevent.
        let healthy = DnsProtectionStatus {
            enabled: true,
            snapshot_present: true,
            adapters: 3,
            last_error: None,
        };
        assert!(!protected_dns_unhealthy(Some(&healthy)));

        for warning in [
            "TONO_DNS_UNVERIFIED: applied but unverified on 2 of 5 adapter(s)",
            "kill switch: TONO_DNS_RESTORE_DEGRADED: accepted on registry evidence",
        ] {
            let warned = DnsProtectionStatus {
                last_error: Some(warning.to_string()),
                ..healthy.clone()
            };
            assert!(
                !protected_dns_unhealthy(Some(&warned)),
                "a warning marker must not read as unhealthy: {warning}"
            );
        }

        // A real failure still is one.
        let failed = DnsProtectionStatus {
            last_error: Some("DNS restore could not be proven".to_string()),
            ..healthy.clone()
        };
        assert!(protected_dns_unhealthy(Some(&failed)));
        // And a state that is not actually protected stays unhealthy whatever it says.
        let off = DnsProtectionStatus {
            enabled: false,
            ..healthy
        };
        assert!(protected_dns_unhealthy(Some(&off)));
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
    fn only_self_clearing_guard_rejections_keep_the_reconnect_chain_alive() {
        // These clear without anyone doing anything, so ending the chain on them leaves the
        // machine blocked with no scheduled retry and nothing shown.
        assert!(guard_rejection_is_transient(&format!(
            "{RELEASE_RECONCILING_PREFIX}: network protection release is still reconciling; wait before reconnecting"
        )));
        assert!(guard_rejection_is_transient(TRANSITION_IN_FLIGHT_REJECTION));
        assert!(guard_rejection_is_transient(CATALOG_NOT_READY_REJECTION));
        // These need a person; retrying them forever would only spin.
        assert!(!guard_rejection_is_transient("not signed in"));
        assert!(!guard_rejection_is_transient("account is suspended"));
        assert!(!guard_rejection_is_transient("select a server first"));
        assert!(!guard_rejection_is_transient(
            "the selected node left the catalog; pick a server again"
        ));
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
            tunnel_permit_rendered: true,
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
                tunnel_permit_rendered: true,
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
    fn controller_error_detail_extracts_redacts_and_caps_mihomo_errors() {
        assert_eq!(
            controller_error_detail(r#"{"message":"all DNS requests failed\nAuthorization: Bearer secret-value"}"#),
            Some("all DNS requests failed Authorization: ***".to_string())
        );
        assert_eq!(
            controller_error_detail(r#"{"error":"GET https://resolver.test/dns-query?token=secret timed out"}"#),
            Some("GET https://resolver.test/dns-query?*** timed out".to_string())
        );
        assert_eq!(controller_error_detail("  \r\n\t"), None);
        let capped = controller_error_detail(&"x".repeat(600)).expect("non-empty detail");
        assert_eq!(capped.chars().count(), super::CONTROLLER_ERROR_DETAIL_LIMIT + 1);
        assert!(capped.ends_with('…'));
    }

    #[test]
    fn cloud_dns_retries_only_transient_controller_statuses() {
        assert!(super::controller_dns_status_is_retryable(
            reqwest::StatusCode::TOO_MANY_REQUESTS
        ));
        assert!(super::controller_dns_status_is_retryable(
            reqwest::StatusCode::INTERNAL_SERVER_ERROR
        ));
        assert!(!super::controller_dns_status_is_retryable(
            reqwest::StatusCode::BAD_REQUEST
        ));
        assert!(!super::controller_dns_status_is_retryable(
            reqwest::StatusCode::UNAUTHORIZED
        ));
    }

    #[tokio::test]
    async fn cloud_dns_retries_a_transient_burst_and_reuses_one_client() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            for (status, body) in [
                (500, r#"{"message":"temporary burst"}"#),
                (200, r#"{"Answer":[{"A":"93.184.216.34"}]}"#),
            ] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let mut chunk = [0_u8; 1024];
                    let read = stream.read(&mut chunk).await.unwrap();
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let reason = if status == 200 { "OK" } else { "Internal Server Error" };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });

        let client = super::controller_client(Duration::from_secs(3)).unwrap();
        let addresses = super::dns_query_a_with_retry(&client, "test-secret", port, "www.example.com")
            .await
            .expect("the second controller answer should recover the transient first one");
        assert_eq!(addresses, [Ipv4Addr::new(93, 184, 216, 34)]);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn persistent_cloud_dns_500_skips_optional_direct_policy() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let body = r#"{"message":"context deadline exceeded"}"#;
            for _ in 0..super::CLOUD_DNS_QUERY_ATTEMPTS {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let mut chunk = [0_u8; 1024];
                    let read = stream.read(&mut chunk).await.unwrap();
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let response = format!(
                    "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });

        let client = super::controller_client(Duration::from_secs(3)).unwrap();
        let error = super::dns_query_a_with_retry(&client, "test-secret", port, "mmbiz.qpic.cn")
            .await
            .expect_err("a persistent controller failure must reject the whole DIRECT plan");
        server.await.unwrap();

        assert_eq!(
            super::classify_optional_direct_resolution::<()>(Err(error)),
            super::OptionalDirectResolution::Skip(
                "dns query for mmbiz.qpic.cn failed after 3 attempts: dns query for mmbiz.qpic.cn answered 500 Internal Server Error: context deadline exceeded".to_string()
            )
        );
        assert_eq!(
            super::classify_optional_direct_resolution(Ok(7_u8)),
            super::OptionalDirectResolution::Ready(7)
        );
    }

    #[test]
    fn windows_direct_policy_does_not_replace_the_proven_full_tunnel_runtime() {
        assert!(
            !WINDOWS_OPTIONAL_DIRECT_ENABLED,
            "re-enable only with transactional rollback and a mainland second-start regression test"
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
