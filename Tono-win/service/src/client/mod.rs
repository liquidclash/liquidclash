use std::{future::Future, path::Path, sync::Arc, time::Duration};

#[cfg(windows)]
use anyhow::Result;
#[cfg(unix)]
use anyhow::{Result, anyhow};
use compact_str::CompactString;
use kode_bridge::{ClientConfig, IpcHttpClient};
use log::{debug, warn};
use once_cell::sync::Lazy;
use tokio::sync::RwLock;

#[cfg(all(windows, any(not(feature = "test"), test)))]
mod windows_identity;

use crate::{
    AuthenticatedRequest, AuthenticatedSessionRequest, DnsProtectionStatus, IPC_AUTH_EXPECT,
    IPC_PATH, IpcCommand, KillSwitchLockRequest, KillSwitchStatus, MIN_REQUIRED_SERVICE_REVISION,
    MacosProxyConfig, OwnerCredentials, OwnerSessionProof, ProtocolInfo, ProtocolVersion,
    ProxyApplyOutcome, RuntimeBundle, ServiceStatusSnapshot, StageRuntimeOutcome,
    StartClashRequest, StartClashResult, WriterConfig,
    core::structure::{JsonConvert, Response},
};

static CLIENT_CONFIG: Lazy<Arc<RwLock<Option<IpcConfig>>>> =
    Lazy::new(|| Arc::new(RwLock::new(None)));
/// Keep every Service IPC call off the application's Tauri runtime, and — the part that actually
/// froze the app — keep the synchronous half of a connect off *any* runtime worker.
/// `kode-bridge` opens the Windows named pipe and verifies the server process inline, in the
/// middle of its async connect path and not through `spawn_blocking`. A Service parked inside a
/// WFP/BFE kernel call parks whichever thread polls that future for as long as the wedge lasts,
/// and a `tokio::time::timeout` wrapped around it can never fire, because the future never
/// yields. Adding workers only bought more threads to lose.
///
/// Requests therefore run on this runtime's *blocking* pool (see [`run_ipc_request`]); its
/// workers now only ever await a `JoinHandle`, so two are enough. `max_blocking_threads` bounds
/// the damage of a Service that never answers: a parked blocking thread cannot be cancelled, so
/// the cap is the ceiling on how many can be lost before further calls simply queue and fail on
/// their own guard — degraded and visible, never a frozen application.
static IPC_RUNTIME: Lazy<std::result::Result<tokio::runtime::Runtime, String>> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(16)
        .thread_name("tono-service-ipc")
        .enable_all()
        .build()
        .map_err(|error| error.to_string())
});

static IPC_AUTH_HEADER_KEY: &str = "X-IPC-Magic";
/// The Service budgets each privileged step inside a handler at 60 seconds and never cancels a
/// handler at the transport. A mutating client must wait at least slightly longer than one step
/// so it cannot time out, retry, and race the still-running handler on a second connection. A
/// multi-step handler can still outlive this — that is the lost-response case (the mutation may
/// have committed), which mutating routes never replay and session generations repair late.
const LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(65);
/// Read-only status calls still round-trip through the service's state (and, on Windows,
/// cached verify results), so they get more than the interactive default but far less than
/// a lifecycle mutation.
const STATUS_TIMEOUT: Duration = Duration::from_secs(2);
/// Log fetches ship whole in-memory buffers across the pipe, so they get well beyond a status
/// probe but stay explicit — no route may fall through to the transport's interactive default.
const LOG_FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// `kode-bridge` applies `max_retries` to both connection establishment and the complete HTTP
/// request. The Run State already owns startup retry/backoff, so an individual read must stay
/// small and bounded; otherwise two status calls can occupy the dedicated IPC runtime for
/// minutes and queue a safety-critical release behind them.
const READ_REQUEST_ATTEMPTS: usize = 2;
/// A mutating request is never replayed after an ambiguous transport failure. The Service may
/// already have committed it even when its response was lost.
const MUTATING_REQUEST_ATTEMPTS: usize = 1;
/// A route's own timeout only begins to apply once the transport is connected; the connect
/// itself is synchronous on Windows and outside every timeout. `kode-bridge` can repeat it at
/// two levels (its own connect loop and its request retry executor), and a protected call makes
/// two requests — the magic probe and the route — so a call performs at most
/// `2 * READ_REQUEST_ATTEMPTS * READ_REQUEST_ATTEMPTS` server verifications. Each is capped by
/// the verifier's own Service Control Manager deadline (see `windows_identity`), so this is the
/// head-room a guard adds on top of the route timeout to cover that phase.
const CONNECT_PHASE_BUDGET: Duration = Duration::from_secs(30);

/// The out-of-band deadline for one whole call.
///
/// Always strictly longer than the timeout the request itself carries, so it fires only when
/// that timeout is unenforceable — never as a shortcut that could stop waiting on a mutating
/// request the Service is still executing normally. It must also stay well inside the
/// application's own connect deadline, or a wedge would surface as that deadline rather than as
/// a mappable IPC failure.
fn call_guard(timeout: Option<Duration>) -> Duration {
    timeout.unwrap_or(LIFECYCLE_TIMEOUT) + CONNECT_PHASE_BUDGET
}

/// Run synchronous work on the isolated IPC runtime's blocking pool, awaited with a guard.
///
/// The await is an ordinary `JoinHandle`, so the guard is enforceable no matter what the work
/// does to its thread — that is the whole point. Nothing cancels the work: `spawn_blocking`
/// cannot be interrupted, and a guard that fires abandons the thread rather than stopping it.
/// That is deliberate. A mutating request the Service may already have committed must never be
/// cut short, only stopped being waited on — the lost-response case mutating routes never
/// replay and session generations repair. The cost is a detached thread per abandoned call,
/// which is why attempts are capped (`READ_REQUEST_ATTEMPTS`/`MUTATING_REQUEST_ATTEMPTS`) and
/// nothing here retries on its own.
async fn run_blocking<T, F>(guard: Duration, work: F) -> Result<T>
where
    F: FnOnce() -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    let runtime = IPC_RUNTIME
        .as_ref()
        .map_err(|error| anyhow::anyhow!("failed to initialize Service IPC runtime: {error}"))?;
    let task = runtime.spawn_blocking(work);
    match tokio::time::timeout(guard, task).await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => Err(anyhow::anyhow!("Service IPC runtime task failed: {error}")),
        Err(_) => Err(anyhow::anyhow!(
            "the Tono Service did not answer within {}s",
            guard.as_secs()
        )),
    }
}

/// Drive one complete IPC request — connect, verify, send, decode — on a blocking thread.
///
/// The request is built and awaited on a private current-thread runtime owned by that thread,
/// so the connect `kode-bridge` performs synchronously inside its async path can only ever park
/// this one thread, never a shared worker. Everything the request owns — client, pool, any
/// half-built connection — belongs to that runtime and is dropped with it, so a call that gives
/// up on its guard cannot hand a partially verified connection to a later one.
async fn run_ipc_request<T, F, Fut>(guard: Duration, request: F) -> Result<T>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Result<T>> + 'static,
    T: Send + 'static,
{
    run_blocking(guard, move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| {
                anyhow::anyhow!("failed to build Service IPC request runtime: {error}")
            })?;
        runtime.block_on(request())
    })
    .await
}

/// Run blocking OS work on a detached helper thread and stop waiting for it after `deadline`.
///
/// Returns `None` when the work has not answered in time; the caller decides what that means
/// (for server verification it means *refuse*, never *accept*). The thread is deliberately not
/// joined: a Service Control Manager RPC parked in the kernel cannot be cancelled, and joining
/// it would reintroduce exactly the unbounded wait this exists to bound. The leak is bounded by
/// the caller — connect attempts are capped, and nothing retries a verification on its own.
#[cfg(any(all(windows, not(feature = "test")), test))]
pub(crate) fn run_with_deadline<T, F>(deadline: Duration, work: F) -> Option<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("tono-service-ipc-verify".to_string())
        .spawn(move || {
            // A closed channel means the caller already gave up; dropping the answer is right.
            let _ = sender.send(work());
        })
        .ok()?;
    receiver.recv_timeout(deadline).ok()
}

fn protected<'a>(
    request: kode_bridge::HttpRequestBuilder<'a>,
) -> kode_bridge::HttpRequestBuilder<'a> {
    request.header(
        crate::SERVICE_PROTOCOL_HEADER,
        ProtocolVersion::current().header_value(),
    )
}

/// The verb a route answers on. Kept beside [`IpcCommand`], which deliberately carries only the
/// path, so the two halves of a route's address travel together on this side of the wire.
#[derive(Clone, Copy)]
enum Verb {
    Get,
    Post,
    Delete,
}

impl Verb {
    const fn is_read_only(self) -> bool {
        matches!(self, Self::Get)
    }

    const fn max_attempts(self) -> usize {
        if self.is_read_only() {
            READ_REQUEST_ATTEMPTS
        } else {
            MUTATING_REQUEST_ATTEMPTS
        }
    }
}

/// One protected request: connect, wrap the payload in the envelope the route expects, declare
/// the protocol revision, send, decode.
///
/// Every route below is this call with different data. Routing the protocol header through here
/// rather than through each caller is the point — a request that reaches the service without it
/// is refused, and forgetting it was previously a runtime failure rather than an impossible one.
///
/// `session` chooses the envelope: routes that need only an authenticated owner pass `None`,
/// routes that need proof of the current session pass `Some`.
async fn protected_call<P, R>(
    verb: Verb,
    command: IpcCommand,
    credentials: &OwnerCredentials,
    session: Option<&OwnerSessionProof>,
    payload: P,
    timeout: Option<Duration>,
) -> Result<Response<R>>
where
    P: serde::Serialize + for<'de> serde::Deserialize<'de> + Send + 'static,
    R: for<'de> serde::Deserialize<'de> + Send + 'static,
{
    let credentials = credentials.clone();
    let session = session.cloned();
    run_ipc_request(call_guard(timeout), move || async move {
        protected_call_inner(
            verb,
            command,
            &credentials,
            session.as_ref(),
            payload,
            timeout,
        )
        .await
    })
    .await
}

async fn protected_call_inner<P, R>(
    verb: Verb,
    command: IpcCommand,
    credentials: &OwnerCredentials,
    session: Option<&OwnerSessionProof>,
    payload: P,
    timeout: Option<Duration>,
) -> Result<Response<R>>
where
    P: serde::Serialize + for<'de> serde::Deserialize<'de>,
    R: for<'de> serde::Deserialize<'de>,
{
    // kode-bridge retries transport errors by default. That is useful for reads, but unsafe for
    // lifecycle writes: a response can be lost after the Service committed, and an automatic
    // retry would execute the mutation again. Product-level callers own any deliberate retry.
    let client = connect_with_max_retries(Some(verb.max_attempts())).await?;
    let body = match session {
        None => AuthenticatedRequest {
            credentials: credentials.clone(),
            payload,
        }
        .to_json_value()?,
        Some(session) => AuthenticatedSessionRequest {
            credentials: credentials.clone(),
            session: session.clone(),
            payload,
        }
        .to_json_value()?,
    };
    let path = command.as_ref();
    let request = protected(match verb {
        Verb::Get => client.get(path),
        Verb::Post => client.post(path),
        Verb::Delete => client.delete(path),
    });
    let request = match timeout {
        Some(timeout) => request.timeout(timeout),
        None => request,
    };
    let response = request
        .json_body(&body)
        .send()
        .await?
        .json::<Response<R>>()?;
    Ok(response)
}

#[derive(Debug, Clone)]
pub struct IpcConfig {
    pub default_timeout: Duration,
    pub max_retries: usize,
    pub retry_delay: Duration,
}

impl Default for IpcConfig {
    fn default() -> Self {
        Self {
            default_timeout: Duration::from_millis(50),
            max_retries: 8,
            retry_delay: Duration::from_millis(150),
        }
    }
}

pub async fn set_config(config: Option<IpcConfig>) {
    let mut guard = CLIENT_CONFIG.write().await;
    *guard = config;
}

/// Build a verified transport. Callers must already be inside [`run_ipc_request`]: on Windows
/// the pipe open and the server verification below happen synchronously inside `kode-bridge`,
/// so this may only ever run on a blocking thread. It is not exported for that reason — a
/// client handed out to an arbitrary runtime would carry that hazard with it.
async fn connect_with_max_retries(max_retries: Option<usize>) -> Result<IpcHttpClient> {
    debug!("Connecting to IPC at {}", IPC_PATH);

    #[cfg(unix)]
    {
        if let Err(err) = Path::metadata(IPC_PATH.as_ref()) {
            return Err(anyhow!("IPC path unavailable: {err}"));
        }
    }

    let mut c = { CLIENT_CONFIG.read().await.clone() }.unwrap_or_default();
    if let Some(max_retries) = max_retries {
        c.max_retries = max_retries;
    }
    debug!("Using config: {:?}", c);
    let client = kode_bridge::IpcHttpClient::with_config(
        IPC_PATH,
        ClientConfig {
            default_timeout: c.default_timeout,
            max_retries: c.max_retries,
            retry_delay: c.retry_delay,
            enable_pooling: true,
            require_windows_server_system: false,
            #[cfg(all(windows, not(feature = "test")))]
            windows_server_pid_verifier: Some(
                windows_identity::verify_registered_service_process_id,
            ),
            #[cfg(all(windows, feature = "test"))]
            windows_server_pid_verifier: None,
            ..Default::default()
        },
    )?;

    if let Err(e) = client
        .get(IpcCommand::Magic.as_ref())
        .header(IPC_AUTH_HEADER_KEY, IPC_AUTH_EXPECT)
        .send()
        .await
    {
        warn!("Failed to connect to IPC server: {}", e);
        return Err(anyhow::anyhow!("Failed to connect to IPC server: {}", e));
    }

    Ok(client)
}

/// Synchronous by design and synchronous in fact — an async caller must offload it, the way
/// [`is_reinstall_service_needed`] does, rather than probe the pipe namespace from a runtime
/// worker.
pub fn is_ipc_path_exists() -> bool {
    Path::new(IPC_PATH).exists()
}

/// Liveness probe: prove a verified transport can be built, and drop it again.
///
/// The client itself is deliberately never handed out (see [`connect_with_max_retries`]) — on
/// Windows its connect is synchronous, so a client living on an arbitrary runtime would carry
/// that hazard with it. Building and dropping one inside [`run_ipc_request`] answers "is the
/// Service reachable" without exporting the hazard.
pub async fn connect() -> Result<()> {
    run_ipc_request(call_guard(Some(STATUS_TIMEOUT)), || async {
        connect_with_max_retries(Some(READ_REQUEST_ATTEMPTS))
            .await
            .map(drop)
    })
    .await
}

/// Integration-test transport for the `/__test/*` routes, which have no typed wrapper.
///
/// Test-gated on purpose: this hands out the client the production API deliberately does not,
/// and it is sound only because the integration suite runs on unix sockets where the connect is
/// not synchronous. It must never become reachable from a shipping build.
#[cfg(feature = "test")]
pub async fn test_client() -> Result<IpcHttpClient> {
    connect_with_max_retries(Some(READ_REQUEST_ATTEMPTS)).await
}

pub async fn get_version() -> Result<Response<ProtocolInfo>> {
    run_ipc_request(call_guard(Some(STATUS_TIMEOUT)), get_version_inner).await
}

async fn get_version_inner() -> Result<Response<ProtocolInfo>> {
    // Startup retry/backoff belongs to `RunState::await_ready`; keep each probe bounded so it
    // cannot monopolize the isolated IPC runtime.
    let client = connect_with_max_retries(Some(READ_REQUEST_ATTEMPTS)).await?;
    let response = client
        .get(IpcCommand::GetVersion.as_ref())
        .header(IPC_AUTH_HEADER_KEY, IPC_AUTH_EXPECT)
        .send()
        .await?
        .json::<Response<ProtocolInfo>>()?;
    Ok(response)
}

pub async fn get_status(credentials: &OwnerCredentials) -> Result<Response<ServiceStatusSnapshot>> {
    protected_call(
        Verb::Get,
        IpcCommand::Status,
        credentials,
        None,
        (),
        Some(STATUS_TIMEOUT),
    )
    .await
}

pub async fn preflight_macos_kill_switch(credentials: &OwnerCredentials) -> Result<Response<()>> {
    protected_call(
        Verb::Get,
        IpcCommand::PreflightMacosKillSwitch,
        credentials,
        None,
        (),
        None,
    )
    .await
}

/// `GET /kill-switch/status`: which phase of the two-phase arm is live (protocol rev 5).
pub async fn get_kill_switch_status(
    credentials: &OwnerCredentials,
) -> Result<Response<KillSwitchStatus>> {
    protected_call(
        Verb::Get,
        IpcCommand::GetKillSwitchStatus,
        credentials,
        None,
        (),
        Some(STATUS_TIMEOUT),
    )
    .await
}

/// `POST /kill-switch/lock`: second phase of the arm — permit the tunnel interface and retract
/// the bootstrap API channel. Idempotent on the service side; also asserts the TUN adapter
/// exists, so callers retry it while the adapter comes up. Session-gated.
pub async fn lock_kill_switch(
    credentials: &OwnerCredentials,
    session: &OwnerSessionProof,
    body: KillSwitchLockRequest,
) -> Result<Response<()>> {
    protected_call(
        Verb::Post,
        IpcCommand::LockKillSwitch,
        credentials,
        Some(session),
        body,
        Some(LIFECYCLE_TIMEOUT),
    )
    .await
}

/// Persist completion of the full app verification barrier. Session-gated and idempotent.
pub async fn mark_kill_switch_verified(
    credentials: &OwnerCredentials,
    session: &OwnerSessionProof,
) -> Result<Response<()>> {
    protected_call(
        Verb::Post,
        IpcCommand::MarkKillSwitchVerified,
        credentials,
        Some(session),
        (),
        Some(LIFECYCLE_TIMEOUT),
    )
    .await
}

/// `POST /kill-switch/restrict-bootstrap`: drop back to block-all plus the bounded bootstrap
/// API channel (the control-plane recovery channel). Owner-gated so it remains callable after
/// the arming session is gone.
pub async fn restrict_kill_switch_bootstrap(
    credentials: &OwnerCredentials,
) -> Result<Response<()>> {
    protected_call(
        Verb::Post,
        IpcCommand::RestrictKillSwitchBootstrap,
        credentials,
        None,
        (),
        Some(LIFECYCLE_TIMEOUT),
    )
    .await
}

/// `POST /dns/enable`: snapshot adapter DNS and point resolvers at loopback. Session-gated.
pub async fn enable_protected_dns(
    credentials: &OwnerCredentials,
    session: &OwnerSessionProof,
) -> Result<Response<DnsProtectionStatus>> {
    protected_call(
        Verb::Post,
        IpcCommand::EnableProtectedDns,
        credentials,
        Some(session),
        (),
        Some(LIFECYCLE_TIMEOUT),
    )
    .await
}

/// `POST /dns/restore`: restore the snapshotted adapter DNS. Owner-gated so the disconnect
/// path can call it after the session is gone.
pub async fn restore_protected_dns(
    credentials: &OwnerCredentials,
) -> Result<Response<DnsProtectionStatus>> {
    protected_call(
        Verb::Post,
        IpcCommand::RestoreProtectedDns,
        credentials,
        None,
        (),
        Some(LIFECYCLE_TIMEOUT),
    )
    .await
}

/// `POST /kill-switch/release`: the explicit user-requested disarm (protocol rev 6).
///
/// Owner-gated — **no session is required**, so the Disconnect/Sign-Out path can call it even
/// after a stop already invalidated the session (the Protected Offline deadlock this route
/// breaks). The service refuses, staying armed, when DNS restore cannot be proven; a
/// successful response carries the post-release status. Idempotent. Gate on
/// [`ProtocolInfo::supports_kill_switch_release`] for older services.
pub async fn release_kill_switch(
    credentials: &OwnerCredentials,
) -> Result<Response<KillSwitchStatus>> {
    protected_call(
        Verb::Post,
        IpcCommand::ReleaseKillSwitch,
        credentials,
        None,
        (),
        Some(LIFECYCLE_TIMEOUT),
    )
    .await
}

/// `GET /dns/status`: whether the service currently holds adapters on loopback DNS.
pub async fn get_protected_dns_status(
    credentials: &OwnerCredentials,
) -> Result<Response<DnsProtectionStatus>> {
    protected_call(
        Verb::Get,
        IpcCommand::GetProtectedDnsStatus,
        credentials,
        None,
        (),
        Some(STATUS_TIMEOUT),
    )
    .await
}

pub async fn is_reinstall_service_needed() -> bool {
    // `Path::exists` is a synchronous filesystem probe, and on Windows it touches the pipe
    // namespace itself. Keep it off the caller's runtime for the same reason the request path
    // is kept off it; a probe that cannot answer counts as no pipe at all.
    let ipc_path_exists = run_blocking(CONNECT_PHASE_BUDGET, || Ok(is_ipc_path_exists()))
        .await
        .unwrap_or(false);
    ipc_path_exists
        && match get_version().await {
            Ok(resp) => resp.data.is_none_or(|info| {
                !info.supports_client(ProtocolVersion::current(), MIN_REQUIRED_SERVICE_REVISION)
            }),
            Err(_) => true,
        }
}

pub async fn start_clash(
    credentials: &OwnerCredentials,
    body: &StartClashRequest,
) -> Result<Response<StartClashResult>> {
    protected_call(
        Verb::Post,
        IpcCommand::StartClash,
        credentials,
        None,
        body.clone(),
        Some(LIFECYCLE_TIMEOUT),
    )
    .await
}

pub async fn get_clash_logs(
    credentials: &OwnerCredentials,
) -> Result<Response<Vec<CompactString>>> {
    protected_call(
        Verb::Get,
        IpcCommand::GetClashLogs,
        credentials,
        None,
        (),
        Some(LOG_FETCH_TIMEOUT),
    )
    .await
}

pub async fn get_clash_log_snapshot(credentials: &OwnerCredentials) -> Result<Response<String>> {
    protected_call(
        Verb::Get,
        IpcCommand::GetClashLogSnapshot,
        credentials,
        None,
        (),
        Some(LOG_FETCH_TIMEOUT),
    )
    .await
}

pub async fn stop_clash(
    credentials: &OwnerCredentials,
    session: &OwnerSessionProof,
) -> Result<Response<()>> {
    protected_call(
        Verb::Delete,
        IpcCommand::StopClash,
        credentials,
        Some(session),
        (),
        Some(LIFECYCLE_TIMEOUT),
    )
    .await
}

pub async fn stop_clash_with_options(
    credentials: &OwnerCredentials,
    session: &OwnerSessionProof,
    options: crate::StopClashOptions,
) -> Result<Response<()>> {
    protected_call(
        Verb::Delete,
        IpcCommand::StopClash,
        credentials,
        Some(session),
        crate::StopClashPayload::Options(options),
        Some(LIFECYCLE_TIMEOUT),
    )
    .await
}

/// Ask the service to make the running core's generation match `body`, without restarting it.
///
/// Returns what the service decided, not whether it worked: a service that declines reports
/// `RestartRequired` with a `code` of zero. Only the caller can act on that, by stopping and
/// starting the core the way it did before staging existed. Gate the call on
/// [`ProtocolInfo::supports_runtime_staging`] — an older service has no such route at all.
pub async fn stage_runtime(
    credentials: &OwnerCredentials,
    session: &OwnerSessionProof,
    body: &RuntimeBundle,
) -> Result<Response<StageRuntimeOutcome>> {
    protected_call(
        Verb::Post,
        IpcCommand::StageRuntime,
        credentials,
        Some(session),
        body.clone(),
        Some(LIFECYCLE_TIMEOUT),
    )
    .await
}

pub async fn update_writer(
    credentials: &OwnerCredentials,
    session: &OwnerSessionProof,
    body: &WriterConfig,
) -> Result<Response<()>> {
    protected_call(
        Verb::Post,
        IpcCommand::UpdateWriter,
        credentials,
        Some(session),
        body.clone(),
        Some(LIFECYCLE_TIMEOUT),
    )
    .await
}

pub async fn set_system_proxy(
    credentials: &OwnerCredentials,
    session: &OwnerSessionProof,
    body: &MacosProxyConfig,
) -> Result<Response<ProxyApplyOutcome>> {
    protected_call(
        Verb::Post,
        IpcCommand::SetSystemProxy,
        credentials,
        Some(session),
        body.clone(),
        Some(LIFECYCLE_TIMEOUT),
    )
    .await
}

#[cfg(test)]
mod retry_safety_tests {
    use super::{
        CONNECT_PHASE_BUDGET, LIFECYCLE_TIMEOUT, LOG_FETCH_TIMEOUT, MUTATING_REQUEST_ATTEMPTS,
        READ_REQUEST_ATTEMPTS, STATUS_TIMEOUT, Verb, call_guard, run_blocking, run_ipc_request,
        run_with_deadline,
    };
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::time::{Duration, Instant};

    #[test]
    fn only_reads_are_safe_for_automatic_transport_retry() {
        assert!(Verb::Get.is_read_only());
        assert!(!Verb::Post.is_read_only());
        assert!(!Verb::Delete.is_read_only());
        assert_eq!(Verb::Get.max_attempts(), READ_REQUEST_ATTEMPTS);
        assert_eq!(Verb::Post.max_attempts(), MUTATING_REQUEST_ATTEMPTS);
        assert_eq!(Verb::Delete.max_attempts(), MUTATING_REQUEST_ATTEMPTS);
    }

    #[test]
    fn mutating_timeout_outwaits_a_service_handler_step() {
        // The service budgets one privileged handler step at 60 seconds; a mutating client
        // must outwait that so it cannot give up and race the still-running handler. Reads
        // stay far below it so they cannot queue a safety-critical release behind them.
        assert!(LIFECYCLE_TIMEOUT > Duration::from_secs(60));
        assert!(STATUS_TIMEOUT < LIFECYCLE_TIMEOUT);
        assert!(LOG_FETCH_TIMEOUT < LIFECYCLE_TIMEOUT);
    }

    #[test]
    fn a_guard_always_outwaits_the_timeout_the_request_carries() {
        // The guard is a backstop for the window in which the request's own timeout cannot be
        // enforced — the synchronous connect. It must never be the thing that gives up first on
        // a mutating call the Service is still executing normally.
        assert!(call_guard(Some(LIFECYCLE_TIMEOUT)) > LIFECYCLE_TIMEOUT);
        assert!(call_guard(Some(STATUS_TIMEOUT)) > STATUS_TIMEOUT);
        assert!(call_guard(None) > LIFECYCLE_TIMEOUT);
        // And it must stay inside the application's 120s connect deadline, so a wedged Service
        // surfaces as a mappable IPC failure rather than as that outer deadline.
        assert!(call_guard(Some(LIFECYCLE_TIMEOUT)) < Duration::from_secs(120));
        assert!(CONNECT_PHASE_BUDGET > Duration::ZERO);
    }

    #[test]
    fn synchronous_ipc_work_does_not_starve_a_single_threaded_caller() {
        let caller = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|error| panic!("failed to build caller runtime: {error}"));
        caller.block_on(async {
            let started = Instant::now();
            let blocked = run_ipc_request(Duration::from_secs(5), || async {
                std::thread::sleep(Duration::from_millis(250));
                Ok(())
            });
            let tick = async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                started.elapsed()
            };
            let (result, ticked_at) = tokio::join!(blocked, tick);
            result.unwrap_or_else(|error| panic!("isolated IPC work failed: {error}"));
            assert!(
                ticked_at < Duration::from_millis(200),
                "caller runtime was starved for {ticked_at:?}"
            );
        });
    }

    #[test]
    fn a_request_that_blocks_its_thread_still_hits_its_guard() {
        // The regression: a request wedged in synchronous OS work used to be polled inside the
        // async future, where no `tokio::time::timeout` could fire and every worker it parked
        // was lost. On a blocking thread the guard is an ordinary `JoinHandle` await, so it
        // fires on time and the caller keeps running.
        let caller = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|error| panic!("failed to build caller runtime: {error}"));
        caller.block_on(async {
            let started = Instant::now();
            let wedged = run_ipc_request(Duration::from_millis(100), || async {
                std::thread::sleep(Duration::from_secs(3));
                Ok(())
            })
            .await;
            assert!(wedged.is_err(), "a wedged request must report a failure");
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "the guard did not fire: waited {:?}",
                started.elapsed()
            );
        });
    }

    #[test]
    fn a_wedged_request_does_not_block_the_next_one() {
        // The app-wide freeze was every later IPC — status, disconnect, quit-time release —
        // queueing behind parked workers. A wedged call must cost one blocking thread, nothing
        // more.
        let caller = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap_or_else(|error| panic!("failed to build caller runtime: {error}"));
        caller.block_on(async {
            let wedged = tokio::spawn(run_ipc_request(Duration::from_secs(30), || async {
                std::thread::sleep(Duration::from_secs(3));
                Ok(())
            }));
            tokio::time::sleep(Duration::from_millis(50)).await;
            let started = Instant::now();
            run_blocking(Duration::from_secs(5), || Ok(()))
                .await
                .unwrap_or_else(|error| panic!("a later IPC call was blocked: {error}"));
            assert!(
                started.elapsed() < Duration::from_millis(500),
                "a later IPC call queued behind the wedged one for {:?}",
                started.elapsed()
            );
            wedged.abort();
        });
    }

    #[test]
    fn dropping_the_caller_does_not_cancel_started_ipc_work() {
        let caller = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|error| panic!("failed to build caller runtime: {error}"));
        caller.block_on(async {
            let completed = Arc::new(AtomicBool::new(false));
            let task_completed = Arc::clone(&completed);
            let outer = tokio::spawn(run_ipc_request(
                Duration::from_secs(5),
                move || async move {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    task_completed.store(true, Ordering::SeqCst);
                    Ok(())
                },
            ));
            tokio::time::sleep(Duration::from_millis(10)).await;
            outer.abort();
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert!(completed.load(Ordering::SeqCst));
        });
    }

    #[test]
    fn bounded_os_work_returns_its_answer() {
        assert_eq!(
            run_with_deadline(Duration::from_secs(5), || 7_u32),
            Some(7),
            "work that answers in time must not be discarded"
        );
    }

    #[test]
    fn bounded_os_work_gives_up_and_reports_nothing() {
        // What the Windows verifier turns into a refusal: no answer is not an answer.
        let started = Instant::now();
        let answer = run_with_deadline(Duration::from_millis(100), || {
            std::thread::sleep(Duration::from_secs(3));
            7_u32
        });
        assert!(answer.is_none());
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the deadline did not bound the wait: {:?}",
            started.elapsed()
        );
    }
}
