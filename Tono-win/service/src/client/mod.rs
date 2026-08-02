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
/// Keep synchronous Windows named-pipe and Service Control Manager verification away from the
/// application's Tauri runtime. `kode-bridge` performs those checks inline before its first
/// async pipe operation, so a slow SCM can otherwise occupy every worker on a small Windows VM.
static IPC_RUNTIME: Lazy<std::result::Result<tokio::runtime::Runtime, String>> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("tono-service-ipc")
        .enable_all()
        .build()
        .map_err(|error| error.to_string())
});

static IPC_AUTH_HEADER_KEY: &str = "X-IPC-Magic";
/// The Service bounds one handler at 60 seconds. A mutating client must wait slightly longer so
/// it cannot time out, retry, and race the still-running handler on a second connection.
const LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(65);
/// Read-only status calls still round-trip through the service's state (and, on Windows,
/// cached verify results), so they get more than the interactive default but far less than
/// a lifecycle mutation.
const STATUS_TIMEOUT: Duration = Duration::from_secs(2);
/// `kode-bridge` applies `max_retries` to both connection establishment and the complete HTTP
/// request. The Run State already owns startup retry/backoff, so an individual read must stay
/// small and bounded; otherwise two status calls can occupy the dedicated IPC runtime for
/// minutes and queue a safety-critical release behind them.
const READ_REQUEST_ATTEMPTS: usize = 2;
/// A mutating request is never replayed after an ambiguous transport failure. The Service may
/// already have committed it even when its response was lost.
const MUTATING_REQUEST_ATTEMPTS: usize = 1;

async fn run_on_ipc_runtime<T, F>(future: F) -> Result<T>
where
    T: Send + 'static,
    F: Future<Output = Result<T>> + Send + 'static,
{
    let runtime = IPC_RUNTIME
        .as_ref()
        .map_err(|error| anyhow::anyhow!("failed to initialize Service IPC runtime: {error}"))?;
    runtime
        .spawn(future)
        .await
        .map_err(|error| anyhow::anyhow!("Service IPC runtime task failed: {error}"))?
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
    run_on_ipc_runtime(async move {
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

pub async fn connect() -> Result<IpcHttpClient> {
    connect_with_max_retries(None).await
}

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

pub fn is_ipc_path_exists() -> bool {
    Path::new(IPC_PATH).exists()
}

pub async fn get_version() -> Result<Response<ProtocolInfo>> {
    run_on_ipc_runtime(get_version_inner()).await
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
    is_ipc_path_exists()
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
        None,
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
        None,
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
        None,
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
        None,
    )
    .await
}

#[cfg(test)]
mod retry_safety_tests {
    use super::{MUTATING_REQUEST_ATTEMPTS, READ_REQUEST_ATTEMPTS, Verb, run_on_ipc_runtime};
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
    fn synchronous_ipc_work_does_not_starve_a_single_threaded_caller() {
        let caller = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|error| panic!("failed to build caller runtime: {error}"));
        caller.block_on(async {
            let started = Instant::now();
            let blocked = run_on_ipc_runtime(async {
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
    fn dropping_the_caller_does_not_cancel_started_ipc_work() {
        let caller = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|error| panic!("failed to build caller runtime: {error}"));
        caller.block_on(async {
            let completed = Arc::new(AtomicBool::new(false));
            let task_completed = Arc::clone(&completed);
            let outer = tokio::spawn(run_on_ipc_runtime(async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
                task_completed.store(true, Ordering::SeqCst);
                Ok(())
            }));
            tokio::time::sleep(Duration::from_millis(10)).await;
            outer.abort();
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(completed.load(Ordering::SeqCst));
        });
    }
}
