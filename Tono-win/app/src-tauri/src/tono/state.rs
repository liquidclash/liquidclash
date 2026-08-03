//! Tono product state, injected as `tauri::State<TonoState>`.
//!
//! One tokio mutex guards the whole product layer: account session, catalog
//! tracker, selection, connect FSM, and the cached Service observations.
//! Long-running work (catalog sync, reconnect backoff, network monitoring)
//! lives in spawned tasks whose abort handles are registered here.

use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::{
        Arc, Mutex as StdMutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

/// How many retired generations keep their H-1 intent; see `TonoInner::retired_intents`.
const RETIRED_INTENT_HISTORY: usize = 16;

use anyhow::{Context as _, Result};
use clash_verge_service_ipc::KillSwitchStatus;
use tauri::async_runtime::JoinHandle;
use tokio_util::sync::CancellationToken;
use tono_core::{
    CatalogTracker,
    auth::{ApiClient, User, new_installation_id},
    catalog::CatalogCache,
    connection::ConnectionFsm,
    node::ValidatedNode,
};

use crate::{
    tono::{credentials::SessionCredentialStore, transport::TonoTransport},
    utils::dirs,
};

/// Concrete account API client used across the product layer.
pub type TonoApiClient = ApiClient<TonoTransport, SessionCredentialStore>;

/// One explicit DNS/Core/WFP release shared by Disconnect, Sign Out, Quit, and startup
/// reconciliation. The result lives outside `TonoInner`, so waiting for it never holds the large
/// product-state mutex. `Notify` also lets a later caller join an operation whose original UI
/// waiter already timed out without launching a second, racing release.
pub struct ReleaseOperation {
    id: u64,
    result: StdMutex<Option<std::result::Result<(), String>>>,
    notify: tokio::sync::Notify,
}

impl ReleaseOperation {
    fn new(id: u64) -> Self {
        Self {
            id,
            result: StdMutex::new(None),
            notify: tokio::sync::Notify::new(),
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn complete(&self, result: std::result::Result<(), String>) {
        *self.result.lock().unwrap_or_else(PoisonError::into_inner) = Some(result);
        self.notify.notify_waiters();
    }

    pub async fn wait(&self) -> std::result::Result<(), String> {
        loop {
            // Register before reading the result so completion cannot slip between the check and
            // the await. `enable` is required for `notify_waiters`: merely constructing a
            // `Notified` future does not enroll it until its first poll.
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(result) = self.result.lock().unwrap_or_else(PoisonError::into_inner).clone() {
                return result;
            }
            notified.as_mut().await;
        }
    }
}

/// Account state machine (product-contract.md §2, macOS parity):
/// `restoring → signedOut | authenticating | ready | suspended | error`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountState {
    Restoring,
    SignedOut,
    Authenticating,
    Ready,
    Suspended,
    Error(String),
}

impl AccountState {
    /// Stable wire key for the frontend (`TonoStatus.account_state`).
    pub fn key(&self) -> &'static str {
        match self {
            AccountState::Restoring => "restoring",
            AccountState::SignedOut => "signedOut",
            AccountState::Authenticating => "authenticating",
            AccountState::Ready => "ready",
            AccountState::Suspended => "suspended",
            AccountState::Error(_) => "error",
        }
    }
}

/// Abort handles for the spawned product tasks. All of them stop on
/// sign-out; the reconnect, switch, and network monitor tasks also stop on
/// an explicit disconnect.
#[derive(Default)]
pub struct TaskRegistry {
    pub catalog_sync: Option<JoinHandle<()>>,
    pub reconnect: Option<JoinHandle<()>>,
    pub network_monitor: Option<JoinHandle<()>>,
    pub switch: Option<JoinHandle<()>>,
}

impl TaskRegistry {
    fn abort(slot: &mut Option<JoinHandle<()>>) {
        if let Some(handle) = slot.take() {
            handle.abort();
        }
    }

    pub fn abort_catalog_sync(&mut self) {
        Self::abort(&mut self.catalog_sync);
    }

    pub fn abort_reconnect(&mut self) {
        Self::abort(&mut self.reconnect);
    }

    pub fn abort_network_monitor(&mut self) {
        Self::abort(&mut self.network_monitor);
    }

    pub fn abort_switch(&mut self) {
        Self::abort(&mut self.switch);
    }

    /// Connection-scoped tasks: everything that drives the connect
    /// transaction or reacts to the tunnel. Aborted on disconnect and on a
    /// node switch; the catalog sync is account-scoped and survives both.
    pub fn abort_connection_tasks(&mut self) {
        self.abort_reconnect();
        self.abort_network_monitor();
        self.abort_switch();
    }
}

pub struct TonoInner {
    pub client: Arc<TonoApiClient>,
    /// Memory-first session credentials (never touches the vault on the
    /// calling thread; see `tono::credentials`).
    pub credentials: Arc<SessionCredentialStore>,
    /// Startup credential hydration completed (load task ran, whatever the
    /// outcome). Restore/sign-in wait for it before deciding anything.
    pub credentials_loaded: bool,
    /// Vault read failure recorded by the load task (M1: drives the
    /// `error` account state instead of a mistaken signed-out).
    pub credential_error: Option<String>,
    pub account_state: AccountState,
    /// Last verified account payload (`GET me` or the sign-in response).
    pub account: Option<User>,
    /// In-flight email sign-in challenge, consumed by `tono_sign_in_verify`.
    pub challenge_id: Option<String>,
    /// Generation of the current email-auth transaction. Starting/resending, signing out, or
    /// replacing a challenge invalidates network responses from every older transaction.
    pub sign_in_generation: u64,
    pub installation_id: String,
    pub catalog_tracker: CatalogTracker,
    /// Directory holding `managed-exit-catalog.json` (`app_home_dir()/tono`).
    /// The cache itself is built on demand: `CatalogCache` boxes its safety
    /// check without `Send` bounds, so it cannot live behind the async mutex.
    pub catalog_dir: PathBuf,
    /// Nodes of the currently installed, fully validated catalog.
    pub nodes: Vec<ValidatedNode>,
    pub selected_node: Option<String>,
    /// The selected node vanished from a newer catalog: auto-reconnect stays
    /// blocked until the user picks a surviving node (§3).
    pub catalog_requires_choice: bool,
    pub fsm: ConnectionFsm,
    /// Last observed kill switch aggregate.
    pub kill_switch: Option<KillSwitchStatus>,
    /// Last observed `network_events.counter` from the Service `/status` feed.
    pub network_events_counter: Option<u64>,
    /// Per-start controller secret of the running runtime (memory only, §5).
    pub controller_secret: Option<String>,
    /// Per-generation loopback controller port. It is chosen before each first Core start and
    /// reused by the optional policy restart, so another local proxy cannot hold Tono hostage on
    /// a globally fixed 9090 listener.
    pub controller_port: Option<u16>,
    /// Connect transaction generation. Disconnect, sign-out, and node
    /// switches bump it; an in-flight attempt re-checks it at every stage
    /// boundary and exits without side effects when it moved.
    pub connect_generation: u64,
    /// Immediate cancellation signal for read-only/current-stage work. Privileged IPC mutations
    /// are deliberately detached and reconcile after commit, but the user-facing transaction no
    /// longer waits for them after Disconnect, node replacement, Quit, or its absolute deadline.
    pub connect_cancellation: CancellationToken,
    /// The intent of the latest generation bump (H-1): `true` when the
    /// bumper releases the barrier (disconnect / sign-out / quit), `false`
    /// when it re-arms or keeps blocking (node switch, catalog teardown).
    /// A stale attempt past a committed StartClash patches the late arm
    /// only for the releasing kind — otherwise it would disarm the barrier
    /// the switch's fresh transaction is about to own.
    ///
    /// Read through [`TonoInner::release_intent_for`], never directly: on its own this is a
    /// single last-writer-wins bit, and a stale attempt returning after two bumps would read
    /// the newer bumper's intent rather than the intent of the bump that retired *it*.
    pub release_on_stale: bool,
    /// The same intent, recorded per retired generation.
    ///
    /// The global bit above is safe today only positionally: every non-releasing bumper
    /// requires `is_connected || is_connecting`, which `begin_disconnect()` clears atomically
    /// under the same guard, so a releasing intent cannot currently be overwritten by a later
    /// non-releasing one. Any future bumper firing from `is_disconnecting` or
    /// `is_protection_blocked` would silently downgrade a pending releasing intent to "keep
    /// blocking" and strand WFP armed after a completed Disconnect. The history is short
    /// because a stale attempt that has not returned within this many bumps lost every race it
    /// could have won long ago.
    retired_intents: VecDeque<(u64, bool)>,
    /// Last `core_pid` / `restart_count` seen in the Service `/status`
    /// feed (runtime crash / TUN rebuild detection, M4).
    pub last_core_pid: Option<u32>,
    pub last_restart_count: Option<u32>,
    /// Last time the network monitor invalidated Connected (P0-13
    /// debounce: bursts of counter changes within the window merge into one
    /// reconnect transaction).
    pub last_network_event_at: Option<std::time::Instant>,
    /// F3: per-step record of the latest connect transaction (reset at
    /// each attempt start, kept afterwards for the UI).
    pub connect_steps: Vec<crate::tono::steps::StepRecord>,
    /// When the currently-current step became current (per-step elapsed).
    pub step_started_at: Option<std::time::Instant>,
    /// F3: last connect failure details (stage key, sanitized error, when).
    pub failed_stage: Option<&'static str>,
    pub connect_error: Option<String>,
    pub connect_error_at_ms: Option<i64>,
    /// F3: retry bookkeeping — failed attempts so far and the scheduled
    /// reconnect deadline (epoch millis).
    pub retry_attempt: u32,
    pub next_retry_at_ms: Option<i64>,
    /// Cloud WeChat-DIRECT policy (Build 28): monotonic tracker plus the
    /// latest validated document. The cache shares the catalog's directory
    /// and safety checks (`managed-traffic-policy.json`).
    pub policy_tracker: tono_core::policy::PolicyTracker,
    pub traffic_policy: Option<tono_core::policy::TonoTrafficPolicy>,
    pub tasks: TaskRegistry,
}

impl TonoInner {
    /// Retire the current connection generation and wake every stage waiting on its cancellation
    /// token. `release_on_stale` preserves the existing late-commit contract: releasing flows
    /// patch a late arm; protected reconnect/switch flows keep the barrier.
    pub fn invalidate_connection(&mut self, release_on_stale: bool) {
        self.retire_connection_generation(release_on_stale);
        self.tasks.abort_connection_tasks();
    }

    /// [`invalidate_connection`] minus the task aborts, for the connect-timeout path only. The
    /// timed-out attempt may itself be running inside a registered connection task (the
    /// reconnect loop, the network monitor's re-entry, a node switch); aborting the registry
    /// there would abort the caller at its next await, so `fail_connect` and the reconnect
    /// scheduling never run and the FSM is stranded in Connecting. The generation bump plus
    /// token cancellation already retire every other task's in-flight work at its next stage
    /// boundary.
    pub fn retire_connection_generation(&mut self, release_on_stale: bool) {
        let retired = self.connect_generation;
        self.connect_generation = self.connect_generation.wrapping_add(1);
        self.release_on_stale = release_on_stale;
        if self.retired_intents.len() == RETIRED_INTENT_HISTORY {
            self.retired_intents.pop_front();
        }
        self.retired_intents.push_back((retired, release_on_stale));
        self.connect_cancellation.cancel();
        self.connect_cancellation = CancellationToken::new();
    }

    /// The intent of the bump that retired `generation` (H-1).
    ///
    /// Callers pass the generation they were *running under*, so the answer describes the bump
    /// that made them stale rather than whatever happened most recently.
    #[must_use]
    pub fn release_intent_for(&self, generation: u64) -> bool {
        self.retired_intents
            .iter()
            .rev()
            .find_map(|(retired, intent)| (*retired == generation).then_some(*intent))
            // Older than the window: fall back to the global bit, which is what every caller
            // used to read unconditionally.
            .unwrap_or(self.release_on_stale)
    }

    /// Build the on-disk catalog cache rooted at the state's directory.
    pub fn catalog_cache(&self) -> CatalogCache {
        catalog_cache_at(&self.catalog_dir)
    }

    /// Build the on-disk traffic-policy cache (same directory, same
    /// platform safety policy as the catalog cache).
    pub fn policy_cache(&self) -> tono_core::policy::PolicyCache {
        policy_cache_at(&self.catalog_dir)
    }
}

/// The `tauri::State` handle. Every access goes through the async mutex;
/// commands take it, do their I/O, and drop it before emitting. The audit
/// handle is separate and lock-free (its own channel + atomic flag).
pub struct TonoState {
    inner: tokio::sync::Mutex<TonoInner>,
    audit: Arc<crate::tono::audit::Audit>,
    release_operation: tokio::sync::Mutex<Option<Arc<ReleaseOperation>>>,
    /// A late StartClash or DNS-enable commit must settle before explicit release reaches the
    /// Service. Connect mutations hold a read guard inside their detached reconciliation task;
    /// the one release worker holds the write guard through the atomic Service release.
    privileged_transition: Arc<tokio::sync::RwLock<()>>,
    next_release_id: AtomicU64,
}

impl TonoState {
    pub fn create() -> Result<Self> {
        let catalog_dir = tono_data_dir()?;
        std::fs::create_dir_all(&catalog_dir)
            .with_context(|| format!("failed to create Tono data dir {}", catalog_dir.display()))?;

        let credentials = Arc::new(SessionCredentialStore::new());
        let transport = TonoTransport::new()?;
        let client = Arc::new(TonoApiClient::new(
            tono_core::auth::DEFAULT_BASE_URL,
            transport,
            credentials.clone(),
        )?);

        // installationId: a fresh in-memory UUID for now — NO vault I/O on
        // the setup thread (a prompting macOS securityd blocked setup
        // forever). The startup load task hydrates the persisted id (or
        // persists this one) off-thread with a timeout.
        let installation_id = new_installation_id();

        // §8 audit: JSONL under `tono/logs`, toggle from `tono/settings.json`.
        let audit = crate::tono::audit::Audit::new(&catalog_dir.join("logs"), &catalog_dir);

        Ok(Self {
            inner: tokio::sync::Mutex::new(TonoInner {
                client,
                credentials,
                credentials_loaded: false,
                credential_error: None,
                account_state: AccountState::SignedOut,
                account: None,
                challenge_id: None,
                sign_in_generation: 0,
                installation_id,
                catalog_tracker: CatalogTracker::new(),
                catalog_dir,
                nodes: Vec::new(),
                selected_node: None,
                catalog_requires_choice: false,
                fsm: ConnectionFsm::new(),
                kill_switch: None,
                network_events_counter: None,
                controller_secret: None,
                controller_port: None,
                connect_generation: 0,
                connect_cancellation: CancellationToken::new(),
                release_on_stale: false,
                retired_intents: VecDeque::new(),
                last_core_pid: None,
                last_restart_count: None,
                last_network_event_at: None,
                connect_steps: crate::tono::steps::initial_steps(),
                step_started_at: None,
                failed_stage: None,
                connect_error: None,
                connect_error_at_ms: None,
                retry_attempt: 0,
                next_retry_at_ms: None,
                policy_tracker: tono_core::policy::PolicyTracker::new(),
                traffic_policy: None,
                tasks: TaskRegistry::default(),
            }),
            audit,
            release_operation: tokio::sync::Mutex::new(None),
            privileged_transition: Arc::new(tokio::sync::RwLock::new(())),
            next_release_id: AtomicU64::new(1),
        })
    }

    pub fn audit(&self) -> &crate::tono::audit::Audit {
        &self.audit
    }

    pub async fn lock(&self) -> tokio::sync::MutexGuard<'_, TonoInner> {
        self.inner.lock().await
    }

    /// Start one release or join the already-running one. The boolean is true only for the caller
    /// responsible for spawning the supervisor.
    pub async fn begin_release(&self) -> (Arc<ReleaseOperation>, bool) {
        let mut slot = self.release_operation.lock().await;
        if let Some(operation) = slot.as_ref() {
            return (Arc::clone(operation), false);
        }
        let id = self.next_release_id.fetch_add(1, Ordering::Relaxed);
        let operation = Arc::new(ReleaseOperation::new(id));
        *slot = Some(Arc::clone(&operation));
        (operation, true)
    }

    pub async fn finish_release(&self, id: u64) {
        let mut slot = self.release_operation.lock().await;
        if slot.as_ref().is_some_and(|operation| operation.id() == id) {
            slot.take();
        }
    }

    pub async fn release_in_progress(&self) -> bool {
        self.release_operation.lock().await.is_some()
    }

    pub async fn begin_connect_mutation(&self) -> tokio::sync::OwnedRwLockReadGuard<()> {
        Arc::clone(&self.privileged_transition).read_owned().await
    }

    pub async fn begin_privileged_release(&self) -> tokio::sync::OwnedRwLockWriteGuard<()> {
        Arc::clone(&self.privileged_transition).write_owned().await
    }
}

/// `app_home_dir()/tono`, falling back to the pre-init data dir when the app
/// handle is not bound yet (early setup).
fn tono_data_dir() -> Result<PathBuf> {
    let base = dirs::app_home_dir().or_else(|_| dirs::preinit_app_data_dir())?;
    Ok(base.join("tono"))
}

/// Platform catalog cache (§3 cache safety).
fn catalog_cache_at(dir: &std::path::Path) -> CatalogCache {
    #[cfg(unix)]
    {
        CatalogCache::platform(dir)
    }
    #[cfg(windows)]
    {
        CatalogCache::new(dir, Box::new(WindowsCacheSafetyCheck))
    }
}

/// Platform traffic-policy cache (same directory, same safety policy).
fn policy_cache_at(dir: &std::path::Path) -> tono_core::policy::PolicyCache {
    #[cfg(unix)]
    {
        tono_core::policy::PolicyCache::new(dir, Box::new(tono_core::catalog::UnixCacheSafetyCheck))
    }
    #[cfg(windows)]
    {
        tono_core::policy::PolicyCache::new(dir, Box::new(WindowsCacheSafetyCheck))
    }
}

// ---- Selection persistence (L4) ----

/// File holding the last selected node inside the Tono data dir.
pub const SELECTION_FILE_NAME: &str = "selection.json";

#[derive(serde::Serialize, serde::Deserialize)]
struct SelectionFile {
    selected: String,
}

pub fn selection_path(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join(SELECTION_FILE_NAME)
}

/// Persist the selection with owner-only protection (0600 on unix, a
/// private DACL on Windows). Best-effort by contract: callers log and move
/// on, a lost selection file only costs one re-pick.
pub fn save_selection(dir: &std::path::Path, selected: &str) -> Result<()> {
    let body = serde_json::to_string(&SelectionFile {
        selected: selected.to_string(),
    })
    .context("failed to serialize the selection")?;
    write_private_file(&selection_path(dir), body.as_bytes())
}

/// Load a persisted selection. A missing or corrupt file is simply absent.
pub fn load_selection(dir: &std::path::Path) -> Option<String> {
    let body = std::fs::read_to_string(selection_path(dir)).ok()?;
    let parsed: SelectionFile = serde_json::from_str(&body).ok()?;
    let name = parsed.selected.trim();
    // Node names are bounded by the admission contract (<= 128 bytes).
    if name.is_empty() || name.len() > 128 {
        return None;
    }
    Some(name.to_string())
}

#[cfg(unix)]
pub(crate) fn write_private_file(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    // `mode` only applies to freshly created files; tighten pre-existing ones too.
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    Ok(())
}

#[cfg(windows)]
pub(crate) fn write_private_file(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;

    let mut file = crate::core::owner_identity::open_or_create_private_current_user_file(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    file.set_len(0)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Open a log file for appending with owner-only protection (0600 on unix,
/// a private DACL on Windows). Used by the audit writer (§8).
#[cfg(unix)]
pub(crate) fn open_private_append(path: &std::path::Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    Ok(file)
}

/// Open a log file for appending with owner-only protection (0600 on unix,
/// a private DACL on Windows). Used by the audit writer (§8).
#[cfg(windows)]
pub(crate) fn open_private_append(path: &std::path::Path) -> Result<std::fs::File> {
    use std::io::{Seek as _, SeekFrom};

    let mut file = crate::core::owner_identity::open_or_create_private_current_user_file(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    file.seek(SeekFrom::End(0))?;
    Ok(file)
}

/// Windows cache safety (§3): no reparse points, a regular file owned by the
/// current user whose DACL grants exactly the owner, SYSTEM, and
/// Administrators full access — nobody else.
#[cfg(windows)]
pub(crate) struct WindowsCacheSafetyCheck;

#[cfg(windows)]
impl tono_core::catalog::CacheSafetyCheck for WindowsCacheSafetyCheck {
    /// `CatalogCache::store` calls this on the temp file right before the
    /// rename: apply exactly the DACL `check_open` below demands (protected,
    /// owner + SYSTEM + Administrators full control, nobody else). The two
    /// sides are deliberately symmetric — without this the cache could be
    /// written but never read back (H3).
    fn secure_written_file(&self, path: &std::path::Path) -> std::io::Result<()> {
        use std::os::windows::ffi::OsStrExt as _;
        use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT, SetSecurityInfo,
        };
        use windows_sys::Win32::Security::{
            ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION,
        };
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
        };

        let io_other = |message: String| std::io::Error::new(std::io::ErrorKind::Other, message);

        let sid = current_user_sid_text().map_err(|err| io_other(err.to_string()))?;
        // The exact SDDL `check_open` verifies.
        let sddl = format!("O:{sid}D:P(A;;FA;;;{sid})(A;;FA;;;SY)(A;;FA;;;BA)");
        let mut sddl_wide: Vec<u16> = sddl.encode_utf16().collect();
        sddl_wide.push(0);
        let mut descriptor = std::ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        } == 0
            || descriptor.is_null()
        {
            return Err(std::io::Error::last_os_error());
        }
        let descriptor = SecurityDescriptorGuard(descriptor);

        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl: *mut ACL = std::ptr::null_mut();
        if unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted) } == 0
            || present == 0
            || dacl.is_null()
        {
            return Err(std::io::Error::last_os_error());
        }

        // The store's own handle lacks WRITE_DAC; open a fresh one by path.
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        wide.push(0);
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                READ_CONTROL | WRITE_DAC,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }
        let file = unsafe { std::fs::File::from_raw_handle(handle) };
        let status = unsafe {
            SetSecurityInfo(
                file.as_raw_handle() as _,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null_mut(),
            )
        };
        if status != 0 {
            return Err(io_other(format!(
                "failed to protect the cache DACL: Windows error {status}"
            )));
        }
        Ok(())
    }
    fn check_path(&self, path: &std::path::Path) -> Result<(), tono_core::CatalogError> {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

        let metadata = std::fs::symlink_metadata(path).map_err(|err| tono_core::CatalogError::Io(err.to_string()))?;
        if metadata.file_type().is_symlink() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(tono_core::CatalogError::Io("cache path is a reparse point".to_string()));
        }
        Ok(())
    }

    fn check_open(&self, file: &std::fs::File) -> Result<(), tono_core::CatalogError> {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
        use windows_sys::Win32::Security::{
            ACCESS_ALLOWED_ACE, ACL, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetSecurityDescriptorControl,
            IsWellKnownSid, OWNER_SECURITY_INFORMATION, PSID, SE_DACL_PROTECTED, WinBuiltinAdministratorsSid,
            WinLocalSystemSid,
        };
        use windows_sys::Win32::Storage::FileSystem::{FILE_ALL_ACCESS, FILE_TYPE_DISK, GetFileType};

        let io = |message: &str| tono_core::CatalogError::Io(message.to_string());

        let metadata = file
            .metadata()
            .map_err(|err| tono_core::CatalogError::Io(err.to_string()))?;
        if !metadata.file_type().is_file() {
            return Err(io("cache is not a regular file"));
        }
        let size = metadata.len();
        if size == 0 || size > tono_core::catalog::MAX_CACHE_FILE_BYTES {
            return Err(io("cache size out of bounds"));
        }
        if unsafe { GetFileType(file.as_raw_handle() as _) } != FILE_TYPE_DISK {
            return Err(io("cache is not on a disk device"));
        }

        let mut owner: PSID = std::ptr::null_mut();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut security = std::ptr::null_mut();
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle() as _,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut security,
            )
        };
        if status != 0 || security.is_null() {
            return Err(io("cache security descriptor is unreadable"));
        }
        let security = SecurityDescriptorGuard(security);
        if owner.is_null() || dacl.is_null() {
            return Err(io("cache has no owner or DACL"));
        }

        let current = CurrentUserSid::query()?;
        if unsafe { EqualSid(owner, current.0) } == 0 {
            return Err(io("cache is owned by another user"));
        }

        let mut control = 0_u16;
        let mut revision = 0_u32;
        if unsafe { GetSecurityDescriptorControl(security.0, &mut control, &mut revision) } == 0
            || control & SE_DACL_PROTECTED == 0
        {
            return Err(io("cache DACL is not protected"));
        }
        let mut owner_ace = false;
        let mut system_ace = false;
        let mut administrators_ace = false;
        for index in 0..unsafe { (*dacl).AceCount } as u32 {
            let mut ace = std::ptr::null_mut();
            if unsafe { GetAce(dacl, index, &mut ace) } == 0 || ace.is_null() {
                return Err(io("cache DACL could not be inspected"));
            }
            let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            // ACCESS_ALLOWED_ACE_TYPE == 0, no inheritance flags, full
            // access only — exactly what `secure_written_file` writes (L-3).
            if allowed.Header.AceType != 0
                || allowed.Header.AceFlags != 0
                || allowed.Mask & FILE_ALL_ACCESS != FILE_ALL_ACCESS
            {
                return Err(io("cache DACL contains an unexpected ACE"));
            }
            let ace_sid: PSID = std::ptr::addr_of!(allowed.SidStart).cast_mut().cast();
            if unsafe { EqualSid(ace_sid, current.0) } != 0 {
                owner_ace = true;
            } else if unsafe { IsWellKnownSid(ace_sid, WinLocalSystemSid) } != 0 {
                system_ace = true;
            } else if unsafe { IsWellKnownSid(ace_sid, WinBuiltinAdministratorsSid) } != 0 {
                administrators_ace = true;
            } else {
                return Err(io("cache DACL grants another principal"));
            }
        }
        if unsafe { (*dacl).AceCount } != 3 || !owner_ace || !system_ace || !administrators_ace {
            return Err(io("cache DACL is missing a required principal"));
        }
        Ok(())
    }
}

#[cfg(windows)]
struct SecurityDescriptorGuard(windows_sys::Win32::Security::PSECURITY_DESCRIPTOR);

#[cfg(windows)]
impl Drop for SecurityDescriptorGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { windows_sys::Win32::Foundation::LocalFree(self.0.cast()) };
        }
    }
}

/// The current user's SID text, with a cheap shape check (L-3, defense in
/// depth: anything reaching an SDDL string must look like `S-<digits>`).
#[cfg(windows)]
fn is_valid_sid_text(sid: &str) -> bool {
    let Some(rest) = sid.strip_prefix("S-") else {
        return false;
    };
    !rest.is_empty()
        && rest
            .split('-')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

/// The current user's SID string, validated.
#[cfg(windows)]
fn current_user_sid_text() -> Result<String, tono_core::CatalogError> {
    let identity = crate::core::owner_identity::current_owner_identity()
        .map_err(|err| tono_core::CatalogError::Io(err.to_string()))?;
    let clash_verge_service_ipc::OwnerIdentity::Windows { sid } = identity else {
        return Err(tono_core::CatalogError::Io("not a Windows identity".to_string()));
    };
    if !is_valid_sid_text(&sid) {
        return Err(tono_core::CatalogError::Io(
            "current user SID has an unexpected shape".to_string(),
        ));
    }
    Ok(sid)
}

/// The current user's SID as a `PSID`, freed on drop.
#[cfg(windows)]
struct CurrentUserSid(windows_sys::Win32::Security::PSID);

#[cfg(windows)]
impl CurrentUserSid {
    fn query() -> Result<Self, tono_core::CatalogError> {
        use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;

        let sid = current_user_sid_text()?;
        let mut wide: Vec<u16> = sid.encode_utf16().collect();
        wide.push(0);
        let mut psid: windows_sys::Win32::Security::PSID = std::ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut psid) } == 0 || psid.is_null() {
            return Err(tono_core::CatalogError::Io(
                "current user SID is unavailable".to_string(),
            ));
        }
        Ok(Self(psid))
    }
}

#[cfg(windows)]
impl Drop for CurrentUserSid {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { windows_sys::Win32::Foundation::LocalFree(self.0.cast()) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AccountState, ReleaseOperation};
    use std::{sync::Arc, time::Duration};

    #[test]
    fn account_state_keys_are_stable() {
        assert_eq!(AccountState::Restoring.key(), "restoring");
        assert_eq!(AccountState::SignedOut.key(), "signedOut");
        assert_eq!(AccountState::Authenticating.key(), "authenticating");
        assert_eq!(AccountState::Ready.key(), "ready");
        assert_eq!(AccountState::Suspended.key(), "suspended");
        assert_eq!(AccountState::Error("x".to_string()).key(), "error");
    }

    #[tokio::test]
    async fn release_operation_wakes_every_joiner_and_replays_the_result() {
        let operation = Arc::new(ReleaseOperation::new(7));
        let first = tokio::spawn({
            let operation = Arc::clone(&operation);
            async move { operation.wait().await }
        });
        let second = tokio::spawn({
            let operation = Arc::clone(&operation);
            async move { operation.wait().await }
        });
        tokio::task::yield_now().await;
        operation.complete(Err("kept protected".to_string()));

        for waiter in [first, second] {
            let result = tokio::time::timeout(Duration::from_secs(1), waiter)
                .await
                .expect("every registered waiter must wake")
                .expect("waiter task must not fail");
            assert_eq!(result, Err("kept protected".to_string()));
        }
        assert_eq!(operation.wait().await, Err("kept protected".to_string()));
    }
}
