//! Tono Service - Cross-platform IPC service daemon
//!
//! This service can run as a standalone process or as a Windows service.
//! It listens for shutdown signals (Ctrl+C, SIGTERM, or service stop) to gracefully terminate.

use anyhow::Result;
use clash_verge_service_ipc::{
    acquire_service_owner, add_restored_kill_switch_tunnel, initialize_protected_dns_status,
    reconcile_service_startup, restore_desired_state, restore_kill_switch,
    restore_windows_kill_switch, retire_unverified_windows_kill_switch,
    run_ipc_supervisor_until_shutdown, spawn_kill_switch_watchdog, spawn_protected_dns_watchdog,
    spawn_windows_kill_switch_watchdog,
};
use tracing::{Level, info, warn};
use tracing_subscriber::FmtSubscriber;

#[cfg(windows)]
use {
    platform_lib::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
        service_dispatcher,
    },
    std::ffi::OsString,
    std::sync::Arc,
    std::sync::OnceLock,
    std::sync::atomic::{AtomicBool, Ordering},
    std::time::Duration,
};

/// What SCM is told to expect while teardown runs.
///
/// Teardown stops the core, restores DNS and writes the tombstone, so it is not instant. Without
/// a hint SCM decides the service is hung after its own default.
#[cfg(windows)]
const STOP_WAIT_HINT: Duration = Duration::from_secs(45);

// --- Main Entry Points ---

/// Main entry point for non-Windows platforms (Linux, macOS).
#[cfg(not(windows))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    set_secure_process_umask();
    init_logger();
    if std::env::args().any(|arg| arg == "--emergency-disarm") {
        if unsafe { platform_lib::geteuid() } != 0 {
            anyhow::bail!("--emergency-disarm must be run as root");
        }
        let Some(_owner_guard) = clash_verge_service_ipc::acquire_service_owner().await? else {
            anyhow::bail!("service daemon is still running; refusing to open the kill switch");
        };
        // Uninstall has verified launchd bootout, and the owner lock proves no daemon/core
        // lifecycle currently owns this state.
        clash_verge_service_ipc::emergency_disarm_kill_switch().await?;
        println!("Kill switch disarmed; network opened");
        return Ok(());
    }
    run_standalone().await
}

#[cfg(unix)]
fn set_secure_process_umask() {
    unsafe {
        platform_lib::umask(0o077);
    }
}

/// Main entry point for Windows.
/// Tries to run as a service, falls back to standalone mode if that fails.
#[cfg(windows)]
fn main() -> Result<()> {
    init_logger();
    if std::env::args().any(|arg| arg == "--emergency-disarm") {
        return run_emergency_disarm();
    }
    if service_dispatcher::start(
        clash_verge_service_ipc::WINDOWS_SERVICE_NAME,
        ffi_service_main,
    )
    .is_err()
    {
        info!("Not running as a service, starting in standalone mode.");
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(run_standalone())?;
    }
    Ok(())
}

/// The last-resort escape hatch, and the one command a stuck user actually runs.
///
/// It is reached from an elevated prompt or from the Start-Menu recovery shortcut, on a machine
/// that by definition has no working network to look anything up on — so every outcome explains
/// itself, in both shipped languages, and says what to do next. English and Chinese are on
/// separate lines deliberately: a console left on a legacy code page mangles the Chinese, and the
/// English line has to survive that.
///
/// Nothing about the authority changes: elevation is still required, the owner lock is still
/// taken so a live daemon's lifecycle cannot race the disarm, and the exit codes are unchanged.
#[cfg(windows)]
fn run_emergency_disarm() -> Result<()> {
    // SAFETY: no inputs; reports whether the current token is elevated.
    if unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() } == 0 {
        print_disarm_result(
            "需要管理员权限，操作未执行。",
            "Administrator rights are required; nothing was changed.",
            &[
                "请右键点击“Tono — 恢复网络”，选择“以管理员身份运行”。",
                "Right-click \"Tono - Restore Network\" and choose \"Run as administrator\".",
            ],
        );
        anyhow::bail!("--emergency-disarm must be run from an elevated prompt");
    }

    let rt = tokio::runtime::Runtime::new()?;
    // Opt into the uninstall DNS ladder so ProgramData tombstone failures cannot abort disarm.
    // SAFETY: single-threaded; this process is the elevated recovery CLI only.
    unsafe { std::env::set_var("TONO_UNINSTALL_DNS_LADDER", "1") };
    let outcome = rt.block_on(async {
        // Owner lock is preferred but not required: Chinese machines fail
        // ensure_private_service_directory with ERROR_INVALID_OWNER (1307) and would otherwise
        // never reach WFP removal. The service is stopped (or absent) when users run this.
        let _owner_guard = match clash_verge_service_ipc::acquire_service_owner().await {
            Ok(guard) => guard,
            Err(error) => {
                eprintln!(
                    "Could not take the service owner lock ({error:#}); continuing emergency disarm."
                );
                None
            }
        };
        clash_verge_service_ipc::emergency_disarm_windows_kill_switch()
            .await
            .map(|()| true)
    });

    match outcome {
        Ok(true) => {
            print_disarm_result(
                "网络保护已解除，可以正常上网了。",
                "Protection removed; your network is restored.",
                &["可以关闭此窗口。", "You can close this window."],
            );
            Ok(())
        }
        Ok(false) => {
            // The service still holds the owner lock, which means the supported route is still
            // open: the App's control pipe is not affected by the barrier.
            print_disarm_result(
                "Tono 服务仍在运行，未做更改。",
                "The Tono service is still running; nothing was changed.",
                &[
                    "请先在 Tono 应用里点击“断开”；若无效，请在“服务”里停止 TonoService 后重试。",
                    "Use Disconnect in the Tono app first; if that fails, stop the TonoService \
                     service and run this again.",
                ],
            );
            anyhow::bail!("service daemon is still running; refusing to open the kill switch")
        }
        Err(error) => {
            print_disarm_result(
                "解除失败，网络保护仍然生效。",
                "The disarm failed; protection is still in place.",
                &[
                    "请重试一次；若仍失败，重启电脑后再运行本快捷方式。技术细节见下方。",
                    "Try again; if it still fails, reboot and run this shortcut once more. \
                     Technical detail follows.",
                ],
            );
            Err(error)
        }
    }
}

/// One readable block per outcome: headline, then what to do next.
#[cfg(windows)]
fn print_disarm_result(headline_zh: &str, headline_en: &str, next_steps: &[&str]) {
    println!();
    println!("  {headline_zh}");
    println!("  {headline_en}");
    println!();
    for step in next_steps {
        println!("  {step}");
    }
    println!();
}

// --- Windows Service Implementation ---

#[cfg(windows)]
define_windows_service!(ffi_service_main, my_service_main);

/// The entry point for the Windows service.
#[cfg(windows)]
fn my_service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        info!("Service failed to run: {}", e);
    }
}

/// Contains the core logic for running as a Windows service.
#[cfg(windows)]
fn run_service() -> platform_lib::Result<()> {
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
    // The status handle only exists after `register` returns, but the handler needs it to move
    // the service out of Running — so it is handed over through a cell the handler already holds.
    let status_handle: Arc<OnceLock<ServiceStatusHandle>> = Arc::new(OnceLock::new());
    let handler_status = Arc::clone(&status_handle);
    let stopping = Arc::new(AtomicBool::new(false));

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            // Preshutdown, not Shutdown: they are mutually exclusive, and only the preshutdown
            // phase leaves enough time to restore the DNS snapshot and write a clean tombstone.
            // Without it a reboot never delivers a stop at all.
            ServiceControl::Stop | ServiceControl::Preshutdown => {
                begin_stop(&handler_status, &stopping, &shutdown_tx);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::PowerEvent(event) => {
                // Only genuine sleep/wake transitions invalidate connectivity. AC/battery
                // flaps, power-setting changes, and battery-low fire the same control code;
                // reacting to them would force a full reconnect on every charger plug.
                use platform_lib::service::PowerEventParam;
                if matches!(
                    event,
                    PowerEventParam::Suspend
                        | PowerEventParam::ResumeAutomatic
                        | PowerEventParam::ResumeSuspend
                ) {
                    // The WFP barrier stays armed; netmon records the event for /status and
                    // the product layer reconnects behind it.
                    clash_verge_service_ipc::note_power_event();
                }
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let registered = service_control_handler::register(
        clash_verge_service_ipc::WINDOWS_SERVICE_NAME,
        event_handler,
    )?;
    let _ = status_handle.set(registered);

    registered.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP
            | ServiceControlAccept::PRESHUTDOWN
            | ServiceControlAccept::POWER_EVENT,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    // Keep recovery/status IPC schedulable while another handler coordinates SCM, filesystem,
    // DNS, WFP/BFE, or process teardown. WFP/DNS calls already use blocking workers, but a
    // current-thread runtime still made any accidental synchronous wait a total Service freeze.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_name("tono-service")
        .enable_all()
        .build()
        .unwrap();
    let fatal = rt.block_on(async {
        let owner_guard = match acquire_service_owner().await {
            Ok(Some(owner_guard)) => owner_guard,
            Ok(None) => {
                // A predecessor's pipe can still answer health probes for a couple of seconds
                // after SCM has already started us. Exiting zero is a *clean* stop, which the
                // configured failure actions deliberately ignore, so the machine would be left
                // with no service at all. Report a failure and let SCM restart us.
                tracing::warn!("Another service owner is still active; exiting for an SCM restart");
                return true;
            }
            Err(error) => {
                tracing::warn!("Failed to acquire service owner lock: {}", error);
                return true;
            }
        };

        // WFP intent is restored before IPC exists, so no client can race a fail-open
        // startup; the watchdog keeps the expected rule set verified by key.
        if let Err(error) = restore_windows_kill_switch().await {
            tracing::warn!(
                "Windows kill-switch restore failed; keeping IPC available for recovery: {error:#}"
            );
        }
        initialize_protected_dns_status().await;
        spawn_protected_dns_watchdog();
        spawn_windows_kill_switch_watchdog();
        clash_verge_service_ipc::start_network_monitor();

        match reconcile_service_startup().await {
            Ok(()) => restore_reconciled_desired_state().await,
            Err(error) => tracing::warn!(
                "Service startup reconciliation failed; core starts remain blocked while IPC is available: {}",
                error
            ),
        }

        let result = run_ipc_supervisor_until_shutdown(async {
            let _ = shutdown_rx.recv().await;
        })
        .await;
        if let Err(error) = result {
            tracing::warn!("IPC supervisor failed: {}", error);
            drop(owner_guard);
            return true;
        }

        drop(owner_guard);
        false
    });

    registered.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(if fatal { 1 } else { 0 }),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    if fatal {
        std::process::exit(1);
    }

    Ok(())
}

/// Accept a stop exactly once, without ever blocking the SCM dispatch thread.
///
/// Two separate hazards live here. Reporting `StopPending` — and withdrawing `STOP` from the
/// accepted set while doing it — is what makes SCM stop forwarding further Stop controls; while
/// the service still advertised `Running`/`STOP`, a slow shutdown collected them. And the send
/// must be non-blocking: the channel holds one message, the receiver drains it once, so the
/// second `blocking_send` filled the buffer and the third parked this thread forever.
#[cfg(windows)]
fn begin_stop(
    status: &OnceLock<ServiceStatusHandle>,
    stopping: &AtomicBool,
    shutdown_tx: &tokio::sync::mpsc::Sender<()>,
) {
    if let Some(handle) = status.get() {
        // Repeats refresh the wait hint rather than being dropped: that is the progress report
        // SCM is looking for while teardown runs.
        let _ = handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::StopPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 1,
            wait_hint: STOP_WAIT_HINT,
            process_id: None,
        });
    }
    if stopping.swap(true, Ordering::SeqCst) {
        return;
    }
    let _ = shutdown_tx.try_send(());
}

// --- Common Logic ---

/// Initializes the global logger.
///
/// Under the SCM a `SERVICE_WIN32_OWN_PROCESS` has no stdout — `GetStdHandle` hands back NULL —
/// so on a customer machine every diagnostic the WFP/DNS/netmon paths emit was being written to
/// nowhere. The file sink is therefore the *primary* one on Windows and stdout is kept beside it
/// for standalone/dev runs.
fn init_logger() {
    #[cfg(windows)]
    if let Some(writer) = service_log_writer() {
        use tracing_subscriber::fmt::writer::MakeWriterExt as _;

        // File first: `Tee` writes both before propagating either result, and ANSI escapes have
        // no business in a log file.
        let subscriber = FmtSubscriber::builder()
            .with_max_level(Level::INFO)
            .with_writer(writer.and(std::io::stdout))
            .with_ansi(false)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
        return;
    }

    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_writer(std::io::stdout)
        .with_ansi(true)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
}

/// The service's own log file, or `None` when the state tree is not there to write into.
///
/// The directory is only ever created *below* an existing state root, so it inherits that root's
/// protected `OICI` SYSTEM/Administrators DACL instead of a default one. A missing root means an
/// install that has not run yet; stdout-only is the correct answer then, not a directory created
/// with whatever ACL happened to apply.
#[cfg(windows)]
fn service_log_writer() -> Option<RotatingLogFile> {
    let root = clash_verge_service_ipc::service_paths()
        .persistent_state_dir()
        .to_path_buf();
    if !root.is_dir() {
        return None;
    }
    let directory = root.join("logs");
    std::fs::create_dir_all(&directory).ok()?;
    Some(RotatingLogFile::new(directory.join("tono-service.log")))
}

/// Bytes one log file may reach before it is rolled over. One rollover is kept.
#[cfg(windows)]
const SERVICE_LOG_MAX_BYTES: u64 = 4 * 1024 * 1024;

/// A minimal size-rotating file sink.
///
/// Deliberately dependency-free and deliberately infallible: a diagnostic must never be able to
/// fail — or panic — a privileged operation, so every I/O error here drops the line and re-opens
/// on the next one, a poisoned lock is recovered rather than unwrapped, and the lock is never
/// held across anything but a write.
#[cfg(windows)]
#[derive(Clone)]
struct RotatingLogFile(Arc<std::sync::Mutex<RotatingLogFileInner>>);

#[cfg(windows)]
struct RotatingLogFileInner {
    path: std::path::PathBuf,
    file: Option<std::fs::File>,
    written: u64,
}

#[cfg(windows)]
impl RotatingLogFile {
    fn new(path: std::path::PathBuf) -> Self {
        Self(Arc::new(std::sync::Mutex::new(RotatingLogFileInner {
            path,
            file: None,
            written: 0,
        })))
    }
}

#[cfg(windows)]
impl RotatingLogFileInner {
    fn write_record(&mut self, buf: &[u8]) {
        use std::io::Write as _;

        if self.file.is_none() {
            self.written = std::fs::metadata(&self.path)
                .map(|metadata| metadata.len())
                .unwrap_or_default();
            self.file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
                .ok();
        }
        let Some(file) = self.file.as_mut() else {
            return;
        };
        if file.write_all(buf).is_err() {
            self.file = None;
            return;
        }
        self.written = self.written.saturating_add(buf.len() as u64);
        if self.written >= SERVICE_LOG_MAX_BYTES {
            // Close before renaming: the replacement is opened lazily on the next record.
            self.file = None;
            let _ = std::fs::rename(&self.path, self.path.with_extension("log.1"));
            self.written = 0;
        }
    }
}

#[cfg(windows)]
impl std::io::Write for RotatingLogFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut inner = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.write_record(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(windows)]
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for RotatingLogFile {
    type Writer = RotatingLogFile;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Reconciliation has proved that no process from the previous service instance survived. Only
/// now may an unverified first-attempt barrier be retired. If that retirement is ambiguous, keep
/// the machine fail-closed and do not restore a desired Core behind an ownership mismatch.
async fn restore_reconciled_desired_state() {
    if let Err(error) = retire_unverified_windows_kill_switch().await {
        warn!(
            "Unverified Windows protection could not be safely retired after Core reconciliation; \
             keeping IPC available for recovery and skipping desired Core restore: {error:#}"
        );
        return;
    }

    match restore_desired_state().await {
        Ok(true) => {
            if let Err(error) = add_restored_kill_switch_tunnel().await {
                warn!(
                    "Restored core remains fail-closed because its tunnel could not be authorized: {error:#}"
                );
            }
            if let Err(error) = clash_verge_service_ipc::relock_restored_tunnel().await {
                warn!(
                    "Restored core remains fail-closed because its tunnel could not be re-locked: {error:#}"
                );
            }
        }
        Ok(false) => {}
        Err(error) => warn!(
            "Desired state restoration failed; keeping IPC available for GUI recovery: {error:#}"
        ),
    }
}

async fn run_standalone() -> Result<()> {
    let pid = std::process::id();
    info!("Tono Service - Standalone Mode");
    info!("Current process PID: {}", pid);

    let Some(_owner_guard) = acquire_service_owner().await? else {
        return Ok(());
    };

    // PF intent is restored before IPC exists, so no client can race a fail-open startup.
    restore_kill_switch().await?;
    spawn_kill_switch_watchdog();
    // WFP intent gets the same fail-closed-before-IPC treatment; a no-op off Windows.
    restore_windows_kill_switch().await?;
    initialize_protected_dns_status().await;
    spawn_protected_dns_watchdog();
    spawn_windows_kill_switch_watchdog();
    #[cfg(windows)]
    clash_verge_service_ipc::start_network_monitor();

    // 启动恢复只做 best-effort；即使失败也要启动 IPC，让 GUI 重连后重推配置自愈。
    // 否则失效的 desired-state 路径会导致进程退出并被 launchd 反复拉起。
    match reconcile_service_startup().await {
        Ok(()) => restore_reconciled_desired_state().await,
        Err(error) => warn!(
            "Service startup reconciliation failed; core starts remain blocked while IPC is available: {error:#}"
        ),
    }

    run_ipc_supervisor_until_shutdown(shutdown_signal()).await?;

    info!("Service shutdown complete.");
    Ok(())
}

/// Waits for a shutdown signal appropriate for the current platform.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigint = signal(SignalKind::interrupt()).expect("Failed to install SIGINT handler");
        let mut sigterm =
            signal(SignalKind::terminate()).expect("Failed to install SIGTERM handler");

        tokio::select! {
            _ = sigint.recv() => info!("Received SIGINT (Ctrl+C)"),
            _ = sigterm.recv() => info!("Received SIGTERM"),
        }
    }

    #[cfg(windows)]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
        info!("Received Ctrl+C");
    }
}
