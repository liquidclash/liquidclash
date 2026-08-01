//! Tono Service - Cross-platform IPC service daemon
//!
//! This service can run as a standalone process or as a Windows service.
//! It listens for shutdown signals (Ctrl+C, SIGTERM, or service stop) to gracefully terminate.

use anyhow::Result;
use clash_verge_service_ipc::{
    acquire_service_owner, add_restored_kill_switch_tunnel, reconcile_service_startup,
    restore_desired_state, restore_kill_switch, restore_windows_kill_switch,
    run_ipc_supervisor_until_shutdown, spawn_kill_switch_watchdog,
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
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    },
    std::ffi::OsString,
    std::time::Duration,
};

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
        // Mirrors the unix entry point: elevation plus the owner lock, so a running daemon's
        // lifecycle cannot race the disarm.
        // SAFETY: no inputs; reports whether the current token is elevated.
        if unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() } == 0 {
            anyhow::bail!("--emergency-disarm must be run from an elevated prompt");
        }
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            let Some(_owner_guard) = clash_verge_service_ipc::acquire_service_owner().await?
            else {
                anyhow::bail!("service daemon is still running; refusing to open the kill switch");
            };
            clash_verge_service_ipc::emergency_disarm_windows_kill_switch().await
        })?;
        println!("Kill switch disarmed; network opened");
        return Ok(());
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

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                let _ = shutdown_tx.blocking_send(());
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

    let status_handle = service_control_handler::register(
        clash_verge_service_ipc::WINDOWS_SERVICE_NAME,
        event_handler,
    )?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::POWER_EVENT,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let fatal = rt.block_on(async {
        let owner_guard = match acquire_service_owner().await {
            Ok(Some(owner_guard)) => owner_guard,
            Ok(None) => return false,
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
        spawn_windows_kill_switch_watchdog();
        clash_verge_service_ipc::start_network_monitor();

        match reconcile_service_startup().await {
            Ok(()) => {
                match restore_desired_state().await {
                    Ok(true) => {
                        if let Err(error) = add_restored_kill_switch_tunnel().await {
                            tracing::warn!("Restored core remains fail-closed because its tunnel could not be authorized: {error:#}");
                        }
                        if let Err(error) =
                            clash_verge_service_ipc::relock_restored_tunnel().await
                        {
                            tracing::warn!(
                                "Restored core remains fail-closed because its tunnel could not be re-locked: {error:#}"
                            );
                        }
                    }
                    Ok(false) => {}
                    Err(error) => tracing::warn!(
                        "Desired state restoration failed; keeping IPC available for GUI recovery: {}",
                        error
                    ),
                }
            }
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

    status_handle.set_service_status(ServiceStatus {
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

// --- Common Logic ---

/// Initializes the global logger.
fn init_logger() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_writer(std::io::stdout)
        .with_ansi(true)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
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
    spawn_windows_kill_switch_watchdog();
    #[cfg(windows)]
    clash_verge_service_ipc::start_network_monitor();

    // 启动恢复只做 best-effort；即使失败也要启动 IPC，让 GUI 重连后重推配置自愈。
    // 否则失效的 desired-state 路径会导致进程退出并被 launchd 反复拉起。
    match reconcile_service_startup().await {
        Ok(()) => match restore_desired_state().await {
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
                "Failed to restore desired core state on startup; core will not be auto-started. \
                     Keeping the IPC server up so the GUI can reconnect and recover: {error:#}"
            ),
        },
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
