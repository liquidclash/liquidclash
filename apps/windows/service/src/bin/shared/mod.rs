//! What the installer and the uninstaller both have to do.
//!
//! These two binaries are one job seen from either end: they take the same repair gate, run the
//! same maintenance flag, shell out the same way, and both have to clear the helper that shipped
//! before the service had a channel. Neither can import the other, and none of this belongs in the
//! library — it is how a privileged command-line tool behaves, not part of the IPC contract — so
//! it lives here and both declare it.

use anyhow::Error;

pub(crate) fn enter_repair_gate() -> Result<clash_verge_service_ipc::ServiceRepairGate, Error> {
    match clash_verge_service_ipc::acquire_service_repair_gate()? {
        Some(gate) => Ok(gate),
        None => {
            eprintln!("Service repair is already in progress");
            std::process::exit(clash_verge_service_ipc::REPAIR_IN_PROGRESS_EXIT_CODE);
        }
    }
}

pub(crate) fn run_maintenance_if_requested() -> Result<bool, Error> {
    if !std::env::args().any(|argument| argument == "--cleanup-stale-owners") {
        return Ok(false);
    }
    let removed = clash_verge_service_ipc::cleanup_stale_owner_state()?;
    println!("Removed {} stale owner state directories", removed.len());
    Ok(true)
}

#[cfg(windows)]
const STOP_POLL_ATTEMPTS: usize = 200;
#[cfg(windows)]
const STOP_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

/// Stop an SCM Service without treating normal StartPending/StopPending windows as failures,
/// escalating to process termination when the daemon never honours the stop. A wedged daemon
/// otherwise dead-ends both the installer (it cannot replace the service) and the uninstaller
/// (it cannot disarm) with a retry that can never succeed. Killing the process is safe on
/// either path: the WFP kill switch is persistent state that survives its process, so the
/// machine stays fail-closed until a fresh service reconciles it or a verified disarm runs.
/// Returns whether it was active when first observed so an installer can roll it back on error.
#[cfg(windows)]
pub(crate) fn stop_windows_service(
    service: &platform_lib::service::Service,
) -> Result<bool, Error> {
    use platform_lib::service::ServiceState;

    let initially_active = service.query_status()?.current_state != ServiceState::Stopped;
    if let Err(graceful_error) = stop_windows_service_gracefully(service) {
        println!(
            "Graceful SCM stop failed ({graceful_error:#}); force-terminating the service process."
        );
        force_stop_windows_service(service)?;
    }
    Ok(initially_active)
}

#[cfg(windows)]
fn stop_windows_service_gracefully(service: &platform_lib::service::Service) -> Result<(), Error> {
    use platform_lib::{Error as WindowsServiceError, service::ServiceState};

    const ERROR_SERVICE_CANNOT_ACCEPT_CTRL: i32 = 1061;
    const ERROR_SERVICE_NOT_ACTIVE: i32 = 1062;

    for _ in 0..STOP_POLL_ATTEMPTS {
        let state = service.query_status()?.current_state;
        if state == ServiceState::Stopped {
            return Ok(());
        }

        if matches!(
            state,
            ServiceState::StartPending
                | ServiceState::StopPending
                | ServiceState::ContinuePending
                | ServiceState::PausePending
        ) {
            std::thread::sleep(STOP_POLL_INTERVAL);
            continue;
        }

        if let Err(error) = service.stop()
            && !matches!(
                &error,
                WindowsServiceError::Winapi(error)
                    if matches!(
                        error.raw_os_error(),
                        Some(ERROR_SERVICE_CANNOT_ACCEPT_CTRL | ERROR_SERVICE_NOT_ACTIVE)
                    )
            )
        {
            return Err(error.into());
        }
        std::thread::sleep(STOP_POLL_INTERVAL);
    }

    anyhow::bail!("timed out waiting for service to stop")
}

/// The escalation path for a daemon that ignored the SCM stop. Suppress the configured
/// crash-restart actions first (best effort — without it the SCM relaunches the daemon five
/// seconds after the kill and races whatever the caller does next; the installer reinstates
/// the actions via `configure_windows_service_recovery`, the uninstaller deletes the service),
/// then terminate the process and wait until the SCM reports Stopped. The pid comes from
/// `QueryServiceStatusEx` (`SERVICE_STATUS_PROCESS.dwProcessId`); the pid file the daemon
/// writes beside its owner lock is the fallback when the SCM no longer reports one.
#[cfg(windows)]
fn force_stop_windows_service(service: &platform_lib::service::Service) -> Result<(), Error> {
    use platform_lib::service::{
        ServiceAction, ServiceActionType, ServiceFailureActions, ServiceFailureResetPeriod,
        ServiceState,
    };

    let no_restart = ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::Never,
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction {
                action_type: ServiceActionType::None,
                delay: std::time::Duration::ZERO,
            };
            3
        ]),
    };
    if let Err(error) = service.update_failure_actions(no_restart) {
        // Not fatal: a restarted daemon loses the disarm race on the owner lock and the caller
        // reports a hard, retryable error instead of proceeding — still fail-closed.
        println!("Could not suppress SCM crash-restart before termination: {error}");
    }

    let pid = service
        .query_status()
        .ok()
        .and_then(|status| status.process_id)
        .filter(|pid| *pid != 0)
        .or_else(read_service_pid_file);
    match pid {
        Some(pid) => {
            terminate_process_by_pid(pid)?;
            println!("Terminated wedged service process {pid}.");
        }
        // No pid anywhere: the process may already be gone with only the SCM state stale.
        // Fall through to the wait; failing there reports the truth.
        None => println!("Wedged service process id is unknown; waiting for the SCM state."),
    }

    for _ in 0..STOP_POLL_ATTEMPTS {
        if service.query_status()?.current_state == ServiceState::Stopped {
            return Ok(());
        }
        std::thread::sleep(STOP_POLL_INTERVAL);
    }
    anyhow::bail!("service did not reach Stopped even after its process was terminated")
}

/// The daemon records its pid beside the owner lock (`owner.rs`). The file outlives a wedged
/// or killed process, making it the pid source of last resort for escalations.
#[cfg(windows)]
pub(crate) fn read_service_pid_file() -> Option<u32> {
    std::fs::read_to_string(clash_verge_service_ipc::service_paths().pid_file_path())
        .ok()
        .and_then(|content| content.trim().parse().ok())
}

/// Native, locale-independent process termination with a hard wait bound. The service library
/// keeps its own copy private (`core/process.rs`); this bin-side duplicate is deliberate —
/// these binaries must stay buildable from the public crate surface alone.
#[cfg(windows)]
pub(crate) fn terminate_process_by_pid(pid: u32) -> Result<(), Error> {
    use anyhow::Context as _;
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
    use windows_sys::Win32::Foundation::{
        ERROR_INVALID_PARAMETER, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_TERMINATE, TerminateProcess, WaitForSingleObject,
    };

    if pid == 0 {
        return Ok(());
    }
    let raw = unsafe {
        OpenProcess(
            PROCESS_TERMINATE | windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE,
            0,
            pid,
        )
    };
    if raw.is_null() {
        let error = std::io::Error::last_os_error();
        // An invalid pid means the process is already gone, which is the goal.
        if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
            return Ok(());
        }
        return Err(error).with_context(|| format!("failed to open process {pid} for termination"));
    }
    // SAFETY: `OpenProcess` returned an owned process handle.
    let handle = unsafe { OwnedHandle::from_raw_handle(raw.cast()) };
    let raw = handle.as_raw_handle() as HANDLE;

    if unsafe { TerminateProcess(raw, 1) } == 0 {
        // The process may have exited between OpenProcess and TerminateProcess.
        if unsafe { WaitForSingleObject(raw, 0) } != WAIT_OBJECT_0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("failed to terminate process {pid}"));
        }
    }
    match unsafe { WaitForSingleObject(raw, 5_000) } {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => anyhow::bail!("process {pid} did not exit within 5 seconds of termination"),
        _ => Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed while waiting for terminated process {pid}")),
    }
}

#[cfg(all(target_os = "macos", not(feature = "development-channel")))]
pub fn uninstall_old_service() -> Result<(), Error> {
    use std::path::Path;

    let target_binary_path = "/Library/PrivilegedHelperTools/io.github.clashverge.helper";
    let plist_file = "/Library/LaunchDaemons/io.github.clashverge.helper.plist";

    // Stop and unload service
    run_command("launchctl", &["stop", "io.github.clashverge.helper"], false)?;
    run_command("launchctl", &["bootout", "system", plist_file], false)?;
    run_command(
        "launchctl",
        &["disable", "system/io.github.clashverge.helper"],
        false,
    )?;

    // Remove files
    if Path::new(plist_file).exists() {
        std::fs::remove_file(plist_file)
            .map_err(|e| anyhow::anyhow!("Failed to remove plist file: {}", e))?;
    }

    if Path::new(target_binary_path).exists() {
        std::fs::remove_file(target_binary_path)
            .map_err(|e| anyhow::anyhow!("Failed to remove service binary: {}", e))?;
    }

    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn run_command(cmd: &str, args: &[&str], debug: bool) -> Result<(), Error> {
    if debug {
        println!("Executing: {} {}", cmd, args.join(" "));
    }

    let output = std::process::Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to execute '{}': {}", cmd, e))?;

    if output.status.success() {
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if debug {
        eprintln!(
            "Command failed (status: {}):\nstdout: {}\nstderr: {}",
            output.status, stdout, stderr
        );
    }

    Err(anyhow::anyhow!(
        "Command '{}' failed (status: {}):\nstdout: {}\nstderr: {}",
        cmd,
        output.status,
        stdout,
        stderr
    ))
}
