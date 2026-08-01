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

/// Stop an SCM Service without treating normal StartPending/StopPending windows as failures.
/// Returns whether it was active when first observed so an installer can roll it back on error.
#[cfg(windows)]
pub(crate) fn stop_windows_service(
    service: &platform_lib::service::Service,
) -> Result<bool, Error> {
    use platform_lib::{Error as WindowsServiceError, service::ServiceState};
    use std::time::Duration;

    const ERROR_SERVICE_CANNOT_ACCEPT_CTRL: i32 = 1061;
    const ERROR_SERVICE_NOT_ACTIVE: i32 = 1062;
    const POLL_ATTEMPTS: usize = 200;
    const POLL_INTERVAL: Duration = Duration::from_millis(100);

    let initially_active = service.query_status()?.current_state != ServiceState::Stopped;
    for _ in 0..POLL_ATTEMPTS {
        let state = service.query_status()?.current_state;
        if state == ServiceState::Stopped {
            return Ok(initially_active);
        }

        if matches!(
            state,
            ServiceState::StartPending
                | ServiceState::StopPending
                | ServiceState::ContinuePending
                | ServiceState::PausePending
        ) {
            std::thread::sleep(POLL_INTERVAL);
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
        std::thread::sleep(POLL_INTERVAL);
    }

    anyhow::bail!("timed out waiting for service to stop")
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
