#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn main() {
    panic!("This program is not intended to run on this platform.");
}

mod shared;

use anyhow::Error;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use shared::run_command;
#[cfg(windows)]
use shared::{read_service_pid_file, stop_windows_service, terminate_process_by_pid};
#[cfg(all(target_os = "macos", not(feature = "development-channel")))]
use shared::uninstall_old_service;
use shared::{enter_repair_gate, run_maintenance_if_requested};

/// How Windows cleanup ended. `main` maps this onto the exit-code contract with the NSIS
/// uninstall macro, which must only block when the machine cannot be proven safe; the mapping
/// is a pure, tested function rather than an implicit process exit.
#[cfg(any(windows, test))]
#[derive(Debug)]
enum CleanupOutcome {
    /// Nothing is armed and nothing of the service remains (or nothing existed to begin with).
    Clean,
    /// The disarm was proven, but a cosmetic step (SCM record or binary removal) failed.
    /// Removing further files is safe; the leftovers neither protect nor block anything.
    CosmeticFailure(Error),
    /// Cleanup could not prove the network was restored. The kill switch stays armed and every
    /// recovery file was preserved; only this outcome may block an uninstall.
    StillProtected(Error),
}

/// Exit-code contract with `installer.nsi` (`RemoveVergeService`): 0 continues, 2 continues
/// with a warning, 3 — like every other non-zero result, including nsExec's "error"/"timeout"
/// strings — blocks the uninstall because the machine is still protected.
#[cfg(any(windows, test))]
const EXIT_COSMETIC_FAILURE: i32 = 2;
#[cfg(any(windows, test))]
const EXIT_STILL_PROTECTED: i32 = 3;

#[cfg(any(windows, test))]
fn cleanup_exit_code(outcome: &CleanupOutcome) -> i32 {
    match outcome {
        CleanupOutcome::Clean => 0,
        CleanupOutcome::CosmeticFailure(_) => EXIT_COSMETIC_FAILURE,
        CleanupOutcome::StillProtected(_) => EXIT_STILL_PROTECTED,
    }
}

#[cfg(any(windows, test))]
fn poll_until<T>(
    max_attempts: usize,
    mut probe: impl FnMut() -> Result<Option<T>, Error>,
    mut pause: impl FnMut(),
    timeout_message: &str,
) -> Result<T, Error> {
    for attempt in 0..max_attempts {
        if let Some(value) = probe()? {
            return Ok(value);
        }
        if attempt + 1 < max_attempts {
            pause();
        }
    }
    Err(anyhow::anyhow!("{timeout_message}"))
}

#[cfg(target_os = "macos")]
fn launchd_service_is_loaded(service_id: &str) -> Result<bool, Error> {
    let target = format!("system/{service_id}");
    let output = std::process::Command::new("launchctl")
        .args(["print", &target])
        .output()?;
    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    match output.status.code() {
        Some(0) => Ok(true),
        Some(113) => Ok(false),
        code => Err(anyhow::anyhow!(
            "unexpected launchctl state for {target} (exit {code:?}): {diagnostic}"
        )),
    }
}

#[cfg(target_os = "macos")]
fn main() -> Result<(), Error> {
    use std::env;
    use std::path::Path;

    if run_maintenance_if_requested()? {
        return Ok(());
    }
    let _gate = enter_repair_gate()?;
    let debug = env::args().any(|arg| arg == "--debug");

    #[cfg(not(feature = "development-channel"))]
    let _ = uninstall_old_service();
    // 定义路径
    let bundle_path = format!(
        "/Library/PrivilegedHelperTools/{}.bundle",
        clash_verge_service_ipc::MACOS_SERVICE_ID
    );
    let plist_file = format!(
        "/Library/LaunchDaemons/{}.plist",
        clash_verge_service_ipc::MACOS_SERVICE_ID
    );
    let service_id = clash_verge_service_ipc::MACOS_SERVICE_ID;

    // A separate recovery process must never open PF while KeepAlive can still relaunch the
    // service/core. Require a verified bootout; only a positively absent service is skippable.
    if launchd_service_is_loaded(service_id)? {
        run_command(
            "launchctl",
            &["disable", &format!("system/{}", service_id)],
            debug,
        )?;
        run_command("launchctl", &["bootout", "system", &plist_file], debug)?;
    }
    if launchd_service_is_loaded(service_id)? {
        anyhow::bail!("launchd service is still loaded; refusing to open the kill switch");
    }

    // The owned core is now stopped. Disarm before deleting the binary/state needed to recover.
    let service_binary = format!("{bundle_path}/Contents/MacOS/tono-service");
    run_command(&service_binary, &["--emergency-disarm"], debug).map_err(|error| {
        anyhow::anyhow!(
            "service stopped but emergency disarm failed; network remains blocked: {error:#}"
        )
    })?;

    // 删除文件
    if Path::new(&plist_file).exists() {
        std::fs::remove_file(&plist_file)
            .map_err(|e| anyhow::anyhow!("Failed to remove plist file: {}", e))?;
    }

    // 删除整个 bundle 目录
    if Path::new(&bundle_path).exists() {
        std::fs::remove_dir_all(&bundle_path)
            .map_err(|e| anyhow::anyhow!("Failed to remove bundle directory: {}", e))?;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn main() -> Result<(), Error> {
    use std::env;

    if run_maintenance_if_requested()? {
        return Ok(());
    }
    let _gate = enter_repair_gate()?;
    let debug = env::args().any(|arg| arg == "--debug");
    let service_name = clash_verge_service_ipc::SERVICE_SLUG;

    // Stop and disable service
    let _ = run_command(
        "systemctl",
        &["stop", &format!("{}.service", service_name)],
        debug,
    );
    let _ = run_command(
        "systemctl",
        &["disable", &format!("{}.service", service_name)],
        debug,
    );

    // Remove service file
    let unit_file = format!("/etc/systemd/system/{}.service", service_name);
    if std::path::Path::new(&unit_file).exists() {
        std::fs::remove_file(&unit_file)
            .map_err(|e| anyhow::anyhow!("Failed to remove service file: {}", e))?;
    }

    // Reload systemd
    let _ = run_command("systemctl", &["daemon-reload"], debug);
    let target = clash_verge_service_ipc::prepare_service_install_directory()?.join("tono-service");
    if target.exists() {
        std::fs::remove_file(&target).map_err(|error| {
            anyhow::anyhow!("Failed to remove service binary {target:?}: {error}")
        })?;
    }

    Ok(())
}

/// stop and uninstall the service
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    if run_maintenance_if_requested()? {
        return Ok(());
    }
    let _gate = enter_repair_gate()?;

    // The repair gate is an OS file lock, so `std::process::exit` releasing it via handle
    // close (not Drop) is safe here.
    let outcome = windows_cleanup();
    let code = cleanup_exit_code(&outcome);
    match outcome {
        CleanupOutcome::Clean => {
            println!("Service and protected network state were removed successfully.");
            Ok(())
        }
        CleanupOutcome::CosmeticFailure(error) => {
            eprintln!(
                "Protected network state was restored, but service debris remains and will be \
                 cleaned up by a future install: {error:#}"
            );
            std::process::exit(code);
        }
        CleanupOutcome::StillProtected(error) => {
            eprintln!(
                "Cleanup could not prove the network was restored; the kill switch stays armed \
                 and all recovery files were preserved: {error:#}"
            );
            std::process::exit(code);
        }
    }
}

#[cfg(windows)]
fn windows_cleanup() -> CleanupOutcome {
    use anyhow::Context as _;
    use platform_lib::{
        Error as WindowsServiceError,
        service::ServiceAccess,
        service_manager::{ServiceManager, ServiceManagerAccess},
    };
    use std::{thread, time::Duration};

    const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
    const POLL_ATTEMPTS: usize = 200;
    const POLL_INTERVAL: Duration = Duration::from_millis(100);

    fn has_raw_error(error: &WindowsServiceError, code: i32) -> bool {
        matches!(error, WindowsServiceError::Winapi(error) if error.raw_os_error() == Some(code))
    }

    // Everything up to the proven disarm is fail-closed: any error keeps the kill switch armed.
    let manager_access = ServiceManagerAccess::CONNECT;
    let service_manager = match ServiceManager::local_computer(None::<&str>, manager_access) {
        Ok(manager) => manager,
        Err(error) => return CleanupOutcome::StillProtected(error.into()),
    };

    // CHANGE_CONFIG lets the stop escalation suppress the SCM crash-restart actions before
    // terminating a wedged daemon (see `force_stop_windows_service`).
    let service_access = ServiceAccess::QUERY_STATUS
        | ServiceAccess::STOP
        | ServiceAccess::DELETE
        | ServiceAccess::CHANGE_CONFIG;
    let service = match service_manager.open_service(
        clash_verge_service_ipc::WINDOWS_SERVICE_NAME,
        service_access,
    ) {
        Ok(service) => Some(service),
        Err(error) if has_raw_error(&error, ERROR_SERVICE_DOES_NOT_EXIST) => None,
        Err(error) => return CleanupOutcome::StillProtected(error.into()),
    };

    // No service, no kill-switch intent, no DNS snapshot, no live daemon: the machine is
    // already clean. Report success instead of failing a repeated uninstall over disarm
    // plumbing that has nothing left to operate on.
    if service.is_none() && !windows_recovery_state_present() {
        println!("No service, kill-switch intent, or DNS snapshot present; nothing to clean up.");
        return match remove_windows_service_binary() {
            Ok(()) => CleanupOutcome::Clean,
            Err(error) => CleanupOutcome::CosmeticFailure(error),
        };
    }

    if let Some(service) = service.as_ref()
        && let Err(error) = stop_windows_service(service)
    {
        return CleanupOutcome::StillProtected(error);
    }

    // The helper links the same recovery library as the service binary, so cleanup does not
    // depend on an intact installed `tono-service.exe` and cannot pipe-wait on a child process.
    // The owner lock proves no standalone daemon/core still owns the WFP and DNS state.
    let disarm = (|| -> Result<(), Error> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let owner_guard = match clash_verge_service_ipc::acquire_service_owner().await? {
                Some(guard) => Some(guard),
                // A daemon that still answers on the pipe even though the SCM record is gone or
                // stopped (a standalone or orphaned build) would race the disarm. Terminate it
                // by the pid it recorded, then take the lock over.
                None => {
                    let pid = read_service_pid_file().context(
                        "a running daemon holds the owner lock but left no pid file; \
                         refusing to open the kill switch",
                    )?;
                    println!(
                        "Owner lock is held by live daemon {pid}; terminating it before disarm."
                    );
                    terminate_process_by_pid(pid)?;
                    clash_verge_service_ipc::acquire_service_owner().await?
                }
            };
            let Some(_owner_guard) = owner_guard else {
                anyhow::bail!("service daemon is still running; refusing to open the kill switch");
            };
            clash_verge_service_ipc::emergency_disarm_windows_kill_switch().await
        })
    })();
    if let Err(error) = disarm {
        return CleanupOutcome::StillProtected(error);
    }
    println!("Kill switch was disarmed and protected DNS restore was verified.");

    // Only cosmetic state remains. A failure below must not block the uninstall: the network
    // is provably restored, and nothing left behind protects or blocks anything.
    if let Some(service) = service {
        if let Err(error) = service.delete() {
            return CleanupOutcome::CosmeticFailure(error.into());
        }
        drop(service);
        if let Err(error) = poll_until(
            POLL_ATTEMPTS,
            || match service_manager.open_service(
                clash_verge_service_ipc::WINDOWS_SERVICE_NAME,
                ServiceAccess::QUERY_STATUS,
            ) {
                Ok(service) => {
                    drop(service);
                    Ok(None)
                }
                Err(error) if has_raw_error(&error, ERROR_SERVICE_DOES_NOT_EXIST) => Ok(Some(())),
                Err(error) => Err(error.into()),
            },
            || thread::sleep(POLL_INTERVAL),
            "timed out waiting for service deletion",
        ) {
            return CleanupOutcome::CosmeticFailure(error);
        }
    }
    match remove_windows_service_binary() {
        Ok(()) => CleanupOutcome::Clean,
        Err(error) => CleanupOutcome::CosmeticFailure(error),
    }
}

/// Whether any fail-closed recovery state may still exist. File names must match the library
/// (`windows_kill_switch::intent_path`, `dns::snapshot_path`, `owner.rs`): the intent record
/// and the DNS snapshot are the artifacts service-start recovery acts on, and a pid file means
/// a daemon may be alive that could still be arming them.
#[cfg(windows)]
fn windows_recovery_state_present() -> bool {
    // `Path::exists()` collapses ACCESS_DENIED and SHARING_VIOLATION into `false`, which would
    // turn an unreadable artifact into a fail-open "nothing to clean up" on the one signal that
    // guards the irreversible half of the uninstall. Anything but a proven absence means present.
    fn may_exist(path: &std::path::Path) -> bool {
        path.try_exists().unwrap_or(true)
    }

    let paths = clash_verge_service_ipc::service_paths();
    let state = paths.persistent_state_dir();
    may_exist(&state.join("kill-switch.json"))
        || may_exist(&state.join("protected-dns.json"))
        || may_exist(&paths.pid_file_path())
}

/// Best-effort binary removal; runs only after the disarm was proven (or nothing was armed),
/// so a failure is cosmetic. Uses the plain paths accessor: an uninstall must not recreate or
/// re-ACL the install directory just to look inside it.
#[cfg(windows)]
fn remove_windows_service_binary() -> Result<(), Error> {
    let target = clash_verge_service_ipc::service_paths()
        .install_dir()
        .join("tono-service.exe");
    if target.exists() {
        std::fs::remove_file(&target).map_err(|error| {
            anyhow::anyhow!("Failed to remove service binary {target:?}: {error}")
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        CleanupOutcome, EXIT_COSMETIC_FAILURE, EXIT_STILL_PROTECTED, cleanup_exit_code, poll_until,
    };
    use std::cell::Cell;

    #[test]
    fn clean_outcome_exits_zero() {
        assert_eq!(cleanup_exit_code(&CleanupOutcome::Clean), 0);
    }

    #[test]
    fn cosmetic_failure_is_distinct_and_never_reads_as_blocking() {
        let code =
            cleanup_exit_code(&CleanupOutcome::CosmeticFailure(anyhow::anyhow!("leftover")));
        assert_eq!(code, EXIT_COSMETIC_FAILURE);
        assert_ne!(code, 0);
        assert_ne!(code, EXIT_STILL_PROTECTED);
        // A generic `fn main` anyhow failure exits 1; the continue-anyway code must never
        // collide with it, or an unproven cleanup could pass as cosmetic.
        assert_ne!(code, 1);
    }

    #[test]
    fn still_protected_maps_to_the_blocking_exit_code() {
        let code = cleanup_exit_code(&CleanupOutcome::StillProtected(anyhow::anyhow!("armed")));
        assert_eq!(code, EXIT_STILL_PROTECTED);
        assert_ne!(code, 0);
        assert_ne!(code, 1);
    }

    #[test]
    fn poll_until_retries_transient_state_before_success() -> anyhow::Result<()> {
        let attempts = Cell::new(0);
        let pauses = Cell::new(0);

        let result = poll_until(
            3,
            || {
                let next = attempts.get() + 1;
                attempts.set(next);
                Ok((next == 3).then_some("deleted"))
            },
            || pauses.set(pauses.get() + 1),
            "service deletion timed out",
        )?;

        assert_eq!(result, "deleted");
        assert_eq!(attempts.get(), 3);
        assert_eq!(pauses.get(), 2);
        Ok(())
    }
}
