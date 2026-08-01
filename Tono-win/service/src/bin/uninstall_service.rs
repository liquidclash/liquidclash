#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn main() {
    panic!("This program is not intended to run on this platform.");
}

mod shared;

use anyhow::Error;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use shared::run_command;
#[cfg(windows)]
use shared::stop_windows_service;
#[cfg(all(target_os = "macos", not(feature = "development-channel")))]
use shared::uninstall_old_service;
use shared::{enter_repair_gate, run_maintenance_if_requested};

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

    if run_maintenance_if_requested()? {
        return Ok(());
    }
    let _gate = enter_repair_gate()?;
    let manager_access = ServiceManagerAccess::CONNECT;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;

    let service_access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
    let service = match service_manager.open_service(
        clash_verge_service_ipc::WINDOWS_SERVICE_NAME,
        service_access,
    ) {
        Ok(service) => Some(service),
        Err(error) if has_raw_error(&error, ERROR_SERVICE_DOES_NOT_EXIST) => None,
        Err(error) => return Err(error.into()),
    };

    if let Some(service) = service.as_ref() {
        stop_windows_service(service)?;
    }

    // The helper links the same recovery library as the service binary, so cleanup does not
    // depend on an intact installed `tono-service.exe` and cannot pipe-wait on a child process.
    // The owner lock proves no standalone daemon/core still owns the WFP and DNS state.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let Some(_owner_guard) = clash_verge_service_ipc::acquire_service_owner().await? else {
            anyhow::bail!("service daemon is still running; refusing to open the kill switch");
        };
        clash_verge_service_ipc::emergency_disarm_windows_kill_switch().await
    })?;

    if let Some(service) = service {
        service.delete()?;
        drop(service);
        poll_until(
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
        )?;
    }
    let target =
        clash_verge_service_ipc::prepare_service_install_directory()?.join("tono-service.exe");
    if target.exists() {
        std::fs::remove_file(&target).map_err(|error| {
            anyhow::anyhow!("Failed to remove service binary {target:?}: {error}")
        })?;
    }
    println!("Service and protected network state were removed successfully.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::poll_until;
    use std::cell::Cell;

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
