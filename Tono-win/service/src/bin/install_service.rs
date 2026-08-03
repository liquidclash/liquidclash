#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn main() {
    panic!("This program is not intended to run on this platform.");
}

mod shared;

use anyhow::Error;
use anyhow::{Context as _, bail};
use sha2::{Digest as _, Sha256};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use shared::run_command;
#[cfg(windows)]
use shared::stop_windows_service;
#[cfg(all(target_os = "macos", not(feature = "development-channel")))]
use shared::uninstall_old_service;
use shared::{enter_repair_gate, run_maintenance_if_requested};
use std::fs::{File, OpenOptions};
use std::io::Read as _;
#[cfg(unix)]
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn bundled_service_binary() -> Result<PathBuf, Error> {
    let source = std::env::current_exe()?.with_file_name(if cfg!(windows) {
        "tono-service.exe"
    } else {
        "tono-service"
    });
    let metadata = std::fs::symlink_metadata(&source)
        .with_context(|| format!("failed to inspect bundled service binary {source:?}"))?;
    if !metadata.file_type().is_file() {
        bail!("bundled service binary is not an ordinary file: {source:?}");
    }
    Ok(source)
}

fn sha256(path: &Path) -> Result<[u8; 32], Error> {
    let mut file = File::open(path).with_context(|| format!("failed to open {path:?}"))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("failed to read {path:?}"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

fn remove_ordinary_file_if_exists(path: &Path) -> Result<(), Error> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {path:?}"));
        }
    };
    if !metadata.file_type().is_file() {
        bail!("refusing to replace non-file service entry {path:?}");
    }
    std::fs::remove_file(path).with_context(|| format!("failed to remove {path:?}"))
}

fn stage_service_binary(source: &Path, target: &Path) -> Result<PathBuf, Error> {
    let parent = target
        .parent()
        .context("protected service target has no parent")?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create protected service directory {parent:?}"))?;
    let staged = target.with_extension(if cfg!(windows) { "exe.next" } else { "next" });
    remove_ordinary_file_if_exists(&staged)?;

    let mut source_file = File::open(source)
        .with_context(|| format!("failed to open service candidate {source:?}"))?;
    let mut staged_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged)
        .with_context(|| format!("failed to create staged service binary {staged:?}"))?;
    std::io::copy(&mut source_file, &mut staged_file)
        .with_context(|| format!("failed to stage service binary at {staged:?}"))?;
    staged_file
        .sync_all()
        .with_context(|| format!("failed to sync staged service binary {staged:?}"))?;
    drop(staged_file);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o550))
            .with_context(|| format!("failed to secure staged service binary {staged:?}"))?;
    }

    if sha256(source)? != sha256(&staged)? {
        let _ = std::fs::remove_file(&staged);
        bail!("staged service binary hash does not match its bundled source");
    }
    Ok(staged)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(windows), allow(dead_code))]
enum PublishOutcome {
    Published,
    RebootRequired,
}

fn publish_staged_binary(staged: &Path, target: &Path) -> Result<PublishOutcome, Error> {
    match std::fs::symlink_metadata(target) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            bail!("refusing to replace non-file service entry {target:?}");
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {target:?}"));
        }
    }

    #[cfg(unix)]
    {
        std::fs::rename(staged, target).with_context(|| {
            format!("failed to publish service binary {staged:?} at {target:?}")
        })?;
        Ok(PublishOutcome::Published)
    }

    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            MOVEFILE_DELAY_UNTIL_REBOOT, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
            MoveFileExW,
        };

        let wide = |path: &Path| {
            let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
            value.push(0);
            value
        };
        let staged_wide = wide(staged);
        let target_wide = wide(target);
        // A just-stopped service (or an AV scanner) may still hold the old binary: retry
        // through short backoffs, then schedule the replace for reboot rather than failing
        // the whole install.
        let backoffs = [
            std::time::Duration::from_millis(200),
            std::time::Duration::from_millis(500),
            std::time::Duration::from_millis(1000),
        ];
        let mut last_error = std::io::Error::last_os_error();
        for attempt in 0..=backoffs.len() {
            // SAFETY: both paths are NUL-terminated UTF-16 buffers alive for the call.
            let moved = unsafe {
                MoveFileExW(
                    staged_wide.as_ptr(),
                    target_wide.as_ptr(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                )
            };
            if moved != 0 {
                return Ok(PublishOutcome::Published);
            }
            last_error = std::io::Error::last_os_error();
            if let Some(backoff) = backoffs.get(attempt) {
                std::thread::sleep(*backoff);
            }
        }
        // SAFETY: as above; DELAY_UNTIL_REBOOT queues the replace with the session manager.
        let scheduled = unsafe {
            MoveFileExW(
                staged_wide.as_ptr(),
                target_wide.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_DELAY_UNTIL_REBOOT,
            )
        };
        if scheduled == 0 {
            return Err(last_error).with_context(|| {
                format!("failed to publish service binary {staged:?} at {target:?}")
            });
        }
        println!(
            "service binary is in use; the update to {target:?} was scheduled for the next reboot — restart the machine to finish installation"
        );
        Ok(PublishOutcome::RebootRequired)
    }
}

fn wait_for_service_ready() -> Result<(), Error> {
    const READY_TIMEOUT: Duration = Duration::from_secs(20);
    const READY_INTERVAL: Duration = Duration::from_millis(250);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to create service readiness runtime")?;
    runtime.block_on(async {
        clash_verge_service_ipc::set_config(Some(clash_verge_service_ipc::IpcConfig {
            default_timeout: Duration::from_millis(250),
            max_retries: 1,
            retry_delay: Duration::from_millis(25),
        }))
        .await;

        let deadline = Instant::now() + READY_TIMEOUT;
        let result = loop {
            if let Ok(response) = clash_verge_service_ipc::get_version().await
                && response.code == 0
                && response.data.is_some_and(|info| {
                    info.supports_client(
                        clash_verge_service_ipc::ProtocolVersion::current(),
                        clash_verge_service_ipc::MIN_REQUIRED_SERVICE_REVISION,
                    )
                })
            {
                break Ok(());
            }
            if Instant::now() >= deadline {
                break Err(anyhow::anyhow!(
                    "service IPC did not become protocol-ready within {READY_TIMEOUT:?}"
                ));
            }
            tokio::time::sleep(READY_INTERVAL).await;
        };

        clash_verge_service_ipc::set_config(None).await;
        result
    })
}

// Only launchd code calls this, and the tests below exercise the plan classifier rather than the
// target string — so widening the gate to `test` only made it dead code everywhere but macOS.
#[cfg(target_os = "macos")]
fn launchd_service_target() -> String {
    format!("system/{}", clash_verge_service_ipc::MACOS_SERVICE_ID)
}

#[cfg(any(target_os = "macos", test))]
#[derive(Debug, PartialEq, Eq)]
enum LaunchdInstallPlan {
    SkipBootout,
    Bootout,
}

#[cfg(any(target_os = "macos", test))]
fn classify_launchd_service_probe(
    exit_code: Option<i32>,
    diagnostic: &str,
) -> Result<LaunchdInstallPlan, Error> {
    match exit_code {
        Some(0) => Ok(LaunchdInstallPlan::Bootout),
        Some(113) => Ok(LaunchdInstallPlan::SkipBootout),
        _ => Err(anyhow::anyhow!(
            "Unexpected launchctl service probe result (exit code: {:?}): {}",
            exit_code,
            diagnostic
        )),
    }
}

#[cfg(target_os = "macos")]
fn probe_launchd_service(debug: bool) -> Result<LaunchdInstallPlan, Error> {
    if debug {
        println!("Executing: launchctl print {}", launchd_service_target());
    }

    let output = std::process::Command::new("launchctl")
        .args(["print", &launchd_service_target()])
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to probe launchd service: {}", e))?;
    let diagnostic = format!(
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    classify_launchd_service_probe(output.status.code(), &diagnostic)
}

#[cfg(unix)]
fn env_u32(key: &str) -> Option<u32> {
    std::env::var(key).ok()?.parse().ok()
}

#[cfg(unix)]
fn resolve_service_group_name() -> Result<String, Error> {
    use nix::unistd::{Gid, Group, Uid, User};

    if let Some(gid) = env_u32("CLASH_VERGE_SERVICE_GID")
        && let Ok(Some(group)) = Group::from_gid(Gid::from_raw(gid))
    {
        return Ok(group.name);
    }

    if let Some(uid) = env_u32("SUDO_UID").or_else(|| env_u32("PKEXEC_UID"))
        && let Ok(Some(user)) = User::from_uid(Uid::from_raw(uid))
        && let Ok(Some(group)) = Group::from_gid(user.gid)
    {
        return Ok(group.name);
    }

    if let Some(gid) = env_u32("SUDO_GID")
        && let Ok(Some(group)) = Group::from_gid(Gid::from_raw(gid))
    {
        return Ok(group.name);
    }

    bail!("unable to resolve the invoking user's service group; use sudo or pkexec")
}

#[cfg(target_os = "macos")]
fn installed_mihomo_gid(plist: &std::path::Path) -> Result<Option<u32>, Error> {
    let contents = match std::fs::read_to_string(plist) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let Some(after_key) = contents
        .split_once("<key>CLASH_VERGE_MIHOMO_GID</key>")
        .map(|(_, tail)| tail)
    else {
        return Ok(None);
    };
    let Some(after_open) = after_key.split_once("<string>").map(|(_, tail)| tail) else {
        return Ok(None);
    };
    let Some(raw) = after_open.split_once("</string>").map(|(value, _)| value) else {
        return Ok(None);
    };
    Ok(raw.trim().parse().ok())
}

#[cfg(target_os = "macos")]
fn select_mihomo_gid(plist: &std::path::Path) -> Result<u32, Error> {
    use nix::unistd::{Gid, Group};
    if let Some(raw) = installed_mihomo_gid(plist)?
        && (60_000..=64_999).contains(&raw)
        && Group::from_gid(Gid::from_raw(raw))?.is_none()
    {
        return Ok(raw);
    }
    for raw in 60_000..=64_999 {
        if Group::from_gid(Gid::from_raw(raw))?.is_none() {
            return Ok(raw);
        }
    }
    bail!("no unregistered dedicated Mihomo GID is available")
}

#[cfg(target_os = "macos")]
fn main() -> Result<(), Error> {
    if run_maintenance_if_requested()? {
        return Ok(());
    }
    let _gate = enter_repair_gate()?;
    let debug = std::env::args().any(|arg| arg == "--debug");
    let launchd_install_plan = probe_launchd_service(debug)?;
    let service_binary_path = bundled_service_binary()?;

    // 定义 bundle 路径
    let bundle_path = PathBuf::from("/Library/PrivilegedHelperTools").join(format!(
        "{}.bundle",
        clash_verge_service_ipc::MACOS_SERVICE_ID
    ));
    let contents_path = bundle_path.join("Contents");
    let macos_path = contents_path.join("MacOS");

    // 创建 bundle 目录结构
    std::fs::create_dir_all(&macos_path)
        .map_err(|e| anyhow::anyhow!("Failed to create bundle directories: {}", e))?;

    // 复制二进制文件到 bundle 的 MacOS 目录
    let target_binary_path = macos_path.join("tono-service");
    let staged = stage_service_binary(&service_binary_path, &target_binary_path)?;

    // 创建并写入 Info.plist
    let info_plist_path = contents_path.join("Info.plist");

    // 创建 LaunchDaemons 目录（如果不存在）
    let plist_dir = PathBuf::from("/Library/LaunchDaemons");
    if !plist_dir.exists() {
        std::fs::create_dir(&plist_dir)
            .map_err(|e| anyhow::anyhow!("Failed to create plist directory: {}", e))?;
    }

    // 创建并写入 launchd plist
    let plist_file = plist_dir.join(format!(
        "{}.plist",
        clash_verge_service_ipc::MACOS_SERVICE_ID
    ));

    let launchd_plist_content = format!(
        include_str!("../../resources/launchd.plist.tmpl"),
        group_name = resolve_service_group_name()?,
        mihomo_gid = select_mihomo_gid(&plist_file)?,
        service_id = clash_verge_service_ipc::MACOS_SERVICE_ID,
        app_bundle_id = clash_verge_service_ipc::MACOS_APP_BUNDLE_ID,
        service_binary = target_binary_path.to_string_lossy(),
    );
    let info_plist_content = format!(
        include_str!("../../resources/info.plist.tmpl"),
        display_name = clash_verge_service_ipc::SERVICE_DISPLAY_NAME,
        service_id = clash_verge_service_ipc::MACOS_SERVICE_ID,
    );
    let plist_path = plist_file.to_string_lossy().into_owned();
    let target_path = target_binary_path.to_string_lossy().into_owned();
    let bundle_path_string = bundle_path.to_string_lossy().into_owned();

    if launchd_install_plan == LaunchdInstallPlan::Bootout {
        run_command("launchctl", &["bootout", "system", &plist_path], debug)?;
    }
    let _ = publish_staged_binary(&staged, &target_binary_path)?;
    std::fs::write(&info_plist_path, info_plist_content)
        .with_context(|| format!("failed to write Info.plist {info_plist_path:?}"))?;
    File::create(&plist_file)
        .and_then(|mut file| file.write_all(launchd_plist_content.as_bytes()))
        .map_err(|e| anyhow::anyhow!("Failed to write plist file: {}", e))?;

    // 设置权限
    // 设置 LaunchDaemons plist 权限
    run_command("chmod", &["644", &plist_path], debug)?;
    run_command("chown", &["root:wheel", &plist_path], debug)?;

    // 设置二进制文件权限
    run_command("chmod", &["544", &target_path], debug)?;
    run_command("chown", &["root:wheel", &target_path], debug)?;

    // 设置 bundle 目录及其内容的权限
    run_command("chmod", &["755", &bundle_path_string], debug)?;
    run_command("chown", &["-R", "root:wheel", &bundle_path_string], debug)?;

    // 加载和启动服务
    let launchd_target = launchd_service_target();
    run_command("launchctl", &["enable", &launchd_target], debug)?;
    run_command("launchctl", &["bootstrap", "system", &plist_path], debug)?;
    run_command(
        "launchctl",
        &["start", clash_verge_service_ipc::MACOS_SERVICE_ID],
        debug,
    )?;
    wait_for_service_ready()?;
    #[cfg(not(feature = "development-channel"))]
    let _ = uninstall_old_service();

    Ok(())
}

#[cfg(target_os = "linux")]
fn main() -> Result<(), Error> {
    if run_maintenance_if_requested()? {
        return Ok(());
    }
    let _gate = enter_repair_gate()?;
    let debug = std::env::args().any(|arg| arg == "--debug");
    let source = bundled_service_binary()?;
    let install_dir = clash_verge_service_ipc::prepare_service_install_directory()?;
    let target = install_dir.join("tono-service");
    let staged = stage_service_binary(&source, &target)?;
    let unit_name = format!("{}.service", clash_verge_service_ipc::SERVICE_SLUG);
    let unit_path = PathBuf::from("/etc/systemd/system").join(&unit_name);

    let _ = run_command("systemctl", &["stop", &unit_name], debug);
    let _ = publish_staged_binary(&staged, &target)?;

    let unit_file_content = format!(
        include_str!("../../resources/systemd_service_unit.tmpl"),
        exec_start = target.to_string_lossy(),
        group = resolve_service_group_name()?,
        runtime_directory = clash_verge_service_ipc::SERVICE_SLUG,
    );

    let mut unit_file = File::create(&unit_path)
        .with_context(|| format!("failed to create systemd unit {unit_path:?}"))?;
    unit_file
        .write_all(unit_file_content.as_bytes())
        .with_context(|| format!("failed to write systemd unit {unit_path:?}"))?;
    unit_file
        .sync_all()
        .with_context(|| format!("failed to sync systemd unit {unit_path:?}"))?;

    run_command("systemctl", &["daemon-reload"], debug)?;
    run_command("systemctl", &["enable", &unit_name], debug)?;
    run_command("systemctl", &["start", &unit_name], debug)?;
    wait_for_service_ready()?;

    Ok(())
}

/// Best-effort rollback for an update that already stopped a previously active Service.
#[cfg(windows)]
struct RestartServiceOnFailure<'a> {
    service: &'a platform_lib::service::Service,
    armed: bool,
}

#[cfg(windows)]
impl<'a> RestartServiceOnFailure<'a> {
    fn new(service: &'a platform_lib::service::Service, armed: bool) -> Self {
        Self { service, armed }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(windows)]
impl Drop for RestartServiceOnFailure<'_> {
    fn drop(&mut self) {
        use platform_lib::service::ServiceState;

        if !self.armed
            || matches!(
                self.service
                    .query_status()
                    .map(|status| status.current_state),
                Ok(ServiceState::Running | ServiceState::StartPending)
            )
        {
            return;
        }

        eprintln!(
            "service update failed after stopping the existing service; attempting to restart it"
        );
        if let Err(error) = self.service.start(&Vec::<&std::ffi::OsStr>::new()) {
            eprintln!("failed to restart the existing service during rollback: {error}");
        }
    }
}

/// install and start the service
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use platform_lib::{
        Error as WindowsServiceError,
        service::{
            ServiceAccess, ServiceDependency, ServiceErrorControl, ServiceInfo, ServiceStartType,
            ServiceType,
        },
        service_manager::{ServiceManager, ServiceManagerAccess},
    };
    use std::ffi::{OsStr, OsString};

    if run_maintenance_if_requested()? {
        return Ok(());
    }
    let _gate = enter_repair_gate()?;
    let source = bundled_service_binary()?;
    let install_dir = clash_verge_service_ipc::prepare_service_install_directory()?;
    let target = install_dir.join("tono-service.exe");
    let staged = stage_service_binary(&source, &target)?;

    let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;
    let start_type = if cfg!(feature = "development-channel") {
        ServiceStartType::OnDemand
    } else {
        ServiceStartType::AutoStart
    };
    let service_info = ServiceInfo {
        name: OsString::from(clash_verge_service_ipc::WINDOWS_SERVICE_NAME),
        display_name: OsString::from(clash_verge_service_ipc::SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type,
        error_control: ServiceErrorControl::Normal,
        executable_path: target.clone(),
        launch_arguments: vec![],
        // Start after the Base Filtering Engine so the service never races the filtering
        // engine at boot (docs/wfp-kill-switch.md §1).
        dependencies: vec![ServiceDependency::Service(OsString::from("BFE"))],
        account_name: None,
        account_password: None,
    };

    const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
    const ERROR_SERVICE_MARKED_FOR_DELETE: i32 = 1072;
    const ERROR_SERVICE_EXISTS: i32 = 1073;

    fn raw_error_code(error: &WindowsServiceError) -> Option<i32> {
        match error {
            WindowsServiceError::Winapi(error) => error.raw_os_error(),
            _ => None,
        }
    }

    let service_access = ServiceAccess::QUERY_STATUS
        | ServiceAccess::START
        | ServiceAccess::STOP
        | ServiceAccess::CHANGE_CONFIG;
    match service_manager.open_service(
        clash_verge_service_ipc::WINDOWS_SERVICE_NAME,
        service_access,
    ) {
        Ok(service) => {
            let was_active = stop_windows_service(&service)?;

            // From this point onward every `?` must leave a previously active Service usable.
            // UAC succeeded, but publishing/configuring/starting the replacement can still fail;
            // without this rollback a repair attempt turns that failure into a permanent outage.
            let mut restart_on_failure = RestartServiceOnFailure::new(&service, was_active);
            // Reconfigure before the binary swap, which is the first irreversible step: a record
            // a previous uninstall only marked for deletion still opens and still stops, but
            // every write to it fails with 1072. Discovering that after `publish_staged_binary`
            // would abort the install on top of a half-swapped binary.
            match service.change_config(&service_info) {
                Ok(()) => {
                    let publish_outcome = publish_staged_binary(&staged, &target)?;
                    configure_windows_service_recovery(&service)?;
                    service.start(&Vec::<&OsStr>::new())?;
                    // The service is running on either path here — the old binary when the swap
                    // was deferred — so readiness stays provable, and a build that dies on start
                    // must not pass as a successful "reboot pending" install.
                    wait_for_service_ready()?;
                    restart_on_failure.disarm();
                    if publish_outcome == PublishOutcome::RebootRequired {
                        println!(
                            "Service restarted with the existing binary; reboot is required to publish the replacement."
                        );
                        std::process::exit(3010);
                    }
                    return Ok(());
                }
                Err(error) if raw_error_code(&error) == Some(ERROR_SERVICE_MARKED_FOR_DELETE) => {
                    // Nothing irreversible has run yet. SCM unregisters a deleted record only
                    // once the last handle to it closes, so release ours — and the rollback that
                    // borrows it, since a marked record cannot be restarted — before waiting.
                    restart_on_failure.disarm();
                    drop(restart_on_failure);
                    drop(service);
                    println!(
                        "The existing service record is marked for deletion; waiting for Windows to unregister it."
                    );
                    if !wait_for_service_record_removal(&service_manager) {
                        bail!(
                            "the existing {} record is still marked for deletion because another program holds it open (services.msc, an MMC snap-in, or a monitoring agent); close it or reboot Windows, then run this installer again — nothing was modified",
                            clash_verge_service_ipc::WINDOWS_SERVICE_NAME
                        );
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(error) if raw_error_code(&error) == Some(ERROR_SERVICE_DOES_NOT_EXIST) => {}
        Err(error) => return Err(error.into()),
    }

    let publish_outcome = publish_staged_binary(&staged, &target)?;
    let service = match service_manager.create_service(&service_info, service_access) {
        Ok(service) => service,
        // TOCTOU mirror of the probe above: the record was (re)registered between the two calls,
        // by a concurrent installer or by whatever recreated the deletion we just waited out.
        // Adopting it reaches the same end state instead of aborting after the binary swap.
        Err(error) if raw_error_code(&error) == Some(ERROR_SERVICE_EXISTS) => {
            let service = service_manager.open_service(
                clash_verge_service_ipc::WINDOWS_SERVICE_NAME,
                service_access,
            )?;
            stop_windows_service(&service)?;
            service.change_config(&service_info)?;
            service
        }
        Err(error) => return Err(error.into()),
    };

    service.set_description("Tono Service helps to launch the Tono core")?;
    configure_windows_service_recovery(&service)?;
    if publish_outcome == PublishOutcome::RebootRequired {
        // The binary only exists as a rename queued with the session manager, so there is
        // nothing to start and nothing to verify. Say that instead of implying a live service.
        println!(
            "Service was registered, but its binary is queued for the next reboot: it was not started and its readiness could not be verified. Restart the machine to finish installation."
        );
        std::process::exit(3010);
    }
    service.start(&Vec::<&OsStr>::new())?;
    wait_for_service_ready()?;

    Ok(())
}

/// Wait out an SCM record that a previous `DeleteService` only marked for deletion. The record
/// survives until the last handle to it closes, so a services.msc window, an MMC snap-in or a
/// monitoring agent can keep it — and the 1072 every write to it returns — alive long past the
/// uninstall that deleted it. Reports whether the record is gone.
#[cfg(windows)]
fn wait_for_service_record_removal(
    service_manager: &platform_lib::service_manager::ServiceManager,
) -> bool {
    use platform_lib::{Error as WindowsServiceError, service::ServiceAccess};

    const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
    const REMOVAL_ATTEMPTS: usize = 50;
    const REMOVAL_INTERVAL: Duration = Duration::from_millis(100);

    for _ in 0..REMOVAL_ATTEMPTS {
        match service_manager.open_service(
            clash_verge_service_ipc::WINDOWS_SERVICE_NAME,
            ServiceAccess::QUERY_STATUS,
        ) {
            Ok(service) => drop(service),
            Err(WindowsServiceError::Winapi(error))
                if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST) =>
            {
                return true;
            }
            // Any other failure says nothing about the record itself, so keep polling rather
            // than guessing; the caller reports the timeout as the actionable condition.
            Err(_) => {}
        }
        std::thread::sleep(REMOVAL_INTERVAL);
    }
    false
}

#[cfg(windows)]
fn configure_windows_service_recovery(
    service: &platform_lib::service::Service,
) -> platform_lib::Result<()> {
    use platform_lib::service::{
        ServiceAction, ServiceActionType, ServiceFailureActions, ServiceFailureResetPeriod,
    };
    use std::time::Duration;

    let actions = [5, 10, 30]
        .into_iter()
        .map(|delay_secs| ServiceAction {
            action_type: ServiceActionType::Restart,
            delay: Duration::from_secs(delay_secs),
        })
        .collect();

    service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 60 * 60)),
        reboot_msg: None,
        command: None,
        actions: Some(actions),
    })?;
    service.set_failure_actions_on_non_crash_failures(true)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_launchd_service_skips_bootout() {
        let plan = classify_launchd_service_probe(
            Some(113),
            "Could not find service \"io.github.clash-verge-rev.clash-verge-rev.service\" in domain for system",
        )
        .unwrap();

        assert_eq!(plan, LaunchdInstallPlan::SkipBootout);
    }

    #[test]
    fn loaded_launchd_service_runs_bootout() {
        let plan = classify_launchd_service_probe(Some(0), "").unwrap();

        assert_eq!(plan, LaunchdInstallPlan::Bootout);
    }

    #[test]
    fn unexpected_launchd_exit_is_an_error() {
        let result = classify_launchd_service_probe(Some(5), "Could not find service");

        assert!(result.is_err());
    }

    #[test]
    fn absent_exit_does_not_depend_on_launchd_wording() {
        let result = classify_launchd_service_probe(Some(113), "Operation not permitted");

        assert_eq!(result.unwrap(), LaunchdInstallPlan::SkipBootout);
    }
}
