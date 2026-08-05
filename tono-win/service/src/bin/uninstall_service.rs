#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn main() {
    panic!("This program is not intended to run on this platform.");
}

mod shared;

use anyhow::Error;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use shared::run_command;
#[cfg(all(target_os = "macos", not(feature = "development-channel")))]
use shared::uninstall_old_service;
use shared::{enter_repair_gate, run_maintenance_if_requested};
#[cfg(windows)]
use shared::{read_service_pid_file, stop_windows_service, terminate_process_by_pid};

/// How Windows cleanup ended. `main` maps this onto the exit-code contract with the NSIS
/// uninstall macro, which must only block when the machine cannot be proven safe; the mapping
/// is a pure, tested function rather than an implicit process exit.
///
/// **What "safe" means here, and what it used to mean.** This helper used to refuse the whole
/// uninstall unless the network was *provably* restored to the user's exact prior DNS
/// configuration. On a machine whose live CIM/netsh apply keeps failing that proof is never
/// obtainable, so the refusal fired every time and produced an **application that cannot be
/// uninstalled** — the failure this ladder exists to correct. The danger being guarded against
/// is real, but it is narrower than the guard was: what must never happen is *removing the app
/// while leaving persistent WFP filters armed*, i.e. a blocked machine with no software left to
/// unblock it. That is now the whole of the blocking condition. An inexact resolver is not a
/// blocked machine: the user can change DNS from Windows' own network settings, and cannot
/// conjure back an uninstaller that refuses to run.
#[cfg(any(windows, test))]
#[derive(Debug)]
enum CleanupOutcome {
    /// Nothing is armed and nothing of the service remains (or nothing existed to begin with).
    Clean,
    /// The disarm was proven, but a cosmetic step (SCM record or binary removal) failed.
    /// Removing further files is safe; the leftovers neither protect nor block anything.
    CosmeticFailure(Error),
    /// Rung 2 of the DNS ladder: the WFP filters are gone and the affected adapters were reset
    /// to automatic (DHCP) DNS because the saved servers could not be proven restored. The
    /// machine is neither blocked nor redirected, so the uninstall **continues**; the deviation
    /// is reported so the installer can log it.
    RestoredToAutomatic(Error),
    /// Cleanup could not prove the machine is unblocked. The recovery files were preserved;
    /// only this outcome may block an uninstall.
    StillProtected(Error),
}

/// Exit-code contract with `installer.nsi` (`RemoveVergeService`):
///   0 — clean; continue.
///   2 — network restored, cosmetic debris remains; continue with a log line.
///   4 — WFP removed, DNS reset to automatic (DHCP) instead of the exact saved servers;
///       continue with a log line.
///   3 — and every other non-zero result, including nsExec's "error"/"timeout" strings and a
///       plain `anyhow` exit 1: blocks, because nothing showed the machine was made safe.
/// Unknown results must keep blocking; that discipline is the reason the codes are explicit and
/// the mapping is tested.
#[cfg(any(windows, test))]
const EXIT_COSMETIC_FAILURE: i32 = 2;
#[cfg(any(windows, test))]
const EXIT_STILL_PROTECTED: i32 = 3;
#[cfg(any(windows, test))]
const EXIT_RESTORED_AUTOMATIC: i32 = 4;

/// Markers the library puts in a disarm error **only after** WFP objects are deleted. Duplicated
/// as literals on purpose — the constants are `pub(crate)` in the library, and this is the same
/// cross-boundary marker convention the App already uses for `TONO_WFP_ENGINE_WEDGED`
/// (`app/src-tauri/src/tono/connection.rs`). Matched by substring, because every layer wraps the
/// message in its own context.
///
/// Any of these lets the uninstall/install continue (exit 4 family). The only blocking condition
/// is "the WFP barrier may still be installed".
#[cfg(any(windows, test))]
const DNS_RESTORED_AUTOMATIC_MARKER: &str = "TONO_DNS_RESTORED_AUTOMATIC";
#[cfg(any(windows, test))]
const DNS_STILL_ON_LOOPBACK_MARKER: &str = "TONO_DNS_STILL_ON_LOOPBACK";
#[cfg(any(windows, test))]
const WFP_REMOVED_CONTINUE_MARKER: &str = "TONO_WFP_REMOVED";

/// Customer logs show this exact status when Tono never installed a WFP provider. That is a
/// **clean** machine, not an armed kill switch. Matched by substring so every layer's wrapping
/// still classifies correctly.
#[cfg(any(windows, test))]
fn error_means_no_tono_wfp_provider(error: &Error) -> bool {
    let message = format!("{error:#}");
    message.contains("0x80320005")
        || message.contains("0x8032_0005")
        || message.contains("PROVIDER_NOT_FOUND")
        || message.contains("provider does not exist")
}

/// Environment variable that opts this process into the uninstall-only DNS escalation ladder.
/// Must match `windows_kill_switch::UNINSTALL_LADDER_ENV`. Set in this process image only, so
/// the Service and the App never inherit it.
#[cfg(any(windows, test))]
const UNINSTALL_LADDER_ENV: &str = "TONO_UNINSTALL_DNS_LADDER";

#[cfg(any(windows, test))]
fn cleanup_exit_code(outcome: &CleanupOutcome) -> i32 {
    match outcome {
        CleanupOutcome::Clean => 0,
        CleanupOutcome::CosmeticFailure(_) => EXIT_COSMETIC_FAILURE,
        CleanupOutcome::RestoredToAutomatic(_) => EXIT_RESTORED_AUTOMATIC,
        CleanupOutcome::StillProtected(_) => EXIT_STILL_PROTECTED,
    }
}

/// Whether an exit code lets the NSIS macro proceed with deleting the application.
///
/// The invariant, stated once and asserted in the tests: an uninstall may only continue on an
/// outcome whose *precondition is that the WFP filters are gone*. `Clean` and
/// `CosmeticFailure` are reached only after a proven disarm; `RestoredToAutomatic` is reached
/// only from a disarm error carrying a post-WFP continue marker
/// (`TONO_DNS_RESTORED_AUTOMATIC` / `TONO_DNS_STILL_ON_LOOPBACK` / `TONO_WFP_REMOVED`), and
/// `windows_kill_switch::emergency_disarm_windows_kill_switch` produces those markers strictly
/// after the WFP objects have been deleted. Everything else blocks.
///
/// It lives here rather than only in `installer.nsi` so the rule is stated in a language that
/// can enumerate the outcome space; the macro's `$0 != "0"` fallthrough is its mirror image,
/// and the tests below cover the unknown-result case that fallthrough has to catch.
#[cfg(test)]
fn uninstall_may_continue(exit_code: i32) -> bool {
    matches!(
        exit_code,
        0 | EXIT_COSMETIC_FAILURE | EXIT_RESTORED_AUTOMATIC
    )
}

/// Classify the disarm result. Any marker that is only ever emitted **after** WFP removal
/// downgrades a disarm "failure" to continue-with-warning. Everything else — a wedged WFP
/// engine, a failed tombstone write before removal, an unrecognised message — stays blocking,
/// because none of those can show that the barrier was removed.
#[cfg(any(windows, test))]
fn classify_disarm_failure(error: Error) -> CleanupOutcome {
    let message = format!("{error:#}");
    if message.contains(DNS_RESTORED_AUTOMATIC_MARKER)
        || message.contains(DNS_STILL_ON_LOOPBACK_MARKER)
        || message.contains(WFP_REMOVED_CONTINUE_MARKER)
    {
        CleanupOutcome::RestoredToAutomatic(error)
    } else {
        CleanupOutcome::StillProtected(error)
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

/// The only safe "already clean" classification. A missing SCM record and missing state files
/// are insufficient: persistent WFP filters can outlive both, and Service startup intentionally
/// converts exactly that orphaned combination back into a strict emergency block.
#[cfg(any(windows, test))]
fn cleanup_fast_path_allowed(
    service_present: bool,
    recovery_state_present: bool,
    residual_filters_present: bool,
) -> bool {
    !service_present && !recovery_state_present && !residual_filters_present
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
        CleanupOutcome::RestoredToAutomatic(error) => {
            eprintln!(
                "The network barrier was removed, but the saved DNS servers could not be proven \
                 restored, so the affected adapters were set back to automatic (DHCP) instead. \
                 The machine is neither blocked nor pointed at Tono's resolver, so the uninstall \
                 continues; DNS now comes from the network rather than from the exact previous \
                 configuration: {error:#}"
            );
            std::process::exit(code);
        }
        CleanupOutcome::StillProtected(error) => {
            eprintln!(
                "Cleanup could not prove this machine was made safe, so nothing was deleted and \
                 all recovery files were preserved: {error:#}"
            );
            std::process::exit(code);
        }
    }
}

#[cfg(windows)]
fn windows_cleanup() -> CleanupOutcome {
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

    // No service/state is *not* enough to report success. A real customer install reached this
    // branch with orphaned persistent WFP filters; this helper returned Clean, then the next
    // Service start correctly saw those filters and installed a strict emergency block, taking
    // the machine offline until the App released it. Probe the WFP engine itself before the
    // fast path. A probe *error* used to block install/uninstall as result 3 even when a full
    // disarm would have cleared the machine — that is the worse end state for Chinese test
    // installs. Treat probe failure as "unknown, run the full disarm" instead of aborting.
    let recovery_state_present = windows_recovery_state_present();
    if service.is_none() && !recovery_state_present {
        let residual_filters_present = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => match runtime
                .block_on(clash_verge_service_ipc::residual_filters_present())
            {
                Ok(present) => present,
                // 0x80320005 = FWP_E_PROVIDER_NOT_FOUND: no Tono provider → not residual, CLEAN.
                // Treating this as "unknown, force disarm" was the result-3 loop on customer PCs.
                Err(error) if error_means_no_tono_wfp_provider(&error) => {
                    println!(
                        "WFP reports no Tono provider (clean machine; {error:#}); nothing to disarm."
                    );
                    false
                }
                Err(error) => {
                    eprintln!(
                        "Could not probe residual Tono WFP filters ({error:#}); running the full \
                         network disarm instead of blocking install/uninstall."
                    );
                    true
                }
            },
            Err(error) => {
                eprintln!(
                    "Could not create the residual WFP verification runtime ({error:#}); running \
                     the full network disarm instead of blocking install/uninstall."
                );
                true
            }
        };
        if cleanup_fast_path_allowed(false, false, residual_filters_present) {
            println!(
                "No service, recovery state, or residual Tono WFP filters present; nothing to clean up."
            );
            return match remove_windows_service_binary() {
                Ok(()) => CleanupOutcome::Clean,
                Err(error) => CleanupOutcome::CosmeticFailure(error),
            };
        }
        println!(
            "No service or recovery state remains, but orphaned Tono WFP filters exist (or could \
             not be ruled out); running the full network disarm."
        );
    }

    if let Some(service) = service.as_ref()
        && let Err(error) = stop_windows_service(service)
    {
        return CleanupOutcome::StillProtected(error);
    }

    // Opt this process — and only this process — into the DNS escalation ladder before the
    // disarm. Without it the library keeps the strict "prove the exact restore or refuse"
    // behaviour that made this application impossible to uninstall on a machine whose live DNS
    // apply keeps failing; with it, an unprovable exact restore escalates to automatic (DHCP)
    // and the uninstall continues. The variable is scoped to this process image, so the Service
    // and the App can never inherit it.
    //
    // SAFETY: single-threaded at this point — the tokio runtime below is built after this, and
    // nothing else in this binary reads or writes the environment concurrently.
    unsafe { std::env::set_var(UNINSTALL_LADDER_ENV, "1") };

    // The helper links the same recovery library as the service binary, so cleanup does not
    // depend on an intact installed `tono-service.exe` and cannot pipe-wait on a child process.
    // The owner lock proves no standalone daemon/core still owns the WFP and DNS state.
    let disarm = (|| -> Result<(), Error> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            // Prefer the owner lock so we do not race a live daemon. If lock acquisition fails
            // after the SCM stop (ProgramData ACL damage, missing pid file, stuck lock), still
            // attempt the disarm: the uninstall ladder removes WFP even when tombstone writes
            // fail, and refusing here is exactly the result-3 install/uninstall deadlock.
            let owner_guard = match clash_verge_service_ipc::acquire_service_owner().await {
                Ok(Some(guard)) => Some(guard),
                Ok(None) => match read_service_pid_file() {
                    Some(pid) => {
                        println!(
                            "Owner lock is held by live daemon {pid}; terminating it before disarm."
                        );
                        terminate_process_by_pid(pid)?;
                        clash_verge_service_ipc::acquire_service_owner()
                            .await
                            .ok()
                            .flatten()
                    }
                    None => {
                        eprintln!(
                            "Owner lock is held but no pid file is available; attempting disarm \
                             without the lock so install/uninstall can proceed."
                        );
                        None
                    }
                },
                Err(error) => {
                    eprintln!(
                        "Could not acquire the service owner lock ({error:#}); attempting disarm \
                         anyway so a stuck ProgramData ACL cannot brick install/uninstall."
                    );
                    None
                }
            };
            if owner_guard.is_none() {
                eprintln!(
                    "Proceeding with emergency disarm without an exclusive owner lock; service \
                     was already stopped (or never registered)."
                );
            }
            let _owner_guard = owner_guard;
            clash_verge_service_ipc::emergency_disarm_windows_kill_switch().await
        })
    })();
    // The escalation ladder collapses back into two questions here: are the WFP filters gone,
    // and if the exact DNS restore failed, is the machine at least off Tono's resolver? Only
    // post-WFP continue markers answer "yes" without an exact restore. If the disarm error is
    // unmarked, re-probe residual filters: when the barrier is already gone, continue rather
    // than result-3 brick (tombstone/ACL noise after a successful engine delete).
    let dns_fallback = match disarm {
        Ok(()) => None,
        Err(error) => match classify_disarm_failure(error) {
            CleanupOutcome::RestoredToAutomatic(error) => {
                eprintln!(
                    "Kill switch was disarmed; the saved DNS servers could not be proven \
                     restored, so the affected adapters were reset to automatic (DHCP): \
                     {error:#}"
                );
                Some(error)
            }
            CleanupOutcome::StillProtected(error) => {
                // Hard guarantee for the customer log: provider-absent is CLEAN, not armed.
                if error_means_no_tono_wfp_provider(&error) {
                    println!(
                        "Disarm reported WFP provider-not-found (0x80320005): no Tono kill switch \
                         is installed. Treating the machine as clean so install/uninstall continues."
                    );
                    None
                } else {
                    let residual = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .ok()
                        .and_then(|runtime| {
                            runtime
                                .block_on(clash_verge_service_ipc::residual_filters_present())
                                .ok()
                        });
                    match residual {
                        Some(false) => {
                            eprintln!(
                                "Disarm reported failure ({error:#}), but no residual Tono WFP \
                                 filters remain; treating the machine as unblocked so \
                                 install/uninstall can continue."
                            );
                            Some(anyhow::anyhow!(
                                "{WFP_REMOVED_CONTINUE_MARKER}: disarm reported an error but residual \
                                 WFP filters are absent: {error:#}"
                            ))
                        }
                        _ => return CleanupOutcome::StillProtected(error),
                    }
                }
            }
            other => return other,
        },
    };
    if dns_fallback.is_none() {
        println!("Kill switch was disarmed and protected DNS restore was verified.");
    }

    // Only cosmetic state remains. A failure below must not block the uninstall: the machine is
    // provably unblocked, and nothing left behind protects or blocks anything. A cosmetic
    // failure is reported *instead of* the DNS fallback: both continue, and the leftovers are
    // the thing a future install has to act on.
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
        Ok(()) => match dns_fallback {
            None => CleanupOutcome::Clean,
            Some(error) => CleanupOutcome::RestoredToAutomatic(error),
        },
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
        CleanupOutcome, DNS_RESTORED_AUTOMATIC_MARKER, DNS_STILL_ON_LOOPBACK_MARKER,
        EXIT_COSMETIC_FAILURE, EXIT_RESTORED_AUTOMATIC, EXIT_STILL_PROTECTED,
        WFP_REMOVED_CONTINUE_MARKER, classify_disarm_failure, cleanup_exit_code,
        cleanup_fast_path_allowed, poll_until, uninstall_may_continue,
    };
    use std::cell::Cell;

    #[test]
    fn clean_outcome_exits_zero() {
        assert_eq!(cleanup_exit_code(&CleanupOutcome::Clean), 0);
    }

    #[test]
    fn already_clean_fast_path_requires_wfp_absence_too() {
        assert!(cleanup_fast_path_allowed(false, false, false));
        for inputs in [
            (true, false, false),
            (false, true, false),
            (false, false, true),
        ] {
            assert!(
                !cleanup_fast_path_allowed(inputs.0, inputs.1, inputs.2),
                "service, recovery state, and residual WFP are each independently enough to require the full disarm: {inputs:?}"
            );
        }
    }

    #[test]
    fn cosmetic_failure_is_distinct_and_never_reads_as_blocking() {
        let code = cleanup_exit_code(&CleanupOutcome::CosmeticFailure(anyhow::anyhow!(
            "leftover"
        )));
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

    // --- The escalation ladder ---

    /// Rung 2 needs an exit code of its own: distinct from clean, from cosmetic debris, from the
    /// blocking code, and from the `anyhow` exit 1 — but on the continuing side of the line.
    #[test]
    fn restored_to_automatic_is_a_distinct_continuing_exit_code() {
        let code = cleanup_exit_code(&CleanupOutcome::RestoredToAutomatic(anyhow::anyhow!(
            "{DNS_RESTORED_AUTOMATIC_MARKER}: reset to DHCP"
        )));
        assert_eq!(code, EXIT_RESTORED_AUTOMATIC);
        for other in [0, 1, EXIT_COSMETIC_FAILURE, EXIT_STILL_PROTECTED] {
            assert_ne!(code, other);
        }
        assert!(uninstall_may_continue(code));
    }

    /// Post-WFP continue markers (rung 2, rung 3, generic WFP-removed) all let install/uninstall
    /// proceed. They are only ever attached after the barrier is gone.
    #[test]
    fn post_wfp_markers_downgrade_a_disarm_failure_to_continue() {
        for message in [
            format!("{DNS_RESTORED_AUTOMATIC_MARKER}: uninstall fallback"),
            format!("{DNS_STILL_ON_LOOPBACK_MARKER}: still on protected DNS"),
            format!("{WFP_REMOVED_CONTINUE_MARKER}: WFP was removed, but DNS restore could not be proven"),
        ] {
            let outcome = classify_disarm_failure(anyhow::anyhow!("{message}"));
            assert!(
                matches!(outcome, CleanupOutcome::RestoredToAutomatic(_)),
                "{message}"
            );
            assert!(
                uninstall_may_continue(cleanup_exit_code(&outcome)),
                "{message}"
            );
        }
    }

    /// Messages that cannot prove the barrier is gone keep blocking: a wedged WFP engine, a
    /// failed tombstone write *before* removal, and any message this build does not recognise.
    /// Continuing on those is exactly the "app removed, filters left armed" end state the
    /// ladder must never produce.
    #[test]
    fn every_unmarked_disarm_failure_still_blocks() {
        for message in [
            "TONO_WFP_ENGINE_WEDGED: the WFP engine did not answer",
            "TONO_DNS_RESTORE_STALLED: DNS restore did not answer",
            "failed to write the disarm tombstone",
            "some future error nobody has written yet",
            "",
        ] {
            let outcome = classify_disarm_failure(anyhow::anyhow!("{message}"));
            assert!(
                matches!(outcome, CleanupOutcome::StillProtected(_)),
                "{message} must not be read as a proven-safe machine"
            );
            let code = cleanup_exit_code(&outcome);
            assert_eq!(code, EXIT_STILL_PROTECTED, "{message}");
            assert!(!uninstall_may_continue(code), "{message}");
        }
    }

    #[test]
    fn post_wfp_continue_markers_are_the_documented_literals() {
        assert_eq!(DNS_RESTORED_AUTOMATIC_MARKER, "TONO_DNS_RESTORED_AUTOMATIC");
        assert_eq!(DNS_STILL_ON_LOOPBACK_MARKER, "TONO_DNS_STILL_ON_LOOPBACK");
        assert_eq!(WFP_REMOVED_CONTINUE_MARKER, "TONO_WFP_REMOVED");
    }

    /// The exact customer failure string must classify as "no Tono provider" (clean), not armed.
    #[test]
    fn customer_0x80320005_log_line_means_clean_not_armed() {
        let error = anyhow::anyhow!(
            "FwpmProviderGetByKey0 failed: WFP error 0x80320005"
        );
        assert!(
            super::error_means_no_tono_wfp_provider(&error),
            "customer residual/disarm log must be treated as clean"
        );
        let wrapped = error.context("could not prove that orphaned Tono WFP filters are absent");
        assert!(super::error_means_no_tono_wfp_provider(&wrapped));
    }

    /// The invariant, asserted over the whole outcome space rather than per case: every outcome
    /// the uninstall may continue on is one whose precondition is that the WFP filters are gone.
    /// `Clean` and `CosmeticFailure` are only constructed after a successful disarm;
    /// `RestoredToAutomatic` only from the marker, which the library emits strictly after the
    /// WFP objects were deleted. `StillProtected` — the one outcome that can be reached while
    /// filters may still be installed — is the one that blocks.
    #[test]
    fn no_continuing_outcome_can_leave_wfp_filters_installed() {
        let outcomes = [
            CleanupOutcome::Clean,
            CleanupOutcome::CosmeticFailure(anyhow::anyhow!("leftover")),
            CleanupOutcome::RestoredToAutomatic(anyhow::anyhow!(
                "{DNS_RESTORED_AUTOMATIC_MARKER}: reset to DHCP"
            )),
            CleanupOutcome::StillProtected(anyhow::anyhow!("armed")),
        ];
        for outcome in &outcomes {
            let wfp_proven_removed = !matches!(outcome, CleanupOutcome::StillProtected(_));
            assert_eq!(
                uninstall_may_continue(cleanup_exit_code(outcome)),
                wfp_proven_removed,
                "{outcome:?} continues if and only if the barrier is proven gone"
            );
        }
    }

    /// nsExec hands back "error"/"timeout" strings and future builds may add codes; anything the
    /// macro cannot place must block. This mirrors `installer.nsi`'s `$0 != "0"` fallthrough.
    #[test]
    fn unknown_results_never_read_as_permission_to_continue() {
        for code in [1, 5, 6, 100, 3010, -1] {
            assert!(!uninstall_may_continue(code), "exit {code} must block");
        }
    }

    /// Same contract in the other direction: the ladder only runs if this process image sets the
    /// exact variable `windows_kill_switch::UNINSTALL_LADDER_ENV` reads. A mismatch silently
    /// restores the old refuse-forever behaviour.
    #[test]
    fn the_uninstall_ladder_opt_in_matches_the_library() {
        assert_eq!(super::UNINSTALL_LADDER_ENV, "TONO_UNINSTALL_DNS_LADDER");
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
