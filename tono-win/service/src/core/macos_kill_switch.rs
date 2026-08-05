use crate::core::structure::{MacosKillSwitchConfig, MacosKillSwitchMode};
use anyhow::{Context, Result, bail};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
#[cfg(all(target_os = "macos", not(feature = "test")))]
use std::process::Stdio;
use std::sync::Mutex;
#[cfg(all(target_os = "macos", not(feature = "test")))]
use std::time::Duration;
#[cfg(all(target_os = "macos", not(feature = "test")))]
use tokio::io::AsyncReadExt as _;

const GID_ENV: &str = "CLASH_VERGE_MIHOMO_GID";
const GID_MIN: u32 = 60_000;
const GID_MAX: u32 = 64_999;
#[cfg(any(all(target_os = "macos", not(feature = "test")), test))]
const ANCHOR: &str = "com.clash-verge.service.kill-switch";
#[cfg(any(all(target_os = "macos", not(feature = "test")), test))]
const BEGIN: &str = "# BEGIN CLASH VERGE MANAGED KILL SWITCH";
#[cfg(any(all(target_os = "macos", not(feature = "test")), test))]
const END: &str = "# END CLASH VERGE MANAGED KILL SWITCH";
#[cfg(all(target_os = "macos", not(feature = "test")))]
const PF_COMMAND_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Desired {
    mode: MacosKillSwitchMode,
    tunnel_interface: Option<String>,
    tunnel_ready: bool,
}

static DESIRED: Lazy<Mutex<Option<Desired>>> = Lazy::new(|| Mutex::new(None));
static PF_OPERATION: Lazy<tokio::sync::Mutex<()>> = Lazy::new(|| tokio::sync::Mutex::new(()));
#[cfg(all(target_os = "macos", not(feature = "test")))]
static PF_COMMAND_OPERATION: Lazy<tokio::sync::Mutex<()>> =
    Lazy::new(|| tokio::sync::Mutex::new(()));

pub(crate) fn dedicated_gid() -> Result<u32> {
    let raw = std::env::var(GID_ENV).context("dedicated Mihomo GID is not configured")?;
    let gid: u32 = raw.parse().context("dedicated Mihomo GID is malformed")?;
    if !(GID_MIN..=GID_MAX).contains(&gid) {
        bail!("dedicated Mihomo GID is outside the installer range");
    }
    #[cfg(target_os = "macos")]
    if nix::unistd::Group::from_gid(nix::unistd::Gid::from_raw(gid))?.is_some() {
        bail!("dedicated Mihomo GID resolves to a registered group");
    }
    Ok(gid)
}

pub(crate) fn validate_interface(value: &str) -> Result<()> {
    let Some(decimal) = value.strip_prefix("utun") else {
        bail!("tunnel interface must start with utun")
    };
    if decimal.is_empty() || decimal.len() > 4 || !decimal.bytes().all(|c| c.is_ascii_digit()) {
        bail!("tunnel interface must be utun followed by 1-4 decimal digits");
    }
    if decimal.len() > 1 && decimal.starts_with('0') {
        bail!("tunnel interface is not canonical")
    }
    Ok(())
}

#[cfg(any(all(target_os = "macos", not(feature = "test")), test))]
pub(crate) fn render_rules(gid: u32, tunnel: Option<&str>) -> String {
    let mut rules = format!(
        "pass quick on lo0 all no state\npass out quick proto {{ tcp udp }} group {gid} no state\n\
pass out quick on {{ en0 en1 }} proto udp from any port 68 to any port 67 no state\n\
pass in quick on {{ en0 en1 }} proto udp from any port 67 to any port 68 no state\n\
pass out quick inet6 proto udp from any port 546 to any port 547 no state\n\
pass in quick inet6 proto udp from any port 547 to any port 546 no state\n\
pass quick inet6 proto icmp6 icmp6-type {{ neighbrsol, neighbradv, routersol, routeradv }} no state\n"
    );
    if let Some(interface) = tunnel {
        rules.push_str(&format!("pass quick on {interface} all no state\n"));
    }
    // `all` is deliberately not restricted to `inet`: this is the final IPv4 + IPv6 policy.
    rules.push_str("block drop out quick all\n");
    rules
}

fn state_path() -> PathBuf {
    crate::service_paths()
        .persistent_state_dir()
        .join("macos-kill-switch.json")
}

#[cfg(all(target_os = "macos", not(feature = "test")))]
fn rules_path() -> PathBuf {
    crate::service_paths()
        .persistent_state_dir()
        .join("macos-kill-switch.pf")
}

async fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    crate::core::paths::ensure_persistent_state_layout()?;
    crate::core::platform_security::secure_private_service_file_if_exists(path)?;
    let temporary = path.with_extension("tmp");
    if std::fs::symlink_metadata(&temporary).is_ok() {
        std::fs::remove_file(&temporary)?;
    }
    tokio::fs::write(&temporary, bytes).await?;
    crate::core::platform_security::secure_private_service_file_if_exists(&temporary)?;
    crate::core::atomic_file::replace(&temporary, path).await?;
    crate::core::platform_security::secure_private_service_file_if_exists(path)?;
    Ok(())
}

#[cfg(all(target_os = "macos", not(feature = "test")))]
fn stage_pf_config_preserving_metadata(contents: &[u8]) -> Result<PathBuf> {
    use std::ffi::CString;
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;

    let path = Path::new("/etc/pf.conf");
    let temporary = Path::new("/etc/.pf.conf.clash-verge.tmp");
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        bail!("/etc/pf.conf is not a regular file");
    }
    match std::fs::symlink_metadata(temporary) {
        Ok(metadata) if metadata.file_type().is_file() => std::fs::remove_file(temporary)?,
        Ok(_) => bail!("refusing to replace unexpected PF temporary path"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    let source = CString::new(path.as_os_str().as_bytes())?;
    let destination = CString::new(temporary.as_os_str().as_bytes())?;
    let copied = unsafe {
        platform_lib::copyfile(
            source.as_ptr(),
            destination.as_ptr(),
            std::ptr::null_mut(),
            platform_lib::COPYFILE_METADATA
                | platform_lib::COPYFILE_EXCL
                | platform_lib::COPYFILE_NOFOLLOW,
        )
    };
    if copied != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to clone pf.conf metadata");
    }

    let result = (|| -> Result<PathBuf> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        Ok(temporary.to_path_buf())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}

#[cfg(all(target_os = "macos", not(feature = "test")))]
fn commit_staged_pf_config(staged: &Path) -> Result<()> {
    std::fs::rename(staged, "/etc/pf.conf")?;
    std::fs::File::open("/etc")?.sync_all()?;
    Ok(())
}

#[cfg(all(target_os = "macos", not(feature = "test")))]
async fn install_unlocked(desired: &Desired) -> Result<()> {
    let gid = dedicated_gid()?;
    let rules_path = rules_path();
    let tunnel = desired
        .tunnel_ready
        .then_some(desired.tunnel_interface.as_deref())
        .flatten();
    let rules = render_rules(gid, tunnel);
    atomic_write(&rules_path, rules.as_bytes()).await?;
    let pf = tokio::fs::read_to_string("/etc/pf.conf").await?;
    reject_competing_pf_filter_policy(&pf)?;
    let managed = format!(
        "{BEGIN}\nanchor \"{ANCHOR}\"\nload anchor \"{ANCHOR}\" from \"{}\"\n{END}\n",
        rules_path.display()
    );
    let next = replace_managed(&pf, &managed)?;
    if next != pf {
        replace_and_reload_pf_config(next.as_bytes(), pf.as_bytes()).await?;
    } else {
        let live_main = run_pf(&["-sr"]).await?;
        if parent_anchor_is_first(&live_main) {
            run_pf(&["-a", ANCHOR, "-f", rules_path.to_string_lossy().as_ref()]).await?;
        } else {
            // The file still owns the attachment but another PF consumer dropped it from the
            // live main ruleset. An anchor-only load cannot recreate the parent call.
            run_pf(&["-f", "/etc/pf.conf"]).await?;
        }
    }
    // `pfctl -E` emits a reference token on stderr but Apple exposes no stable machine-readable
    // token contract. We deliberately do not fake ownership; the watchdog repairs PF disable.
    run_pf(&["-e"]).await.or_else(|error| {
        if error.to_string().contains("already enabled") {
            Ok(String::new())
        } else {
            Err(error)
        }
    })?;
    // PF evaluates established states before filter rules. This global barrier is intentionally
    // disruptive: without it, direct TCP/UDP sessions opened before arm (or while PF was disabled)
    // could bypass a correctly installed block indefinitely.
    run_pf(&["-F", "states"]).await?;
    verify_live_unlocked(desired).await
}

#[cfg(all(target_os = "macos", not(feature = "test")))]
async fn run_pf(args: &[&str]) -> Result<String> {
    let args = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
    tokio::spawn(async move { run_pf_owned(args).await })
        .await
        .context("pfctl supervisor task failed")?
}

#[cfg(all(target_os = "macos", not(feature = "test")))]
async fn run_pf_owned(args: Vec<String>) -> Result<String> {
    // Keep ownership of the child in this supervisor task. If an IPC handler is cancelled, the
    // task still kills and reaps pfctl before the next PF command can acquire this lock.
    let _command = PF_COMMAND_OPERATION.lock().await;
    let mut child = tokio::process::Command::new("/sbin/pfctl")
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let pid = child.id();
    let stdout = child
        .stdout
        .take()
        .context("failed to capture pfctl stdout")?;
    let stderr = child
        .stderr
        .take()
        .context("failed to capture pfctl stderr")?;
    let stdout = tokio::spawn(async move {
        let mut bytes = Vec::new();
        let mut stdout = stdout;
        stdout.read_to_end(&mut bytes).await.map(|_| bytes)
    });
    let stderr = tokio::spawn(async move {
        let mut bytes = Vec::new();
        let mut stderr = stderr;
        stderr.read_to_end(&mut bytes).await.map(|_| bytes)
    });
    let status = match tokio::time::timeout(PF_COMMAND_TIMEOUT, child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(error)) => {
            stdout.abort();
            stderr.abort();
            let _ = stdout.await;
            let _ = stderr.await;
            return Err(error).context(format!("failed to wait for pfctl {args:?}"));
        }
        Err(_) => {
            let kill = child.kill().await;
            stdout.abort();
            stderr.abort();
            let _ = stdout.await;
            let _ = stderr.await;
            kill.context(format!(
                "pfctl {args:?} timed out after {PF_COMMAND_TIMEOUT:?} and could not be killed (pid {pid:?})"
            ))?;
            bail!("pfctl {args:?} timed out after {PF_COMMAND_TIMEOUT:?} (pid {pid:?})");
        }
    };
    let stdout = stdout.await??;
    let stderr = stderr.await??;
    if !status.success() {
        bail!("pfctl {:?}: {}", args, String::from_utf8_lossy(&stderr))
    }
    Ok(String::from_utf8_lossy(&stdout).into_owned())
}

#[cfg(all(target_os = "macos", not(feature = "test")))]
async fn replace_and_reload_pf_config(next: &[u8], previous: &[u8]) -> Result<()> {
    let staged = stage_pf_config_preserving_metadata(next)?;
    if let Err(error) = run_pf(&["-vnf", staged.to_string_lossy().as_ref()]).await {
        let _ = std::fs::remove_file(&staged);
        return Err(error).context("replacement pf.conf failed validation");
    }
    commit_staged_pf_config(&staged)?;
    if let Err(error) = run_pf(&["-f", "/etc/pf.conf"]).await {
        let rollback = async {
            let staged = stage_pf_config_preserving_metadata(previous)?;
            commit_staged_pf_config(&staged)?;
            run_pf(&["-f", "/etc/pf.conf"]).await?;
            Result::<()>::Ok(())
        }
        .await;
        return match rollback {
            Ok(()) => Err(error).context("failed to load replacement pf.conf; restored previous configuration"),
            Err(rollback_error) => Err(error).context(format!(
                "failed to load replacement pf.conf and failed to restore previous configuration: {rollback_error:#}"
            )),
        };
    }
    Ok(())
}

#[cfg(all(target_os = "macos", not(feature = "test")))]
fn parent_anchor_is_first(main: &str) -> bool {
    main.lines()
        .find(|line| !line.trim().is_empty())
        .is_some_and(|line| line.trim() == format!("anchor \"{ANCHOR}\" all"))
}

#[cfg(all(target_os = "macos", not(feature = "test")))]
async fn verify_live_unlocked(desired: &Desired) -> Result<()> {
    let info = run_pf(&["-s", "info"]).await?;
    if !info.to_ascii_lowercase().contains("status: enabled") {
        bail!("PF is disabled");
    }

    let main = run_pf(&["-sr"]).await?;
    if !parent_anchor_is_first(&main) {
        bail!("kill-switch anchor is not the first effective filter rule");
    }

    let live = run_pf(&["-a", ANCHOR, "-sr"]).await?;
    let parsed = run_pf(&["-vnf", rules_path().to_string_lossy().as_ref()]).await?;
    if normalize_pf_rules(&live) != normalize_pf_rules(&parsed) {
        bail!("live kill-switch rules differ from the generated rules");
    }
    if !live
        .to_ascii_lowercase()
        .contains("block drop out quick all")
    {
        bail!("live kill-switch rules have no final block");
    }
    if desired.tunnel_ready {
        let interface = desired
            .tunnel_interface
            .as_deref()
            .context("ready kill switch has no tunnel interface")?;
        if !live.contains(interface) {
            bail!("live kill-switch rules omit the protected tunnel");
        }
    }
    Ok(())
}

#[cfg(all(target_os = "macos", not(feature = "test")))]
fn normalize_pf_rules(value: &str) -> Vec<String> {
    value
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("No ALTQ support"))
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(any(all(target_os = "macos", not(feature = "test")), test))]
fn replace_managed(existing: &str, managed: &str) -> Result<String> {
    let mut cleaned = match (existing.find(BEGIN), existing.find(END)) {
        (None, None) => existing.to_owned(),
        (Some(begin), Some(end)) if begin < end => {
            let tail = end + END.len();
            format!(
                "{}{}",
                &existing[..begin],
                existing[tail..].trim_start_matches('\n')
            )
        }
        _ => {
            return Err(anyhow::anyhow!(
                "pf.conf contains damaged Clash Verge managed markers"
            ));
        }
    };
    if managed.is_empty() {
        return Ok(cleaned);
    }
    if cleaned.contains(&format!("anchor \"{ANCHOR}\""))
        || cleaned.contains(&format!("load anchor \"{ANCHOR}\""))
    {
        bail!("pf.conf contains an unmanaged Clash Verge kill-switch anchor");
    }

    // PF evaluates the last matching filter rule unless a rule is `quick`. The child anchor must
    // therefore be called before every pre-existing filter rule, including Apple's filter anchor.
    // Translation/scrub/dummynet declarations stay ahead of it to preserve PF grammar ordering.
    let mut lines = cleaned.lines().map(ToOwned::to_owned).collect::<Vec<_>>();
    let insertion = lines
        .iter()
        .position(|line| {
            let line = line.trim_start();
            line.starts_with("anchor ")
                || line.starts_with("pass ")
                || line.starts_with("block ")
                || line.starts_with("match ")
        })
        .unwrap_or(lines.len());
    lines.insert(insertion, managed.trim_end().to_owned());
    cleaned = lines.join("\n");
    if existing.ends_with('\n') {
        cleaned.push('\n');
    }
    Ok(cleaned)
}

#[cfg(any(all(target_os = "macos", not(feature = "test")), test))]
fn reject_competing_pf_filter_policy(existing: &str) -> Result<()> {
    let cleaned = replace_managed(existing, "")?;
    // PF permits a backslash-newline continuation and any ASCII whitespace between tokens.
    // Includes are rejected rather than recursively interpreted because they may introduce an
    // arbitrary top-level filter policy outside this ownership check.
    let logical = cleaned.replace("\\\r\n", " ").replace("\\\n", " ");
    for line in logical.lines() {
        let statement = line
            .split_once('#')
            .map_or(line, |(prefix, _)| prefix)
            .trim();
        if statement.is_empty() {
            continue;
        }
        let tokens = statement.split_ascii_whitespace().collect::<Vec<_>>();
        let apple_anchor = matches!(tokens.as_slice(), ["anchor", "\"com.apple/*\""])
            || matches!(
                tokens.as_slice(),
                [
                    "load",
                    "anchor",
                    "\"com.apple\"",
                    "from",
                    "\"/etc/pf.anchors/com.apple\""
                ]
            );
        let filter_policy = tokens.first().is_some_and(|token| token.starts_with('$'))
            || matches!(
                tokens.first().copied(),
                Some("anchor" | "pass" | "block" | "match" | "antispoof" | "include" | "load")
            );
        if filter_policy && !apple_anchor {
            bail!(
                "an unsupported external PF filter policy is configured ({statement}); disable its PF manager before enabling Clash Verge protection"
            );
        }
    }
    Ok(())
}

pub(crate) async fn preflight() -> Result<()> {
    #[cfg(all(target_os = "macos", not(feature = "test")))]
    {
        let pf = tokio::fs::read_to_string("/etc/pf.conf").await?;
        reject_competing_pf_filter_policy(&pf)?;
    }
    Ok(())
}

#[cfg(not(all(target_os = "macos", not(feature = "test"))))]
async fn install_unlocked(_desired: &Desired) -> Result<()> {
    Ok(())
}

pub(crate) async fn arm(config: &MacosKillSwitchConfig) -> Result<()> {
    if config.mode == MacosKillSwitchMode::Disabled {
        return release().await;
    }
    let interface = config
        .tunnel_interface
        .as_deref()
        .context("enabled kill switch requires tunnel_interface")?;
    validate_interface(interface)?;
    dedicated_gid()?;
    let desired = Desired {
        mode: config.mode,
        tunnel_interface: Some(interface.to_owned()),
        tunnel_ready: false,
    };
    let _operation = PF_OPERATION.lock().await;
    preflight().await?;
    // Persist fail-closed intent before touching PF. A daemon restart will install at least the
    // bootstrap-only block if this process dies during the following transaction.
    atomic_write(&state_path(), &serde_json::to_vec_pretty(&desired)?).await?;
    *DESIRED.lock().unwrap() = Some(desired.clone());
    install_unlocked(&desired).await
}

pub(crate) async fn add_tunnel() -> Result<()> {
    let _operation = PF_OPERATION.lock().await;
    let mut desired = DESIRED
        .lock()
        .unwrap()
        .clone()
        .context("kill switch is not armed")?;
    #[cfg(all(target_os = "macos", not(feature = "test")))]
    {
        let interface = desired
            .tunnel_interface
            .as_deref()
            .context("armed kill switch has no tunnel interface")?;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while !Path::new("/sys/class/net").join(interface).exists() {
            let found = tokio::process::Command::new("/sbin/ifconfig")
                .arg(interface)
                .status()
                .await
                .is_ok_and(|status| status.success());
            if found {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                bail!("requested tunnel interface did not appear");
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
    desired.tunnel_ready = true;
    // Update live PF first. If this fails, the previous bootstrap-only rules remain effective and
    // the persisted state still restores them after a crash.
    install_unlocked(&desired).await?;
    atomic_write(&state_path(), &serde_json::to_vec_pretty(&desired)?).await?;
    *DESIRED.lock().unwrap() = Some(desired);
    Ok(())
}

pub async fn add_restored_kill_switch_tunnel() -> Result<()> {
    if DESIRED.lock().unwrap().is_none() {
        return Ok(());
    }
    add_tunnel().await
}

pub(crate) async fn release() -> Result<()> {
    let _operation = PF_OPERATION.lock().await;
    release_unlocked().await
}

async fn release_unlocked() -> Result<()> {
    let previous = DESIRED.lock().unwrap().clone();
    #[cfg(all(target_os = "macos", not(feature = "test")))]
    {
        // Keep the empty parent attachment in place during normal operation. This avoids
        // repeatedly reloading and disturbing Apple or third-party rules in the host ruleset.
        if let Err(error) = run_pf(&["-a", ANCHOR, "-F", "all"]).await {
            if let Some(previous) = previous.as_ref() {
                let _ = install_unlocked(previous).await;
            }
            return Err(error.context("failed to clear live kill-switch rules"));
        }
    }
    match tokio::fs::remove_file(state_path()).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            if let Some(previous) = previous.as_ref() {
                install_unlocked(previous)
                    .await
                    .context("network opened and persisted-state cleanup failed; failed to restore protection")?;
            }
            return Err(error).context("network opened but persisted-state cleanup failed");
        }
    }
    *DESIRED.lock().unwrap() = None;
    Ok(())
}

pub(crate) async fn keep_blocked_after_stop() -> Result<()> {
    let _operation = PF_OPERATION.lock().await;
    let mut desired = DESIRED
        .lock()
        .unwrap()
        .clone()
        .context("kill switch is not armed")?;
    desired.tunnel_ready = false;
    // Persist first so a crash at any later point restores the stricter bootstrap-only block.
    atomic_write(&state_path(), &serde_json::to_vec_pretty(&desired)?).await?;
    *DESIRED.lock().unwrap() = Some(desired.clone());
    install_unlocked(&desired).await
}

pub(crate) async fn transition_after_stop(release_requested: bool) -> Result<()> {
    let _operation = PF_OPERATION.lock().await;
    let Some(mut desired) = DESIRED.lock().unwrap().clone() else {
        return Ok(());
    };
    if release_requested && desired.mode == MacosKillSwitchMode::Standard {
        return release_unlocked().await;
    }
    desired.tunnel_ready = false;
    atomic_write(&state_path(), &serde_json::to_vec_pretty(&desired)?).await?;
    *DESIRED.lock().unwrap() = Some(desired.clone());
    install_unlocked(&desired).await
}

pub async fn restore_kill_switch() -> Result<()> {
    let _operation = PF_OPERATION.lock().await;
    match tokio::fs::read(state_path()).await {
        Ok(bytes) => match serde_json::from_slice::<Desired>(&bytes) {
            Ok(mut desired) => {
                if desired.mode == MacosKillSwitchMode::Disabled
                    || desired
                        .tunnel_interface
                        .as_deref()
                        .is_none_or(|interface| validate_interface(interface).is_err())
                {
                    let emergency = Desired {
                        mode: MacosKillSwitchMode::Permanent,
                        tunnel_interface: None,
                        tunnel_ready: false,
                    };
                    *DESIRED.lock().unwrap() = Some(emergency.clone());
                    return install_unlocked(&emergency)
                        .await
                        .context("invalid state: failed to install emergency block");
                }
                // A persisted utun name is not proof that this boot's interface is owned by the
                // recovered core. Restore the bootstrap block first and add the tunnel only after
                // the normal start transaction observes it.
                desired.tunnel_ready = false;
                atomic_write(&state_path(), &serde_json::to_vec_pretty(&desired)?).await?;
                *DESIRED.lock().unwrap() = Some(desired.clone());
                install_unlocked(&desired).await
            }
            Err(_) => {
                let emergency = Desired {
                    mode: MacosKillSwitchMode::Permanent,
                    tunnel_interface: None,
                    tunnel_ready: false,
                };
                *DESIRED.lock().unwrap() = Some(emergency.clone());
                install_unlocked(&emergency)
                    .await
                    .context("corrupt state: failed to install emergency block")
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub fn spawn_kill_switch_watchdog() {
    tokio::spawn(async {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            let _operation = PF_OPERATION.lock().await;
            let wanted = { DESIRED.lock().unwrap().clone() };
            if let Some(desired) = wanted {
                #[cfg(all(target_os = "macos", not(feature = "test")))]
                let healthy = verify_live_unlocked(&desired).await.is_ok();
                #[cfg(not(all(target_os = "macos", not(feature = "test"))))]
                let healthy = true;
                if !healthy && let Err(error) = install_unlocked(&desired).await {
                    tracing::error!("kill-switch reconciliation failed: {error:#}");
                }
            }
        }
    });
}

pub async fn emergency_disarm_kill_switch() -> Result<()> {
    let _operation = PF_OPERATION.lock().await;
    release_unlocked().await?;
    #[cfg(all(target_os = "macos", not(feature = "test")))]
    {
        let pf = tokio::fs::read_to_string("/etc/pf.conf").await?;
        let next = replace_managed(&pf, "")?;
        if next != pf {
            replace_and_reload_pf_config(next.as_bytes(), pf.as_bytes()).await?;
        }
    }
    Ok(())
}

pub(crate) async fn status() -> (bool, bool, MacosKillSwitchMode) {
    let desired = DESIRED.lock().unwrap().clone();
    let Some(desired) = desired else {
        return (false, false, MacosKillSwitchMode::Disabled);
    };
    let _operation = PF_OPERATION.lock().await;
    #[cfg(all(target_os = "macos", not(feature = "test")))]
    let live = verify_live_unlocked(&desired).await.is_ok();
    #[cfg(not(all(target_os = "macos", not(feature = "test"))))]
    let live = true;
    (true, live, desired.mode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_are_closed_and_identity_scoped() {
        let rules = render_rules(62001, Some("utun12"));
        assert!(rules.ends_with("block drop out quick all\n"));
        assert!(
            rules
                .lines()
                .filter(|line| line.starts_with("pass"))
                .all(|line| line.ends_with("no state"))
        );
        assert!(rules.contains("group 62001"));
        assert!(!rules.contains("user root"));
    }

    #[test]
    fn validates_utun() {
        assert!(validate_interface("utun0").is_ok());
        assert!(validate_interface("utun1024").is_ok());
        for bad in ["en0", "utun", "utun01", "utun10000"] {
            assert!(validate_interface(bad).is_err());
        }
    }

    #[test]
    fn managed_anchor_precedes_existing_filter_rules() {
        let original =
            "scrub-anchor \"com.apple/*\"\nnat-anchor \"com.apple/*\"\nanchor \"com.apple/*\"\n";
        let managed = format!("{BEGIN}\nanchor \"{ANCHOR}\"\n{END}\n");
        let result = replace_managed(original, &managed).unwrap();
        let apple_filter = result.find("\nanchor \"com.apple/*\"").unwrap();
        assert!(result.find(&format!("anchor \"{ANCHOR}\"")).unwrap() < apple_filter);
        assert!(result.find("nat-anchor").unwrap() < result.find(BEGIN).unwrap());
    }

    #[test]
    fn markers_must_be_consistent() {
        assert!(replace_managed(BEGIN, "x").is_err());
    }

    #[test]
    fn rejects_another_top_level_filter_policy() {
        let tono = "scrub-anchor \"com.apple/*\"\nanchor \"tono.killswitch\"\nload anchor \"tono.killswitch\" from \"/tmp/tono.pf\"\nanchor \"com.apple/*\"\n";
        let error = reject_competing_pf_filter_policy(tono).unwrap_err();
        assert!(error.to_string().contains("tono.killswitch"));
    }

    #[test]
    fn rejects_filter_policy_syntax_variants() {
        for policy in [
            "block\n",
            "pass\tall\n",
            "load\tanchor \"tono.killswitch\" from \"/tmp/tono.pf\"\n",
            "anchor\\\n  \"tono.killswitch\"\n",
            "include \"/tmp/extra.pf\"\n",
            "anchor \"com.apple.evil\"\n",
            "anchor \"com.apple-malware\"\n",
            "policy = \"block all\"\n$policy\n",
            "kind = \"anchor\"\nload $kind \"tono.killswitch\" from \"/tmp/tono.pf\"\n",
        ] {
            assert!(
                reject_competing_pf_filter_policy(policy).is_err(),
                "accepted external filter policy: {policy:?}"
            );
        }
    }

    #[test]
    fn ignores_comments_when_checking_filter_policy() {
        reject_competing_pf_filter_policy(
            "  # anchor \"tono.killswitch\"\nanchor \"com.apple/*\" # stock filter anchor\n",
        )
        .unwrap();
    }

    #[test]
    fn accepts_stock_apple_and_our_managed_filter_policy() {
        let config = format!(
            "scrub-anchor \"com.apple/*\"\nnat-anchor \"com.apple/*\"\n{BEGIN}\nanchor \"{ANCHOR}\"\nload anchor \"{ANCHOR}\" from \"/tmp/clash.pf\"\n{END}\nanchor \"com.apple/*\"\nload anchor \"com.apple\" from \"/etc/pf.anchors/com.apple\"\n"
        );
        reject_competing_pf_filter_policy(&config).unwrap();
    }
}
