use crate::utils::dirs::{self, PathBufExec as _};
use anyhow::{Result, anyhow};
use clash_verge_logging::{Type, logging};
use std::fs;
use std::os::windows::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};
use windows::Win32::Globalization::{GetACP, GetOEMCP, MULTI_BYTE_TO_WIDE_CHAR_FLAGS, MultiByteToWideChar};

const CREATE_NO_WINDOW: u32 = 0x08000000;
/// Hard cap on one `schtasks` invocation. Querying a task is a millisecond call on a healthy
/// machine, but `Command::output` reads the child's pipes to EOF and has no timeout of its own:
/// a stopped or wedged Task Scheduler service, or a Group Policy refresh holding it, parks the
/// caller for as long as the child lives. The auto-launch status must always be answerable.
const SCHTASKS_TIMEOUT: Duration = Duration::from_secs(10);
/// How often the wait re-checks the child. Short enough that a fast query is not measurably
/// delayed, long enough that the wait is not a spin.
const SCHTASKS_POLL_INTERVAL: Duration = Duration::from_millis(20);
// Scheduled-task names carry the Tono identity; there is no upgrade path
// from Clash Verge, so no legacy names are registered or preserved.
const TASK_NAME_USER: &str = "Tono";
const TASK_NAME_ADMIN: &str = "Tono (Admin)";
const TASK_XML_DIR: &str = "tasks";
const TASK_XML_USER: &str = "clash-verge-task-user.xml";
const TASK_XML_ADMIN: &str = "clash-verge-task-admin.xml";

#[derive(Clone, Copy)]
pub enum TaskMode {
    User,
    Admin,
}

impl TaskMode {
    const fn name(self) -> &'static str {
        match self {
            Self::User => TASK_NAME_USER,
            Self::Admin => TASK_NAME_ADMIN,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Admin => "admin",
        }
    }

    const fn xml_run_level(self) -> &'static str {
        match self {
            Self::User => "LeastPrivilege",
            Self::Admin => "HighestAvailable",
        }
    }

    const fn xml_file_name(self) -> &'static str {
        match self {
            Self::User => TASK_XML_USER,
            Self::Admin => TASK_XML_ADMIN,
        }
    }
}

/// The absolute path to `schtasks.exe`.
///
/// `Command::new("schtasks")` resolves through the CreateProcess search order, which starts at
/// the application directory and the current directory — a `schtasks.exe` dropped next to the
/// app would be run instead of the system one. The bare name stays as a fallback only for a
/// missing `%SystemRoot%`, which on Windows means the environment is already broken.
fn schtasks_command() -> Command {
    match std::env::var_os("SystemRoot") {
        Some(root) => Command::new(Path::new(&root).join("System32").join("schtasks.exe")),
        None => Command::new("schtasks"),
    }
}

fn get_exe_path() -> Result<PathBuf> {
    let exe_path = std::env::current_exe().map_err(|e| anyhow!("failed to get exe path: {}", e))?;
    Ok(exe_path)
}

/// The principal the logon task runs as.
///
/// The process SID is authoritative and always resolvable; `%USERDOMAIN%\%USERNAME%` is not —
/// AzureAD and Microsoft-account logons report names the Task Scheduler cannot map back to a
/// principal, so task creation failed outright for those users. `<UserId>` accepts a SID string.
/// The environment variables stay as the fallback for a token that cannot be read at all.
fn get_task_user_id() -> Result<String> {
    if let Ok(sid) = crate::core::owner_identity::current_sid() {
        return Ok(sid);
    }

    let username = std::env::var_os("USERNAME")
        .or_else(|| std::env::var_os("USER"))
        .ok_or_else(|| anyhow!("failed to get current user name"))?;
    let username = username.to_string_lossy();
    let username = username.trim();
    if username.is_empty() {
        return Err(anyhow!("current user name is empty"));
    }

    let domain = std::env::var_os("USERDOMAIN")
        .or_else(|| std::env::var_os("COMPUTERNAME"))
        .map(|value| value.to_string_lossy().to_string());

    if let Some(domain) = domain {
        let domain = domain.trim();
        if !domain.is_empty() {
            return Ok(format!("{domain}\\{username}"));
        }
    }

    Ok(username.to_string())
}

fn get_startup_dir() -> Result<PathBuf> {
    let appdata = std::env::var("APPDATA").map_err(|_| anyhow!("failed to read APPDATA env var"))?;
    let startup_dir = Path::new(&appdata)
        .join("Microsoft")
        .join("Windows")
        .join("Start Menu")
        .join("Programs")
        .join("Startup");

    if !startup_dir.exists() {
        return Err(anyhow!("startup folder does not exist: {:?}", startup_dir));
    }

    Ok(startup_dir)
}

async fn cleanup_legacy_shortcuts() -> Result<()> {
    let startup_dir = get_startup_dir()?;
    // Legacy Clash Verge links are residue and stay under their old names;
    // the Tono link is the current identity and is refreshed alongside.
    let old_shortcut = startup_dir.join("Clash-Verge.lnk");
    let new_shortcut = startup_dir.join("Clash Verge.lnk");
    let tono_shortcut = startup_dir.join("Tono.lnk");

    old_shortcut.remove_if_exists().await?;
    new_shortcut.remove_if_exists().await?;
    tono_shortcut.remove_if_exists().await?;
    Ok(())
}

fn task_xml_path(mode: TaskMode) -> Result<PathBuf> {
    let dir = dirs::app_home_dir()?.join(TASK_XML_DIR);
    fs::create_dir_all(&dir).map_err(|e| anyhow!("failed to create task xml dir: {}", e))?;
    Ok(dir.join(mode.xml_file_name()))
}

fn xml_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn build_task_xml(mode: TaskMode) -> Result<String> {
    let exe_path = get_exe_path()?.to_string_lossy().to_string();
    let exe_path = xml_escape(&exe_path);
    let user_id = xml_escape(&get_task_user_id()?);
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>{}</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>3</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{}</Command>
    </Exec>
  </Actions>
</Task>
"#,
        user_id,
        user_id,
        mode.xml_run_level(),
        exe_path
    ))
}

fn encode_utf16le_with_bom(content: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(2 + content.len() * 2);
    bytes.extend_from_slice(&[0xFF, 0xFE]);
    for unit in content.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

fn write_task_xml(mode: TaskMode) -> Result<PathBuf> {
    let task_xml = build_task_xml(mode)?;
    let task_xml_path = task_xml_path(mode)?;
    let encoded = encode_utf16le_with_bom(&task_xml);
    fs::write(&task_xml_path, encoded).map_err(|e| anyhow!("failed to write task xml: {}", e))?;
    Ok(task_xml_path)
}

fn decode_with_code_page(bytes: &[u8], code_page: u32) -> Option<String> {
    if bytes.is_empty() {
        return Some(String::new());
    }

    let len = bytes.len();
    if len > i32::MAX as usize {
        return None;
    }

    let required = unsafe { MultiByteToWideChar(code_page, MULTI_BYTE_TO_WIDE_CHAR_FLAGS(0), bytes, None) };

    if required <= 0 {
        return None;
    }

    let mut wide = vec![0u16; required as usize];
    let written = unsafe { MultiByteToWideChar(code_page, MULTI_BYTE_TO_WIDE_CHAR_FLAGS(0), bytes, Some(&mut wide)) };

    if written <= 0 {
        return None;
    }

    wide.truncate(written as usize);
    Some(String::from_utf16_lossy(&wide))
}

fn decode_console_output(bytes: &[u8]) -> String {
    if let Ok(text) = std::str::from_utf8(bytes) {
        return text.to_string();
    }

    let oem = unsafe { GetOEMCP() };
    if let Some(text) = decode_with_code_page(bytes, oem) {
        return text;
    }

    let acp = unsafe { GetACP() };
    if let Some(text) = decode_with_code_page(bytes, acp) {
        return text;
    }

    String::from_utf8_lossy(bytes).to_string()
}

fn output_message(output: &Output) -> String {
    let stdout = decode_console_output(&output.stdout);
    let stderr = decode_console_output(&output.stderr);
    let stdout = stdout.trim();
    let stderr = stderr.trim();

    match (stdout.is_empty(), stderr.is_empty()) {
        (true, true) => "unknown error".to_string(),
        (false, true) => stdout.to_string(),
        (true, false) => stderr.to_string(),
        (false, false) => format!("{stdout} | {stderr}"),
    }
}

/// Run `schtasks` and collect its output, giving up after [`SCHTASKS_TIMEOUT`].
///
/// Blocking by construction — every caller is already off the main thread — but bounded:
/// the child is polled to completion and killed if it overruns, so a wedged Task Scheduler
/// surfaces as an error instead of an unkillable wait. `schtasks` output is a few hundred
/// bytes, well inside the pipe buffer, so collecting it after the child exits cannot deadlock.
fn schtasks_output(mut cmd: Command) -> Result<Output> {
    let mut child = cmd
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow!("failed to execute schtasks: {}", e))?;

    let deadline = Instant::now() + SCHTASKS_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(e) => return Err(anyhow!("failed to wait for schtasks: {}", e)),
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            // Reap it: a killed child left unwaited stays a zombie handle for the process life.
            let _ = child.wait();
            return Err(anyhow!(
                "schtasks did not answer within {:?}; the Task Scheduler service may be stopped or busy",
                SCHTASKS_TIMEOUT
            ));
        }
        std::thread::sleep(SCHTASKS_POLL_INTERVAL);
    }

    child
        .wait_with_output()
        .map_err(|e| anyhow!("failed to read schtasks output: {}", e))
}

/// Whether `line` of `schtasks /Query /FO CSV /NH` names the task `name`.
///
/// The first CSV field is the task path (`"\Tono"`). Task paths are not localized; the Status
/// column is, which is why existence is decided here and the enabled flag is read from XML.
fn csv_line_names_task(line: &str, name: &str) -> bool {
    let field = line.trim().trim_start_matches('"');
    let field = match field.find('"') {
        Some(end) => &field[..end],
        None => field.split(',').next().unwrap_or(field),
    };
    field.trim_start_matches('\\').eq_ignore_ascii_case(name)
}

/// Whether the task is registered at all.
///
/// Deliberately a *listing* rather than `/Query /TN <name>`. Querying one task exits non-zero
/// for "no such task", "access denied" and "the Task Scheduler is not running" alike, and the
/// old code collapsed all three into `false`: `update_launch` then reported auto-launch as off
/// while the task kept launching the app at logon, and the "does the other mode's task exist"
/// guards silently answered no, letting a user task and an admin task co-exist (double launch).
/// A successful listing is proof either way; a failed listing is an error and now says so.
pub fn task_exists(mode: TaskMode) -> Result<bool> {
    let output = schtasks_output({
        let mut cmd = schtasks_command();
        cmd.args(["/Query", "/FO", "CSV", "/NH"]);
        cmd
    })?;

    if !output.status.success() {
        return Err(anyhow!("failed to list scheduled tasks: {}", output_message(&output)));
    }

    let listing = decode_console_output(&output.stdout);
    Ok(listing.lines().any(|line| csv_line_names_task(line, mode.name())))
}

/// Read the task-level `<Enabled>` flag out of a task definition.
///
/// The logon trigger carries an `<Enabled>` of its own, so only the one inside `<Settings>`
/// answers "did the user turn this task off". Absent means enabled — the scheduler's own default.
fn xml_task_enabled(xml: &str) -> bool {
    let Some(start) = xml.find("<Settings>") else {
        return true;
    };
    let Some(end) = xml[start..].find("</Settings>").map(|offset| offset + start) else {
        return true;
    };
    let settings = &xml[start..end];
    let Some(value_start) = settings.find("<Enabled>").map(|offset| offset + "<Enabled>".len()) else {
        return true;
    };
    let Some(value_end) = settings[value_start..]
        .find("</Enabled>")
        .map(|offset| offset + value_start)
    else {
        return true;
    };
    !settings[value_start..value_end].trim().eq_ignore_ascii_case("false")
}

/// Decode `schtasks /XML` output, which is UTF-16LE with a BOM rather than console text.
fn decode_task_xml(bytes: &[u8]) -> String {
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    decode_console_output(bytes)
}

/// Whether the task exists *and* is enabled.
///
/// `/Query` succeeds for a task the user disabled in the Task Scheduler UI, so existence alone
/// reported auto-launch as on for a task that will never run.
fn task_enabled(mode: TaskMode) -> Result<bool> {
    if !task_exists(mode)? {
        return Ok(false);
    }
    let output = schtasks_output({
        let mut cmd = schtasks_command();
        cmd.args(["/Query", "/TN", mode.name(), "/XML"]);
        cmd
    })?;
    if !output.status.success() {
        // It exists — the listing just said so. Failing to read its definition says nothing
        // about the flag, and answering "disabled" would be a guess that turns the setting off
        // in the UI while the task keeps running.
        logging!(
            warn,
            Type::Setup,
            "Could not read the {} task definition ({}); assuming it is enabled",
            mode.label(),
            output_message(&output)
        );
        return Ok(true);
    }
    Ok(xml_task_enabled(&decode_task_xml(&output.stdout)))
}

pub fn create_task(mode: TaskMode) -> Result<()> {
    let task_xml_path = write_task_xml(mode)?;
    let output = schtasks_output({
        let mut cmd = schtasks_command();
        cmd.args(["/Create", "/TN", mode.name(), "/XML"]);
        cmd.arg(&task_xml_path);
        cmd.arg("/F");
        cmd
    })?;

    if !output.status.success() {
        return Err(anyhow!(
            "failed to create {} task: {}",
            mode.label(),
            output_message(&output)
        ));
    }

    logging!(info, Type::Setup, "Created {} auto-launch task", mode.label());
    Ok(())
}

pub fn remove_task(mode: TaskMode) -> Result<()> {
    let output = schtasks_output({
        let mut cmd = schtasks_command();
        cmd.args(["/Delete", "/TN", mode.name(), "/F"]);
        cmd
    })?;

    if output.status.success() {
        logging!(info, Type::Setup, "Removed {} auto-launch task", mode.label());
        return Ok(());
    }

    if !task_exists(mode)? {
        logging!(
            info,
            Type::Setup,
            "{} auto-launch task not found, skipping removal",
            mode.label()
        );
        return Ok(());
    }

    Err(anyhow!(
        "failed to remove {} task: {}",
        mode.label(),
        output_message(&output)
    ))
}

pub async fn set_auto_launch(is_enable: bool, is_admin: bool) -> Result<()> {
    let target = if is_admin { TaskMode::Admin } else { TaskMode::User };
    let other = if is_admin { TaskMode::User } else { TaskMode::Admin };

    if let Err(err) = cleanup_legacy_shortcuts().await {
        logging!(warn, Type::Setup, "Failed to cleanup legacy startup shortcuts: {}", err);
    }

    if is_enable {
        if is_admin {
            create_task(target)?;
            if let Err(err) = remove_task(other) {
                let _ = remove_task(target);
                return Err(err);
            }
        } else {
            if task_exists(other)? {
                return Err(anyhow!(
                    "admin auto-launch task exists; run the app as administrator to remove it before creating a user task"
                ));
            }
            create_task(target)?;
        }
        return Ok(());
    }

    if is_admin {
        let mut errors = Vec::new();
        if let Err(err) = remove_task(TaskMode::User) {
            errors.push(err);
        }
        if let Err(err) = remove_task(TaskMode::Admin) {
            errors.push(err);
        }

        if let Some(err) = errors.into_iter().next() {
            return Err(err);
        }

        return Ok(());
    }

    remove_task(TaskMode::User)?;
    if task_exists(TaskMode::Admin)? {
        return Err(anyhow!(
            "admin auto-launch task exists; run the app as administrator to remove it"
        ));
    }

    Ok(())
}

pub fn is_auto_launch_enabled() -> Result<bool> {
    if task_enabled(TaskMode::Admin)? {
        return Ok(true);
    }

    task_enabled(TaskMode::User)
}

#[cfg(test)]
mod tests {
    use super::{csv_line_names_task, xml_task_enabled};

    #[test]
    fn csv_listing_matches_the_task_path_case_insensitively() {
        assert!(csv_line_names_task(r#""\Tono","N/A","Ready""#, "Tono"));
        assert!(csv_line_names_task(r#""\tono","N/A","Disabled""#, "Tono"));
        assert!(csv_line_names_task(r#""\Tono (Admin)","N/A","Ready""#, "Tono (Admin)"));
        // A different task whose name merely starts the same must not match.
        assert!(!csv_line_names_task(r#""\TonoUpdater","N/A","Ready""#, "Tono"));
        assert!(!csv_line_names_task(r#""\Tono","N/A","Ready""#, "Tono (Admin)"));
    }

    #[test]
    fn a_disabled_task_is_not_reported_as_enabled() {
        let xml = "<Task><Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>\
                   <Settings><Enabled>false</Enabled></Settings></Task>";
        assert!(!xml_task_enabled(xml));
    }

    #[test]
    fn the_trigger_flag_is_not_mistaken_for_the_task_flag() {
        let xml = "<Task><Triggers><LogonTrigger><Enabled>false</Enabled></LogonTrigger></Triggers>\
                   <Settings><Enabled>true</Enabled></Settings></Task>";
        assert!(xml_task_enabled(xml));
    }

    #[test]
    fn a_definition_without_the_flag_defaults_to_enabled() {
        assert!(xml_task_enabled(
            "<Task><Settings><Hidden>false</Hidden></Settings></Task>"
        ));
        assert!(xml_task_enabled("not xml at all"));
    }
}
