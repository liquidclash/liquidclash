//! Local traffic audit (product-contract.md §8, macOS `LocalTrafficAudit`
//! parity subset): a JSONL protection/connection event log with size-capped
//! rotation, owner-only file protection, and regex redaction for
//! credentials/URL patterns.
//!
//! Non-blocking by contract: `Audit::log` is a `try_send` into a bounded
//! channel — a full channel drops the event (counted), and nothing here
//! ever panics or stalls the connect path. Redaction happens on the raw
//! payload fields *before* serialization (M1), so escaping can never
//! corrupt the JSON. Out of scope for this subset: export bundles, mihomo
//! connection 5-tuples, and anything carrying a token, a secret, or
//! catalog YAML.

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use anyhow::{Context as _, Result};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;

use crate::{process::AsyncHandler, tono::state};

/// Log file name inside `app_home_dir()/tono/logs` (§8).
pub const AUDIT_FILE_NAME: &str = "traffic-audit.jsonl";
/// The single retained backup generation.
pub const AUDIT_BACKUP_FILE_NAME: &str = "traffic-audit.1.jsonl";
/// §8 size cap: rotate at 10 MiB, keeping 2 generations.
pub const MAX_AUDIT_FILE_BYTES: u64 = 10 * 1024 * 1024;
/// Settings file (`{audit_enabled: bool}`) inside the Tono data dir.
pub const SETTINGS_FILE_NAME: &str = "settings.json";
/// Bounded channel capacity; overflow drops events (counted).
const CHANNEL_CAPACITY: usize = 256;

// ---- Event model (§8): one JSON object per line, `{ts, kind, ...}` ----

/// One audit record: epoch-millis timestamp plus the flattened event, so a
/// line reads `{"ts":…,"kind":"connectBegin","node":"…"}`.
#[derive(Debug, Clone, Serialize)]
pub struct AuditRecord {
    pub ts: i64,
    #[serde(flatten)]
    pub event: AuditEvent,
}

impl AuditRecord {
    pub fn now(event: AuditEvent) -> Self {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis() as i64)
            .unwrap_or(0);
        Self { ts, event }
    }
}

/// Audit events. Tokens, verification codes, controller secrets, and
/// catalog YAML never appear in any payload; emails are recorded verbatim
/// (this is a local-only log).
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum AuditEvent {
    // account
    SignInStart {
        email: String,
    },
    SignInOk {
        email: String,
    },
    SignOut,
    RevokeDevice {
        id: String,
    },
    RetryRestore,
    // catalog
    SyncOk {
        revision: i64,
        node_count: usize,
    },
    SyncFail {
        error: String,
    },
    SelectionVanished {
        node: String,
    },
    RequiresChoiceCleared,
    // protection
    ConnectBegin {
        node: String,
    },
    Stage {
        stage: &'static str,
        elapsed_ms: u64,
    },
    ConnectFail {
        stage: Option<&'static str>,
        error: String,
        action: &'static str,
    },
    ConnectOk {
        node: String,
        elapsed_ms: u64,
    },
    DisconnectBegin {
        cause: &'static str,
    },
    DisconnectOk,
    ReleaseFail {
        error: String,
    },
    ReconnectScheduled {
        delay_ms: u64,
    },
    NodeSwitch {
        from: String,
        to: String,
    },
    ProtectedOffline {
        reason: &'static str,
    },
    // service
    KillSwitchSnapshot {
        wanted: bool,
        live: bool,
        mode: &'static str,
        endpoints: usize,
    },
    NetworkChange {
        counter: u64,
    },
    CoreRestart {
        old_pid: Option<u32>,
        new_pid: Option<u32>,
        restart_count: u32,
    },
    HealthProbeFail {
        probe: &'static str,
        error: String,
    },
    // cloud traffic policy (Build 28)
    PolicySyncOk {
        revision: i64,
        domains: usize,
        media: usize,
    },
    PolicyActivated {
        tcp: usize,
        udp: usize,
    },
    PolicySyncFail {
        error: String,
    },
    // lifecycle
    AuditEnabled,
    AuditDisabled,
}

impl AuditEvent {
    /// Redact every free-text payload field before serialization (M1):
    /// raw strings only, so the serde escaping afterwards stays intact and
    /// adversarial content (embedded quotes, JSON fragments) cannot corrupt
    /// the line.
    pub fn redacted(self) -> Self {
        use AuditEvent::*;
        match self {
            SignInStart { email } => SignInStart { email: redact(&email) },
            SignInOk { email } => SignInOk { email: redact(&email) },
            RevokeDevice { id } => RevokeDevice { id: redact(&id) },
            SyncFail { error } => SyncFail { error: redact(&error) },
            SelectionVanished { node } => SelectionVanished { node: redact(&node) },
            ConnectBegin { node } => ConnectBegin { node: redact(&node) },
            ConnectFail { stage, error, action } => ConnectFail {
                stage,
                error: redact(&error),
                action,
            },
            ConnectOk { node, elapsed_ms } => ConnectOk {
                node: redact(&node),
                elapsed_ms,
            },
            ReleaseFail { error } => ReleaseFail { error: redact(&error) },
            NodeSwitch { from, to } => NodeSwitch {
                from: redact(&from),
                to: redact(&to),
            },
            HealthProbeFail { probe, error } => HealthProbeFail {
                probe,
                error: redact(&error),
            },
            PolicySyncFail { error } => PolicySyncFail { error: redact(&error) },
            other => other,
        }
    }
}

// ---- Redaction (§8, macOS LocalTrafficAudit pattern parity) ----

static REDACTIONS: Lazy<Vec<(Regex, &'static str)>> = Lazy::new(|| {
    vec![
        // Authorization / Cookie header values (up to quote/comma/newline,
        // so a "Bearer <token>" value is consumed whole).
        (
            Regex::new(r#"(?i)Authorization\s*:\s*[^\n",]*"#).unwrap(),
            "Authorization: ***",
        ),
        (Regex::new(r#"(?i)Cookie\s*:\s*[^"\n]*"#).unwrap(), "Cookie: ***"),
        // Bearer tokens (case-insensitive).
        (Regex::new(r#"(?i)Bearer\s+\S+"#).unwrap(), "Bearer ***"),
        // JSON-ish token shapes: "token":"…", token=…, accessToken / refreshToken.
        (
            Regex::new(r#"(?i)((?:access_|refresh_)?token)["\\]*\s*[:=]\s*["\\]*[^\s"\\,&]+"#).unwrap(),
            "${1}=***",
        ),
        // token= / password= values (case-insensitive).
        (Regex::new(r#"(?i)token=[^&\s"]+"#).unwrap(), "token=***"),
        (Regex::new(r#"(?i)password=[^&\s"]+"#).unwrap(), "password=***"),
        // URL query strings.
        (Regex::new(r#"\?[^\s"]+"#).unwrap(), "?***"),
        // userinfo (creds@host) inside URLs.
        (Regex::new(r#"://[^/@\s"]+@"#).unwrap(), "://***@"),
    ]
});

/// Redact credentials, tokens, and URL-borne secrets from a raw payload
/// fragment. Pure; applied to every String event field before serde ever
/// sees it.
pub fn redact(input: &str) -> String {
    let mut output = input.to_string();
    for (pattern, replacement) in REDACTIONS.iter() {
        output = pattern.replace_all(&output, *replacement).into_owned();
    }
    output
}

// ---- Rotating writer ----

/// Appends JSONL lines to `path`, rotating into a single backup generation
/// when the cap is exceeded. Files are created owner-only (0600 / private
/// DACL) via the shared helpers.
struct RotatingWriter {
    file: std::fs::File,
    path: PathBuf,
    written: u64,
    cap: u64,
}

impl RotatingWriter {
    fn open(path: &Path, cap: u64) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = state::open_private_append(path)?;
        let written = file.metadata()?.len();
        Ok(Self {
            file,
            path: path.to_path_buf(),
            written,
            cap,
        })
    }

    fn backup_path(&self) -> PathBuf {
        self.path.with_file_name(AUDIT_BACKUP_FILE_NAME)
    }

    /// Live lines flush per write (low volume, immediately observable);
    /// the quit drain passes `flush = false` and flushes once at the end
    /// (L4: WM_ENDSESSION gives the process a bounded budget).
    fn write_line(&mut self, line: &str, flush: bool) -> std::io::Result<()> {
        use std::io::Write as _;

        let incoming = line.len() as u64 + 1;
        if self.written > 0 && self.written + incoming > self.cap {
            self.rotate()?;
        }
        writeln!(self.file, "{line}")?;
        if flush {
            self.file.flush()?;
        }
        self.written += incoming;
        Ok(())
    }

    /// current → `.1` (single retained generation), fresh current file.
    fn rotate(&mut self) -> std::io::Result<()> {
        use std::io::Write as _;

        self.file.flush()?;
        let backup = self.backup_path();
        match std::fs::remove_file(&backup) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        std::fs::rename(&self.path, &backup)?;
        self.file = state::open_private_append(&self.path).map_err(|err| std::io::Error::other(err.to_string()))?;
        self.written = 0;
        Ok(())
    }

    /// Final flush + durable sync (used once at drain end, L4).
    fn sync(&mut self) -> std::io::Result<()> {
        self.file.sync_all()
    }
}

/// The blocking writer loop: drains the channel until every sender is gone
/// (the quit path drops the last one to flush), then syncs once and exits.
/// Live lines flush per write; drain-phase lines (channel closed) batch.
fn writer_loop(mut receiver: tokio::sync::mpsc::Receiver<AuditRecord>, path: PathBuf) {
    let mut writer = match RotatingWriter::open(&path, MAX_AUDIT_FILE_BYTES) {
        Ok(writer) => writer,
        Err(_) => {
            // Drain anyway so senders never see a full channel with no
            // reader; the events are simply lost.
            while receiver.blocking_recv().is_some() {}
            return;
        }
    };
    while let Some(record) = receiver.blocking_recv() {
        let Ok(line) = serde_json::to_string(&record) else {
            continue;
        };
        // A disk error drops the line; the loop must keep draining so the
        // bounded channel never backs up into the product paths.
        let _ = writer.write_line(&line, !receiver.is_closed());
    }
    let _ = writer.sync();
}

// ---- Settings (`tono/settings.json`) ----

#[derive(serde::Serialize, serde::Deserialize)]
struct SettingsFile {
    audit_enabled: bool,
}

/// Default is ON (macOS parity): a missing or corrupt settings file reads
/// as enabled.
pub fn audit_enabled_from_settings(dir: &Path) -> bool {
    std::fs::read_to_string(dir.join(SETTINGS_FILE_NAME))
        .ok()
        .and_then(|body| serde_json::from_str::<SettingsFile>(&body).ok())
        .map(|settings| settings.audit_enabled)
        .unwrap_or(true)
}

/// Atomic settings write (L3): temp file with owner-only protection, then
/// rename over the live one.
fn save_audit_enabled(dir: &Path, enabled: bool) -> Result<()> {
    let body =
        serde_json::to_string(&SettingsFile { audit_enabled: enabled }).context("failed to serialize settings")?;
    let temp = dir.join(format!(".{SETTINGS_FILE_NAME}.tmp-{}", std::process::id()));
    let write_result = state::write_private_file(&temp, body.as_bytes());
    let result = write_result
        .and_then(|()| std::fs::rename(&temp, dir.join(SETTINGS_FILE_NAME)).context("failed to publish settings"));
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

// ---- Audit handle ----

/// The product-wide audit handle: an atomic enable flag plus a bounded
/// channel feeding the writer task. The writer self-heals when its task
/// died unexpectedly (L1); after `close_sender` (quit) it never revives.
pub struct Audit {
    sender: parking_lot::Mutex<Option<tokio::sync::mpsc::Sender<AuditRecord>>>,
    writer: parking_lot::Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
    enabled: AtomicBool,
    /// Set by the quit path: permanently silences logging and blocks the
    /// self-heal respawn (L1's "closed is not dead" distinction).
    closed: AtomicBool,
    /// L1: whether a dead writer task may be respawned (false in tests,
    /// where the channel is wired externally).
    self_heal: bool,
    /// Events dropped because the channel was full (L2).
    dropped: AtomicU64,
    settings_dir: PathBuf,
    log_path: PathBuf,
}

impl Audit {
    /// Open the log under `logs_dir`, load the toggle from `settings_dir`,
    /// and spawn the writer task.
    pub fn new(logs_dir: &Path, settings_dir: &Path) -> Arc<Self> {
        let audit = Arc::new(Self {
            sender: parking_lot::Mutex::new(None),
            writer: parking_lot::Mutex::new(None),
            enabled: AtomicBool::new(audit_enabled_from_settings(settings_dir)),
            closed: AtomicBool::new(false),
            self_heal: true,
            dropped: AtomicU64::new(0),
            settings_dir: settings_dir.to_path_buf(),
            log_path: logs_dir.join(AUDIT_FILE_NAME),
        });
        audit.ensure_writer();
        audit
    }

    /// A diskless instance for tests: events go to `sender`, nothing is
    /// written to disk, settings persist into `settings_dir`, and the
    /// writer never respawns over the external wiring.
    #[cfg(test)]
    pub fn for_test(sender: tokio::sync::mpsc::Sender<AuditRecord>, settings_dir: &Path, enabled: bool) -> Arc<Self> {
        Arc::new(Self {
            sender: parking_lot::Mutex::new(Some(sender)),
            writer: parking_lot::Mutex::new(None),
            enabled: AtomicBool::new(enabled),
            closed: AtomicBool::new(false),
            self_heal: false,
            dropped: AtomicU64::new(0),
            settings_dir: settings_dir.to_path_buf(),
            log_path: settings_dir.join(AUDIT_FILE_NAME),
        })
    }

    /// Spawn a fresh channel + writer when the previous task died (crash)
    /// and the handle was never closed. No-op while alive, after close, or
    /// without self-heal (tests).
    fn ensure_writer(&self) {
        if self.closed.load(Ordering::Acquire) || !self.self_heal {
            return;
        }
        let mut writer = self.writer.lock();
        let alive = writer.as_ref().is_some_and(|handle| !handle.inner().is_finished());
        if alive {
            return;
        }
        let (sender, receiver) = tokio::sync::mpsc::channel(CHANNEL_CAPACITY);
        *self.sender.lock() = Some(sender);
        let path = self.log_path.clone();
        *writer = Some(AsyncHandler::spawn_blocking(move || {
            writer_loop(receiver, path);
        }));
    }

    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Non-blocking, best-effort, never panics: disabled, closed, or a full
    /// channel drops the event (the last one counted).
    pub fn log(&self, event: AuditEvent) {
        if !self.enabled() || self.closed.load(Ordering::Acquire) {
            return;
        }
        self.ensure_writer();
        self.record(event);
    }

    /// Bypasses the toggle — used only for the lifecycle markers
    /// (`auditDisabled` must land as the last line before silence).
    fn record(&self, event: AuditEvent) {
        let sender = self.sender.lock();
        if let Some(sender) = sender.as_ref()
            && sender.try_send(AuditRecord::now(event.redacted())).is_err()
        {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Toggle the switch (L3): persist first — the in-memory flag flips
    /// only on success, so the two never diverge — then emit the matching
    /// lifecycle marker (§8).
    pub fn set_enabled(&self, enabled: bool) -> Result<(), String> {
        if self.enabled() == enabled {
            return Ok(());
        }
        save_audit_enabled(&self.settings_dir, enabled).map_err(|err| err.to_string())?;
        self.enabled.store(enabled, Ordering::Release);
        if enabled {
            self.record(AuditEvent::AuditEnabled);
        } else {
            self.record(AuditEvent::AuditDisabled);
        }
        Ok(())
    }

    /// Quit path: mark closed (no self-heal resurrection) and drop the
    /// sender so the writer drains and exits; the caller then awaits the
    /// task handle from `take_writer`.
    pub fn close_sender(&self) {
        self.closed.store(true, Ordering::Release);
        self.sender.lock().take();
    }

    pub fn take_writer(&self) -> Option<tauri::async_runtime::JoinHandle<()>> {
        self.writer.lock().take()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Audit, AuditEvent, AuditRecord, MAX_AUDIT_FILE_BYTES, RotatingWriter, audit_enabled_from_settings, redact,
    };
    use std::path::{Path, PathBuf};

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let serial = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("tono-audit-test-{tag}-{}-{serial}", std::process::id()));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    // ---- redaction: one case per pattern group ----

    #[test]
    fn redact_authorization_header() {
        // The value runs to quote/comma/newline: prose after it is consumed
        // too — over-redaction is deliberate, leaking is not an option.
        assert_eq!(
            redact("failed: Authorization: abc.def.ghi rejected"),
            "failed: Authorization: ***"
        );
        assert_eq!(redact("authorization: xyz"), "Authorization: ***");
    }

    #[test]
    fn redact_cookie_header() {
        assert_eq!(redact("Cookie: session=abc; theme=dark"), "Cookie: ***");
    }

    #[test]
    fn redact_bearer_token() {
        assert_eq!(redact("Authorization: Bearer abc123.def456"), "Authorization: ***");
        assert_eq!(redact("sent Bearer abc123"), "sent Bearer ***");
        // Case-insensitive (M1).
        assert_eq!(redact("sent BEARER abc123"), "sent Bearer ***");
    }

    #[test]
    fn redact_token_and_password_params() {
        assert_eq!(redact("refresh?token=abc123&ok=1"), "refresh?***");
        assert_eq!(redact("body token=abc123 end"), "body token=*** end");
        assert_eq!(redact("body password=hunter2 end"), "body password=*** end");
        // Case-insensitive (M1).
        assert_eq!(redact("body Token=abc123 end"), "body token=*** end");
        assert_eq!(redact("body PASSWORD=hunter2 end"), "body password=*** end");
    }

    #[test]
    fn redact_json_token_shapes() {
        // M1: `"token":"…"` / accessToken / refreshToken JSON forms.
        assert_eq!(redact(r#"payload {"token":"abc"}"#), r#"payload {"token=***"}"#);
        assert!(!redact(r#"{"accessToken":"zzz"}"#).contains("zzz"));
        assert!(!redact(r#"{"refreshToken": "yyy"}"#).contains("yyy"));
    }

    #[test]
    fn redact_url_query() {
        assert_eq!(
            redact("GET https://api.example.com/devices?token=abc&x=1 failed"),
            "GET https://api.example.com/devices?*** failed"
        );
    }

    #[test]
    fn redact_userinfo() {
        assert_eq!(
            redact("dial https://user:pass@example.com/path"),
            "dial https://***@example.com/path"
        );
    }

    #[test]
    fn redacted_fields_keep_the_serialized_line_valid_json() {
        // Adversarial (M1): raw field with an embedded quote — redaction
        // happens before serde, so escaping stays correct.
        let record = AuditRecord::now(
            AuditEvent::SyncFail {
                error:
                    "GET https://x.test/a?token=abc failed: token=abc\"x Authorization: secret Bearer zzz password=p"
                        .to_string(),
            }
            .redacted(),
        );
        let line = serde_json::to_string(&record).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["kind"], "syncFail");
        let error = parsed["error"].as_str().unwrap();
        for secret in ["secret", "zzz", "abc"] {
            assert!(!error.contains(secret), "leaked {secret} in {error}");
        }
    }

    #[test]
    fn redacted_covers_every_string_field() {
        let events = vec![
            AuditEvent::SignInStart {
                email: "a?token=x@b.co".to_string(),
            },
            AuditEvent::SignInOk {
                email: "a?token=x@b.co".to_string(),
            },
            AuditEvent::RevokeDevice {
                id: "id token=abc".to_string(),
            },
            AuditEvent::SyncFail {
                error: "token=abc".to_string(),
            },
            AuditEvent::SelectionVanished {
                node: "n token=abc".to_string(),
            },
            AuditEvent::ConnectBegin {
                node: "n token=abc".to_string(),
            },
            AuditEvent::ConnectFail {
                stage: None,
                error: "token=abc".to_string(),
                action: "fullRelease",
            },
            AuditEvent::ConnectOk {
                node: "n token=abc".to_string(),
                elapsed_ms: 1,
            },
            AuditEvent::ReleaseFail {
                error: "token=abc".to_string(),
            },
            AuditEvent::NodeSwitch {
                from: "a token=abc".to_string(),
                to: "b token=abc".to_string(),
            },
        ];
        for event in events {
            let line = serde_json::to_string(&AuditRecord::now(event.redacted())).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
            let text = serde_json::to_string(&parsed).unwrap();
            assert!(!text.contains("abc"), "unredacted field in {text}");
            assert!(!text.contains("token=x"), "unredacted field in {text}");
        }
    }

    // ---- rotation ----

    fn log_path(dir: &TempDir) -> PathBuf {
        dir.path().join(super::AUDIT_FILE_NAME)
    }

    #[test]
    fn rotation_keeps_two_generations_and_parseable_lines() {
        let dir = TempDir::new("rotate");
        let path = log_path(&dir);
        let cap = 512_u64;
        let mut writer = RotatingWriter::open(&path, cap).unwrap();
        for index in 0..40 {
            let line = serde_json::to_string(&AuditRecord::now(AuditEvent::NetworkChange { counter: index })).unwrap();
            writer.write_line(&line, true).unwrap();
        }
        writer.sync().unwrap();

        let backup = dir.path().join(super::AUDIT_BACKUP_FILE_NAME);
        assert!(backup.exists(), "rotation must produce the backup generation");
        assert!(path.exists());
        // The fresh generation starts small; the backup holds the overflow.
        assert!(std::fs::metadata(&path).unwrap().len() < cap + 256);
        assert!(std::fs::metadata(&backup).unwrap().len() <= cap + 256);
        // Exactly two generations exist.
        let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().filter_map(|e| e.ok()).collect();
        assert_eq!(entries.len(), 2);
        // Every line in both files is a parseable record.
        for file in [&path, &backup] {
            for line in std::fs::read_to_string(file).unwrap().lines() {
                let value: serde_json::Value = serde_json::from_str(line).unwrap();
                assert_eq!(value["kind"], "networkChange");
                assert!(value["ts"].is_number());
                assert!(value["counter"].is_number());
            }
        }
        // Unix: both generations are owner-only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            for file in [&path, &backup] {
                assert_eq!(std::fs::metadata(file).unwrap().permissions().mode() & 0o777, 0o600);
            }
        }
    }

    #[test]
    fn rotation_size_cap_constant_is_10_mib() {
        assert_eq!(MAX_AUDIT_FILE_BYTES, 10 * 1024 * 1024);
    }

    // ---- toggle behaviour ----

    #[tokio::test]
    async fn disabled_drops_events_but_audit_disabled_is_the_last_line() {
        let dir = TempDir::new("toggle");
        let (sender, mut receiver) = tokio::sync::mpsc::channel(8);
        let audit = Audit::for_test(sender, dir.path(), true);

        audit.log(AuditEvent::SignOut);
        assert!(receiver.try_recv().is_ok(), "enabled: events flow");

        audit.set_enabled(false).unwrap();
        let last = receiver
            .try_recv()
            .expect("auditDisabled must be written before silence");
        assert_eq!(
            serde_json::to_value(&last).unwrap()["kind"],
            serde_json::json!("auditDisabled")
        );
        audit.log(AuditEvent::SignOut);
        assert!(receiver.try_recv().is_err(), "disabled: events are dropped");

        audit.set_enabled(true).unwrap();
        let marker = receiver.try_recv().expect("auditEnabled must be written on re-enable");
        assert_eq!(
            serde_json::to_value(&marker).unwrap()["kind"],
            serde_json::json!("auditEnabled")
        );
        audit.log(AuditEvent::RetryRestore);
        assert!(receiver.try_recv().is_ok(), "re-enabled: events flow again");

        // The toggle round-tripped through settings.json.
        let body = std::fs::read_to_string(dir.path().join(super::SETTINGS_FILE_NAME)).unwrap();
        let settings: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(settings["audit_enabled"], true);
    }

    #[tokio::test]
    async fn set_enabled_failure_keeps_flag_and_reports_error() {
        // L3: settings dir is a regular file — persistence must fail, the
        // flag must not flip, and the error must surface.
        let dir = TempDir::new("settings-fail");
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"not a directory").unwrap();
        let (sender, _receiver) = tokio::sync::mpsc::channel(8);
        let audit = Audit::for_test(sender, &blocker, true);

        assert!(audit.set_enabled(false).is_err());
        assert!(audit.enabled(), "failed persistence must not flip the flag");
        // The marker must not have been emitted either.
        assert_eq!(audit.dropped_count(), 0);
    }

    #[test]
    fn dropped_events_are_counted() {
        // L2: capacity-1 channel with no reader — the overflow is counted.
        let dir = TempDir::new("dropped");
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        let audit = Audit::for_test(sender, dir.path(), true);
        assert_eq!(audit.dropped_count(), 0);
        audit.log(AuditEvent::SignOut);
        audit.log(AuditEvent::SignOut);
        audit.log(AuditEvent::SignOut);
        assert_eq!(audit.dropped_count(), 2);
    }

    #[test]
    fn corrupt_or_missing_settings_defaults_to_enabled() {
        let dir = TempDir::new("settings");
        assert!(audit_enabled_from_settings(dir.path()), "missing file defaults to true");
        std::fs::write(dir.path().join(super::SETTINGS_FILE_NAME), "{not json").unwrap();
        assert!(audit_enabled_from_settings(dir.path()), "corrupt file defaults to true");
        std::fs::write(dir.path().join(super::SETTINGS_FILE_NAME), r#"{"audit_enabled":false}"#).unwrap();
        assert!(!audit_enabled_from_settings(dir.path()));
        // Unknown extra fields are tolerated.
        std::fs::write(
            dir.path().join(super::SETTINGS_FILE_NAME),
            r#"{"audit_enabled":false,"future":1}"#,
        )
        .unwrap();
        assert!(!audit_enabled_from_settings(dir.path()));
    }
}
