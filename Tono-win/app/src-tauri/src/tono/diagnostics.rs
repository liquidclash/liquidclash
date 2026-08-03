//! The user-initiated diagnostics report: assembly, scrubbing, whitelist.
//!
//! # Why this exists
//!
//! When a connect fails, the kill switch usually has the machine fully
//! network-blocked — but the WFP bootstrap policy deliberately keeps the
//! pinned API host IPs reachable on TCP/443 as a control-plane recovery
//! channel (`tono::bootstrap`), and the app's API client is pinned to those
//! same addresses (`tono::transport`). So an upload over the ordinary Tono
//! API transport succeeds *precisely* when the user has no other
//! connectivity, which is when the report is worth having.
//!
//! # Privacy posture (non-negotiable — this is a VPN)
//!
//! * The upload is **user-initiated only**. This module has no timer, no
//!   crash hook, and no background caller; the only entry points are the two
//!   Tauri commands the "Upload diagnostics" button drives.
//! * [`build_report`] is a **whitelist**. Every field is named by hand and
//!   copied from a specific source. No product struct is ever serialized
//!   wholesale, and there is no redact-and-hope blacklist pass over a blob.
//! * Free text (connect error, kill-switch/DNS `last_error`) is redacted a
//!   second time through the audit redactor *and* has IPv4 literals removed,
//!   because catalog node addresses are IPv4 literals by contract
//!   (`tono_core::node::ValidatedNode::server`) and could otherwise ride
//!   along inside an error message.
//! * Filesystem paths are scrubbed of the user's profile directory, so the
//!   Windows account name is not uploaded.
//!
//! Never uploaded, by construction (there is no field for them): the
//! generated runtime YAML or any part of it, the controller secret, node
//! UUIDs, Reality public keys / short ids, access or refresh tokens, the
//! Service owner token, and node IP addresses — including
//! `KillSwitchStatus::endpoints`, which is a list of node endpoints and is
//! deliberately *not* read here.
//!
//! # The Service's own log
//!
//! `C:\ProgramData\Tono\logs\tono-service.log` lives in a SYSTEM/Admins-only
//! directory, so the unprivileged app cannot read it. The report carries its
//! *path* only. Shipping its tail would need a new privileged IPC route and
//! is a deliberate follow-up, not part of this change.

use std::path::{Path, PathBuf};

use clash_verge_service_ipc::{DnsProtectionStatus, KillSwitchStatus, ProtocolInfo};
use once_cell::sync::Lazy;
use regex::Regex;
use tono_core::auth::{DIAGNOSTICS_SCHEMA_VERSION, DiagnosticsStep};
// Re-exported so callers say `tono::diagnostics::DiagnosticsReport`: the
// payload's single definition lives in `tono_core::auth` next to the
// endpoint it is posted to.
pub use tono_core::auth::DiagnosticsReport;

use crate::tono::steps::{StepRecord, state_key};

/// Upper bound on any single free-text field. A runaway error string must not
/// turn a diagnostics upload into a bulk transfer over the recovery channel.
const MAX_TEXT_LEN: usize = 2000;

/// Shortest known-secret value worth substituting. Below this a "secret"
/// is as likely to be a substring of ordinary words, and blanking it would
/// shred the message without protecting anything.
const MIN_KNOWN_SECRET_LEN: usize = 6;

/// IPv4 literals in free text. Catalog nodes are guaranteed IPv4 literals, so
/// this is the shape that could leak an exit address through an error
/// message. IPv6 is not matched: no product value is an IPv6 literal, and a
/// loose IPv6 pattern mangles timestamps and durations instead.
static IPV4: Lazy<Regex> = Lazy::new(|| {
    #[expect(clippy::unwrap_used, reason = "a constant pattern that is covered by tests")]
    Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap()
});

/// Canonical UUIDs — the shape of a catalog node id.
static UUID: Lazy<Regex> = Lazy::new(|| {
    #[expect(clippy::unwrap_used, reason = "a constant pattern that is covered by tests")]
    Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b").unwrap()
});

/// Long opaque runs from the base64/hex/JWT alphabet. This is the catch-all
/// for secret material the product may grow that no rule above knows about:
/// the per-start controller secret (base64 of 32 bytes), the Service owner
/// token (hex), Reality public keys, and bearer/refresh tokens all land here.
/// A run is only blanked when it mixes letters and digits, which is what
/// keeps ordinary prose, stage keys, and error class names intact.
static OPAQUE_RUN: Lazy<Regex> = Lazy::new(|| {
    #[expect(clippy::unwrap_used, reason = "a constant pattern that is covered by tests")]
    Regex::new(r"[A-Za-z0-9+/=_-]{20,}").unwrap()
});

/// Substring markers for adapters that can carry traffic around the tunnel,
/// mapped to the fixed class token the report is allowed to contain. The
/// adapter's actual name is never uploaded: a user can rename an adapter, and
/// the name would then be free-form user text.
const VIRTUAL_ADAPTER_MARKERS: &[(&str, &str)] = &[
    ("vethernet", "hyperV"),
    ("hyper-v", "hyperV"),
    ("default switch", "hyperV"),
    ("wsl", "wsl"),
    ("vmware", "vmware"),
    ("virtualbox", "virtualBox"),
    ("vboxnet", "virtualBox"),
    ("docker", "docker"),
    ("km-test", "loopbackAdapter"),
];

/// Scrub one free-text field, strictest-first:
///
/// 1. exact matches of the live secrets the app is currently holding
///    (`known` — controller secret, node ids/keys/addresses, refresh token),
/// 2. the product's own audit redactor (headers, bearer/token shapes, query
///    strings, URL userinfo),
/// 3. UUIDs, IPv4 literals, and long opaque runs,
/// 4. trim and cap.
///
/// Steps 1 and 3 overlap on purpose: (1) is exact but only covers what the
/// app happens to hold in memory, (3) is structural and covers the rest.
fn scrub_text_with(raw: &str, known: &[String]) -> String {
    let mut text = raw.to_string();
    for secret in known {
        let secret = secret.trim();
        if secret.chars().count() >= MIN_KNOWN_SECRET_LEN {
            text = text.replace(secret, "<redacted>");
        }
    }
    let text = crate::tono::audit::redact(&text);
    let text = UUID.replace_all(&text, "<uuid>");
    let text = IPV4.replace_all(&text, "<ip>");
    let text = OPAQUE_RUN.replace_all(&text, |captures: &regex::Captures<'_>| {
        let run = &captures[0];
        let mixed = run.chars().any(|character| character.is_ascii_digit())
            && run.chars().any(|character| character.is_ascii_alphabetic());
        if mixed { "<redacted>".to_string() } else { run.to_string() }
    });
    let trimmed = text.trim();
    let mut capped: String = trimmed.chars().take(MAX_TEXT_LEN).collect();
    if trimmed.chars().count() > MAX_TEXT_LEN {
        capped.push('…');
    }
    capped
}

fn scrub_opt_text(raw: Option<&str>, known: &[String]) -> Option<String> {
    raw.map(|text| scrub_text_with(text, known))
        .filter(|text| !text.is_empty())
}

/// Replace the user's profile directory with `%USERPROFILE%` so the Windows
/// account name is not uploaded. The result is still something support can
/// tell the user to paste into Explorer verbatim.
///
/// Matching is case-insensitive: Windows paths compare that way, and the
/// value of `%USERPROFILE%` frequently differs in case from the path the
/// audit writer recorded.
pub fn scrub_home(path: &Path, home: Option<&Path>) -> String {
    let text = path.to_string_lossy().into_owned();
    let Some(home) = home else { return text };
    let home = home.to_string_lossy();
    let home = home.trim_end_matches(['\\', '/']);
    if home.is_empty() {
        return text;
    }
    if text.len() >= home.len() && text[..home.len()].eq_ignore_ascii_case(home) {
        return format!("%USERPROFILE%{}", &text[home.len()..]);
    }
    text
}

/// The user's profile directory, for [`scrub_home`].
pub fn home_dir() -> Option<PathBuf> {
    let key = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(key).map(PathBuf::from).filter(|path| !path.as_os_str().is_empty())
}

/// Classify adapter names into the fixed class tokens above: sorted, deduped,
/// and never carrying the raw name.
pub fn classify_virtual_adapters(names: &[String]) -> Vec<String> {
    let mut classes: Vec<String> = Vec::new();
    for name in names {
        let lowered = name.to_lowercase();
        for (marker, class) in VIRTUAL_ADAPTER_MARKERS {
            if lowered.contains(marker) && !classes.iter().any(|existing| existing == class) {
                classes.push((*class).to_string());
            }
        }
    }
    classes.sort_unstable();
    classes
}

/// Where the Service writes its own log. The app cannot read it (see the
/// module docs); only the path travels.
pub fn service_log_path() -> PathBuf {
    clash_verge_service_ipc::service_paths()
        .persistent_state_dir()
        .join("logs")
        .join("tono-service.log")
}

/// Everything [`build_report`] is allowed to read. Passing the sources
/// explicitly — rather than handing the builder the product state — is what
/// makes "this is a whitelist" checkable: a field that is not in this struct
/// cannot reach the payload, and the tests feed it deliberately poisoned
/// values to prove nothing else escapes.
pub struct DiagnosticsSources<'a> {
    pub app_version: &'a str,
    pub os_version: &'a str,
    pub os_arch: &'a str,
    pub service_protocol: Option<&'a ProtocolInfo>,
    pub ui_state: &'a str,
    pub account_state: &'a str,
    /// The catalog *display* name of the selection ("US West 1"), never its
    /// address or UUID.
    pub selected_server: Option<&'a str>,
    pub catalog_revision: Option<i64>,
    /// Read for mode/wanted/live/last_error only — `endpoints` (node IPs) is
    /// deliberately ignored.
    pub kill_switch: Option<&'a KillSwitchStatus>,
    pub dns: Option<&'a DnsProtectionStatus>,
    pub failed_stage: Option<&'a str>,
    pub connect_error: Option<&'a str>,
    pub retry_attempt: u32,
    pub steps: &'a [StepRecord],
    /// Raw adapter names in; only class tokens come out.
    pub adapter_names: &'a [String],
    /// Live secret values the app is currently holding — the per-start
    /// controller secret, every catalog node's UUID / Reality public key /
    /// Reality short id / address, and the refresh token. They are removed
    /// from every free-text field by exact match, on top of the structural
    /// rules. Nothing here is ever *emitted*; it is only ever subtracted.
    pub known_secrets: &'a [String],
    pub audit_log_path: &'a Path,
    pub service_log_path: &'a Path,
    pub home_dir: Option<&'a Path>,
    pub reported_at_ms: i64,
}

/// Assemble the whitelisted report. Pure: the same sources always produce the
/// same payload, which is what lets the UI show the user exactly what will be
/// uploaded before they confirm.
pub fn build_report(sources: &DiagnosticsSources<'_>) -> DiagnosticsReport {
    let steps: Vec<DiagnosticsStep> = sources
        .steps
        .iter()
        .map(|step| DiagnosticsStep {
            // `key` is a compile-time stage token, never user text.
            key: step.key.to_string(),
            state: state_key(step.state).to_string(),
            elapsed_ms: step.elapsed_ms,
        })
        .collect();
    let total_elapsed_ms = crate::tono::steps::total_elapsed_ms(sources.steps);
    let known = sources.known_secrets;

    DiagnosticsReport {
        schema_version: DIAGNOSTICS_SCHEMA_VERSION,
        reported_at_ms: sources.reported_at_ms,
        app_version: scrub_text_with(sources.app_version, known),
        os_version: scrub_text_with(sources.os_version, known),
        os_arch: scrub_text_with(sources.os_arch, known),
        service_protocol: sources
            .service_protocol
            .map(|info| info.protocol.header_value()),
        service_build: sources
            .service_protocol
            .map(|info| scrub_text_with(&info.build_version, known)),
        ui_state: sources.ui_state.to_string(),
        account_state: sources.account_state.to_string(),
        selected_server: scrub_opt_text(sources.selected_server, known),
        catalog_revision: sources.catalog_revision,
        kill_switch_mode: sources
            .kill_switch
            .map(|status| format!("{:?}", status.mode).to_lowercase()),
        kill_switch_wanted: sources.kill_switch.map(|status| status.wanted),
        kill_switch_live: sources.kill_switch.map(|status| status.live),
        kill_switch_last_error: sources
            .kill_switch
            .and_then(|status| scrub_opt_text(status.last_error.as_deref(), known)),
        dns_enabled: sources.dns.map(|status| status.enabled),
        dns_last_error: sources
            .dns
            .and_then(|status| scrub_opt_text(status.last_error.as_deref(), known)),
        failed_stage: sources.failed_stage.map(str::to_string),
        error: scrub_opt_text(sources.connect_error, known),
        retry_attempt: sources.retry_attempt,
        total_elapsed_ms,
        steps,
        virtual_adapters: classify_virtual_adapters(sources.adapter_names),
        audit_log_path: scrub_home(sources.audit_log_path, sources.home_dir),
        service_log_path: scrub_home(sources.service_log_path, sources.home_dir),
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert by panicking")]
mod tests {
    use super::*;
    use clash_verge_service_ipc::{KillSwitchStatusMode, ProtocolVersion, ProxyEndpoint, ProxyProtocol};
    use tono_core::connection::ConnectStage;

    /// Every key the payload is allowed to contain. Kept spelled out so a new
    /// field is a deliberate, reviewable edit rather than a silent widening.
    const ALLOWED_KEYS: &[&str] = &[
        "accountState",
        "appVersion",
        "auditLogPath",
        "catalogRevision",
        "dnsEnabled",
        "dnsLastError",
        "error",
        "failedStage",
        "killSwitchLastError",
        "killSwitchLive",
        "killSwitchMode",
        "killSwitchWanted",
        "osArch",
        "osVersion",
        "reportedAtMs",
        "retryAttempt",
        "schemaVersion",
        "selectedServer",
        "serviceBuild",
        "serviceLogPath",
        "serviceProtocol",
        "steps",
        "totalElapsedMs",
        "uiState",
        "virtualAdapters",
    ];

    // Secret material in its real shapes — base64 controller secret, hex
    // owner token, UUID node id, JWT access token — so the scrubber is tested
    // against what it will actually meet rather than against strings chosen
    // to be easy to match.

    /// Per-start controller secret: base64 of 32 bytes (`generate_controller_secret`).
    const CONTROLLER_SECRET: &str = "Zk9sQ2h3TnBWMmJYcTdSdEx1TWc4WWFFakRmSzFuMD0=";
    /// Service owner token: 64 hex characters.
    const OWNER_TOKEN: &str = "8f14e45fceea167a5a36dedd4bea2543f14e45fceea167a5a36dedd4bea25431";
    const NODE_UUID: &str = "0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9";
    const REALITY_PUBLIC_KEY: &str = "xB3kQ2mZ9pL0vN7sT1yU4wA6cE8gI5oR7dF2hJ4kL6M";
    /// Reality short id: 8 hex characters — too short and too low-entropy for
    /// any structural rule, so only the known-secret pass can catch it.
    const REALITY_SHORT_ID: &str = "a1b2c3d4";
    const REFRESH_TOKEN: &str = "rt_9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c";
    const ACCESS_TOKEN: &str = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MSJ9.QmFkU2lnbmF0dXJl";
    const NODE_IP: &str = "203.0.113.77";
    const OTHER_NODE_IP: &str = "198.51.100.9";

    /// None of these may appear in a payload, whichever rule catches them.
    const SECRETS: &[&str] = &[
        CONTROLLER_SECRET,
        OWNER_TOKEN,
        NODE_UUID,
        REALITY_PUBLIC_KEY,
        REALITY_SHORT_ID,
        REFRESH_TOKEN,
        ACCESS_TOKEN,
        NODE_IP,
        OTHER_NODE_IP,
    ];
    // The generated runtime YAML is absent for a structural reason rather
    // than a scrubbing one: no field carries it, which
    // `the_payload_contains_exactly_the_whitelisted_keys` is what proves.

    /// Product state at report time, deliberately poisoned: the kill-switch
    /// aggregate carries node endpoints, and every free-text field carries a
    /// different class of secret.
    struct Fixture {
        steps: Vec<StepRecord>,
        adapters: Vec<String>,
        kill_switch: KillSwitchStatus,
        dns: DnsProtectionStatus,
        protocol: ProtocolInfo,
        /// What the app is holding in memory and therefore knows to subtract.
        known: Vec<String>,
        connect_error: String,
    }

    impl Fixture {
        fn new(adapters: &[&str]) -> Self {
            let mut steps = crate::tono::steps::initial_steps();
            crate::tono::steps::advance(&mut steps, ConnectStage::PreparingService, 1200);
            crate::tono::steps::fail_current(&mut steps, 8000);
            Self {
                steps,
                adapters: adapters.iter().map(|name| (*name).to_string()).collect(),
                kill_switch: KillSwitchStatus {
                    wanted: true,
                    verified: false,
                    live: false,
                    mode: KillSwitchStatusMode::Blocked,
                    // Node endpoints. The builder must never read this field.
                    endpoints: vec![
                        ProxyEndpoint {
                            ip: NODE_IP.to_string(),
                            port: 443,
                            protocol: ProxyProtocol::Tcp,
                        },
                        ProxyEndpoint {
                            ip: OTHER_NODE_IP.to_string(),
                            port: 443,
                            protocol: ProxyProtocol::Udp,
                        },
                    ],
                    tunnel_permit_rendered: false,
                    last_error: Some(format!(
                        "WFP permit for {NODE_IP}:443 rejected; Authorization: Bearer {ACCESS_TOKEN}"
                    )),
                },
                dns: DnsProtectionStatus {
                    enabled: false,
                    snapshot_present: true,
                    adapters: 3,
                    last_error: Some(format!(
                        "resolver {OTHER_NODE_IP} unreachable; token={REFRESH_TOKEN}"
                    )),
                },
                protocol: ProtocolInfo::current(),
                known: [
                    CONTROLLER_SECRET,
                    NODE_UUID,
                    REALITY_PUBLIC_KEY,
                    REALITY_SHORT_ID,
                    REFRESH_TOKEN,
                    NODE_IP,
                    OTHER_NODE_IP,
                ]
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
                connect_error: format!(
                    "core start failed: node {NODE_UUID} at {NODE_IP}:443, \
                     refreshToken={REFRESH_TOKEN}, controller secret {CONTROLLER_SECRET}, \
                     owner token {OWNER_TOKEN}, public-key {REALITY_PUBLIC_KEY} \
                     short-id {REALITY_SHORT_ID}"
                ),
            }
        }

        fn sources(&self) -> DiagnosticsSources<'_> {
            DiagnosticsSources {
                app_version: "0.0.3",
                os_version: "Windows 11 Pro 23H2",
                os_arch: "x86_64",
                service_protocol: Some(&self.protocol),
                ui_state: "protectedOffline",
                account_state: "ready",
                selected_server: Some("US West 1"),
                catalog_revision: Some(12),
                kill_switch: Some(&self.kill_switch),
                dns: Some(&self.dns),
                failed_stage: Some("securingDNS"),
                connect_error: Some(&self.connect_error),
                retry_attempt: 2,
                steps: &self.steps,
                adapter_names: &self.adapters,
                known_secrets: &self.known,
                audit_log_path: Path::new(
                    r"C:\Users\Jane Doe\AppData\Roaming\io.tono\tono\logs\traffic-audit.jsonl",
                ),
                service_log_path: Path::new(r"C:\ProgramData\Tono\logs\tono-service.log"),
                home_dir: Some(Path::new(r"C:\Users\Jane Doe")),
                reported_at_ms: 1_712_345_678_901,
            }
        }
    }

    #[test]
    fn the_payload_contains_exactly_the_whitelisted_keys() {
        let fixture = Fixture::new(&["Ethernet"]);
        let report = build_report(&fixture.sources());

        let value = serde_json::to_value(&report).unwrap();
        let mut keys: Vec<&str> = value.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ALLOWED_KEYS, "the report must be a whitelist");

        for step in value["steps"].as_array().unwrap() {
            let mut step_keys: Vec<&str> = step.as_object().unwrap().keys().map(String::as_str).collect();
            step_keys.sort_unstable();
            assert_eq!(step_keys, ["elapsedMs", "key", "state"]);
        }
    }

    #[test]
    fn a_report_built_from_state_carrying_secrets_leaks_none_of_them() {
        let fixture = Fixture::new(&[
            "Ethernet",
            "vEthernet (WSL (Hyper-V firewall))",
            "VMware Network Adapter VMnet8",
        ]);
        let report = build_report(&fixture.sources());

        let serialized = serde_json::to_string(&report).unwrap();
        for secret in SECRETS {
            assert!(
                !serialized.contains(secret),
                "payload leaked {secret:?}:\n{serialized}"
            );
        }
        // Node endpoints are not merely redacted — the field is never read.
        assert!(!serialized.contains("endpoints"), "{serialized}");
        // The error still reads as a useful sentence afterwards.
        let error = report.error.as_deref().unwrap();
        assert!(error.starts_with("core start failed: node <redacted> at <redacted>:443"), "{error}");
        let kill_switch_error = report.kill_switch_last_error.as_deref().unwrap();
        assert!(
            kill_switch_error.starts_with("WFP permit for <redacted>:443 rejected"),
            "{kill_switch_error}"
        );
    }

    #[test]
    fn secrets_are_scrubbed_even_when_the_app_does_not_know_their_values() {
        // The structural rules alone (no known-secret list) must still catch
        // the UUID, the IPv4 literal, the JWT, and the opaque key material.
        let fixture = Fixture::new(&[]);
        let mut sources = fixture.sources();
        let empty: [String; 0] = [];
        sources.known_secrets = &empty;
        let report = build_report(&sources);

        let serialized = serde_json::to_string(&report).unwrap();
        for secret in [
            CONTROLLER_SECRET,
            OWNER_TOKEN,
            NODE_UUID,
            REALITY_PUBLIC_KEY,
            ACCESS_TOKEN,
            NODE_IP,
        ] {
            assert!(
                !serialized.contains(secret),
                "structural scrubbing missed {secret:?}:\n{serialized}"
            );
        }
        // …and the structural rules are the ones that named them.
        let error = report.error.as_deref().unwrap();
        assert!(error.contains("<uuid>") && error.contains("<ip>"), "{error}");
    }

    #[test]
    fn the_windows_account_name_is_scrubbed_from_paths() {
        let fixture = Fixture::new(&[]);
        let report = build_report(&fixture.sources());

        assert_eq!(
            report.audit_log_path,
            r"%USERPROFILE%\AppData\Roaming\io.tono\tono\logs\traffic-audit.jsonl"
        );
        // The Service log lives outside the profile and is untouched — and
        // only its path travels: the app cannot read that file.
        assert_eq!(report.service_log_path, r"C:\ProgramData\Tono\logs\tono-service.log");
        // Case-insensitive, and a path outside the profile is left alone.
        assert_eq!(
            scrub_home(Path::new(r"c:\users\jane doe\x.log"), Some(Path::new(r"C:\Users\Jane Doe"))),
            r"%USERPROFILE%\x.log"
        );
        assert_eq!(
            scrub_home(Path::new(r"D:\shared\x.log"), Some(Path::new(r"C:\Users\Jane Doe"))),
            r"D:\shared\x.log"
        );
        assert_eq!(scrub_home(Path::new("/tmp/x.log"), None), "/tmp/x.log");
    }

    #[test]
    fn virtual_adapters_are_reported_as_classes_never_as_names() {
        let names: Vec<String> = [
            "Ethernet 2",
            "vEthernet (Default Switch)",
            "vEthernet (WSL)",
            "VMware Network Adapter VMnet1",
            "VirtualBox Host-Only Network",
            "Wi-Fi",
        ]
        .iter()
        .map(|name| (*name).to_string())
        .collect();
        assert_eq!(
            classify_virtual_adapters(&names),
            vec!["hyperV", "virtualBox", "vmware", "wsl"]
        );
        // No physical adapter classifies, and no raw name ever survives.
        assert!(classify_virtual_adapters(&["Ethernet".to_string(), "Wi-Fi".to_string()]).is_empty());
    }

    #[test]
    fn free_text_is_capped() {
        let long = "x".repeat(MAX_TEXT_LEN * 2);
        let scrubbed = scrub_text_with(&long, &[]);
        assert_eq!(scrubbed.chars().count(), MAX_TEXT_LEN + 1);
        assert!(scrubbed.ends_with('…'));
    }

    #[test]
    fn structural_scrubbing_leaves_versions_durations_and_prose_alone() {
        assert_eq!(scrub_text_with("connect 10.0.0.1:443 failed", &[]), "connect <ip>:443 failed");
        assert_eq!(
            scrub_text_with("app 0.0.3 protocol 1.14 after 4.6s: securingDNS timed out", &[]),
            "app 0.0.3 protocol 1.14 after 4.6s: securingDNS timed out"
        );
        // A long run without digits is prose, not key material.
        assert_eq!(
            scrub_text_with("interfaceUnavailableForBinding", &[]),
            "interfaceUnavailableForBinding"
        );
    }

    #[test]
    fn a_short_known_secret_is_not_substituted_into_ordinary_words() {
        // Below the minimum length the value is more likely to be a substring
        // of real text than a secret worth blanking.
        assert_eq!(scrub_text_with("dns probe failed", &["dns".to_string()]), "dns probe failed");
    }

    #[test]
    fn empty_optional_text_is_dropped_rather_than_uploaded_as_blank() {
        assert_eq!(scrub_opt_text(Some("   "), &[]), None);
        assert_eq!(scrub_opt_text(None, &[]), None);
        assert_eq!(scrub_opt_text(Some(" ok "), &[]), Some("ok".to_string()));
    }

    #[test]
    fn the_schema_version_and_step_states_match_the_ui_wire_values() {
        let fixture = Fixture::new(&[]);
        let report = build_report(&fixture.sources());

        assert_eq!(report.schema_version, DIAGNOSTICS_SCHEMA_VERSION);
        assert_eq!(report.steps[0].key, "preparing");
        assert_eq!(report.steps[0].state, "completed");
        assert_eq!(report.steps[1].state, "failed");
        assert_eq!(report.steps[2].state, "pending");
        assert_eq!(report.total_elapsed_ms, Some(9200));
        assert_eq!(report.kill_switch_mode.as_deref(), Some("blocked"));
        assert_eq!(report.kill_switch_wanted, Some(true));
        assert_eq!(report.kill_switch_live, Some(false));
        assert_eq!(report.dns_enabled, Some(false));
        assert_eq!(report.selected_server.as_deref(), Some("US West 1"));
        assert_eq!(
            report.service_protocol.as_deref(),
            Some(ProtocolVersion::current().header_value().as_str())
        );
    }
}
