use serde::{Deserialize, Serialize};
#[cfg(feature = "client")]
use serde_json::Value;
use sha2::{Digest as _, Sha256};

pub const OWNER_TOKEN_FILE_NAME: &str = ".clash-verge-service-owner-token";
pub const SERVICE_PROTOCOL_HEADER: &str = "X-Clash-Verge-Service-Protocol";
pub const SESSION_TOKEN_HEX_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersion {
    pub epoch: u16,
    pub revision: u16,
}

impl ProtocolVersion {
    pub const fn current() -> Self {
        Self {
            epoch: crate::PROTOCOL_EPOCH,
            revision: crate::PROTOCOL_REVISION,
        }
    }

    pub fn header_value(self) -> String {
        format!("{}.{}", self.epoch, self.revision)
    }

    pub fn parse_header(value: &str) -> Option<Self> {
        let (epoch, revision) = value.split_once('.')?;
        Some(Self {
            epoch: epoch.parse().ok()?,
            revision: revision.parse().ok()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolInfo {
    pub build_version: String,
    pub protocol: ProtocolVersion,
    pub min_client_revision: u16,
}

impl ProtocolInfo {
    pub fn current() -> Self {
        Self {
            build_version: crate::VERSION.to_owned(),
            protocol: ProtocolVersion::current(),
            min_client_revision: crate::MIN_SUPPORTED_CLIENT_REVISION,
        }
    }

    pub const fn supports_client(
        &self,
        client: ProtocolVersion,
        min_service_revision: u16,
    ) -> bool {
        self.protocol.epoch == client.epoch
            && self.protocol.revision >= min_service_revision
            && client.revision >= self.min_client_revision
    }

    /// Whether this service can stage a runtime in place instead of being stopped and restarted.
    ///
    /// Deliberately finer-grained than `supports_client`: an installed service that predates
    /// staging is still fully *compatible*, so it must not be pushed into a reinstall. Callers
    /// gate the fast path on this and fall back to stop + start when it is false.
    pub const fn supports_runtime_staging(&self) -> bool {
        self.protocol.epoch == ProtocolVersion::current().epoch
            && self.protocol.revision >= crate::MIN_SERVICE_REVISION_FOR_RUNTIME_STAGING
    }

    pub const fn supports_macos_kill_switch(&self) -> bool {
        self.protocol.epoch == ProtocolVersion::current().epoch
            && self.protocol.revision >= crate::MIN_SERVICE_REVISION_FOR_MACOS_KILL_SWITCH
    }

    pub const fn supports_macos_kill_switch_preflight(&self) -> bool {
        self.protocol.epoch == ProtocolVersion::current().epoch
            && self.protocol.revision >= crate::MIN_SERVICE_REVISION_FOR_MACOS_KILL_SWITCH_PREFLIGHT
    }

    pub const fn supports_windows_kill_switch(&self) -> bool {
        self.protocol.epoch == ProtocolVersion::current().epoch
            && self.protocol.revision >= crate::MIN_SERVICE_REVISION_FOR_WINDOWS_KILL_SWITCH
    }

    /// Whether this service has `POST /kill-switch/release` (the owner-gated release).
    pub const fn supports_kill_switch_release(&self) -> bool {
        self.protocol.epoch == ProtocolVersion::current().epoch
            && self.protocol.revision >= crate::MIN_SERVICE_REVISION_FOR_KILL_SWITCH_RELEASE
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OwnerIdentity {
    Unix { uid: u32, gid: u32 },
    Windows { sid: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerCredentials {
    pub identity: OwnerIdentity,
    pub app_data_dir: String,
    pub token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedRequest<T> {
    pub credentials: OwnerCredentials,
    pub payload: T,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerSessionProof {
    pub generation: u64,
    pub token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedSessionRequest<T> {
    pub credentials: OwnerCredentials,
    pub session: OwnerSessionProof,
    pub payload: T,
}

/// A file the client owns and the service copies into the runtime generation.
///
/// The distinction from [`RemoteProvider`] is who writes the file: these are copied in by the
/// service and can therefore be compared against their source, so an unchanged one is skipped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeAsset {
    pub source: String,
    pub destination: String,
}

/// A provider file the *core* fetches and owns; the service never writes it.
///
/// Recorded only so the service can tell a reusable download cache from a stale one. The core
/// will not re-fetch a provider whose file already exists, so when `url` changes underneath an
/// unchanged `destination` the cache must be deleted before the core reloads — otherwise it
/// keeps serving the previous source's content until the provider's own interval elapses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteProvider {
    pub destination: String,
    pub url: String,
}

/// The complete declaration of what a runtime generation should contain.
///
/// "Complete" is load-bearing: staging decides what to delete by subtracting this declaration
/// from what is on disk, so anything omitted here is something staging cannot reason about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeBundle {
    pub yaml: String,
    pub assets: Vec<RuntimeAsset>,
    /// Absent on the wire from clients older than revision 2; an empty list simply means
    /// staging cannot distinguish a reusable cache from a stale one and keeps neither.
    #[serde(default)]
    pub remote_providers: Vec<RemoteProvider>,
    pub core_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum MacosProxyConfig {
    Disabled,
    Global {
        host: String,
        port: u16,
        bypass: String,
    },
    Pac {
        url: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ProxyApplyOutcome {
    NotRequested,
    Applied,
    DirectFallback { message: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MacosKillSwitchMode {
    #[default]
    Disabled,
    Standard,
    Permanent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosKillSwitchConfig {
    pub mode: MacosKillSwitchMode,
    pub tunnel_interface: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProxyProtocol {
    #[default]
    Tcp,
    Udp,
}

/// One proxy node endpoint the staged core binary is allowed to reach directly.
///
/// `ip` is a literal IP (v4 or v6) — the catalog contract guarantees literals, which is what
/// makes an exact WFP permit cheap. It is validated before any rule is written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyEndpoint {
    pub ip: String,
    pub port: u16,
    #[serde(default)]
    pub protocol: ProxyProtocol,
}

/// The cross-platform (Windows) kill switch configuration, generalized from the macOS-only
/// [`MacosKillSwitchConfig`]. Accepted on Windows in [`StartClashRequest::windows_kill_switch`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KillSwitchConfig {
    pub tunnel_interface: String,
    #[serde(default)]
    pub proxy_endpoints: Vec<ProxyEndpoint>,
    #[serde(default)]
    pub bootstrap_api_hosts: Vec<String>,
    /// Cloud-approved DIRECT endpoints (WeChat acceleration): exact `IP:port` tuples any
    /// process may reach on the physical NIC while armed. **omission = clear**: never
    /// persisted, never restored on service start, never inherited by the next arm.
    #[serde(default)]
    pub direct_endpoints: Vec<ProxyEndpoint>,
}

/// Reported via `GET /kill-switch/status`: which phase of the two-phase arm is live.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum KillSwitchStatusMode {
    /// Floor + session rules up, bootstrap API channel open, tunnel not yet permitted.
    Bootstrap,
    /// Full policy live: tunnel permitted, bootstrap API channel retracted.
    Locked,
    /// Armed but not connected: the API recovery channel stays open, the tunnel is absent.
    #[default]
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KillSwitchStatus {
    pub wanted: bool,
    /// All expected WFP objects verified by key in the last check.
    pub live: bool,
    pub mode: KillSwitchStatusMode,
    #[serde(default)]
    pub endpoints: Vec<ProxyEndpoint>,
    #[serde(default)]
    pub last_error: Option<String>,
}

/// `POST /kill-switch/lock` payload. `None` locks the interface named at arm time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KillSwitchLockRequest {
    #[serde(default)]
    pub tunnel_interface: Option<String>,
}

/// `GET /dns/status` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsProtectionStatus {
    /// The service currently holds adapters on loopback DNS.
    pub enabled: bool,
    /// A pre-protection snapshot exists to restore from.
    pub snapshot_present: bool,
    /// Adapters covered by the snapshot.
    pub adapters: u32,
    #[serde(default)]
    pub last_error: Option<String>,
}

/// The service's network-change feed, aggregated into `/status`.
///
/// The product layer polls and compares `counter` against its last seen value: any increment
/// means sleep/wake or an adapter/route change happened, at which point `Connected` is
/// invalidated and the reconnect runs behind the still-armed barrier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct NetworkEventsStatus {
    /// Monotonic count of debounced network/power events since service start.
    pub counter: u64,
    #[serde(default)]
    pub last_kind: Option<String>,
    /// Unix seconds of the latest event.
    #[serde(default)]
    pub last_at: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StopClashOptions {
    #[serde(default = "default_release_kill_switch")]
    pub release_kill_switch: bool,
}

const fn default_release_kill_switch() -> bool {
    true
}

impl Default for StopClashOptions {
    fn default() -> Self {
        Self {
            release_kill_switch: true,
        }
    }
}

/// `null` was the v2.6.1 payload. Keeping it as a distinct untagged variant means old clients
/// retain release-after-stop behavior while new clients can explicitly request a persistent block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StopClashPayload {
    Legacy(()),
    Options(StopClashOptions),
}

impl StopClashPayload {
    pub fn release_kill_switch(&self) -> bool {
        match self {
            Self::Legacy(()) => true,
            Self::Options(value) => value.release_kill_switch,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartClashRequest {
    pub runtime: RuntimeBundle,
    pub proposed_session_token: String,
    pub macos_proxy: Option<MacosProxyConfig>,
    #[serde(default)]
    pub kill_switch: Option<MacosKillSwitchConfig>,
    /// The Windows kill switch. Kept as a separate field from `kill_switch` so the macOS wire
    /// contract is byte-identical to what existing clients send; absent from older clients.
    #[serde(default)]
    pub windows_kill_switch: Option<KillSwitchConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerSessionHandle {
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartClashResult {
    pub session: OwnerSessionHandle,
    pub proxy_outcome: ProxyApplyOutcome,
}

/// What staging a bundle into the running core's generation achieved.
///
/// `RestartRequired` is an outcome, not an error: staging is an optimisation that is allowed to
/// decline. Every way of declining leaves the generation exactly as the running core left it,
/// so the caller can fall back to stop + start — which builds a fresh generation and therefore
/// has none of the constraints that made staging decline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum StageRuntimeOutcome {
    /// The generation now matches the bundle. The core still runs the previous configuration
    /// until the caller points it at `config_path`.
    Staged {
        config_path: String,
    },
    RestartRequired {
        reason: StageRejection,
    },
}

/// Why staging declined. Each variant is a fact only the service can establish.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum StageRejection {
    /// No core is running, so there is nothing to reload into.
    CoreNotRunning,
    /// The bundle names a different core binary. A configuration reload would succeed and
    /// silently leave the previous binary running, which is worse than declining.
    CorePathChanged,
    /// A file that had to be replaced or removed could not be. Expected on Windows, where the
    /// running core holds handles on its provider files.
    RuntimeUnwritable { detail: String },
    /// The core was replaced while the runtime was being staged, so the work done so far was done
    /// for a core that is no longer there. The service's own watchdog can do this, and it restarts
    /// the core from the configuration still on disk — meaning the generation may now be serving a
    /// mixture nothing recorded.
    CoreRestarted,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceErrorCode {
    UnauthorizedOwner = 1001,
    NotActive = 1002,
    InvalidInstallLocation = 1003,
    InvalidRuntimeAsset = 1004,
    LegacyCleanupFailed = 1005,
    OwnerSwitchFailed = 1006,
    ProtocolMismatch = 1007,
    StaleOwnerSession = 1008,
    InvalidProxyConfig = 1009,
    ProxyClearFailed = 1010,
    ProxyApplyFailed = 1011,
}

pub fn owner_key(identity: &OwnerIdentity) -> String {
    match identity {
        OwnerIdentity::Unix { uid, .. } => uid.to_string(),
        OwnerIdentity::Windows { sid } => Sha256::digest(sid.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ClashConfig {
    pub core_config: CoreConfig,
    pub log_config: WriterConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreConfig {
    pub core_path: String,
    pub core_ipc_path: String,
    pub config_path: String,
    pub config_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriterConfig {
    pub directory: String,
    pub max_log_size: u64,
    pub max_log_files: usize,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceLifecycleState {
    Starting = 0,
    Running = 1,
    RecoveringCore = 2,
    RecoveringIpc = 3,
    Fatal = 4,
}

impl ServiceLifecycleState {
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Running,
            2 => Self::RecoveringCore,
            3 => Self::RecoveringIpc,
            4 => Self::Fatal,
            _ => Self::Starting,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatusSnapshot {
    pub is_active: bool,
    pub active_generation: Option<u64>,
    pub service_state: ServiceLifecycleState,
    pub core_pid: Option<u32>,
    pub core_started_at: Option<u64>,
    pub last_core_exit_reason: Option<String>,
    pub restart_count: u32,
    pub last_recovery_at: Option<u64>,
    pub desired_core_should_be_running: bool,
    pub desired_generation: u64,
    pub desired_updated_at: u64,
    #[serde(default)]
    pub macos_kill_switch_wanted: bool,
    #[serde(default)]
    pub macos_kill_switch_live: bool,
    #[serde(default)]
    pub macos_kill_switch_mode: MacosKillSwitchMode,
    /// Windows kill switch aggregate. `None` on platforms without the WFP backend; the
    /// `macos_kill_switch_*` fields above are untouched.
    #[serde(default)]
    pub kill_switch: Option<KillSwitchStatus>,
    /// Network/power event feed (Windows netmon); zeroed where no monitor exists.
    #[serde(default)]
    pub network_events: NetworkEventsStatus,
}

#[cfg(feature = "response")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response<T> {
    pub code: u16,
    pub message: String,
    pub data: Option<T>,
}

impl Default for CoreConfig {
    fn default() -> Self {
        let core_ipc_path = if cfg!(windows) {
            format!(r"\\.\pipe\verge-mihomo-{}", crate::CHANNEL_IDENTITY.id)
        } else if cfg!(feature = "test") {
            "/tmp/clash-verge-service-ipc-test/mihomo.sock".to_string()
        } else if cfg!(target_os = "macos") {
            format!("/var/run/{}/users/0/verge-mihomo.sock", crate::SERVICE_SLUG)
        } else {
            format!("/run/{}/users/0/verge-mihomo.sock", crate::SERVICE_SLUG)
        };
        Self {
            core_path: "./clash".to_string(),
            core_ipc_path,
            config_path: "./config.yaml".to_string(),
            config_dir: "./configs".to_string(),
        }
    }
}

impl Default for WriterConfig {
    fn default() -> Self {
        Self {
            directory: "./logs".to_string(),
            max_log_size: 10 * 1024 * 1024, // 10 MB
            max_log_files: 8,
        }
    }
}

#[cfg(feature = "client")]
pub trait JsonConvert: Serialize + for<'de> Deserialize<'de> {
    /// 转换为 JSON Value
    fn to_json_value(&self) -> Result<Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    // /// 从 JSON Value 转换
    // fn from_json_value(value: Value) -> Result<Self, serde_json::Error> {
    //     serde_json::from_value(value)
    // }

    // /// 序列化为 JSON 字符串
    // fn to_json_string(&self) -> Result<String, serde_json::Error> {
    //     serde_json::to_string(self)
    // }

    // /// 从 JSON 字符串转换
    // fn from_json_string(json: &str) -> Result<Self, serde_json::Error> {
    //     serde_json::from_str(json)
    // }
}
#[cfg(feature = "client")]
impl<T> JsonConvert for T where T: Serialize + for<'de> Deserialize<'de> {}

#[cfg(test)]
mod tests {
    use super::{
        MacosProxyConfig, OwnerIdentity, ProtocolInfo, ProtocolVersion, RuntimeBundle,
        ServiceErrorCode, StartClashRequest, StopClashPayload, owner_key,
    };

    #[test]
    fn service_250_contract_round_trips_owner_session_and_proxy() {
        let request = StartClashRequest {
            runtime: RuntimeBundle {
                yaml: "mode: rule\n".to_owned(),
                assets: Vec::new(),
                remote_providers: Vec::new(),
                core_path: "/tmp/mihomo".to_owned(),
            },
            proposed_session_token: "11".repeat(32),
            macos_proxy: Some(MacosProxyConfig::Global {
                host: "127.0.0.1".to_owned(),
                port: 7897,
                bypass: "localhost".to_owned(),
            }),
            kill_switch: None,
            windows_kill_switch: None,
        };
        let encoded = serde_json::to_vec(&request).expect("request should serialize");
        let decoded: StartClashRequest =
            serde_json::from_slice(&encoded).expect("request should deserialize");
        assert_eq!(decoded, request);
    }

    #[test]
    fn legacy_start_and_stop_payloads_remain_compatible() {
        let old_start = serde_json::json!({
            "runtime": { "yaml": "", "assets": [], "core_path": "/mihomo" },
            "proposed_session_token": "11".repeat(32),
            "macos_proxy": null
        });
        let decoded: StartClashRequest = serde_json::from_value(old_start).unwrap();
        assert_eq!(decoded.kill_switch, None);
        let stop: StopClashPayload = serde_json::from_str("null").unwrap();
        assert!(stop.release_kill_switch());
        let keep: StopClashPayload =
            serde_json::from_str(r#"{"release_kill_switch":false}"#).unwrap();
        assert!(!keep.release_kill_switch());
    }

    #[test]
    fn stable_session_error_codes_do_not_overlap_existing_codes() {
        assert_eq!(ServiceErrorCode::ProtocolMismatch as u16, 1007);
        assert_eq!(ServiceErrorCode::StaleOwnerSession as u16, 1008);
        assert_eq!(ServiceErrorCode::InvalidProxyConfig as u16, 1009);
        assert_eq!(ServiceErrorCode::ProxyClearFailed as u16, 1010);
        assert_eq!(ServiceErrorCode::ProxyApplyFailed as u16, 1011);
    }

    #[test]
    fn protocol_header_is_independent_from_the_build_version() {
        let current = ProtocolVersion::current();
        assert_eq!(
            ProtocolVersion::parse_header(&current.header_value()),
            Some(current)
        );
        assert!(ProtocolVersion::parse_header(crate::VERSION).is_none());
    }

    #[test]
    fn staging_capability_keeps_its_feature_revision_after_the_protocol_floor_advances() {
        let mut older = ProtocolInfo::current();
        older.protocol.revision = crate::MIN_SERVICE_REVISION_FOR_RUNTIME_STAGING - 1;

        assert!(
            !older.supports_client(
                ProtocolVersion::current(),
                crate::MIN_REQUIRED_SERVICE_REVISION
            ),
            "the current wire contract must reject this old service"
        );
        assert!(
            !older.supports_runtime_staging(),
            "the feature gate must still record when staging itself was introduced"
        );
        assert!(ProtocolInfo::current().supports_runtime_staging());
    }

    #[test]
    fn staging_does_not_survive_an_epoch_change() {
        let mut newer_epoch = ProtocolInfo::current();
        newer_epoch.protocol.epoch += 1;
        newer_epoch.protocol.revision = crate::MIN_SERVICE_REVISION_FOR_RUNTIME_STAGING;

        assert!(
            !newer_epoch.supports_runtime_staging(),
            "a revision number means nothing across an epoch boundary"
        );
    }

    #[test]
    fn kill_switch_preflight_requires_revision_four_in_the_current_epoch() {
        let mut info = ProtocolInfo::current();
        info.protocol.revision = crate::MIN_SERVICE_REVISION_FOR_MACOS_KILL_SWITCH_PREFLIGHT - 1;
        assert!(!info.supports_macos_kill_switch_preflight());

        info.protocol.revision = crate::MIN_SERVICE_REVISION_FOR_MACOS_KILL_SWITCH_PREFLIGHT;
        assert!(info.supports_macos_kill_switch_preflight());

        info.protocol.epoch += 1;
        assert!(!info.supports_macos_kill_switch_preflight());
    }

    #[test]
    fn windows_kill_switch_requires_revision_five_in_the_current_epoch() {
        let mut info = ProtocolInfo::current();
        info.protocol.revision = crate::MIN_SERVICE_REVISION_FOR_WINDOWS_KILL_SWITCH - 1;
        assert!(!info.supports_windows_kill_switch());

        info.protocol.revision = crate::MIN_SERVICE_REVISION_FOR_WINDOWS_KILL_SWITCH;
        assert!(info.supports_windows_kill_switch());

        info.protocol.epoch += 1;
        assert!(!info.supports_windows_kill_switch());
    }

    #[test]
    fn network_events_status_defaults_for_older_snapshots() {
        // Older services never sent the field; newer clients must still parse their snapshots.
        let old_snapshot = serde_json::json!({
            "is_active": false,
            "active_generation": null,
            "service_state": "Running",
            "core_pid": null,
            "core_started_at": null,
            "last_core_exit_reason": null,
            "restart_count": 0,
            "last_recovery_at": null,
            "desired_core_should_be_running": false,
            "desired_generation": 0,
            "desired_updated_at": 0
        });
        let decoded: super::ServiceStatusSnapshot =
            serde_json::from_value(old_snapshot).expect("old snapshot should deserialize");
        assert_eq!(
            decoded.network_events,
            super::NetworkEventsStatus::default()
        );
        assert_eq!(decoded.kill_switch, None);

        let status = super::NetworkEventsStatus {
            counter: 7,
            last_kind: Some("network-change (ip-interface/route)".to_owned()),
            last_at: Some(1_700_000_000),
        };
        let encoded = serde_json::to_vec(&status).expect("status should serialize");
        assert_eq!(
            serde_json::from_slice::<super::NetworkEventsStatus>(&encoded)
                .expect("status should deserialize"),
            status
        );
    }

    #[test]
    fn kill_switch_release_requires_revision_six_in_the_current_epoch() {
        let mut info = ProtocolInfo::current();
        info.protocol.revision = crate::MIN_SERVICE_REVISION_FOR_KILL_SWITCH_RELEASE - 1;
        assert!(!info.supports_kill_switch_release());

        info.protocol.revision = crate::MIN_SERVICE_REVISION_FOR_KILL_SWITCH_RELEASE;
        assert!(info.supports_kill_switch_release());

        info.protocol.epoch += 1;
        assert!(!info.supports_kill_switch_release());
    }

    #[test]
    fn windows_kill_switch_config_is_absent_from_older_clients() {
        use super::{KillSwitchConfig, KillSwitchStatus, KillSwitchStatusMode, ProxyProtocol};

        let old_start = serde_json::json!({
            "runtime": { "yaml": "", "assets": [], "core_path": "/mihomo" },
            "proposed_session_token": "11".repeat(32),
            "macos_proxy": null,
            "kill_switch": null
        });
        let decoded: StartClashRequest = serde_json::from_value(old_start).unwrap();
        assert_eq!(decoded.windows_kill_switch, None);

        let config = KillSwitchConfig {
            tunnel_interface: "Tono".to_owned(),
            proxy_endpoints: vec![super::ProxyEndpoint {
                ip: "203.0.113.7".to_owned(),
                port: 443,
                protocol: ProxyProtocol::Tcp,
            }],
            bootstrap_api_hosts: vec!["api.example.com".to_owned()],
            direct_endpoints: Vec::new(),
        };
        let encoded = serde_json::to_vec(&config).expect("config should serialize");
        assert_eq!(
            serde_json::from_slice::<KillSwitchConfig>(&encoded)
                .expect("config should deserialize"),
            config
        );

        let status = KillSwitchStatus {
            wanted: true,
            live: true,
            mode: KillSwitchStatusMode::Bootstrap,
            endpoints: config.proxy_endpoints.clone(),
            last_error: None,
        };
        let encoded = serde_json::to_vec(&status).expect("status should serialize");
        assert_eq!(
            serde_json::from_slice::<KillSwitchStatus>(&encoded)
                .expect("status should deserialize"),
            status
        );
        assert_eq!(
            serde_json::from_value::<KillSwitchStatusMode>(serde_json::json!("locked")).unwrap(),
            KillSwitchStatusMode::Locked
        );
    }

    #[test]
    fn protocol_compatibility_is_epoch_and_revision_based() {
        let info = ProtocolInfo::current();
        let current = ProtocolVersion::current();
        assert!(info.supports_client(current, crate::MIN_REQUIRED_SERVICE_REVISION));
        assert!(!info.supports_client(
            ProtocolVersion {
                epoch: current.epoch.saturating_add(1),
                revision: current.revision,
            },
            crate::MIN_REQUIRED_SERVICE_REVISION,
        ));
        assert!(!info.supports_client(
            ProtocolVersion {
                epoch: current.epoch,
                revision: info.min_client_revision.saturating_sub(1),
            },
            crate::MIN_REQUIRED_SERVICE_REVISION,
        ));
    }

    #[test]
    fn unix_owner_key_is_decimal_uid() {
        let identity = OwnerIdentity::Unix { uid: 501, gid: 20 };

        assert_eq!(owner_key(&identity), "501");
    }

    #[test]
    fn windows_owner_key_is_stable_and_does_not_embed_sid() {
        let identity = OwnerIdentity::Windows {
            sid: "S-1-5-21-1-2-3-1001".to_string(),
        };

        let first = owner_key(&identity);
        let second = owner_key(&identity);

        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        assert!(!first.contains("S-1-5"));
        assert!(
            first
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
    }
}
