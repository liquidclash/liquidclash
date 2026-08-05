mod channel;
mod core;

#[cfg(feature = "client")]
mod client;

pub use channel::{
    CHANNEL_IDENTITY, ChannelIdentity, MACOS_APP_BUNDLE_ID, MACOS_SERVICE_ID, SERVICE_DISPLAY_NAME,
    SERVICE_SLUG, WINDOWS_SERVICE_NAME, WINDOWS_STATE_DIR_NAME,
};
pub use core::{
    AuthenticatedRequest, AuthenticatedSessionRequest, ClashConfig, CoreConfig,
    DnsProtectionStatus, IpcCommand, KillSwitchConfig, KillSwitchLockRequest, KillSwitchStatus,
    KillSwitchStatusMode, MacosKillSwitchConfig, MacosKillSwitchMode, MacosProxyConfig,
    OWNER_TOKEN_FILE_NAME, OwnerCredentials, OwnerIdentity, OwnerSessionHandle, OwnerSessionProof,
    ProtocolInfo, ProtocolVersion, ProxyApplyOutcome, ProxyEndpoint, ProxyProtocol, RemoteProvider,
    RuntimeAsset, RuntimeBundle, SERVICE_PROTOCOL_HEADER, SESSION_TOKEN_HEX_LEN, ServiceErrorCode,
    ServiceLifecycleState, ServiceOperationKind, ServiceOperationSnapshot, ServiceStatusSnapshot,
    StageRejection, StageRuntimeOutcome, StartClashRequest, StartClashResult, StopClashOptions,
    StopClashPayload, WriterConfig, mihomo_ipc_path, owner_key,
};
pub use core::{OwnerPaths, ServicePaths, service_paths};

#[cfg(feature = "standalone")]
pub use core::{
    ActiveOwnerState, DesiredState, REPAIR_IN_PROGRESS_EXIT_CODE, ServiceOwnerGuard,
    ServiceRepairGate, acquire_service_owner, acquire_service_repair_gate,
    add_restored_kill_switch_tunnel, cleanup_stale_owner_state, emergency_disarm_kill_switch,
    emergency_disarm_windows_kill_switch, initialize_protected_dns_status, load_active_owner,
    load_owner_desired_state, prepare_for_service_replacement, prepare_service_install_directory,
    reconcile_service_startup, relock_restored_tunnel, residual_filters_present,
    restore_desired_state, restore_kill_switch, restore_windows_kill_switch,
    retire_unverified_windows_kill_switch, run_ipc_server, run_ipc_supervisor_until_shutdown,
    service_lifecycle_state, set_service_lifecycle_state, spawn_kill_switch_watchdog,
    spawn_protected_dns_watchdog, spawn_windows_kill_switch_watchdog, stop_ipc_server,
};
#[cfg(all(feature = "standalone", windows))]
pub use core::{note_power_event, recent_network_events, start_network_monitor};

#[cfg(feature = "test")]
pub use core::test_owner_credentials;
#[cfg(all(feature = "test", unix))]
pub use core::test_owner_credentials_for_uid;
#[cfg(all(feature = "standalone", feature = "test"))]
pub use core::write_core_runtime_record_for_tests;
#[cfg(all(feature = "standalone", feature = "test"))]
pub use core::{CoreWatchdogTestConfig, set_core_watchdog_config_for_tests};

#[cfg(feature = "client")]
pub use client::*;

#[cfg(all(
    target_os = "macos",
    not(feature = "test"),
    not(feature = "development-channel")
))]
pub static IPC_PATH: &str = "/var/run/clash-verge-service/service.sock";
#[cfg(all(
    target_os = "macos",
    not(feature = "test"),
    feature = "development-channel"
))]
pub static IPC_PATH: &str = "/var/run/clash-verge-service-dev/service.sock";
#[cfg(all(
    unix,
    not(target_os = "macos"),
    not(feature = "test"),
    not(feature = "development-channel")
))]
pub static IPC_PATH: &str = "/run/clash-verge-service/service.sock";
#[cfg(all(
    unix,
    not(target_os = "macos"),
    not(feature = "test"),
    feature = "development-channel"
))]
pub static IPC_PATH: &str = "/run/clash-verge-service-dev/service.sock";
#[cfg(all(windows, not(feature = "test"), not(feature = "development-channel")))]
pub static IPC_PATH: &str = r"\\.\pipe\tono-service";
#[cfg(all(windows, not(feature = "test"), feature = "development-channel"))]
pub static IPC_PATH: &str = r"\\.\pipe\tono-service-dev";

#[cfg(all(feature = "test", unix))]
pub static IPC_PATH: &str = "/tmp/clash-verge-service-ipc-test/service.sock";
#[cfg(all(feature = "test", windows))]
pub static IPC_PATH: &str = r"\\.\pipe\tono-service-test";

#[cfg(any(feature = "standalone", feature = "client"))]
pub static IPC_AUTH_EXPECT: &str = r#"A thing of beauty is a joy for ever. Its loveliness increases; it will never pass into nothingness."#;

pub static VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PROTOCOL_EPOCH: u16 = 2;
/// Revision 7 replaces the three mutating PUT routes with POST. The pinned transport applies a
/// hidden two-attempt policy to PUT regardless of client configuration, which can replay a write
/// after the Service committed but its response was lost.
/// Revision 8 adds the mandatory verified-tunnel commit; accepting a revision 7 client would
/// leave a genuinely connected session indistinguishable from a stale first attempt on reboot.
/// Revision 9 is the Test 6 system-safety floor: lock-free status snapshots, strict DNS restore,
/// and the bounded Windows Service runtime ship as one inseparable App/Service contract.
/// Requiring it prevents a failed installer replacement from silently pairing the new App with
/// the older Test 5 Service that still has the original freeze/recovery semantics.
pub const PROTOCOL_REVISION: u16 = 9;
/// Revisions 7 through 9 are wire/behaviour incompatible with older peers. Reject a mismatch at
/// the protocol probe rather than failing later during a required mutation.
pub const MIN_SUPPORTED_CLIENT_REVISION: u16 = 9;
pub const MIN_REQUIRED_SERVICE_REVISION: u16 = 9;
/// Revision that introduced `/clash/stage-runtime`.
pub const MIN_SERVICE_REVISION_FOR_RUNTIME_STAGING: u16 = 2;
/// Revision that introduced the service-owned macOS PF kill switch.
pub const MIN_SERVICE_REVISION_FOR_MACOS_KILL_SWITCH: u16 = 3;
/// Revision that introduced a non-mutating host PF ownership preflight.
pub const MIN_SERVICE_REVISION_FOR_MACOS_KILL_SWITCH_PREFLIGHT: u16 = 4;
/// Revision that introduced the Windows WFP kill switch, the cross-platform
/// [`KillSwitchConfig`]/[`KillSwitchStatus`] wire types, and the `/kill-switch/*` + `/dns/*`
/// routes.
pub const MIN_SERVICE_REVISION_FOR_WINDOWS_KILL_SWITCH: u16 = 5;
/// Revision that introduced `POST /kill-switch/release`: the owner-gated explicit release that
/// breaks the Protected Offline deadlock (a stop invalidates the session, so a session-gated
/// release could never run after one).
pub const MIN_SERVICE_REVISION_FOR_KILL_SWITCH_RELEASE: u16 = 6;
/// Revision that introduced logical-session verification persistence.
pub const MIN_SERVICE_REVISION_FOR_KILL_SWITCH_VERIFICATION: u16 = 8;
