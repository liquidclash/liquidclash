use serde::{Deserialize, Serialize};
use strum_macros::{AsRefStr, EnumString};

#[derive(Debug, Clone, Serialize, Deserialize, EnumString, AsRefStr)]
pub enum IpcCommand {
    #[strum(serialize = "/version")]
    GetVersion,
    #[strum(serialize = "/status")]
    Status,
    #[strum(serialize = "/macos-kill-switch/preflight")]
    PreflightMacosKillSwitch,
    #[strum(serialize = "/kill-switch/status")]
    GetKillSwitchStatus,
    #[strum(serialize = "/kill-switch/lock")]
    LockKillSwitch,
    #[strum(serialize = "/kill-switch/restrict-bootstrap")]
    RestrictKillSwitchBootstrap,
    #[strum(serialize = "/kill-switch/release")]
    ReleaseKillSwitch,
    #[strum(serialize = "/dns/enable")]
    EnableProtectedDns,
    #[strum(serialize = "/dns/restore")]
    RestoreProtectedDns,
    #[strum(serialize = "/dns/status")]
    GetProtectedDnsStatus,
    // #[strum(serialize = "/clash")]
    // GetClash,

    // 用于日志界面加载上一次日志内容
    #[strum(serialize = "/clash/logs")]
    GetClashLogs,

    #[strum(serialize = "/clash/log-snapshot")]
    GetClashLogSnapshot,

    #[strum(serialize = "/clash/start")]
    StartClash,
    #[strum(serialize = "/clash/stop")]
    StopClash,
    #[strum(serialize = "/clash/stage-runtime")]
    StageRuntime,
    #[strum(serialize = "/system-proxy")]
    SetSystemProxy,
    #[strum(serialize = "/writer")]
    UpdateWriter,
    #[strum(serialize = "/magic")]
    Magic,
}
