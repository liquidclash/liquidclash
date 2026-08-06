use clash_verge_i18n::t;
use std::borrow::Cow;

macro_rules! define_menu {
    ($($field:ident => $const_name:ident, $id:expr, $text:expr),+ $(,)?) => {
        #[derive(Debug)]
        pub struct MenuTexts {
            $(pub $field: Cow<'static, str>,)+
        }

        pub struct MenuIds;

        impl MenuTexts {
            pub fn new() -> Self {
                Self {
                    $($field: t!($text),)+
                }
            }
        }

        impl MenuIds {
            $(pub const $const_name: &'static str = $id;)+
        }
    };
}

define_menu! {
    connect => CONNECT, "tray_tono_connect", "tray.tono.connect",
    disconnect => DISCONNECT, "tray_tono_disconnect", "tray.tono.disconnect",
    retry => RETRY, "tray_tono_retry", "tray.tono.retry",
    dashboard => DASHBOARD, "tray_dashboard", "tray.dashboard",
    conf_dir => CONF_DIR, "tray_conf_dir", "tray.confDir",
    core_dir => CORE_DIR, "tray_core_dir", "tray.coreDir",
    logs_dir => LOGS_DIR, "tray_logs_dir", "tray.logsDir",
    open_dir => OPEN_DIR, "tray_open_dir", "tray.openDir",
    app_log => APP_LOG, "tray_app_log", "tray.appLog",
    core_log => CORE_LOG, "tray_core_log", "tray.coreLog",
    verge_version => VERGE_VERSION, "tray_verge_version", "tray.vergeVersion",
    exit => EXIT, "tray_exit", "tray.exit",
}

impl MenuIds {
    pub const PROTECTION: &'static str = "tray_tono_protection";
    pub const SERVER: &'static str = "tray_tono_server";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MenuCommand {
    Connect,
    Disconnect,
    Retry,
    Dashboard,
    ConfDir,
    CoreDir,
    LogsDir,
    AppLog,
    CoreLog,
    Exit,
}

impl MenuCommand {
    pub(crate) fn from_id(id: &str) -> Option<Self> {
        match id {
            MenuIds::CONNECT => Some(Self::Connect),
            MenuIds::DISCONNECT => Some(Self::Disconnect),
            MenuIds::RETRY => Some(Self::Retry),
            MenuIds::DASHBOARD => Some(Self::Dashboard),
            MenuIds::CONF_DIR => Some(Self::ConfDir),
            MenuIds::CORE_DIR => Some(Self::CoreDir),
            MenuIds::LOGS_DIR => Some(Self::LogsDir),
            MenuIds::APP_LOG => Some(Self::AppLog),
            MenuIds::CORE_LOG => Some(Self::CoreLog),
            MenuIds::EXIT => Some(Self::Exit),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum TrayAction {
    SystemProxy,
    TunMode,
    MainWindow,
    TrayMenu,
    Unknown,
}

impl From<&str> for TrayAction {
    fn from(s: &str) -> Self {
        match s {
            "system_proxy" => Self::SystemProxy,
            "tun_mode" => Self::TunMode,
            "main_window" => Self::MainWindow,
            "tray_menu" => Self::TrayMenu,
            _ => Self::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MenuCommand, MenuIds};

    #[test]
    fn dispatches_only_tono_and_retained_safe_menu_ids() {
        assert_eq!(MenuCommand::from_id(MenuIds::CONNECT), Some(MenuCommand::Connect));
        assert_eq!(MenuCommand::from_id(MenuIds::DISCONNECT), Some(MenuCommand::Disconnect));
        assert_eq!(MenuCommand::from_id(MenuIds::RETRY), Some(MenuCommand::Retry));
        assert_eq!(MenuCommand::from_id(MenuIds::DASHBOARD), Some(MenuCommand::Dashboard));
        assert_eq!(MenuCommand::from_id(MenuIds::EXIT), Some(MenuCommand::Exit));

        assert_eq!(MenuCommand::from_id("tray_system_proxy"), None);
        assert_eq!(MenuCommand::from_id("tray_tun_mode"), None);
        assert_eq!(MenuCommand::from_id("tray_profiles"), None);
        assert_eq!(MenuCommand::from_id("tray_restart_clash"), None);
        assert_eq!(MenuCommand::from_id(""), None);
    }
}
