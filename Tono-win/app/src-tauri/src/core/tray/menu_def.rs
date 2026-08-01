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
