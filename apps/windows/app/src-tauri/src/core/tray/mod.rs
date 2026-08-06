use crate::config::IVerge;
use crate::core::tray::menu_def::TrayAction;
use crate::module::lightweight;
use crate::process::AsyncHandler;
use crate::singleton;
use crate::tono::{commands, connection, state::TonoState};
use crate::utils::window_manager::WindowManager;
use crate::{
    Type, cmd,
    config::Config,
    feat, logging,
    utils::{dirs::find_target_icons, help},
};
use clash_verge_limiter::{Limiter, SystemClock, SystemLimiter};
use clash_verge_logging::logging_error;
use tauri::tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use tokio::fs;

use super::handle;
use anyhow::Result;
use std::borrow::Cow;
use std::time::Duration;
use tauri::{
    AppHandle, Manager as _, Wry,
    menu::{MenuEvent, MenuItem, PredefinedMenuItem, Submenu},
};

mod menu_def;
#[cfg(target_os = "macos")]
mod speed_task;
use menu_def::{MenuCommand, MenuIds, MenuTexts};

// TODO: 是否需要将可变菜单抽离存储起来，后续直接更新对应菜单实例，无需重新创建菜单(待考虑)

const TRAY_CLICK_DEBOUNCE_MS: u64 = 300;
pub const TRAY_ID: &str = "clash-verge-rev-tray";

#[derive(Clone)]
struct TrayState {}

enum IconKind {
    Common,
    SysProxy,
    Tun,
}

pub struct Tray {
    limiter: SystemLimiter,
    /// Serializes native menu/tooltip snapshots. The guard is acquired before reading TonoState,
    /// so an older status refresh can never overwrite a newer projection after being suspended.
    projection_lock: tokio::sync::Mutex<()>,
    #[cfg(target_os = "macos")]
    speed_controller: speed_task::TraySpeedController,
}

impl TrayState {
    async fn get_tray_icon(verge: &IVerge) -> (bool, Cow<'_, [u8]>) {
        let tun_mode = verge.enable_tun_mode.unwrap_or(false);
        let system_mode = verge.enable_system_proxy.unwrap_or(false);
        let kind = if tun_mode {
            IconKind::Tun
        } else if system_mode {
            IconKind::SysProxy
        } else {
            IconKind::Common
        };
        Self::load_icon(verge, kind).await
    }

    async fn load_icon(verge: &IVerge, kind: IconKind) -> (bool, Cow<'_, [u8]>) {
        let (custom_enabled, icon_name) = match kind {
            IconKind::Common => (verge.common_tray_icon.unwrap_or(false), "common"),
            IconKind::SysProxy => (verge.sysproxy_tray_icon.unwrap_or(false), "sysproxy"),
            IconKind::Tun => (verge.tun_tray_icon.unwrap_or(false), "tun"),
        };

        if custom_enabled
            && let Ok(Some(path)) = find_target_icons(icon_name)
            && let Ok(data) = fs::read(path).await
        {
            return (true, Cow::Owned(data));
        }

        Self::default_icon(verge, kind)
    }

    #[allow(clippy::missing_const_for_fn)]
    fn default_icon(verge: &IVerge, kind: IconKind) -> (bool, Cow<'_, [u8]>) {
        #[cfg(target_os = "macos")]
        {
            let is_mono = verge.tray_icon.as_deref().unwrap_or("monochrome") == "monochrome";
            if is_mono {
                return (
                    false,
                    match kind {
                        IconKind::Common => Cow::Borrowed(include_bytes!("../../../icons/tray-icon-mono.ico")),
                        IconKind::SysProxy => {
                            Cow::Borrowed(include_bytes!("../../../icons/tray-icon-sys-mono-new.ico"))
                        }
                        IconKind::Tun => Cow::Borrowed(include_bytes!("../../../icons/tray-icon-tun-mono-new.ico")),
                    },
                );
            }
        }

        #[cfg(not(target_os = "macos"))]
        let _ = verge;

        (
            false,
            match kind {
                IconKind::Common => Cow::Borrowed(include_bytes!("../../../icons/tray-icon.ico")),
                IconKind::SysProxy => Cow::Borrowed(include_bytes!("../../../icons/tray-icon-sys.ico")),
                IconKind::Tun => Cow::Borrowed(include_bytes!("../../../icons/tray-icon-tun.ico")),
            },
        )
    }
}

impl Default for Tray {
    #[allow(clippy::unwrap_used)]
    fn default() -> Self {
        Self {
            limiter: Limiter::new(Duration::from_millis(TRAY_CLICK_DEBOUNCE_MS), SystemClock),
            projection_lock: tokio::sync::Mutex::new(()),
            #[cfg(target_os = "macos")]
            speed_controller: speed_task::TraySpeedController::new(),
        }
    }
}

singleton!(Tray, TRAY);

impl Tray {
    fn new() -> Self {
        Self::default()
    }

    pub async fn init(&self) -> Result<()> {
        if handle::Handle::global().is_exiting() {
            logging!(debug, Type::Tray, "应用正在退出，跳过托盘初始化");
            return Ok(());
        }

        let app_handle = handle::Handle::app_handle();

        match self.create_tray_from_handle(app_handle).await {
            Ok(_) => {
                logging!(info, Type::Tray, "System tray created successfully");
            }
            Err(e) => {
                // Don't return error, let application continue running without tray
                logging!(
                    warn,
                    Type::Tray,
                    "System tray creation failed: {e}, Application will continue running without tray icon",
                );
            }
        }
        Ok(())
    }

    /// 更新托盘点击行为
    pub async fn update_click_behavior(&self) -> Result<()> {
        if handle::Handle::global().is_exiting() {
            logging!(debug, Type::Tray, "应用正在退出，跳过托盘点击行为更新");
            return Ok(());
        }

        let app_handle = handle::Handle::app_handle();
        let tray_event = { Config::verge().await.latest_arc().tray_event.clone() };
        let tray_event = TrayAction::from(tray_event.as_deref().unwrap_or("main_window"));
        let tray = app_handle
            .tray_by_id(TRAY_ID)
            .ok_or_else(|| anyhow::anyhow!("Failed to get main tray"))?;
        match tray_event {
            TrayAction::TrayMenu => tray.set_show_menu_on_left_click(true)?,
            _ => tray.set_show_menu_on_left_click(false)?,
        }
        Ok(())
    }

    /// 更新托盘菜单
    pub async fn update_menu(&self) -> Result<()> {
        if handle::Handle::global().is_exiting() {
            logging!(debug, Type::Tray, "应用正在退出，跳过托盘菜单更新");
            return Ok(());
        }
        let app_handle = handle::Handle::app_handle();
        self.update_menu_internal(app_handle, true).await
    }

    async fn update_menu_internal(&self, app_handle: &AppHandle, _include_proxy_groups: bool) -> Result<()> {
        let _projection = self.projection_lock.lock().await;
        let Some(tray) = app_handle.tray_by_id(TRAY_ID) else {
            logging!(warn, Type::Tray, "Failed to update tray menu: tray not found");
            return Ok(());
        };

        logging_error!(Type::Tray, tray.set_menu(Some(create_tray_menu(app_handle).await?)));

        logging!(debug, Type::Tray, "托盘菜单更新成功");
        Ok(())
    }

    /// 更新托盘图标
    pub async fn update_icon(&self, verge: &IVerge) -> Result<()> {
        if handle::Handle::global().is_exiting() {
            logging!(debug, Type::Tray, "应用正在退出，跳过托盘图标更新");
            return Ok(());
        }

        let app_handle = handle::Handle::app_handle();

        let Some(tray) = app_handle.tray_by_id(TRAY_ID) else {
            logging!(warn, Type::Tray, "Failed to update tray icon: tray not found");
            return Ok(());
        };

        let (_is_custom_icon, icon_bytes) = TrayState::get_tray_icon(verge).await;

        let template = {
            #[cfg(target_os = "macos")]
            {
                verge.tray_icon.as_ref().is_none_or(|v| v == "monochrome")
            }
            #[cfg(not(target_os = "macos"))]
            {
                false
            }
        };
        let icon = Some(tauri::image::Image::from_bytes(&icon_bytes)?);

        logging_error!(Type::Tray, tray.set_icon_with_as_template(icon, template));

        Ok(())
    }

    /// 更新托盘提示
    pub async fn update_tooltip(&self) -> Result<()> {
        if handle::Handle::global().is_exiting() {
            logging!(debug, Type::Tray, "应用正在退出，跳过托盘提示更新");
            return Ok(());
        }

        let app_handle = handle::Handle::app_handle();
        let _projection = self.projection_lock.lock().await;

        let menu_state = tono_menu_state(app_handle).await;

        let v = env!("CARGO_PKG_VERSION");
        let reassembled_version = v.split_once('+').map_or_else(
            || v.into(),
            |(main, rest)| format!("{main}+{}", rest.split('.').next().unwrap_or("")),
        );

        let tooltip = format!(
            "Tono {reassembled_version}\n{}\n{}",
            menu_state.protection_text(),
            menu_state.server_text()
        );

        let Some(tray) = app_handle.tray_by_id(TRAY_ID) else {
            logging!(warn, Type::Tray, "Failed to update tray tooltip: tray not found");
            return Ok(());
        };

        logging_error!(Type::Tray, tray.set_tooltip(Some(&tooltip)));

        Ok(())
    }

    pub async fn update_part(&self) -> Result<()> {
        if handle::Handle::global().is_exiting() {
            logging!(debug, Type::Tray, "应用正在退出，跳过托盘局部更新");
            return Ok(());
        }
        let verge = Config::verge().await.data_arc();
        let app_handle = handle::Handle::app_handle();
        self.update_menu_internal(app_handle, false).await?;
        AsyncHandler::spawn(|| async {
            logging_error!(Type::Tray, Self::global().update_menu().await);
        });
        self.update_icon(&verge).await?;
        #[cfg(target_os = "macos")]
        self.update_speed_task(verge.enable_tray_speed.unwrap_or(false));
        self.update_tooltip().await?;
        Ok(())
    }

    async fn create_tray_from_handle(&self, app_handle: &AppHandle) -> Result<()> {
        if handle::Handle::global().is_exiting() {
            logging!(debug, Type::Tray, "应用正在退出，跳过托盘创建");
            return Ok(());
        }

        logging!(info, Type::Tray, "正在从AppHandle创建系统托盘");

        let verge = Config::verge().await.data_arc();

        let icon_bytes = TrayState::get_tray_icon(&verge).await.1;
        let icon = tauri::image::Image::from_bytes(&icon_bytes)?;

        #[cfg(target_os = "linux")]
        let builder = TrayIconBuilder::with_id(TRAY_ID).icon(icon).icon_as_template(false);

        #[cfg(any(target_os = "macos", target_os = "windows"))]
        let show_menu_on_left_click = verge.tray_event.as_ref().is_some_and(|v| v == "tray_menu");

        #[cfg(not(target_os = "linux"))]
        let mut builder = TrayIconBuilder::with_id(TRAY_ID).icon(icon).icon_as_template(false);
        #[cfg(target_os = "macos")]
        {
            let is_monochrome = verge.tray_icon.as_ref().is_none_or(|v| v == "monochrome");
            builder = builder.icon_as_template(is_monochrome);
        }

        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            if !show_menu_on_left_click {
                builder = builder.show_menu_on_left_click(false);
            }
        }

        let tray = builder.build(app_handle)?;
        tray.on_tray_icon_event(on_tray_icon_event);
        tray.on_menu_event(on_menu_event);
        Ok(())
    }

    fn should_handle_tray_click(&self) -> bool {
        let allow = self.limiter.check();
        if !allow {
            logging!(debug, Type::Tray, "tray click rate limited");
        }
        allow
    }

    /// 根据配置统一更新托盘速率采集任务状态（macOS）
    #[cfg(target_os = "macos")]
    pub fn update_speed_task(&self, enable_tray_speed: bool) {
        self.speed_controller.update_task(enable_tray_speed);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TonoMenuState {
    account_state: String,
    ui_state: String,
    selected_server: Option<String>,
    selected_server_available: bool,
    catalog_requires_choice: bool,
    release_in_progress: bool,
    protection_blocked: bool,
}

impl Default for TonoMenuState {
    fn default() -> Self {
        Self {
            account_state: "restoring".to_string(),
            ui_state: "notConnected".to_string(),
            selected_server: None,
            selected_server_available: false,
            catalog_requires_choice: false,
            release_in_progress: false,
            protection_blocked: false,
        }
    }
}

impl TonoMenuState {
    fn from_status(status: commands::TonoStatus, selected_server_available: bool, release_in_progress: bool) -> Self {
        Self {
            account_state: status.account_state,
            ui_state: status.ui_state,
            selected_server: status.selected_server,
            selected_server_available,
            catalog_requires_choice: status.catalog_requires_choice,
            release_in_progress,
            protection_blocked: status.protection_blocked,
        }
    }

    fn protection_label(&self) -> Cow<'static, str> {
        clash_verge_i18n::t!(match self.ui_state.as_str() {
            "connecting" => "tray.tono.state.connecting",
            "connected" => "tray.tono.state.connected",
            "protectedOffline" => "tray.tono.state.protectedOffline",
            "disconnecting" => "tray.tono.state.disconnecting",
            _ => "tray.tono.state.notConnected",
        })
    }

    fn protection_text(&self) -> String {
        clash_verge_i18n::t!("tray.tono.protectionValue", value = self.protection_label()).into_owned()
    }

    fn server_text(&self) -> String {
        let value = self
            .selected_server
            .as_deref()
            .map(Cow::Borrowed)
            .unwrap_or_else(|| clash_verge_i18n::t!("tray.tono.noServer"));
        clash_verge_i18n::t!("tray.tono.serverValue", value = value).into_owned()
    }

    fn can_connect(&self) -> bool {
        self.account_state == "ready"
            && self.ui_state == "notConnected"
            && !self.protection_blocked
            && self.selected_server_available
            && !self.catalog_requires_choice
            && !self.release_in_progress
    }

    fn can_disconnect(&self) -> bool {
        self.ui_state != "disconnecting"
            && (self.ui_state == "connected" || self.ui_state == "connecting" || self.protection_blocked)
    }

    fn can_retry(&self) -> bool {
        self.account_state == "ready"
            && self.ui_state == "protectedOffline"
            && self.protection_blocked
            && self.selected_server_available
            && !self.catalog_requires_choice
            && !self.release_in_progress
    }
}

async fn tono_menu_state(app_handle: &AppHandle) -> TonoMenuState {
    let Some(state) = app_handle.try_state::<std::sync::Arc<TonoState>>() else {
        return TonoMenuState::default();
    };
    // Match the backend guard's lock order: release coordination before product state.
    let release_in_progress = state.release_in_progress().await;
    let inner = state.lock().await;
    let status = commands::status_of(&inner);
    let selected_server_available = status
        .selected_server
        .as_ref()
        .is_some_and(|selected| inner.nodes.iter().any(|node| node.name == *selected));
    TonoMenuState::from_status(status, selected_server_available, release_in_progress)
}

/// Tono-owned controls only: connection actions enter the same transaction as frontend IPC.
/// Legacy modes, proxies/profiles, system proxy/TUN, core restart and lightweight mode remain
/// absent. The retained directory/log/version entries are read-only diagnostics.
async fn create_tray_menu(app_handle: &AppHandle) -> Result<tauri::menu::Menu<Wry>> {
    let version = env!("CARGO_PKG_VERSION");
    let texts = MenuTexts::new();
    let state = tono_menu_state(app_handle).await;

    let protection = &MenuItem::with_id(
        app_handle,
        MenuIds::PROTECTION,
        state.protection_text(),
        false,
        None::<&str>,
    )?;
    let server = &MenuItem::with_id(app_handle, MenuIds::SERVER, state.server_text(), false, None::<&str>)?;
    let connect = &MenuItem::with_id(
        app_handle,
        MenuIds::CONNECT,
        &texts.connect,
        state.can_connect(),
        None::<&str>,
    )?;
    let disconnect = &MenuItem::with_id(
        app_handle,
        MenuIds::DISCONNECT,
        &texts.disconnect,
        state.can_disconnect(),
        None::<&str>,
    )?;
    let retry = &MenuItem::with_id(
        app_handle,
        MenuIds::RETRY,
        &texts.retry,
        state.can_retry(),
        None::<&str>,
    )?;
    let open_window = &MenuItem::with_id(app_handle, MenuIds::DASHBOARD, &texts.dashboard, true, None::<&str>)?;
    let open_app_dir = &MenuItem::with_id(app_handle, MenuIds::CONF_DIR, &texts.conf_dir, true, None::<&str>)?;
    let open_core_dir = &MenuItem::with_id(app_handle, MenuIds::CORE_DIR, &texts.core_dir, true, None::<&str>)?;
    let open_logs_dir = &MenuItem::with_id(app_handle, MenuIds::LOGS_DIR, &texts.logs_dir, true, None::<&str>)?;
    let open_app_log = &MenuItem::with_id(app_handle, MenuIds::APP_LOG, &texts.app_log, true, None::<&str>)?;
    let open_core_log = &MenuItem::with_id(app_handle, MenuIds::CORE_LOG, &texts.core_log, true, None::<&str>)?;
    let open_dir = &Submenu::with_id_and_items(
        app_handle,
        MenuIds::OPEN_DIR,
        &texts.open_dir,
        true,
        &[open_app_dir, open_core_dir, open_logs_dir, open_app_log, open_core_log],
    )?;
    let app_version = &MenuItem::with_id(
        app_handle,
        MenuIds::VERGE_VERSION,
        format!("{} {version}", texts.verge_version),
        true,
        None::<&str>,
    )?;

    #[cfg(target_os = "macos")]
    let quit_accelerator = Some("Cmd+Q");
    #[cfg(not(target_os = "macos"))]
    let quit_accelerator = None::<&str>;
    let quit = &MenuItem::with_id(app_handle, MenuIds::EXIT, &texts.exit, true, quit_accelerator)?;

    let separator = &PredefinedMenuItem::separator(app_handle)?;
    let menu = tauri::menu::MenuBuilder::new(app_handle)
        .items(&[
            protection,
            server,
            separator,
            connect,
            disconnect,
            retry,
            separator,
            open_window,
            separator,
            open_dir,
            app_version,
            separator,
            quit,
        ])
        .build()?;
    Ok(menu)
}

fn on_tray_icon_event(_tray_icon: &TrayIcon, tray_event: TrayIconEvent) {
    if matches!(
        tray_event,
        TrayIconEvent::Move { .. } | TrayIconEvent::Leave { .. } | TrayIconEvent::Enter { .. }
    ) {
        return;
    }

    if let TrayIconEvent::Click {
        button: MouseButton::Left,
        button_state: MouseButtonState::Down,
        ..
    } = tray_event
    {
        // 添加防抖检查，防止快速连击
        #[allow(clippy::use_self)]
        if !Tray::global().should_handle_tray_click() {
            return;
        }

        AsyncHandler::spawn(|| async move {
            // Tono: every left-click behavior maps to the dashboard (P0-5) —
            // no system-proxy/TUN toggles from the tray.
            logging!(debug, Type::Tray, "tray click: open dashboard");
            if !lightweight::exit_lightweight_mode().await {
                WindowManager::show_main_window().await;
            };
        });
    }
}

fn on_menu_event(_: &AppHandle, event: MenuEvent) {
    if !Tray::global().should_handle_tray_click() {
        return;
    }
    if event.id.as_ref().is_empty() {
        return;
    }
    AsyncHandler::spawn(|| async move {
        let Some(command) = MenuCommand::from_id(event.id.as_ref()) else {
            logging!(debug, Type::Tray, "Ignored tray menu event: {:?}", event.id.as_ref());
            return;
        };
        match command {
            MenuCommand::Connect | MenuCommand::Disconnect | MenuCommand::Retry => {
                let app = handle::Handle::app_handle().clone();
                let Some(state) = app
                    .try_state::<std::sync::Arc<TonoState>>()
                    .map(|state| state.inner().clone())
                else {
                    logging!(
                        warn,
                        Type::Tray,
                        "Tono tray action ignored: product state is unavailable"
                    );
                    return;
                };
                let result = match command {
                    MenuCommand::Connect => connection::connect(state, app).await,
                    MenuCommand::Disconnect => connection::disconnect(state, app).await,
                    MenuCommand::Retry => commands::retry_now(state, app).await,
                    _ => unreachable!(),
                };
                if let Err(err) = result {
                    logging!(warn, Type::Tray, "Tono tray action {command:?} failed: {err}");
                }
            }
            MenuCommand::Dashboard => {
                logging!(info, Type::Tray, "托盘菜单点击: 打开窗口");
                if !lightweight::exit_lightweight_mode().await {
                    WindowManager::show_main_window().await;
                };
            }
            MenuCommand::ConfDir => {
                let _ = cmd::open_app_dir().await;
            }
            MenuCommand::CoreDir => {
                let _ = cmd::open_core_dir().await;
            }
            MenuCommand::LogsDir => {
                let _ = cmd::open_logs_dir().await;
            }
            MenuCommand::AppLog => {
                let _ = help::open_app_latest_log();
            }
            MenuCommand::CoreLog => {
                let _ = help::open_core_latest_log().await;
            }
            MenuCommand::Exit => {
                feat::quit().await;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::TonoMenuState;

    fn state(ui_state: &str, blocked: bool) -> TonoMenuState {
        TonoMenuState {
            account_state: "ready".to_string(),
            ui_state: ui_state.to_string(),
            selected_server: Some("Seattle".to_string()),
            selected_server_available: true,
            catalog_requires_choice: false,
            release_in_progress: false,
            protection_blocked: blocked,
        }
    }

    #[test]
    fn disconnected_menu_offers_only_connect() {
        let state = state("notConnected", false);
        assert!(state.can_connect());
        assert!(!state.can_disconnect());
        assert!(!state.can_retry());
    }

    #[test]
    fn connected_and_connecting_menu_offer_safe_release() {
        for ui_state in ["connected", "connecting"] {
            let state = state(ui_state, ui_state == "connecting");
            assert!(!state.can_connect());
            assert!(state.can_disconnect());
            assert!(!state.can_retry());
        }
    }

    #[test]
    fn protected_offline_offers_retry_and_release_but_not_connect() {
        let state = state("protectedOffline", true);
        assert!(!state.can_connect());
        assert!(state.can_disconnect());
        assert!(state.can_retry());
    }

    #[test]
    fn transition_and_missing_prerequisites_disable_unsafe_actions() {
        let mut state = state("disconnecting", true);
        assert!(!state.can_connect());
        assert!(!state.can_disconnect());
        assert!(!state.can_retry());

        state.ui_state = "notConnected".to_string();
        state.protection_blocked = false;
        state.selected_server = None;
        state.selected_server_available = false;
        assert!(!state.can_connect());
        state.selected_server = Some("Seattle".to_string());
        state.selected_server_available = true;
        state.account_state = "signedOut".to_string();
        assert!(!state.can_connect());

        state.account_state = "ready".to_string();
        state.ui_state = "protectedOffline".to_string();
        state.protection_blocked = true;
        state.catalog_requires_choice = true;
        assert!(!state.can_connect());
        assert!(!state.can_retry());
        state.catalog_requires_choice = false;
        state.release_in_progress = true;
        assert!(!state.can_connect());
        assert!(!state.can_retry());
    }
}
