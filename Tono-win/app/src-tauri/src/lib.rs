#![allow(non_snake_case)]
#![recursion_limit = "512"]

mod cmd;
pub mod config;
mod constants;
mod core;
mod enhance;
mod feat;
mod module;
mod process;
mod tono;
pub mod utils;

use crate::constants::files;
use crate::{
    core::handle,
    process::AsyncHandler,
    utils::{resolve, server},
};
use anyhow::Result;
use clash_verge_logging::{Type, logging};
use once_cell::sync::OnceCell;
use tauri::{AppHandle, Manager as _};
#[cfg(target_os = "macos")]
use tauri_plugin_autostart::MacosLauncher;

pub static APP_HANDLE: OnceCell<AppHandle> = OnceCell::new();
/// Application initialization helper functions
mod app_init {
    use super::*;

    /// Initialize singleton monitoring for other instances
    pub fn init_singleton_check() -> Result<()> {
        AsyncHandler::block_on(async move {
            logging!(info, Type::Setup, "开始检查单例实例...");
            server::check_singleton().await?;
            Ok(())
        })
    }

    /// Setup plugins for the Tauri builder
    pub fn setup_plugins(builder: tauri::Builder<tauri::Wry>) -> tauri::Builder<tauri::Wry> {
        #[allow(unused_mut)]
        let mut builder = builder
            .plugin(tauri_plugin_clash_verge_sysinfo::init())
            .plugin(tauri_plugin_notification::init())
            .plugin(tauri_plugin_clipboard_manager::init())
            .plugin(tauri_plugin_process::init())
            .plugin(tauri_plugin_global_shortcut::Builder::new().build())
            .plugin(tauri_plugin_fs::init())
            .plugin(tauri_plugin_dialog::init())
            .plugin(tauri_plugin_shell::init())
            .plugin(tauri_plugin_http::init())
            .plugin(
                tauri_plugin_mihomo::Builder::new()
                    .protocol(tauri_plugin_mihomo::models::Protocol::LocalSocket)
                    .socket_path(crate::config::IClashTemp::guard_external_controller_ipc())
                    .build(),
            );

        // Devtools plugin only in debug mode with feature tauri-dev
        // to avoid duplicated registering of logger since the devtools plugin also registers a logger
        #[cfg(all(debug_assertions, not(feature = "tokio-trace"), feature = "tauri-dev"))]
        {
            builder = builder.plugin(tauri_plugin_devtools::init());
        }
        builder
    }

    /// Setup autostart plugin
    pub fn setup_autostart(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(target_os = "macos")]
        let mut auto_start_plugin_builder = tauri_plugin_autostart::Builder::new();
        #[cfg(not(target_os = "macos"))]
        let auto_start_plugin_builder = tauri_plugin_autostart::Builder::new();

        #[cfg(target_os = "macos")]
        {
            auto_start_plugin_builder = auto_start_plugin_builder
                .macos_launcher(MacosLauncher::LaunchAgent)
                .app_name(&app.config().identifier);
        }
        app.handle().plugin(auto_start_plugin_builder.build())?;
        Ok(())
    }

    /// Setup window state management
    pub fn setup_window_state(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
        logging!(info, Type::Setup, "初始化窗口状态管理...");
        let window_state_plugin = tauri_plugin_window_state::Builder::new()
            .with_filename(files::WINDOW_STATE)
            .with_state_flags(tauri_plugin_window_state::StateFlags::default())
            .build();
        app.handle().plugin(window_state_plugin)?;
        Ok(())
    }

    pub fn generate_handlers() -> impl Fn(tauri::ipc::Invoke<tauri::Wry>) -> bool + Send + Sync + 'static {
        tauri::generate_handler![
            tauri_plugin_clash_verge_sysinfo::commands::get_system_info,
            tauri_plugin_clash_verge_sysinfo::commands::get_app_uptime,
            tauri_plugin_clash_verge_sysinfo::commands::app_is_admin,
            tauri_plugin_clash_verge_sysinfo::commands::export_diagnostic_info,
            cmd::probe_listener,
            cmd::save_proxy_ports,
            cmd::get_sys_proxy,
            cmd::get_auto_proxy,
            cmd::get_embedded_server_port,
            cmd::open_app_dir,
            cmd::open_logs_dir,
            cmd::open_web_url,
            cmd::open_core_dir,
            cmd::get_portable_flag,
            cmd::get_network_interfaces,
            cmd::get_system_hostname,
            cmd::restart_app,
            cmd::start_core,
            cmd::stop_core,
            cmd::restart_core,
            cmd::get_runtime_state,
            cmd::get_auto_launch_status,
            cmd::entry_lightweight_mode,
            cmd::exit_lightweight_mode,
            cmd::install_service,
            cmd::uninstall_service,
            cmd::reinstall_service,
            cmd::repair_service,
            cmd::continue_with_sidecar,
            cmd::get_macos_kill_switch_status,
            cmd::get_clash_info,
            cmd::patch_clash_config,
            cmd::patch_clash_mode,
            cmd::get_clash_mode,
            cmd::change_clash_core,
            cmd::get_runtime_config,
            cmd::get_proxy_view,
            cmd::get_runtime_yaml,
            cmd::get_runtime_exists,
            cmd::get_runtime_logs,
            cmd::get_runtime_proxy_chain_config,
            cmd::update_proxy_chain_config_in_runtime,
            cmd::invoke_uwp_tool,
            cmd::copy_clash_env,
            cmd::sync_tray_proxy_selection,
            cmd::record_selected_node,
            cmd::save_dns_config,
            cmd::apply_dns_config,
            cmd::check_dns_config_exists,
            cmd::get_dns_config_content,
            cmd::validate_dns_config,
            cmd::get_clash_logs,
            cmd::get_verge_config,
            cmd::patch_verge_config,
            cmd::test_delay,
            cmd::get_app_dir,
            cmd::copy_icon_file,
            cmd::download_icon_cache,
            cmd::open_devtools,
            cmd::exit_app,
            cmd::get_network_interfaces_info,
            cmd::get_profiles,
            cmd::enhance_profiles,
            cmd::patch_profiles_config,
            cmd::view_profile,
            cmd::patch_profile,
            cmd::create_profile,
            cmd::import_profile,
            cmd::reorder_profile,
            cmd::update_profile,
            cmd::delete_profile,
            cmd::read_profile_file,
            cmd::save_profile_file,
            cmd::get_next_update_time,
            cmd::script_validate_notice,
            cmd::validate_script_file,
            cmd::create_local_backup,
            cmd::list_local_backup,
            cmd::delete_local_backup,
            cmd::restore_local_backup,
            cmd::import_local_backup,
            cmd::export_local_backup,
            cmd::create_webdav_backup,
            cmd::save_webdav_config,
            cmd::list_webdav_backup,
            cmd::delete_webdav_backup,
            cmd::restore_webdav_backup,
            cmd::get_unlock_items,
            cmd::check_media_unlock,
            tono::commands::tono_sign_in_start,
            tono::commands::tono_sign_in_verify,
            tono::commands::tono_sign_out,
            tono::commands::tono_account,
            tono::commands::tono_devices,
            tono::commands::tono_revoke_device,
            tono::commands::tono_servers,
            tono::commands::tono_select_server,
            tono::commands::tono_test_current_server,
            tono::commands::tono_connect,
            tono::commands::tono_disconnect,
            tono::commands::tono_status,
            tono::commands::tono_retry_restore,
            tono::commands::tono_audit_enabled,
            tono::commands::tono_set_audit_enabled,
            tono::commands::tono_audit_log_path,
            tono::commands::tono_connect_progress,
            tono::commands::tono_retry_now,
            tono::commands::tono_diagnostics_report,
            tono::commands::tono_upload_diagnostics,
        ]
    }
}

/// Hard budget for the whole committed-exit cleanup, enforced from the Tauri main thread.
///
/// Sized to cover every inner budget the cleanup can legitimately consume
/// (`QUIT_RELEASE_BUDGET` + the session-ending core stop + the audit flush) plus head-room.
/// The unit test below keeps it above their sum, so a future change to one of them cannot
/// silently make the outer wait the effective limit.
const EXIT_CLEANUP_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);

/// How long the Tono state recovery keeps trying, and how often.
///
/// The failure it recovers from is `TonoState::create`, whose first act is `create_dir_all` on
/// the Tono data directory. Its realistic causes — a full disk, a roaming profile not mounted
/// yet, an ACL a policy refresh repairs — are transient often enough to be worth retrying, and
/// the cost of not retrying is an app in which protection can never be released.
const TONO_STATE_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(15);
const TONO_STATE_RETRY_ATTEMPTS: usize = 8;

/// Keep trying to build the Tono product state, telling the user why the app is degraded.
///
/// Without managed state the window is not merely missing a feature: every Tono command,
/// including Disconnect, fails before it runs, so an armed barrier from a previous session has
/// no owner and no release path. A toast per attempt is the loudest channel available from here
/// and is at least truthful; each retry that succeeds restores the whole product layer.
async fn recover_tono_state(app_handle: AppHandle, first_error: String) {
    let mut error = first_error;
    for attempt in 0..TONO_STATE_RETRY_ATTEMPTS {
        // The first wait also lets the WebView finish loading, otherwise the notice is emitted
        // into a frontend that is not listening yet.
        let delay = if attempt == 0 {
            constants::timing::STARTUP_ERROR_DELAY
        } else {
            TONO_STATE_RETRY_DELAY
        };
        tokio::time::sleep(delay).await;
        handle::Handle::notice_message("tono_state_init_failed", error.clone());
        match tono::TonoState::create() {
            Ok(state) => {
                let state = std::sync::Arc::new(state);
                if app_handle.manage(state.clone()) {
                    logging!(info, Type::Setup, "Tono state recovered after {} attempt(s)", attempt + 1);
                    tono::commands::restore_session_guarded(app_handle.clone(), state).await;
                }
                return;
            }
            Err(err) => error = format!("{err:#}"),
        }
    }
    logging!(
        error,
        Type::Setup,
        "Tono state could not be created after {TONO_STATE_RETRY_ATTEMPTS} attempts: {error}"
    );
    handle::Handle::notice_message("tono_state_init_failed_permanently", error);
}

/// How often the Tauri main thread is probed, and how long a probe may take before it is logged.
///
/// On Windows "(Not Responding)" means exactly one thing: the thread that owns the top-level
/// window stopped servicing its message queue for ~5 s. Two real-machine reports showed that
/// title in states where nothing in this process should have been waiting on anything — and a
/// screenshot cannot tell a blocked native main thread apart from a wedged WebView2 renderer,
/// because both produce the identical title bar. This probe settles it from the app's own log:
/// a `run_on_main_thread` round trip can only complete while the event loop is pumping, so a gap
/// here *is* a stalled pump, and the absence of a gap across a reported freeze rules the main
/// thread out and points at the WebView.
///
/// The threshold is deliberately well under the ~5 s at which Windows starts ghosting the
/// window, so a stall is recorded before the user can see it and can be lined up with the
/// connect-stage lines already in the same log.
const MAIN_THREAD_PROBE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
const MAIN_THREAD_STALL_THRESHOLD: std::time::Duration = std::time::Duration::from_secs(2);
/// How long a *visible* window may go without calling `tono_status` before the WebView is
/// reported as the stuck side. `useTonoStatus` polls every 5 s while visible (plus a read per
/// status push), so this is several missed polls, not a tight race.
const FRONTEND_SILENCE_THRESHOLD: std::time::Duration = std::time::Duration::from_secs(20);

/// Log which side of the app — the native main thread or the WebView — has stopped running.
///
/// Costs one cross-thread dispatch per second and nothing else; it never touches product state,
/// so it cannot itself become the thing that blocks.
async fn main_thread_pump_watchdog(app_handle: AppHandle) {
    let mut interval = tokio::time::interval(MAIN_THREAD_PROBE_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut frontend_reported = false;
    loop {
        interval.tick().await;
        if handle::Handle::global().is_exiting() {
            return;
        }

        let (tx, rx) = tokio::sync::oneshot::channel::<bool>();
        let probe_handle = app_handle.clone();
        let sent_at = std::time::Instant::now();
        // The visibility read rides along inside the dispatched closure: it is already on the
        // main thread there, so it costs nothing extra and can never add a blocking round trip.
        if app_handle
            .run_on_main_thread(move || {
                let visible = probe_handle
                    .get_webview_window("main")
                    .and_then(|window| window.is_visible().ok())
                    .unwrap_or(false);
                let _ = tx.send(visible);
            })
            .is_err()
        {
            // The event loop is gone (exit); there is nothing left to watch.
            return;
        }

        let mut landed = std::pin::pin!(rx);
        let visible = match tokio::time::timeout(MAIN_THREAD_STALL_THRESHOLD, landed.as_mut()).await {
            Ok(Ok(visible)) => visible,
            // Sender dropped: the loop tore the dispatch down, i.e. we are shutting down.
            Ok(Err(_)) => return,
            Err(_) => {
                logging!(
                    warn,
                    Type::System,
                    "Main thread pump STALLED: no dispatch ran in {MAIN_THREAD_STALL_THRESHOLD:?}. \
                     A freeze reported around this timestamp is on the native side, not in the WebView"
                );
                let Ok(visible) = landed.await else {
                    return;
                };
                logging!(
                    warn,
                    Type::System,
                    "Main thread pump resumed after {:?}",
                    sent_at.elapsed()
                );
                visible
            }
        };

        // The pump answered, so the native side is healthy. If a visible window has also stopped
        // making its scheduled status call, the WebView is the stuck side.
        match tono::commands::frontend_ipc_silence() {
            Some(silence) if visible && silence >= FRONTEND_SILENCE_THRESHOLD => {
                if !frontend_reported {
                    frontend_reported = true;
                    logging!(
                        warn,
                        Type::Frontend,
                        "WebView STALLED: main thread is pumping but the visible window has not called \
                         tono_status for {silence:?}. A freeze reported around this timestamp is in the \
                         WebView, not on the native side"
                    );
                }
            }
            _ => {
                if frontend_reported {
                    frontend_reported = false;
                    logging!(info, Type::Frontend, "WebView resumed calling tono_status");
                }
            }
        }
    }
}

/// Everything that must still happen once exit is *committed* (`RunEvent::Exit`).
///
/// Deliberately a plain async fn so it can be driven on the async runtime rather than on the
/// main thread — see the call site for why that distinction is load-bearing.
async fn run_committed_exit_cleanup(app_handle: AppHandle) {
    // Windows session ending currently reaches Tao as WM_ENDSESSION and
    // destroys the loop without a preventable ExitRequested event.
    if !handle::Handle::global().is_exiting() {
        handle::Handle::global().set_is_exiting();
        // L1: Quit is one of the three releasing causes (§6) — restore
        // DNS and disarm via the owner-gated route, best-effort.
        match tokio::time::timeout(
            tono::commands::QUIT_RELEASE_BUDGET,
            tono::commands::quit_release(app_handle.clone()),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => logging!(
                error,
                Type::Service,
                "Tono: session-ending release failed; protection remains fail-closed: {error}"
            ),
            Err(_) => logging!(
                error,
                Type::Service,
                "Tono: session-ending release exceeded {:?}; Service reconciliation may still be running",
                tono::commands::QUIT_RELEASE_BUDGET
            ),
        }
        let cleanup_result = feat::clean_session_ending_best_effort().await;
        logging!(
            info,
            Type::System,
            "Unpreventable session-ending best-effort cleanup returned - core stopped: {}, all cleanup successful: {}",
            cleanup_result.core_stopped,
            cleanup_result.all_success
        );
    }
    // M3: exit is committed here (and only here) — flush the audit
    // writer. Runs on every exit path, guarded or not.
    tono::commands::flush_audit_for_exit(&app_handle).await;
    logging!(info, Type::System, "Application exited");
}

pub fn run() {
    #[cfg(all(target_os = "macos", not(debug_assertions), not(test), not(feature = "verge-dev")))]
    if utils::macos_launch_guard::enforce_before_initialization() == utils::macos_launch_guard::LaunchDisposition::Exit
    {
        return;
    }

    let _ = utils::dirs::init_portable_flag();

    if app_init::init_singleton_check().is_err() {
        return;
    }

    #[cfg(target_os = "linux")]
    utils::linux::workarounds::apply_nvidia_dmabuf_renderer_workaround();
    #[cfg(target_os = "linux")]
    utils::linux::workarounds::apply_wayland_webkit_fix();

    let builder = app_init::setup_plugins(tauri::Builder::default())
        .setup(|app| {
            // Logger may not be ready yet, so mirror setup panics to stderr.
            fn log_setup_panic(stage: &str, panic: Box<dyn std::any::Any + Send>) {
                let msg = panic
                    .downcast_ref::<&str>()
                    .map(|s| (*s).to_string())
                    .or_else(|| panic.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "unknown panic payload".to_string());
                eprintln!("[clash-verge] panic during app setup ({stage}), continuing in degraded mode: {msg}");
                logging!(
                    error,
                    Type::Setup,
                    "setup 阶段 panic（{}）—— 降级继续启动: {}",
                    stage,
                    msg
                );
            }

            // Prevent setup panics from aborting across macOS applicationDidFinishLaunching.
            // Keep pre-init separate so window/core/tray startup is still scheduled after a panic.
            if let Err(panic) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                #[allow(clippy::expect_used)]
                APP_HANDLE
                    .set(app.app_handle().clone())
                    .expect("failed to set global app handle");

                if let Err(e) = resolve::init_work_dir_and_logger() {
                    logging!(error, Type::Setup, "Failed to init work dir/logger: {}", e);
                }

                logging!(info, Type::Setup, "开始应用初始化...");
                if let Err(e) = app_init::setup_autostart(app) {
                    logging!(error, Type::Setup, "Failed to setup autostart: {}", e);
                }

                if let Err(e) = app_init::setup_window_state(app) {
                    logging!(error, Type::Setup, "Failed to setup window state: {}", e);
                }
            })) {
                log_setup_panic("pre-init", panic);
            }

            // Always attempt the startup stage, even if pre-init degraded.
            if let Err(panic) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                resolve::resolve_setup_async();
                resolve::resolve_setup_sync();
                resolve::init_signal();
                logging!(info, Type::Setup, "初始化已启动");
            })) {
                log_setup_panic("window-core", panic);
            }

            // Which side is stuck when the window says "(Not Responding)" — see the constants.
            {
                let app_handle = app.app_handle().clone();
                AsyncHandler::spawn(move || main_thread_pump_watchdog(app_handle));
            }

            // Tono product layer: state injection + startup session restore.
            if let Err(panic) =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match tono::TonoState::create() {
                    Ok(state) => {
                        let state = std::sync::Arc::new(state);
                        app.manage(state.clone());
                        let app_handle = app.app_handle().clone();
                        AsyncHandler::spawn(move || async move {
                            tono::commands::restore_session_guarded(app_handle, state).await;
                        });
                    }
                    Err(e) => {
                        logging!(error, Type::Setup, "Failed to init Tono state: {e:#}");
                        // A log line was the entire response, and the window then opened looking
                        // perfectly normal while every `tono::commands` entry point failed at
                        // state resolution — including the only route that can release an armed
                        // WFP barrier. Make it visible and keep trying.
                        let app_handle = app.app_handle().clone();
                        AsyncHandler::spawn(move || recover_tono_state(app_handle, format!("{e:#}")));
                    }
                }))
            {
                log_setup_panic("tono", panic);
            }

            Ok(())
        })
        .invoke_handler(app_init::generate_handlers());

    // macOS 内存压力下 WKWebView 渲染进程可能被系统终止（表现为白屏），
    // 注册恢复钩子：清理孤儿 WebSocket 订阅防止内存泄漏；窗口可见时立即 reload
    // 恢复页面，不可见时延迟到用户下次打开窗口再 reload。
    #[cfg(target_os = "macos")]
    let builder = builder.on_web_content_process_terminate(resolve::window::on_web_content_process_terminated);

    mod event_handlers {
        #[cfg(target_os = "macos")]
        use crate::module::lightweight;
        use crate::utils::window_manager::WindowManager;
        use crate::{
            config::Config,
            core::{self, handle, hotkey},
            process::AsyncHandler,
        };
        use clash_verge_logging::{Type, logging};
        use tauri::AppHandle;
        #[cfg(target_os = "macos")]
        use tauri::Manager as _;

        pub fn handle_ready_resumed(_app_handle: &AppHandle) {
            if handle::Handle::global().is_exiting() {
                logging!(debug, Type::System, "应用正在退出，跳过处理");
                return;
            }

            logging!(info, Type::System, "应用就绪");
            crate::utils::server::set_commands_ready();

            #[cfg(target_os = "macos")]
            if let Some(window) = _app_handle.get_webview_window("main") {
                let _ = window.set_title("Tono");
            }
        }

        #[cfg(target_os = "macos")]
        pub async fn handle_reopen(has_visible_windows: bool) {
            if lightweight::is_in_lightweight_mode() {
                lightweight::exit_lightweight_mode().await;
                return;
            }

            if !has_visible_windows {
                handle::Handle::global().set_activation_policy_regular();
                let _ = WindowManager::show_main_window().await;
            }
        }

        pub fn handle_window_close(api: &tauri::WindowEvent) {
            #[cfg(target_os = "macos")]
            handle::Handle::global().set_activation_policy_accessory();

            if core::handle::Handle::global().is_exiting() {
                return;
            }

            if let tauri::WindowEvent::CloseRequested { api, .. } = api {
                api.prevent_close();
                if let Some(window) = WindowManager::get_main_window() {
                    let _ = window.hide();
                }
            }
        }

        pub fn handle_window_focus(focused: bool) {
            AsyncHandler::spawn(move || async move {
                let is_enable_global_hotkey = Config::verge().await.data_arc().enable_global_hotkey.unwrap_or(true);

                if focused {
                    #[cfg(target_os = "macos")]
                    {
                        use crate::core::hotkey::SystemHotkey;
                        let _ = hotkey::Hotkey::global()
                            .register_system_hotkey(SystemHotkey::CmdQ)
                            .await;
                        let _ = hotkey::Hotkey::global()
                            .register_system_hotkey(SystemHotkey::CmdW)
                            .await;
                    }
                    if !is_enable_global_hotkey {
                        let _ = hotkey::Hotkey::global().init(false).await;
                    }
                    return;
                }

                #[cfg(target_os = "macos")]
                {
                    use crate::core::hotkey::SystemHotkey;
                    let _ = hotkey::Hotkey::global().unregister_system_hotkey(SystemHotkey::CmdQ);
                    let _ = hotkey::Hotkey::global().unregister_system_hotkey(SystemHotkey::CmdW);
                }

                if !is_enable_global_hotkey {
                    let _ = hotkey::Hotkey::global().reset();
                }
            });
        }

        #[cfg(target_os = "macos")]
        pub fn handle_window_destroyed() {
            use crate::core::hotkey::SystemHotkey;
            AsyncHandler::spawn(move || async move {
                let _ = hotkey::Hotkey::global().unregister_system_hotkey(SystemHotkey::CmdQ);
                let _ = hotkey::Hotkey::global().unregister_system_hotkey(SystemHotkey::CmdW);
                let is_enable_global_hotkey = Config::verge().await.data_arc().enable_global_hotkey.unwrap_or(true);
                if !is_enable_global_hotkey {
                    let _ = hotkey::Hotkey::global().reset();
                }
            });
        }
    }

    #[cfg(feature = "clippy")]
    let context = tauri::test::mock_context(tauri::test::noop_assets());
    #[cfg(feature = "clippy")]
    let app = builder.build(context).unwrap_or_else(|e| {
        logging!(error, Type::Setup, "Failed to build Tauri application: {}", e);
        std::process::exit(1);
    });

    #[cfg(not(feature = "clippy"))]
    let app = builder.build(tauri::generate_context!()).unwrap_or_else(|e| {
        logging!(error, Type::Setup, "Failed to build Tauri application: {}", e);
        std::process::exit(1);
    });

    app.run(|app_handle, e| match e {
        tauri::RunEvent::Ready | tauri::RunEvent::Resumed => {
            if core::handle::Handle::global().is_exiting() {
                return;
            }
            event_handlers::handle_ready_resumed(app_handle);
        }
        #[cfg(target_os = "macos")]
        tauri::RunEvent::Reopen {
            has_visible_windows, ..
        } => {
            if core::handle::Handle::global().is_exiting() {
                return;
            }
            AsyncHandler::spawn(move || async move {
                event_handlers::handle_reopen(has_visible_windows).await;
            });
        }
        tauri::RunEvent::Exit => {
            let app_handle = app_handle.clone();
            // This runs ON the Tauri main thread, so the native message pump is stopped for
            // exactly as long as this handler runs: anything that parks this thread makes the
            // window "Not Responding" and unclosable. Service IPC can park whichever thread
            // polls it (a Service wedged inside a WFP/BFE kernel call never yields), so the
            // cleanup is driven on the async runtime and the main thread only ever awaits a
            // JoinHandle — a wait that is always enforceable — under one hard budget.
            //
            // Abandoning the cleanup is fail-closed by construction: nothing here opens the
            // network, so an unfinished release leaves WFP armed rather than dropping it.
            let cleanup = AsyncHandler::spawn(move || run_committed_exit_cleanup(app_handle));
            AsyncHandler::block_on(async move {
                if tokio::time::timeout(EXIT_CLEANUP_BUDGET, cleanup).await.is_err() {
                    logging!(
                        error,
                        Type::System,
                        "Exit cleanup exceeded {EXIT_CLEANUP_BUDGET:?}; abandoning it so the process can close. Protection stays armed and the Service reconciles on its own"
                    );
                }
            })
        }
        #[allow(unused_variables)]
        tauri::RunEvent::ExitRequested { api, code, .. } => {
            if module::lightweight::is_in_lightweight_mode() && !handle::Handle::global().is_exiting() {
                api.prevent_exit();
            } else if code.is_none() {
                api.prevent_exit();
                if !handle::Handle::global().is_exiting() {
                    // Claim the single-flight synchronously before returning to Tao. Cleanup runs
                    // on the async runtime so the native event loop keeps pumping paint, drag and
                    // minimize messages while Service/Core shutdown completes.
                    handle::Handle::global().set_is_exiting();
                    let app_handle = app_handle.clone();
                    AsyncHandler::spawn(move || async move {
                        // `feat::quit` is the sole explicit-release owner. A second release here
                        // used to consume another 2.5 s budget and could race the Service cleanup.
                        if matches!(feat::quit().await, clash_verge_signal::ShutdownOutcome::Canceled) {
                            // The barrier may already be released while the FSM still claims
                            // protection; re-sync only when quitting was actually cancelled.
                            tono::commands::resync_after_cancelled_quit(app_handle).await;
                        }
                    });
                }
            }
        }
        tauri::RunEvent::WindowEvent { label, event, .. } if label == "main" => match event {
            tauri::WindowEvent::CloseRequested { .. } => {
                event_handlers::handle_window_close(&event);
            }
            tauri::WindowEvent::Focused(focused) => {
                // 兜底：原生取消最小化只触发 Focused、不走 activate_window（macOS）
                #[cfg(target_os = "macos")]
                if focused {
                    crate::utils::resolve::window::reload_main_window_if_needed();
                }
                event_handlers::handle_window_focus(focused);
            }
            #[cfg(target_os = "macos")]
            tauri::WindowEvent::Destroyed => {
                event_handlers::handle_window_destroyed();
            }
            _ => {}
        },
        _ => {}
    });
}

#[cfg(test)]
mod exit_budget_tests {
    use super::EXIT_CLEANUP_BUDGET;
    use crate::feat::SESSION_ENDING_STOP_BUDGET;
    use crate::tono::commands::{AUDIT_FLUSH_BUDGET, QUIT_RELEASE_BUDGET};

    /// The committed-exit wait runs on the Tauri main thread, so it is the message pump's
    /// hard ceiling. It must stay strictly above everything the cleanup can legitimately
    /// spend, otherwise the outer wait — not the inner budgets — becomes the real limit and
    /// every normal exit would look like an abandoned one.
    #[test]
    fn committed_exit_budget_covers_every_inner_budget() {
        let inner = QUIT_RELEASE_BUDGET + SESSION_ENDING_STOP_BUDGET + AUDIT_FLUSH_BUDGET;
        assert!(
            EXIT_CLEANUP_BUDGET > inner,
            "EXIT_CLEANUP_BUDGET ({EXIT_CLEANUP_BUDGET:?}) must exceed the inner budgets it covers ({inner:?})"
        );
    }
}

#[cfg(test)]
mod pump_watchdog_tests {
    use super::{
        FRONTEND_SILENCE_THRESHOLD, MAIN_THREAD_PROBE_INTERVAL, MAIN_THREAD_STALL_THRESHOLD,
    };

    /// Windows ghosts a window ("Not Responding") after roughly five seconds without a pumped
    /// message. The watchdog is only useful if it records the stall *before* the user can see it,
    /// and it can only do that if a probe is outstanding when the stall begins.
    #[test]
    fn stall_is_recorded_before_windows_ghosts_the_window() {
        const WINDOWS_HUNG_WINDOW_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
        assert!(
            MAIN_THREAD_PROBE_INTERVAL < MAIN_THREAD_STALL_THRESHOLD,
            "a probe must be in flight more often than the stall it reports"
        );
        assert!(
            MAIN_THREAD_PROBE_INTERVAL + MAIN_THREAD_STALL_THRESHOLD < WINDOWS_HUNG_WINDOW_TIMEOUT,
            "worst-case detection ({:?}) must land before Windows marks the window unresponsive",
            MAIN_THREAD_PROBE_INTERVAL + MAIN_THREAD_STALL_THRESHOLD
        );
    }

    /// The WebView-side signal is `useTonoStatus`'s 5 s safety-net poll. The threshold must allow
    /// several missed polls, or ordinary scheduling jitter would be reported as a stall.
    #[test]
    fn frontend_silence_threshold_allows_several_missed_polls() {
        const FRONTEND_STATUS_POLL: std::time::Duration = std::time::Duration::from_secs(5);
        assert!(
            FRONTEND_SILENCE_THRESHOLD >= FRONTEND_STATUS_POLL * 3,
            "FRONTEND_SILENCE_THRESHOLD ({FRONTEND_SILENCE_THRESHOLD:?}) must cover several missed {FRONTEND_STATUS_POLL:?} polls"
        );
    }
}
