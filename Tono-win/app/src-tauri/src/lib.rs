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
        ]
    }
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
            AsyncHandler::block_on(async move {
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
