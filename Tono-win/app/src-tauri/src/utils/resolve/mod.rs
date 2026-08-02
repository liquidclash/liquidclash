use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;

use crate::{
    config::Config,
    core::{
        CoreManager,
        logger::Logger,
        service::{SERVICE_MANAGER, ServiceManager},
        tray::Tray,
    },
    feat,
    process::AsyncHandler,
    utils::{init, server, window_manager::WindowManager},
};
use clash_verge_logging::{Type, logging, logging_error};
use clash_verge_signal;

pub mod dns;
pub mod scheme;
pub mod window;
pub mod window_script;

static RESOLVE_DONE: AtomicBool = AtomicBool::new(false);

pub fn init_work_dir_and_logger() -> anyhow::Result<()> {
    AsyncHandler::block_on(async {
        init_work_config().await;
        logging!(info, Type::Setup, "Initializing logger");
        // #[cfg(not(feature = "tokio-trace"))]
        Logger::global().init().await?;
        Ok(())
    })
}

pub fn resolve_setup_sync() {
    AsyncHandler::spawn(|| async {
        AsyncHandler::spawn_blocking(init_scheme);
        AsyncHandler::spawn_blocking(init_embed_server);
    });
}

pub fn resolve_setup_async() {
    AsyncHandler::spawn(|| async {
        logging!(info, Type::ClashVergeRev, "Version: {}", env!("CARGO_PKG_VERSION"));

        #[cfg(target_os = "macos")]
        resolve_dock_show().await;
        init_service_manager().await;
        let config_initialized = init_verge_config_before_window().await;
        // Tono P0-10: hand-edited dangerous fields never survive startup.
        feat::sanitize_verge_config_for_tono().await;
        init_window().await;
        init_resources().await;
        if config_initialized {
            init_verge_config().await;
        }
        Config::verify_config_initialization().await;

        // Tono: the legacy core is never auto-started at boot — the mihomo
        // core may only be started by the Tono connect transaction (§6).
        // Automatic updates stay disabled until Tono owns a release endpoint
        // and signing key; never inherit the upstream Clash Verge channel.
        // Tono keeps the user-facing tray, but does not start legacy profile timers, global
        // hotkeys, lightweight mode, backup jobs, or old Core refresh traffic in the background.
        init_tray().await;
        refresh_tray_menu().await;
        resolve_done();
    });
}

pub async fn resolve_reset_async() -> Result<(), anyhow::Error> {
    CoreManager::global().stop_core().await?;

    #[cfg(target_os = "macos")]
    {
        use dns::restore_public_dns;
        restore_public_dns().await;
    }

    Ok(())
}

pub(super) fn init_scheme() {
    // Tono: the clash:// install pipeline is disabled (P0-4) — no protocol
    // registration, no subscription intake via deep links.
    logging!(info, Type::Setup, "Tono: deep-link scheme registration is disabled");
}

pub async fn resolve_scheme(param: &str) -> Result<()> {
    logging_error!(Type::Setup, scheme::resolve_scheme(param).await);
    Ok(())
}

pub(super) fn init_embed_server() {
    server::embed_server();
}

pub(super) async fn init_resources() {
    logging_error!(Type::Setup, init::init_resources().await);
}

pub fn init_signal() {
    logging!(info, Type::Setup, "Initializing signal handlers...");
    clash_verge_signal::register(feat::quit);
}

pub async fn init_work_config() {
    logging_error!(Type::Setup, init::init_config().await);
}

pub(super) async fn init_tray() {
    logging_error!(Type::Setup, Tray::global().init().await);
}

pub(super) async fn init_verge_config() {
    logging_error!(Type::Setup, Config::init_runtime_config().await);
}

pub(super) async fn init_verge_config_before_window() -> bool {
    let result = Config::init_config_before_window().await;
    let success = result.is_ok();
    logging_error!(Type::Setup, result);
    success
}

pub(super) async fn init_service_manager() {
    clash_verge_service_ipc::set_config(Some(ServiceManager::config())).await;

    SERVICE_MANAGER.detect_startup_status().await;
}

pub(super) async fn refresh_tray_menu() {
    logging_error!(Type::Setup, Tray::global().update_part().await);
}

pub(super) async fn init_window() {
    let is_silent_start = Config::verge().await.data_arc().enable_silent_start.unwrap_or(false);
    WindowManager::create_window(!is_silent_start).await;
}

#[cfg(target_os = "macos")]
pub(super) async fn resolve_dock_show() {
    use crate::core::handle::Handle;

    let is_silent_start = Config::verge().await.data_arc().enable_silent_start.unwrap_or(false);
    if is_silent_start {
        Handle::global().set_activation_policy_accessory();
    }
}

pub fn resolve_done() {
    RESOLVE_DONE.store(true, Ordering::Release);
}

pub fn is_resolve_done() -> bool {
    RESOLVE_DONE.load(Ordering::Acquire)
}
