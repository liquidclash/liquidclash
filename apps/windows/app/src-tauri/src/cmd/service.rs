use super::{CmdResult, WithErrorCode as _};
#[cfg(target_os = "macos")]
use crate::core::owner_identity::current_owner_credentials;
use crate::core::{
    CoreManager,
    service::{SERVICE_MANAGER, ServiceStatus},
};

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MacosKillSwitchStatus {
    capability_available: bool,
    supported: bool,
    status_available: bool,
    wanted: bool,
    live: bool,
    mode: clash_verge_service_ipc::MacosKillSwitchMode,
}

impl Default for MacosKillSwitchStatus {
    fn default() -> Self {
        Self {
            capability_available: false,
            supported: false,
            status_available: false,
            wanted: false,
            live: false,
            mode: clash_verge_service_ipc::MacosKillSwitchMode::Disabled,
        }
    }
}

async fn execute_service_operation_sync(status: ServiceStatus, error_code: &str) -> CmdResult {
    let manager = CoreManager::global();
    let _lifecycle = manager.lifecycle_lock.lock().await;
    SERVICE_MANAGER
        .handle_service_status(status)
        .await
        .with_error_code(error_code)
}

#[tauri::command]
pub async fn install_service() -> CmdResult {
    execute_service_operation_sync(ServiceStatus::InstallRequired, "SERVICE_INSTALL_FAILED").await
}

#[tauri::command]
pub async fn uninstall_service() -> CmdResult {
    // Tono: users may not uninstall the service (it owns the kill switch).
    Err("disabled by Tono".into())
}

#[tauri::command]
pub async fn reinstall_service() -> CmdResult {
    execute_service_operation_sync(ServiceStatus::ReinstallRequired, "SERVICE_REINSTALL_FAILED").await
}

#[tauri::command]
pub async fn repair_service() -> CmdResult {
    execute_service_operation_sync(ServiceStatus::ForceReinstallRequired, "SERVICE_REPAIR_FAILED").await
}

#[tauri::command]
pub async fn continue_with_sidecar() -> CmdResult {
    // Tono has no sidecar fallback.
    Err("disabled by Tono".into())
}

/// Return both protocol capability and the root service's live PF state.
///
/// This deliberately does not infer protection from the app setting: only the privileged
/// service can say whether the PF anchor is actually installed. Service outages are represented
/// as an unavailable snapshot so the UI never mistakes an IPC error for an unprotected system.
#[tauri::command]
pub async fn get_macos_kill_switch_status() -> MacosKillSwitchStatus {
    #[cfg(not(target_os = "macos"))]
    return MacosKillSwitchStatus::default();

    #[cfg(target_os = "macos")]
    {
        let Ok(version) = clash_verge_service_ipc::get_version().await else {
            return MacosKillSwitchStatus::default();
        };
        let supported = version.code == 0
            && version
                .data
                .as_ref()
                .is_some_and(clash_verge_service_ipc::ProtocolInfo::supports_macos_kill_switch);
        if !supported {
            return MacosKillSwitchStatus {
                capability_available: version.code == 0 && version.data.is_some(),
                ..Default::default()
            };
        }

        let Ok(credentials) = current_owner_credentials() else {
            return MacosKillSwitchStatus {
                capability_available: true,
                supported: true,
                ..Default::default()
            };
        };
        let Ok(response) = clash_verge_service_ipc::get_status(&credentials).await else {
            return MacosKillSwitchStatus {
                capability_available: true,
                supported: true,
                ..Default::default()
            };
        };
        let Some(status) = response.data.filter(|_| response.code == 0) else {
            return MacosKillSwitchStatus {
                capability_available: true,
                supported: true,
                ..Default::default()
            };
        };

        MacosKillSwitchStatus {
            capability_available: true,
            supported: true,
            status_available: true,
            wanted: status.macos_kill_switch_wanted,
            live: status.macos_kill_switch_live,
            mode: status.macos_kill_switch_mode,
        }
    }
}
