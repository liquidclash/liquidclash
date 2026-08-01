use super::CmdResult;
use crate::{cmd::StringifyErr as _, config::IVerge, feat};
use clash_verge_draft::SharedDraft;

/// 获取Verge配置
#[tauri::command]
pub async fn get_verge_config() -> CmdResult<SharedDraft<IVerge>> {
    feat::fetch_verge_config().await.stringify_err()
}

/// Tono whitelist: `patch_verge_config` only accepts display/behavior
/// fields. Anything that can steer traffic, the core, the proxy surface,
/// credentials, or backups is rejected *before* it reaches the draft
/// (P0-3). A forbidden key present (non-None) fails the whole patch.
fn forbidden_field_present(patch: &IVerge) -> Option<&'static str> {
    #[allow(clippy::type_complexity)]
    #[allow(unused_mut)] // the platform `extend` below may be compiled out
    let mut forbidden: Vec<(&'static str, bool)> = vec![
        ("enable_tun_mode", patch.enable_tun_mode.is_some()),
        ("enable_system_proxy", patch.enable_system_proxy.is_some()),
        ("enable_proxy_guard", patch.enable_proxy_guard.is_some()),
        ("proxy_guard_duration", patch.proxy_guard_duration.is_some()),
        ("enable_bypass_check", patch.enable_bypass_check.is_some()),
        ("use_default_bypass", patch.use_default_bypass.is_some()),
        ("system_proxy_bypass", patch.system_proxy_bypass.is_some()),
        ("proxy_auto_config", patch.proxy_auto_config.is_some()),
        ("pac_file_content", patch.pac_file_content.is_some()),
        ("proxy_host", patch.proxy_host.is_some()),
        ("verge_mixed_port", patch.verge_mixed_port.is_some()),
        ("verge_socks_port", patch.verge_socks_port.is_some()),
        ("verge_socks_enabled", patch.verge_socks_enabled.is_some()),
        ("verge_port", patch.verge_port.is_some()),
        ("verge_http_enabled", patch.verge_http_enabled.is_some()),
        ("webdav_url", patch.webdav_url.is_some()),
        ("webdav_username", patch.webdav_username.is_some()),
        ("webdav_password", patch.webdav_password.is_some()),
        ("enable_external_controller", patch.enable_external_controller.is_some()),
        ("hotkeys", patch.hotkeys.is_some()),
        ("startup_script", patch.startup_script.is_some()),
        ("clash_core", patch.clash_core.is_some()),
        (
            "enable_auto_backup_schedule",
            patch.enable_auto_backup_schedule.is_some(),
        ),
        ("auto_backup_interval_hours", patch.auto_backup_interval_hours.is_some()),
        ("auto_backup_on_change", patch.auto_backup_on_change.is_some()),
        // Tray click behavior is pinned to `dashboard` (P0-5); any other
        // value is a proxy/TUN steer.
        (
            "tray_event",
            patch.tray_event.as_deref().is_some_and(|event| event != "dashboard"),
        ),
    ];
    #[cfg(target_os = "macos")]
    forbidden.push(("macos_kill_switch_mode", patch.macos_kill_switch_mode.is_some()));
    #[cfg(not(target_os = "windows"))]
    forbidden.extend([
        ("verge_redir_port", patch.verge_redir_port.is_some()),
        ("verge_redir_enabled", patch.verge_redir_enabled.is_some()),
    ]);
    #[cfg(target_os = "linux")]
    forbidden.extend([
        ("verge_tproxy_port", patch.verge_tproxy_port.is_some()),
        ("verge_tproxy_enabled", patch.verge_tproxy_enabled.is_some()),
    ]);
    forbidden
        .into_iter()
        .find_map(|(field, present)| present.then_some(field))
}

/// 修改Verge配置
#[tauri::command]
pub async fn patch_verge_config(payload: IVerge) -> CmdResult {
    if let Some(field) = forbidden_field_present(&payload) {
        return Err(format!("disabled by Tono: {field}").into());
    }
    feat::patch_verge(&payload, false).await.stringify_err()
}

#[cfg(test)]
mod tests {
    use super::forbidden_field_present;
    use crate::config::IVerge;

    #[test]
    fn display_fields_pass_the_whitelist() {
        let patch = IVerge {
            language: Some("en".into()),
            theme_mode: Some("dark".into()),
            enable_auto_launch: Some(true),
            enable_silent_start: Some(true),
            enable_auto_light_weight_mode: Some(true),
            home_cards: None,
            test_list: None,
            tray_event: Some("dashboard".into()),
            ..IVerge::default()
        };
        assert_eq!(forbidden_field_present(&patch), None);
    }

    #[test]
    fn traffic_and_core_fields_are_rejected() {
        for patch in [
            IVerge {
                enable_tun_mode: Some(true),
                ..IVerge::default()
            },
            IVerge {
                enable_system_proxy: Some(false),
                ..IVerge::default()
            },
            IVerge {
                proxy_auto_config: Some(true),
                ..IVerge::default()
            },
            IVerge {
                verge_mixed_port: Some(7890),
                ..IVerge::default()
            },
            IVerge {
                enable_external_controller: Some(true),
                ..IVerge::default()
            },
            IVerge {
                hotkeys: Some(vec!["dashboard,CTRL+Q".into()]),
                ..IVerge::default()
            },
            IVerge {
                startup_script: Some("echo hi".into()),
                ..IVerge::default()
            },
            IVerge {
                clash_core: Some("verge-mihomo".into()),
                ..IVerge::default()
            },
            IVerge {
                webdav_url: Some("https://dav.example.com".into()),
                ..IVerge::default()
            },
            IVerge {
                auto_backup_on_change: Some(true),
                ..IVerge::default()
            },
            IVerge {
                tray_event: Some("system_proxy".into()),
                ..IVerge::default()
            },
        ] {
            assert!(forbidden_field_present(&patch).is_some(), "{patch:?}");
        }
    }
}
