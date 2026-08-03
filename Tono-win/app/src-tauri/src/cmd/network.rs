use super::CmdResult;
use crate::cmd::{StringifyErr as _, blocking};
use crate::core::sysopt::Sysopt;
use clash_verge_logging::{Type, logging};
use gethostname::gethostname;
use network_interface::NetworkInterface;
use serde_yaml_ng::Mapping;
use sysproxy::{Autoproxy, Sysproxy};
use tauri_plugin_clash_verge_sysinfo;

/// get the system proxy
#[tauri::command]
pub async fn get_sys_proxy() -> CmdResult<Mapping> {
    logging!(debug, Type::Network, "异步获取系统代理配置");

    Sysopt::global().wait_idle().await;
    let sys_proxy = Sysproxy::get_system_proxy().stringify_err()?;
    let Sysproxy {
        ref host,
        ref bypass,
        ref port,
        ref enable,
    } = sys_proxy;

    let mut map = Mapping::new();
    map.insert("enable".into(), (*enable).into());
    map.insert("server".into(), format!("{}:{}", host, port).into());
    map.insert("bypass".into(), bypass.as_str().into());

    logging!(
        debug,
        Type::Network,
        "返回系统代理配置: enable={}, {}:{}",
        sys_proxy.enable,
        sys_proxy.host,
        sys_proxy.port
    );
    Ok(map)
}

/// 获取自动代理配置
#[tauri::command]
pub async fn get_auto_proxy() -> CmdResult<Mapping> {
    Sysopt::global().wait_idle().await;
    let auto_proxy = Autoproxy::get_auto_proxy().stringify_err()?;
    let Autoproxy { ref enable, ref url } = auto_proxy;

    let mut map = Mapping::new();
    map.insert("enable".into(), (*enable).into());
    map.insert("url".into(), url.as_str().into());

    logging!(
        debug,
        Type::Network,
        "返回自动代理配置（缓存）: enable={}, url={}",
        auto_proxy.enable,
        auto_proxy.url
    );
    Ok(map)
}

#[tauri::command]
pub fn get_embedded_server_port() -> CmdResult<u16> {
    crate::utils::server::embedded_server_port().stringify_err()
}

/// 获取系统主机名
#[tauri::command]
pub fn get_system_hostname() -> String {
    // 获取系统主机名，处理可能的非UTF-8字符
    match gethostname().into_string() {
        Ok(name) => name,
        Err(os_string) => {
            // 对于包含非UTF-8的主机名，使用调试格式化
            let fallback = format!("{os_string:?}");
            // 去掉可能存在的引号
            fallback.trim_matches('"').to_string()
        }
    }
}

/// 获取网络接口列表
///
/// Async because the enumeration is `GetAdaptersAddresses` underneath: it walks every adapter,
/// including ones a VPN or a flapping Wi-Fi driver is mid-transition on, and has no timeout of
/// its own. A sync command would spend that time on the Tauri main thread.
#[tauri::command]
pub async fn get_network_interfaces() -> Vec<String> {
    crate::process::AsyncHandler::spawn_blocking(tauri_plugin_clash_verge_sysinfo::list_network_interfaces)
        .await
        .unwrap_or_default()
}

/// 获取网络接口详细信息
///
/// Both halves run in one hop: two `GetAdaptersAddresses` walks that must agree with each other
/// are better taken back to back than split across two trips to the blocking pool.
#[tauri::command]
pub async fn get_network_interfaces_info() -> CmdResult<Vec<NetworkInterface>> {
    blocking(|| {
        use network_interface::{NetworkInterface, NetworkInterfaceConfig as _};

        let names = tauri_plugin_clash_verge_sysinfo::list_network_interfaces();
        let interfaces = NetworkInterface::show().stringify_err()?;

        let mut result = Vec::new();

        for interface in interfaces {
            if names.contains(&interface.name) {
                result.push(interface);
            }
        }

        Ok(result)
    })
    .await
}
