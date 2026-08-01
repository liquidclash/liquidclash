use super::{CmdResult, StringifyErr as _};
use crate::{
    core::listener::{ListenerProbe, ListenerProbeOutcome, ProxyPortSettings, SaveProxyPortsOutcome},
    feat,
};

#[tauri::command]
pub async fn probe_listener(request: ListenerProbe) -> CmdResult<ListenerProbeOutcome> {
    feat::probe_listener(request).await.stringify_err()
}

#[tauri::command]
pub async fn save_proxy_ports(settings: ProxyPortSettings) -> CmdResult<SaveProxyPortsOutcome> {
    let _ = settings;
    Err("disabled by Tono".into())
}
