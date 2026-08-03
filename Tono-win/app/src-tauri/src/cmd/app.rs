use super::CmdResult;
use crate::core::autostart;
use crate::{
    cmd::{StringifyErr as _, blocking},
    feat,
    utils::dirs,
};
use smartstring::alias::String;
use std::ffi::OsString;
use tauri::AppHandle;
#[cfg(debug_assertions)]
use tauri::Manager as _;

/// Hand a path or URL to the system handler without waiting for the handler to finish.
///
/// `open::that` waits for the launcher to exit, and on Windows that launcher is
/// `powershell.exe -NoProfile ... Start-Process` (falling back to `explorer.exe`). PowerShell
/// cold start is routinely 0.5–3 s and far worse while AV scans the image load, so waiting for
/// it froze the window on every external link. `that_detached` returns once the process exists;
/// the hop off-thread covers the process creation itself, which a sync command would otherwise
/// perform on the Tauri main thread.
async fn open_detached(target: OsString) -> CmdResult<()> {
    blocking(move || open::that_detached(target).stringify_err()).await
}

/// 打开应用程序所在目录
#[tauri::command]
pub async fn open_app_dir() -> CmdResult<()> {
    let app_dir = dirs::app_home_dir().stringify_err()?;
    open_detached(app_dir.into_os_string()).await
}

/// 打开核心所在目录
#[tauri::command]
pub async fn open_core_dir() -> CmdResult<()> {
    let core_dir = tauri::utils::platform::current_exe().stringify_err()?;
    let core_dir = core_dir.parent().ok_or("failed to get core dir")?;
    open_detached(core_dir.as_os_str().to_owned()).await
}

/// 打开日志目录
#[tauri::command]
pub async fn open_logs_dir() -> CmdResult<()> {
    let log_dir = dirs::app_logs_dir().stringify_err()?;
    open_detached(log_dir.into_os_string()).await
}

/// 打开网页链接
#[tauri::command]
pub async fn open_web_url(url: String) -> CmdResult<()> {
    open_detached(OsString::from(url.as_str())).await
}

/// 打开/关闭开发者工具
#[tauri::command]
pub fn open_devtools(app_handle: AppHandle) {
    // Tono: devtools are a debug-build facility only (P0-11).
    #[cfg(debug_assertions)]
    if let Some(window) = app_handle.get_webview_window("main") {
        if !window.is_devtools_open() {
            window.open_devtools();
        } else {
            window.close_devtools();
        }
    }
    #[cfg(not(debug_assertions))]
    let _ = app_handle;
}

/// 退出应用
#[tauri::command]
pub async fn exit_app() {
    feat::quit().await;
}

/// 重启应用
#[tauri::command]
pub async fn restart_app() -> CmdResult<()> {
    feat::restart_app().await;
    Ok(())
}

/// 获取便携版标识
#[tauri::command]
pub fn get_portable_flag() -> bool {
    *dirs::PORTABLE_FLAG.get().unwrap_or(&false)
}

/// 获取应用目录
#[tauri::command]
pub async fn get_app_dir() -> CmdResult<String> {
    // Usually a path join, but the portable branch canonicalizes the executable path — real
    // filesystem work, and the install directory is exactly the kind of path that can live on a
    // share. Cheap either way, so it takes the same hop as its neighbours instead of the risk.
    blocking(|| {
        let app_home_dir = dirs::app_home_dir().stringify_err()?.to_string_lossy().into();
        Ok(app_home_dir)
    })
    .await
}

/// 获取当前自启动状态
#[tauri::command]
pub async fn get_auto_launch_status() -> CmdResult<bool> {
    // Reads the Task Scheduler through up to two `schtasks` subprocesses. As a sync command this
    // ran inline on the Tauri main thread, so a stopped or Group-Policy-busy scheduler froze the
    // window exactly like an unanswered pipe. Off-thread here, bounded in `utils::schtasks`.
    blocking(|| autostart::get_launch_status().stringify_err()).await
}

/// 下载图标缓存
#[tauri::command]
pub async fn download_icon_cache(url: String, name: String) -> CmdResult<String> {
    feat::download_icon_cache(url, name).await
}

/// 复制图标文件
#[tauri::command]
pub async fn copy_icon_file(path: String, icon_info: feat::IconInfo) -> CmdResult<String> {
    feat::copy_icon_file(path, icon_info).await
}
