use super::CmdResult;
use crate::core::validate::ValidationOutcome;
use smartstring::alias::String;

/// 保存profiles的配置
#[tauri::command]
pub async fn save_profile_file(index: String, file_data: Option<String>) -> CmdResult<ValidationOutcome> {
    let _ = (index, file_data);
    Err("disabled by Tono".into())
}
