use super::{CmdResult, WithErrorCode as _, coded_error};
use crate::{
    config::{Config, IProfiles, PrfItem, PrfOption},
    core::{timer::Timer, validate::ValidationOutcome},
    utils::{dirs, help},
};
use clash_verge_draft::{Draft, SharedDraft};
use clash_verge_logging::{Type, logging};
use smartstring::alias::String;

#[tauri::command]
pub async fn get_profiles() -> CmdResult<SharedDraft<IProfiles>> {
    logging!(debug, Type::Cmd, "获取配置文件列表");
    let draft = Config::profiles().await;
    let data = draft.data_arc();
    Ok(data)
}

/// 增强配置文件
#[tauri::command]
pub async fn enhance_profiles() -> CmdResult<ValidationOutcome> {
    Err("disabled by Tono".into())
}

/// 导入配置文件
#[tauri::command]
pub async fn import_profile(url: std::string::String, option: Option<PrfOption>) -> CmdResult {
    let _ = (url, option);
    Err("disabled by Tono".into())
}

/// 调整profile的顺序
#[tauri::command]
pub async fn reorder_profile(active_id: String, over_id: String) -> CmdResult {
    let _ = (active_id, over_id);
    Err("disabled by Tono".into())
}

/// 创建新的profile
#[tauri::command]
pub async fn create_profile(item: PrfItem, file_data: Option<String>) -> CmdResult {
    let _ = (item, file_data);
    Err("disabled by Tono".into())
}

/// 更新配置文件
#[tauri::command]
pub async fn update_profile(index: String, option: Option<PrfOption>) -> CmdResult {
    let _ = (index, option);
    Err("disabled by Tono".into())
}

/// 删除配置文件
#[tauri::command]
pub async fn delete_profile(index: String) -> CmdResult {
    let _ = index;
    Err("disabled by Tono".into())
}

#[allow(dead_code)]
async fn commit_current_profile(profiles: &Draft<IProfiles>, current: Option<String>) -> anyhow::Result<()> {
    profiles.discard();
    let Some(current) = current else {
        return Ok(());
    };

    profiles
        .with_data_modify(|mut committed| async move {
            committed.patch_config(&IProfiles {
                current: Some(current),
                items: None,
            });
            Ok((committed, ()))
        })
        .await
}

#[allow(dead_code)]
async fn run_profile_config_update_transition<Update, UpdateFuture>(
    update_config: Update,
) -> anyhow::Result<ValidationOutcome>
where
    Update: FnOnce() -> UpdateFuture,
    UpdateFuture: std::future::Future<Output = anyhow::Result<ValidationOutcome>>,
{
    update_config().await
}

/// 修改profiles的配置
#[tauri::command]
pub async fn patch_profiles_config(profiles: IProfiles) -> CmdResult<ValidationOutcome> {
    let _ = profiles;
    Err("disabled by Tono".into())
}

/// 根据profile name修改profiles
#[tauri::command]
#[allow(dead_code)]
pub async fn patch_profiles_config_by_profile_index(profile_index: String) -> CmdResult<ValidationOutcome> {
    let _ = profile_index;
    Err("disabled by Tono".into())
}

/// 修改某个profile item的
#[tauri::command]
pub async fn patch_profile(index: String, profile: PrfItem) -> CmdResult {
    let _ = (index, profile);
    Err("disabled by Tono".into())
}

/// 查看配置文件
#[tauri::command]
pub async fn view_profile(index: String) -> CmdResult {
    let profiles = Config::profiles().await;
    let profiles_ref = profiles.latest_arc();
    let file = profiles_ref
        .get_item(&index)
        .with_error_code("PROFILE_OPEN_FAILED")?
        .file
        .as_ref()
        .ok_or_else(|| coded_error("PROFILE_OPEN_FAILED", "the file field is null"))?;

    let path = dirs::app_profiles_dir()
        .with_error_code("PROFILE_OPEN_FAILED")?
        .join(file.as_str());
    if !path.exists() {
        return CmdResult::Err(coded_error(
            "PROFILE_OPEN_FAILED",
            format!("file not found \"{}\"", path.display()),
        ));
    }

    help::open_file(path).with_error_code("PROFILE_OPEN_FAILED")
}

/// 读取配置文件内容
#[tauri::command]
pub async fn read_profile_file(index: String) -> CmdResult<String> {
    let item = {
        let profiles = Config::profiles().await;
        let profiles_ref = profiles.latest_arc();
        PrfItem {
            file: profiles_ref
                .get_item(&index)
                .with_error_code("PROFILE_READ_FAILED")?
                .file
                .to_owned(),
            ..Default::default()
        }
    };

    if let Some(file) = item.file.as_ref() {
        let path = dirs::app_profiles_dir()
            .with_error_code("PROFILE_READ_FAILED")?
            .join(file.as_str());
        match tokio::fs::try_exists(&path).await {
            Ok(true) => {}
            Ok(false) => return Ok(String::new()),
            Err(err) => {
                return Err(coded_error(
                    "PROFILE_READ_FAILED",
                    format!("failed to check profile file \"{}\": {err}", path.display()),
                ));
            }
        }
    }

    let data = item.read_file().await.with_error_code("PROFILE_READ_FAILED")?;
    Ok(data)
}

/// 获取下一次更新时间
#[tauri::command]
pub async fn get_next_update_time(uid: String) -> CmdResult<Option<i64>> {
    let timer = Timer::global();
    let next_time = timer.get_next_update_time(&uid).await;
    Ok(next_time)
}

#[cfg(test)]
mod tests {
    use super::{commit_current_profile, run_profile_config_update_transition};
    use crate::config::{IProfiles, PrfItem};
    use crate::core::validate::ValidationOutcome;
    use clash_verge_draft::Draft;
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        task::Poll,
        time::Duration,
    };
    use tokio::sync::Barrier;

    struct CancellationProbe {
        cancelled: Arc<AtomicBool>,
        completed: Arc<AtomicBool>,
    }

    impl Drop for CancellationProbe {
        fn drop(&mut self) {
            if !self.completed.load(Ordering::Acquire) {
                self.cancelled.store(true, Ordering::Release);
            }
        }
    }

    fn profile(uid: &str) -> PrfItem {
        PrfItem {
            uid: Some(uid.into()),
            ..PrfItem::default()
        }
    }

    #[tokio::test]
    async fn committing_profile_switch_preserves_profiles_added_after_draft_creation() -> anyhow::Result<()> {
        let profiles = Draft::new(IProfiles {
            current: Some("a".into()),
            items: Some(vec![profile("a"), profile("b")]),
        });
        profiles.edit_draft(|draft| {
            draft.patch_config(&IProfiles {
                current: Some("b".into()),
                items: None,
            });
        });
        profiles
            .with_data_modify(|mut committed| async move {
                committed.items.get_or_insert_with(Vec::new).push(profile("new"));
                Ok((committed, ()))
            })
            .await?;

        commit_current_profile(&profiles, Some("b".into())).await?;

        let committed = profiles.data_arc();
        assert_eq!(committed.current.as_deref(), Some("b"));
        assert!(committed.get_item("new").is_ok());
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn profile_config_update_runs_past_former_deadline_without_cancellation() -> anyhow::Result<()> {
        let update_started = Arc::new(Barrier::new(2));
        let release_update = Arc::new(Barrier::new(2));
        let update_cancelled = Arc::new(AtomicBool::new(false));
        let update_completed = Arc::new(AtomicBool::new(false));

        let mut update = Box::pin(run_profile_config_update_transition({
            let update_started = Arc::clone(&update_started);
            let release_update = Arc::clone(&release_update);
            let update_cancelled = Arc::clone(&update_cancelled);
            let update_completed = Arc::clone(&update_completed);
            move || async move {
                let _probe = CancellationProbe {
                    cancelled: update_cancelled,
                    completed: Arc::clone(&update_completed),
                };
                update_started.wait().await;
                release_update.wait().await;
                update_completed.store(true, Ordering::Release);
                Ok(ValidationOutcome::Valid)
            }
        }));

        assert!(matches!(futures::poll!(update.as_mut()), Poll::Pending));
        update_started.wait().await;
        tokio::time::advance(Duration::from_secs(31)).await;

        assert!(matches!(futures::poll!(update.as_mut()), Poll::Pending));
        assert!(!update_cancelled.load(Ordering::Acquire));

        release_update.wait().await;
        assert!(update.await?.is_valid());
        assert!(update_completed.load(Ordering::Acquire));
        assert!(!update_cancelled.load(Ordering::Acquire));
        Ok(())
    }
}
