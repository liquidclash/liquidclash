use crate::core::auth::AuthenticatedOwner;
use crate::core::desired::{DesiredState, load_active_owner, load_owner_desired_state};
use crate::core::manager::status_snapshot_nonblocking;
use crate::core::state::{core_lifecycle_state, service_lifecycle_state};
use crate::core::structure::{ServiceLifecycleState, ServiceStatusSnapshot};
use anyhow::Result;
use tracing::warn;

pub async fn service_status_snapshot(owner: &AuthenticatedOwner) -> Result<ServiceStatusSnapshot> {
    let reported_service_state = service_lifecycle_state();
    let reported_core_state = core_lifecycle_state();
    // A failed read is not evidence that the owner wants its core stopped. Reported as `false`
    // it was indistinguishable from a deliberate stop, and one such sample — out of a poll every
    // two seconds — is enough for the App to declare owner loss and tear down a healthy session.
    // Report the failure as unknown and let the client keep what it already believes.
    let (desired, desired_state_unknown) = match load_owner_desired_state(&owner.key).await {
        Ok(desired) => (desired, false),
        Err(error) => {
            warn!("Owner desired state could not be read; reporting it as unknown: {error:#}");
            (DesiredState::default(), true)
        }
    };
    let active_owner = load_active_owner().await?;
    let active_generation = active_owner
        .as_ref()
        .filter(|active| active.owner_key == owner.key)
        .map(|active| active.generation);
    let is_active = active_generation.is_some();
    let core = if is_active {
        Some(status_snapshot_nonblocking().await)
    } else {
        None
    };

    let core_pid = core.as_ref().and_then(|core| core.core_pid);
    let service_state = effective_service_state(
        reported_service_state,
        reported_core_state,
        is_active,
        desired.core_should_be_running,
        desired_state_unknown,
        core_pid,
    );

    let (kill_switch_wanted, kill_switch_live, kill_switch_mode) =
        crate::core::macos_kill_switch::status().await;
    let mut windows_kill_switch = crate::core::windows_kill_switch::status_snapshot().await;
    // The endpoint list names the exit node the active owner selected. Every other owner-specific
    // detail in this aggregate is already withheld from a non-active owner; this one was not.
    if !is_active && let Some(status) = windows_kill_switch.as_mut() {
        status.endpoints.clear();
    }
    #[cfg(windows)]
    let network_events = crate::core::netmon::status();
    #[cfg(not(windows))]
    let network_events = crate::core::structure::NetworkEventsStatus::default();
    let (snapshot_generation, active_operation) = crate::core::operation::snapshot();
    Ok(ServiceStatusSnapshot {
        snapshot_generation,
        active_operation,
        is_active,
        active_generation,
        service_state,
        core_pid,
        core_started_at: core.as_ref().and_then(|core| core.core_started_at),
        last_core_exit_reason: core
            .as_ref()
            .and_then(|core| core.last_core_exit_reason.clone()),
        restart_count: core.as_ref().map_or(0, |core| core.restart_count),
        last_recovery_at: core.as_ref().and_then(|core| core.last_recovery_at),
        desired_core_should_be_running: desired.core_should_be_running,
        desired_generation: desired.generation,
        desired_updated_at: desired.updated_at,
        desired_state_unknown,
        macos_kill_switch_wanted: kill_switch_wanted,
        macos_kill_switch_live: kill_switch_live,
        macos_kill_switch_mode: kill_switch_mode,
        kill_switch: windows_kill_switch,
        network_events,
    })
}

fn effective_service_state(
    reported: ServiceLifecycleState,
    core_reported: ServiceLifecycleState,
    is_active: bool,
    desired_running: bool,
    desired_unknown: bool,
    core_pid: Option<u32>,
) -> ServiceLifecycleState {
    // A genuinely Fatal core must not be reported as plain Running just because the desired file
    // could not be read — that turned the worst state into the greenest one. Synthesizing
    // `RecoveringCore` below still requires a *proven* run intent, so an unknown desired state
    // cannot invent a recovery that nobody asked for.
    if matches!(
        core_reported,
        ServiceLifecycleState::Fatal
            | ServiceLifecycleState::RecoveringCore
            | ServiceLifecycleState::Starting
    ) && is_active
        && (desired_running || desired_unknown)
    {
        core_reported
    } else if reported != ServiceLifecycleState::Fatal
        && is_active
        && desired_running
        && core_pid.is_none()
    {
        ServiceLifecycleState::RecoveringCore
    } else {
        reported
    }
}

#[cfg(test)]
mod tests {
    use super::{effective_service_state, service_status_snapshot};
    use crate::core::auth::AuthenticatedOwner;
    use crate::core::desired::{clear_active_owner, commit_active_owner_session};
    use crate::{OwnerIdentity, ServiceLifecycleState};
    use serial_test::serial;

    #[test]
    fn core_recovery_takes_precedence_over_ipc_running_state() {
        assert_eq!(
            effective_service_state(
                ServiceLifecycleState::Running,
                ServiceLifecycleState::Running,
                true,
                true,
                false,
                None,
            ),
            ServiceLifecycleState::RecoveringCore
        );
        assert_eq!(
            effective_service_state(
                ServiceLifecycleState::Fatal,
                ServiceLifecycleState::Running,
                true,
                true,
                false,
                None,
            ),
            ServiceLifecycleState::Fatal
        );
        assert_eq!(
            effective_service_state(
                ServiceLifecycleState::Running,
                ServiceLifecycleState::Fatal,
                true,
                true,
                false,
                None,
            ),
            ServiceLifecycleState::Fatal
        );
    }

    #[test]
    fn an_unreadable_desired_state_neither_hides_fatal_nor_invents_recovery() {
        // Fatal survives an unreadable desired state...
        assert_eq!(
            effective_service_state(
                ServiceLifecycleState::Running,
                ServiceLifecycleState::Fatal,
                true,
                false,
                true,
                None,
            ),
            ServiceLifecycleState::Fatal
        );
        // ...but a missing core alone is not a recovery without a proven run intent.
        assert_eq!(
            effective_service_state(
                ServiceLifecycleState::Running,
                ServiceLifecycleState::Running,
                true,
                false,
                true,
                None,
            ),
            ServiceLifecycleState::Running
        );
    }

    fn owner(uid: u32) -> AuthenticatedOwner {
        AuthenticatedOwner {
            key: uid.to_string(),
            identity: OwnerIdentity::Unix { uid, gid: 20 },
            app_data_root: std::env::temp_dir(),
        }
    }

    #[tokio::test]
    #[serial]
    async fn inactive_owner_status_hides_active_core_details() -> anyhow::Result<()> {
        let active = owner(91_001);
        let inactive = owner(91_002);
        let active_session = commit_active_owner_session(&active, &"66".repeat(32)).await?;

        let status = service_status_snapshot(&inactive).await?;

        assert!(!status.is_active);
        assert_eq!(status.active_generation, None);
        assert_eq!(status.core_pid, None);
        assert_eq!(status.core_started_at, None);
        assert_eq!(status.last_core_exit_reason, None);
        assert_eq!(status.restart_count, 0);
        assert_eq!(status.last_recovery_at, None);
        assert_eq!(
            service_status_snapshot(&active).await?.active_generation,
            Some(active_session.generation)
        );
        clear_active_owner().await?;
        Ok(())
    }
}
