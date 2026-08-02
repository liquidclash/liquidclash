use crate::core::process::{process_identity, terminate_process};
use crate::core::runtime::{
    cleanup_core_socket, is_core_socket_reachable, read_core_runtime_record,
    remove_core_runtime_record,
};
use anyhow::{Context as _, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Mutex;
use tracing::{info, warn};

static STARTUP_RECONCILED: AtomicBool = AtomicBool::new(cfg!(feature = "test"));
/// Serializes reconciliation runs so a retry from a start attempt can never overlap another pass.
static RECONCILE_RUNNING: Mutex<()> = Mutex::const_new(());

pub(super) async fn ensure_startup_reconciled() -> Result<()> {
    if STARTUP_RECONCILED.load(Ordering::Acquire) {
        return Ok(());
    }
    // A transient reconciliation failure at service startup must not block every core start
    // until the service restarts; retry it here before this start is allowed to proceed.
    reconcile_service_startup()
        .await
        .context("core startup reconciliation has not completed")
}

pub async fn reconcile_service_startup() -> Result<()> {
    let _running = RECONCILE_RUNNING.lock().await;
    STARTUP_RECONCILED.store(false, Ordering::Release);
    info!("Running service startup reconciliation");

    let Some(record) = read_core_runtime_record().await? else {
        STARTUP_RECONCILED.store(true, Ordering::Release);
        return Ok(());
    };

    let current_identity = process_identity(record.pid)?;
    let socket_reachable = is_core_socket_reachable(&record.ipc_path).await;

    if current_identity.as_ref() == Some(&record.identity) {
        warn!(
            "Found verified previous core process {} during startup; stopping it before supervision resumes",
            record.pid
        );
        terminate_process(record.pid).await?;
        cleanup_core_socket(&record.ipc_path).await;
        remove_core_runtime_record().await;
        STARTUP_RECONCILED.store(true, Ordering::Release);
        return Ok(());
    }

    if let Some(current_identity) = current_identity {
        warn!(
            "Runtime PID {} now belongs to a different process ({:?}); refusing to terminate it",
            record.pid, current_identity
        );
    }
    if !socket_reachable {
        info!(
            "Cleaning stale core socket from dead process: {}",
            record.ipc_path
        );
        cleanup_core_socket(&record.ipc_path).await;
    } else {
        warn!(
            "Core runtime PID {} is dead but socket {} is reachable; leaving socket untouched",
            record.pid, record.ipc_path
        );
    }

    remove_core_runtime_record().await;
    STARTUP_RECONCILED.store(true, Ordering::Release);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{STARTUP_RECONCILED, ensure_startup_reconciled};
    use serial_test::serial;
    use std::sync::atomic::Ordering;

    #[tokio::test]
    #[serial]
    async fn failed_startup_reconciliation_is_retried_by_the_start_gate() -> anyhow::Result<()> {
        crate::core::runtime::remove_core_runtime_record().await;
        STARTUP_RECONCILED.store(false, Ordering::Release);

        ensure_startup_reconciled().await?;

        assert!(STARTUP_RECONCILED.load(Ordering::Acquire));
        Ok(())
    }
}
