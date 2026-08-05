use crate::{
    core::listener::{ListenerProbe, ListenerProbeOutcome, probe_listener as probe_listener_sync},
    process::AsyncHandler,
};
use anyhow::{Context as _, Result};

/// Read-only listener probe (kept for diagnostics).
pub async fn probe_listener(request: ListenerProbe) -> Result<ListenerProbeOutcome> {
    AsyncHandler::spawn_blocking(move || probe_listener_sync(&request))
        .await
        .context("listener probe task failed")
}
