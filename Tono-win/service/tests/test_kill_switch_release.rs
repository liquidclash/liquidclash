#![cfg(all(feature = "standalone", feature = "client", feature = "test"))]

mod common;

use anyhow::{Context as _, Result};
use clash_verge_service_ipc::{
    OwnerCredentials, OwnerSessionProof, RuntimeBundle, ServiceErrorCode, StartClashRequest,
    StopClashOptions,
    get_kill_switch_status as client_get_kill_switch_status,
    get_protected_dns_status as client_get_protected_dns_status,
    release_kill_switch as client_release_kill_switch,
    restore_protected_dns as client_restore_protected_dns,
    restrict_kill_switch_bootstrap as client_restrict_kill_switch_bootstrap, run_ipc_server,
    start_clash as client_start_clash, stop_clash_with_options as client_stop_clash_with_options,
    stop_ipc_server,
};
use serial_test::serial;

fn runtime_bundle() -> Result<RuntimeBundle> {
    let mock_binary = common::test_bin_path("mock_binary");
    anyhow::ensure!(
        mock_binary.exists(),
        "missing mock_binary at {mock_binary:?}"
    );
    Ok(RuntimeBundle {
        yaml: "mode: rule\n".to_string(),
        assets: vec![],
        remote_providers: Vec::new(),
        core_path: mock_binary.to_string_lossy().into_owned(),
    })
}

async fn start(credentials: &OwnerCredentials, token: &str) -> Result<OwnerSessionProof> {
    let response = client_start_clash(
        credentials,
        &StartClashRequest {
            runtime: runtime_bundle()?,
            proposed_session_token: token.to_owned(),
            macos_proxy: None,
            kill_switch: None,
            windows_kill_switch: None,
        },
    )
    .await?;
    assert_eq!(response.code, 0, "{}", response.message);
    Ok(OwnerSessionProof {
        generation: response
            .data
            .as_ref()
            .context("start response omitted session")?
            .session
            .generation,
        token: token.to_owned(),
    })
}

/// The Protected Offline stop: core down, kill switch deliberately NOT released.
async fn stop_without_release(credentials: &OwnerCredentials, session: &OwnerSessionProof) {
    let response = client_stop_clash_with_options(
        credentials,
        session,
        StopClashOptions {
            release_kill_switch: false,
        },
    )
    .await
    .expect("stop request failed");
    assert_eq!(response.code, 0, "{}", response.message);
}

/// C1: any successful stop clears the active-owner record and invalidates the session. The
/// explicit user Disconnect must still release the kill switch afterwards — before the gate
/// fix, this answered NotActive and the user could never disconnect from Protected Offline.
#[tokio::test]
#[serial]
async fn kill_switch_release_succeeds_after_stop_cleared_the_owner() -> Result<()> {
    common::init_tracing_for_tests();
    let _ = stop_ipc_server().await;
    let server_handle = run_ipc_server().await?;
    common::wait_for_ipc().await?;

    let credentials = common::owner_credentials();
    let token = "ab".repeat(32);
    let session = start(&credentials, &token).await?;
    stop_without_release(&credentials, &session).await;

    let release = client_release_kill_switch(&credentials).await?;
    assert_eq!(
        release.code, 0,
        "release after stop(false) must succeed, got: {}",
        release.message
    );
    let status = release.data.context("release response omitted status")?;
    assert!(!status.wanted, "a successful release reports wanted=false");

    stop_ipc_server().await?;
    server_handle.await??;
    Ok(())
}

/// The rest of the disconnect/Protected Offline surface must reach its handler — not the
/// owner gate — after the same stop. (`restrict-bootstrap` may legitimately fail with a
/// functional "not armed" error; what it must not produce is the NotActive gate rejection.)
#[tokio::test]
#[serial]
async fn disconnect_path_routes_reach_their_handlers_after_stop() -> Result<()> {
    common::init_tracing_for_tests();
    let _ = stop_ipc_server().await;
    let server_handle = run_ipc_server().await?;
    common::wait_for_ipc().await?;

    let credentials = common::owner_credentials();
    let token = "cd".repeat(32);
    let session = start(&credentials, &token).await?;
    stop_without_release(&credentials, &session).await;

    let not_active = ServiceErrorCode::NotActive as u16;

    let dns_restore = client_restore_protected_dns(&credentials).await?;
    assert_eq!(
        dns_restore.code, 0,
        "dns/restore after stop must succeed (nothing to restore): {}",
        dns_restore.message
    );

    let kill_switch_status = client_get_kill_switch_status(&credentials).await?;
    assert_eq!(
        kill_switch_status.code, 0,
        "kill-switch/status after stop must stay readable: {}",
        kill_switch_status.message
    );

    let dns_status = client_get_protected_dns_status(&credentials).await?;
    assert_eq!(
        dns_status.code, 0,
        "dns/status after stop must stay readable: {}",
        dns_status.message
    );

    let restrict = client_restrict_kill_switch_bootstrap(&credentials).await?;
    assert_ne!(
        restrict.code, not_active,
        "restrict-bootstrap must reach the handler, not die at the owner gate"
    );

    stop_ipc_server().await?;
    server_handle.await??;
    Ok(())
}
