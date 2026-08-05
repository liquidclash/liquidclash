#![cfg(feature = "client")]

use anyhow::Context as _;
#[cfg(feature = "test")]
use clash_verge_service_ipc::test_owner_credentials;
use clash_verge_service_ipc::{
    IpcConfig, MIN_REQUIRED_SERVICE_REVISION, OwnerSessionProof, ProtocolVersion, RuntimeBundle,
    StartClashRequest, get_clash_logs, get_kill_switch_status, get_protected_dns_status,
    get_status, get_version, set_config, start_clash, stop_clash,
};
#[cfg(not(feature = "test"))]
use clash_verge_service_ipc::{OwnerCredentials, OwnerIdentity};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tokio::time::sleep;

const IPC_READY_TIMEOUT: Duration = Duration::from_secs(20);
const IPC_PROBE_INTERVAL: Duration = Duration::from_millis(250);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "usage: tono-service-integration-driver <probe|ready|ping|diagnose|logs|watch-logs|start|stop>"
        );
        std::process::exit(1);
    }

    match args[1].as_str() {
        "probe" => probe_protocol().await?,
        "ready" => wait_protocol_ready().await?,
        "ping" => wait_ipc_ready().await?,
        "diagnose" => diagnose_flow().await?,
        "logs" => logs_flow().await?,
        "watch-logs" => watch_logs_flow().await?,
        "start" => start_flow().await?,
        "stop" => stop_flow().await?,
        _ => {
            eprintln!(
                "usage: tono-service-integration-driver <probe|ready|ping|diagnose|logs|watch-logs|start|stop>"
            );
            std::process::exit(1);
        }
    }

    Ok(())
}

/// Print the bounded in-memory core log maintained by the Service. This stays behind the same
/// owner authentication as every other diagnostic request and avoids weakening the protected
/// ProgramData ACL merely to debug a failed real-machine connect.
async fn logs_flow() -> anyhow::Result<()> {
    wait_protocol_ready().await?;
    let response = get_clash_logs(&owner_credentials()?).await?;
    if response.code != 0 {
        anyhow::bail!(
            "service rejected core log request: {} ({})",
            response.message,
            response.code
        );
    }
    for line in response.data.unwrap_or_default() {
        println!("{line}");
    }
    Ok(())
}

/// Wait for the next real owner session and capture its in-memory core log before rollback makes
/// the authenticated session unavailable. This is intentionally a test-driver primitive: a
/// sub-second startup failure otherwise disappears before a human can issue a second command.
async fn watch_logs_flow() -> anyhow::Result<()> {
    wait_protocol_ready().await?;
    let credentials = owner_credentials()?;
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut active_seen = false;
    let mut last_len = 0;

    while Instant::now() < deadline {
        match get_clash_logs(&credentials).await {
            Ok(response) if response.code == 0 => {
                active_seen = true;
                let logs = response.data.unwrap_or_default();
                if logs.len() < last_len {
                    last_len = 0;
                }
                for line in logs.iter().skip(last_len) {
                    println!("{line}");
                }
                last_len = logs.len();
            }
            _ if active_seen => return Ok(()),
            _ => {}
        }
        sleep(Duration::from_millis(25)).await;
    }

    if active_seen {
        Ok(())
    } else {
        anyhow::bail!("no active owner session appeared within 20 seconds")
    }
}

/// Print the live service state needed for Windows triage without exposing endpoint addresses or
/// owner/session secrets. This is intentionally read-only: it issues only protocol/status GETs.
async fn diagnose_flow() -> anyhow::Result<()> {
    wait_protocol_ready().await?;
    let credentials = owner_credentials()?;
    let version = get_version().await?;
    let service = get_status(&credentials).await?;
    let dns = get_protected_dns_status(&credentials).await?;
    let kill_switch = get_kill_switch_status(&credentials).await?;

    let service_data = service.data.as_ref().map(|status| {
        serde_json::json!({
            "snapshot_generation": status.snapshot_generation,
            "active_operation": status.active_operation,
            "is_active": status.is_active,
            "active_generation": status.active_generation,
            "service_state": status.service_state,
            "core_pid": status.core_pid,
            "core_started_at": status.core_started_at,
            "last_core_exit_reason": status.last_core_exit_reason,
            "restart_count": status.restart_count,
            "last_recovery_at": status.last_recovery_at,
            "desired_core_should_be_running": status.desired_core_should_be_running,
            "desired_generation": status.desired_generation,
            "desired_updated_at": status.desired_updated_at,
            "desired_state_unknown": status.desired_state_unknown,
            "network_events": status.network_events,
        })
    });
    let kill_switch_data = kill_switch.data.as_ref().map(|status| {
        serde_json::json!({
            "wanted": status.wanted,
            "verified": status.verified,
            "live": status.live,
            "mode": status.mode,
            "tunnel_permit_rendered": status.tunnel_permit_rendered,
            "endpoint_count": status.endpoints.len(),
            "last_error": status.last_error,
        })
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "version": {
                "code": version.code,
                "message": version.message,
                "data": version.data,
            },
            "service": {
                "code": service.code,
                "message": service.message,
                "data": service_data,
            },
            "dns": {
                "code": dns.code,
                "message": dns.message,
                "data": dns.data,
            },
            "kill_switch": {
                "code": kill_switch.code,
                "message": kill_switch.message,
                "data": kill_switch_data,
            },
        }))?
    );
    Ok(())
}

async fn probe_protocol() -> anyhow::Result<()> {
    set_config(Some(IpcConfig {
        default_timeout: Duration::from_millis(250),
        max_retries: 1,
        retry_delay: Duration::from_millis(25),
    }))
    .await;
    let result = async {
        let response = get_version().await?;
        let info = response
            .data
            .ok_or_else(|| anyhow::anyhow!("service omitted protocol information"))?;
        if response.code != 0
            || !info.supports_client(ProtocolVersion::current(), MIN_REQUIRED_SERVICE_REVISION)
        {
            anyhow::bail!("service protocol is not compatible");
        }
        Ok(())
    }
    .await;
    set_config(None).await;
    result
}

async fn wait_protocol_ready() -> anyhow::Result<()> {
    set_config(Some(IpcConfig {
        default_timeout: Duration::from_millis(250),
        max_retries: 1,
        retry_delay: Duration::from_millis(25),
    }))
    .await;

    let result: anyhow::Result<()> = async {
        let deadline = Instant::now() + IPC_READY_TIMEOUT;
        let mut last_error = None;
        while Instant::now() < deadline {
            match probe_protocol().await {
                Ok(()) => return Ok(()),
                Err(error) => last_error = Some(error),
            }
            sleep(IPC_PROBE_INTERVAL).await;
        }
        if let Some(error) = last_error {
            anyhow::bail!(
                "service protocol did not become ready within {IPC_READY_TIMEOUT:?}; last failure: {error:#}"
            );
        }
        anyhow::bail!("service protocol did not become ready within {IPC_READY_TIMEOUT:?}");
    }
    .await;

    set_config(None).await;
    result
}

async fn start_flow() -> anyhow::Result<()> {
    wait_ipc_ready().await?;
    let config = RuntimeBundle {
        yaml: "mode: rule\n".to_string(),
        assets: vec![],
        remote_providers: Vec::new(),
        core_path: mock_binary_path()?,
    };
    let response = start_clash(
        &owner_credentials()?,
        &StartClashRequest {
            runtime: config,
            proposed_session_token: session_token()?,
            macos_proxy: None,
            kill_switch: None,
            windows_kill_switch: None,
        },
    )
    .await?;
    if response.code != 0 {
        anyhow::bail!(
            "service rejected Start: {} ({})",
            response.message,
            response.code
        );
    }
    let generation = response
        .data
        .ok_or_else(|| anyhow::anyhow!("service Start response omitted session"))?
        .session
        .generation;
    println!("{generation}");
    Ok(())
}

async fn stop_flow() -> anyhow::Result<()> {
    let response = stop_clash(&owner_credentials()?, &session_proof()?).await?;
    if response.code != 0 {
        anyhow::bail!(
            "service rejected Stop: {} ({})",
            response.message,
            response.code
        );
    }
    Ok(())
}

fn session_token() -> anyhow::Result<String> {
    std::env::var("CLASH_VERGE_TEST_SESSION_TOKEN")
        .context("CLASH_VERGE_TEST_SESSION_TOKEN is required")
}

fn session_proof() -> anyhow::Result<OwnerSessionProof> {
    let generation = std::env::var("CLASH_VERGE_TEST_SESSION_GENERATION")
        .context("CLASH_VERGE_TEST_SESSION_GENERATION is required")?;
    Ok(OwnerSessionProof {
        generation: generation
            .parse()
            .context("CLASH_VERGE_TEST_SESSION_GENERATION must be an unsigned integer")?,
        token: session_token()?,
    })
}

async fn wait_ipc_ready() -> anyhow::Result<()> {
    set_config(Some(IpcConfig {
        default_timeout: Duration::from_millis(250),
        max_retries: 1,
        retry_delay: Duration::from_millis(25),
    }))
    .await;

    let result: anyhow::Result<()> = async {
        let deadline = Instant::now() + IPC_READY_TIMEOUT;
        while Instant::now() < deadline {
            if let Ok(response) = get_status(&owner_credentials()?).await
                && response.code == 0
                && response.data.is_some()
            {
                return Ok(());
            }
            sleep(IPC_PROBE_INTERVAL).await;
        }
        anyhow::bail!("IPC server not reachable within {:?}", IPC_READY_TIMEOUT)
    }
    .await;

    set_config(None).await;
    result
}

#[cfg(feature = "test")]
fn owner_credentials() -> anyhow::Result<clash_verge_service_ipc::OwnerCredentials> {
    test_owner_credentials(&std::env::current_dir()?)
}

#[cfg(not(feature = "test"))]
fn owner_credentials() -> anyhow::Result<OwnerCredentials> {
    let app_data_dir = std::env::current_dir()?;
    #[cfg(unix)]
    let identity = OwnerIdentity::Unix {
        uid: unsafe { platform_lib::geteuid() },
        gid: unsafe { platform_lib::getegid() },
    };
    #[cfg(windows)]
    let identity = OwnerIdentity::Windows {
        sid: std::env::var("CLASH_VERGE_TEST_OWNER_SID")?,
    };

    Ok(OwnerCredentials {
        identity,
        app_data_dir: app_data_dir.to_string_lossy().into_owned(),
        token: std::env::var("CLASH_VERGE_TEST_OWNER_TOKEN").ok(),
    })
}

fn mock_binary_path() -> anyhow::Result<String> {
    let current_exe = std::env::current_exe()?;
    let mut path = current_exe;
    path.pop();
    #[cfg(windows)]
    path.push("mock_binary.exe");
    #[cfg(not(windows))]
    path.push("mock_binary");
    if path.exists() {
        return Ok(path.to_string_lossy().to_string());
    }

    let status = Command::new("cargo")
        .args(["build", "--features", "test"])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;
    if !status.success() {
        anyhow::bail!("failed to build mock_binary");
    }
    if path.exists() {
        return Ok(path.to_string_lossy().to_string());
    }
    anyhow::bail!("mock_binary not found after build");
}
