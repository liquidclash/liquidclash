//! Tauri commands for the Tono product layer. All errors are plain strings
//! for the frontend; status changes are pushed via the `tono://status`
//! event (Tauri Emitter).

use std::{net::SocketAddr, sync::Arc, time::Duration};

use arc_swap::ArcSwapOption;
use clash_verge_logging::{Type, logging};
use clash_verge_service_ipc::KillSwitchStatus;
use futures::{StreamExt as _, stream};
use once_cell::sync::Lazy;
use serde::Serialize;
use tauri::{AppHandle, Emitter as _, Manager as _};
use tono_core::{
    auth::{ApiError, DEFAULT_DEVICE_LIMIT, User, normalize_installation_id},
    connection::{ConnectStage, UiState},
    credentials::{CredentialKey, CredentialStore as _},
};

use crate::{
    core::service,
    process::AsyncHandler,
    tono::{
        audit::AuditEvent,
        catalog_sync, connection,
        credentials::TonoCredentialStore,
        state::{AccountState, TonoInner, TonoState},
    },
};

/// L2: only the unpreventable WM_ENDSESSION path uses this short outer budget. Interactive Quit
/// joins the ordinary release operation and cancels the exit when disarm cannot be proven.
pub(crate) const QUIT_RELEASE_BUDGET: std::time::Duration = std::time::Duration::from_millis(2500);
/// M3: bounded wait for the audit writer to drain once exit is committed. Named for the same
/// reason as `QUIT_RELEASE_BUDGET`: the committed-exit budget in `lib.rs` covers it.
pub(crate) const AUDIT_FLUSH_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);
/// Absolute budget for startup authentication restore and its two cloud refreshes. Credential
/// hydration has its own three-second budget before this function starts. Read-only API work can
/// be cancelled safely; protection release keeps its separate reconciliation semantics.
const RESTORE_TRANSACTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Emitted on `tono://status` after every state change.
///
/// TS: `interface TonoStatus { accountState: string; uiState: string; stage: string | null; stageLabel: string | null; selectedServer: string | null; protectionBlocked: boolean; killSwitch: KillSwitchStatus | null; catalogRevision: number | null; catalogRequiresChoice: boolean; controllerGeneration: number }`
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TonoStatus {
    /// "restoring" | "signedOut" | "authenticating" | "ready" | "suspended" | "error"
    pub account_state: String,
    /// "notConnected" | "connecting" | "connected" | "protectedOffline" | "disconnecting"
    pub ui_state: String,
    /// ConnectStage key (e.g. "startingKillSwitch") while connecting.
    pub stage: Option<String>,
    /// macOS-parity stage text ("Starting Kill Switch…").
    pub stage_label: Option<String>,
    pub selected_server: Option<String>,
    pub protection_blocked: bool,
    pub kill_switch: Option<KillSwitchStatus>,
    pub catalog_revision: Option<i64>,
    pub catalog_requires_choice: bool,
    /// Monotonic owner token for controller/WebSocket data. Never expose the controller secret.
    pub controller_generation: u64,
}

/// Last published immutable UI snapshot. The status command reads this without joining the large
/// product-state mutex, so a slow credential-store or transition commit cannot make the WebView
/// lose all progress/diagnostics. Writers still publish only fully assembled states.
static STATUS_SNAPSHOT: Lazy<ArcSwapOption<TonoStatus>> = Lazy::new(ArcSwapOption::empty);

/// Proof-of-life for the *WebView side* of the app, used by the main-thread pump watchdog.
///
/// `tono_status` is the one command the running UI calls on a fixed schedule whenever the window
/// is visible (`useTonoStatus`, 5 s safety-net poll plus every status push). A window that is
/// visible and has not invoked it for far longer than that has stopped executing JavaScript —
/// which is the one thing a "(Not Responding)" screenshot cannot tell us apart from a blocked
/// native main thread. Recording it costs one relaxed store per status read.
static PROCESS_START: Lazy<std::time::Instant> = Lazy::new(std::time::Instant::now);
static LAST_FRONTEND_IPC_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn note_frontend_ipc() {
    // +1 so "never called" stays distinguishable from "called in the first millisecond".
    let stamp = PROCESS_START.elapsed().as_millis().saturating_add(1) as u64;
    LAST_FRONTEND_IPC_MS.store(stamp, std::sync::atomic::Ordering::Relaxed);
}

/// How long since the WebView last invoked `tono_status`, or `None` if it never has.
pub(crate) fn frontend_ipc_silence() -> Option<std::time::Duration> {
    let last = LAST_FRONTEND_IPC_MS.load(std::sync::atomic::Ordering::Relaxed);
    if last == 0 {
        return None;
    }
    Some(
        PROCESS_START
            .elapsed()
            .saturating_sub(std::time::Duration::from_millis(last)),
    )
}

/// TS: `interface TonoSignInChallenge { challengeId: string; expiresIn: number; message: string }`
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TonoSignInChallenge {
    pub challenge_id: String,
    pub expires_in: i64,
    pub message: String,
}

/// TS: `interface TonoAccountInfo { email: string; suspended: boolean; deviceLimit: number }`
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TonoAccountInfo {
    pub email: String,
    pub suspended: bool,
    pub device_limit: i64,
}

/// TS: `interface TonoDevice { id: string; name: string; createdAt: number | null; current: boolean }`
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TonoDevice {
    pub id: String,
    pub name: String,
    pub created_at: Option<i64>,
    pub current: bool,
}

/// TS: `interface TonoServer { name: string; server: string; port: number; selected: boolean; available: boolean }`
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TonoServer {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub selected: bool,
    /// False when the exit is known blocked (e.g. GFW); still listed so users see status.
    pub available: bool,
}

/// Account-scoped catalog metadata. A refresh failure never clears the verified revision/nodes.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TonoCatalogStatus {
    pub revision: Option<i64>,
    pub node_count: usize,
    pub last_synced_at_ms: Option<i64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TonoServerTestResult {
    pub name: String,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

const SERVER_TEST_CONCURRENCY: usize = 4;
const SERVER_TEST_TIMEOUT: Duration = Duration::from_secs(4);

/// Stable wire key for a connect stage (`TonoStatus.stage`).
pub fn stage_key(stage: ConnectStage) -> &'static str {
    match stage {
        ConnectStage::Preparing => "preparing",
        ConnectStage::PreparingService => "preparingService",
        ConnectStage::StartingKillSwitch => "startingKillSwitch",
        ConnectStage::StartingTunnel => "startingTunnel",
        ConnectStage::LockingTraffic => "lockingTraffic",
        ConnectStage::ApplyingCloudPolicy => "applyingCloudPolicy",
        ConnectStage::SecuringDns => "securingDNS",
        ConnectStage::CheckingExit => "checkingExit",
        ConnectStage::VerifyingTraffic => "verifyingTraffic",
    }
}

/// Stable wire key for the top-level UI state (`TonoStatus.uiState`).
pub fn ui_state_key(ui_state: UiState) -> &'static str {
    match ui_state {
        UiState::NotConnected => "notConnected",
        UiState::Connecting(_) => "connecting",
        UiState::Connected => "connected",
        UiState::ProtectedOffline => "protectedOffline",
        UiState::Disconnecting => "disconnecting",
    }
}

/// Snapshot the product state for the status command and the status event.
pub(crate) fn status_of(inner: &TonoInner) -> TonoStatus {
    let status = inner.fsm.status();
    let stage = status.stage;
    let revision = inner.catalog_tracker.current_revision();
    TonoStatus {
        account_state: inner.account_state.key().to_string(),
        ui_state: ui_state_key(status.ui_state()).to_string(),
        stage: stage.map(stage_key).map(str::to_string),
        stage_label: stage.map(|stage| stage.label().to_string()),
        selected_server: inner.selected_node.clone(),
        protection_blocked: status.is_protection_blocked,
        kill_switch: inner.kill_switch.clone(),
        catalog_revision: (revision >= 0).then_some(revision),
        catalog_requires_choice: inner.catalog_requires_choice,
        controller_generation: inner.controller_generation,
    }
}

pub(crate) fn emit_status(app: &AppHandle, status: &TonoStatus) {
    STATUS_SNAPSHOT.store(Some(Arc::new(status.clone())));
    if let Err(err) = app.emit("tono://status", status) {
        logging!(warn, Type::Service, "Tono: 状态事件发送失败: {err}");
    }
    // The tray is another projection of this same product state. Rebuild it asynchronously so
    // callers may continue publishing while holding the state mutex; the tray snapshot will run
    // after that guard is released and therefore cannot deadlock the connection transaction.
    AsyncHandler::spawn(|| async {
        if let Err(err) = crate::core::tray::Tray::global().update_menu().await {
            logging!(warn, Type::Tray, "Tono: failed to refresh tray status: {err:#}");
        }
        if let Err(err) = crate::core::tray::Tray::global().update_tooltip().await {
            logging!(warn, Type::Tray, "Tono: failed to refresh tray tooltip: {err:#}");
        }
    });
}

/// Epoch milliseconds now (F3 retry deadlines / failure timestamps).
pub fn epoch_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

fn account_info_of(user: &User) -> TonoAccountInfo {
    TonoAccountInfo {
        email: user.email.clone(),
        suspended: user.suspended.unwrap_or(false),
        device_limit: user.device_limit.unwrap_or(i64::from(DEFAULT_DEVICE_LIMIT)),
    }
}

/// Startup credential hydration budget: a prompting vault must never stall
/// the session restore (the macOS securityd deadlock this fixes).
const CREDENTIAL_LOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Restore-time token decision (M1): a vault error is not a missing token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenProbe {
    HasToken,
    NoToken,
    StoreError,
}

pub fn token_probe(credential_error: Option<&String>, refresh_token: Option<&String>) -> TokenProbe {
    if credential_error.is_some() {
        return TokenProbe::StoreError;
    }
    if refresh_token.is_some() {
        TokenProbe::HasToken
    } else {
        TokenProbe::NoToken
    }
}

/// Read the vault OFF the executor (one shared 3 s timeout for both keys),
/// hydrate the memory-first store, and record the outcome. Timeout reads as
/// "no credentials" — startup never blocks; store/join errors are recorded
/// for the M1 error branch. Idempotent: restore and sign-in both await it.
pub async fn load_credentials(state: &Arc<TonoState>) {
    let generation = {
        let inner = state.lock().await;
        if inner.credentials_loaded {
            return;
        }
        inner.sign_in_generation
    };
    let outcome = tokio::time::timeout(CREDENTIAL_LOAD_TIMEOUT, async {
        let refresh = TonoCredentialStore::get_async(CredentialKey::RefreshToken).await;
        let id = TonoCredentialStore::get_async(CredentialKey::InstallationId).await;
        (refresh, id)
    })
    .await;

    let mut inner = state.lock().await;
    // Another hydration may have won while this vault read was in flight. More importantly,
    // sign-out or a newer login generation must not let a late startup read resurrect the old
    // refresh token in the memory-first credential store.
    if inner.credentials_loaded {
        return;
    }
    if inner.sign_in_generation != generation {
        inner.credentials_loaded = true;
        return;
    }
    let Ok((refresh, id)) = outcome else {
        // A timeout is not an answer. Reading it as "no credentials" turned a slow Credential
        // Manager into a signed-out user, and latching the gate made that verdict stick until
        // the process restarted — including through `tono_retry_restore`, which re-enters here
        // and used to return immediately. Record it as a store error (the M1 branch, which
        // preserves protection and offers Retry) and leave the gate closed so a retry re-reads.
        inner.credential_error = Some(format!(
            "credential store did not answer within {CREDENTIAL_LOAD_TIMEOUT:?}"
        ));
        return;
    };
    match refresh {
        Ok(Some(token)) => {
            // Hydrate memory only — writing the same bytes back would
            // risk another prompting vault call.
            let _ = inner.credentials.set_local(CredentialKey::RefreshToken, &token);
        }
        Ok(None) => {}
        Err(err) => inner.credential_error = Some(err.to_string()),
    }
    match id {
        Ok(Some(persisted)) => {
            if let Ok(persisted) = normalize_installation_id(&persisted) {
                inner.installation_id = persisted;
            }
        }
        Ok(None) => {
            // First run: persist the in-memory id off-thread (§2).
            let installation_id = inner.installation_id.clone();
            tokio::spawn(async move {
                let _ = TonoCredentialStore::set_async(CredentialKey::InstallationId, &installation_id).await;
            });
        }
        Err(_) => {
            // The id is not auth-critical: keep the ephemeral one.
        }
    }
    // The vault answered — including "there is nothing stored", which is a real answer. The
    // gate opens only here; startup was never blocked, because the read itself is bounded.
    inner.credentials_loaded = true;
}

/// Start email sign-in (`POST auth/email/start`, §1/§2).
#[tauri::command]
pub async fn tono_sign_in_start(
    state: tauri::State<'_, Arc<TonoState>>,
    app: AppHandle,
    email: String,
) -> Result<TonoSignInChallenge, String> {
    // The installation id hydrates from the vault off-thread at startup;
    // wait for it so sign-in registers the stable device id.
    load_credentials(state.inner()).await;
    let (client, installation_id, generation) = {
        let mut inner = state.lock().await;
        inner.sign_in_generation = inner.sign_in_generation.wrapping_add(1);
        (
            inner.client.clone(),
            inner.installation_id.clone(),
            inner.sign_in_generation,
        )
    };
    // Empty device name → the platform default ("Windows PC", §2).
    let challenge = client
        .start_email_sign_in(&email, "", &installation_id)
        .await
        .map_err(|err| err.to_string())?;

    let mut inner = state.lock().await;
    if inner.sign_in_generation != generation {
        return Err("sign-in request was superseded by a newer attempt".to_string());
    }
    inner.account_state = AccountState::Authenticating;
    inner.challenge_id = Some(challenge.challenge_id.clone());
    emit_status(&app, &status_of(&inner));
    drop(inner);
    // Local log only; the email is recorded verbatim, never the code.
    state.audit().log(AuditEvent::SignInStart { email });

    Ok(TonoSignInChallenge {
        challenge_id: challenge.challenge_id,
        expires_in: challenge.expires_in,
        message: challenge.message,
    })
}

/// Complete email sign-in (`POST auth/email/verify`); adopts the tokens and
/// kicks off the catalog sync (§2/§3).
#[tauri::command]
pub async fn tono_sign_in_verify(
    state: tauri::State<'_, Arc<TonoState>>,
    app: AppHandle,
    email: String,
    code: String,
) -> Result<TonoAccountInfo, String> {
    let _ = email; // the challenge, not the address, identifies the attempt
    let (client, challenge_id, generation) = {
        let inner = state.lock().await;
        let challenge_id = inner
            .challenge_id
            .clone()
            .ok_or_else(|| "no sign-in is in progress".to_string())?;
        (inner.client.clone(), challenge_id, inner.sign_in_generation)
    };
    let auth = client
        .verify_email_sign_in(&challenge_id, &code)
        .await
        .map_err(|err| err.to_string())?;

    let info = account_info_of(&auth.user);
    {
        let mut inner = state.lock().await;
        if inner.sign_in_generation != generation || inner.challenge_id.as_deref() != Some(challenge_id.as_str()) {
            return Err("sign-in verification was superseded by a newer attempt".to_string());
        }
        // Keep the Tono state lock through adoption: a resend/sign-out cannot invalidate this
        // generation between the last check and the token write.
        client.adopt(&auth).await.map_err(|err| err.to_string())?;
        inner.challenge_id = None;
        inner.account = Some(auth.user.clone());
        inner.catalog_last_synced_at_ms = None;
        inner.catalog_sync_error = None;
        inner.account_state = if info.suspended {
            AccountState::Suspended
        } else {
            AccountState::Ready
        };
        emit_status(&app, &status_of(&inner));
    }
    state.audit().log(AuditEvent::SignInOk {
        email: auth.user.email.clone(),
    });

    if !info.suspended {
        let state = state.inner().clone();
        // §3: sync immediately on login; a failure here never fails sign-in.
        if let Err(err) = catalog_sync::sync_with_retries_for_auth_generation(&state, &app, generation).await {
            logging!(warn, Type::Service, "Tono: 登录后的目录同步失败: {err}");
        }
        if state.lock().await.sign_in_generation != generation {
            return Err("sign-in was superseded while syncing account data".to_string());
        }
        if let Err(err) =
            crate::tono::policy_sync::sync_with_retries_for_auth_generation(&state, &app, generation).await
        {
            logging!(warn, Type::Service, "Tono: 登录后的策略同步失败: {err}");
        }
        if state.lock().await.sign_in_generation != generation {
            return Err("sign-in was superseded while syncing account data".to_string());
        }
        catalog_sync::spawn_periodic_for_auth_generation(&state, &app, generation).await;
    }
    Ok(info)
}

/// Sign out: bump the connect generation and abort every background task
/// first (H1/H2b), then release with disconnect semantics — DNS restore
/// must be proven and the release is owner-gated, never best-effort (M3,
/// C1). A failed release keeps the system armed and aborts the sign-out.
#[tauri::command]
pub async fn tono_sign_out(state: tauri::State<'_, Arc<TonoState>>, app: AppHandle) -> Result<(), String> {
    let (client, generation) = {
        let mut inner = state.lock().await;
        inner.invalidate_connection(true);
        inner.sign_in_generation = inner.sign_in_generation.wrapping_add(1);
        inner.tasks.abort_catalog_sync();
        inner.cancel_server_tests();
        (inner.client.clone(), inner.sign_in_generation)
    };

    // M-1: the predicate covers an in-flight connect too, matching the
    // disconnect and quit paths.
    let protected = {
        let inner = state.lock().await;
        connection::sign_out_needs_release(inner.fsm.status(), inner.fsm.kill_switch_armed())
    };
    if protected {
        // Same sequence and same failure semantics as disconnect (M3): if
        // the release cannot be proven, stay armed and do not sign out.
        if let Err(err) = connection::release_explicit(&state, &app).await {
            let mut inner = state.lock().await;
            if inner.sign_in_generation != generation {
                return Err("sign-out was superseded by a newer authentication action".to_string());
            }
            // `initial_release_failed`, not `connect_failed`: for an armed-but-unverified
            // session the latter resolves to FullRelease and clears the armed latch even
            // though the Service release just failed (mirrors
            // `stay_armed_after_failed_release`).
            inner.fsm.initial_release_failed();
            emit_status(&app, &status_of(&inner));
            drop(inner);
            // L4: the user is still signed in — restart the catalog sync
            // that `abort_catalog_sync` just stopped.
            catalog_sync::spawn_periodic_for_auth_generation(&state, &app, generation).await;
            return Err(err);
        }
    }
    // Best-effort server logout, then local token wipe (§2; logout itself
    // is deliberately infallible).
    if state.lock().await.sign_in_generation != generation {
        return Err("sign-out was superseded by a newer authentication action".to_string());
    }
    client.logout().await;

    let mut inner = state.lock().await;
    if inner.sign_in_generation != generation {
        return Err("sign-out was superseded by a newer authentication action".to_string());
    }
    inner.fsm.sign_out_or_quit();
    inner.account = None;
    inner.account_state = AccountState::SignedOut;
    inner.challenge_id = None;
    inner.controller_secret = None;
    inner.controller_port = None;
    inner.kill_switch = None;
    inner.network_events_counter = None;
    inner.catalog_last_synced_at_ms = None;
    inner.catalog_sync_error = None;
    emit_status(&app, &status_of(&inner));
    drop(inner);
    state.audit().log(AuditEvent::SignOut);
    Ok(())
}

/// The current account, if signed in.
#[tauri::command]
pub async fn tono_account(state: tauri::State<'_, Arc<TonoState>>) -> Result<Option<TonoAccountInfo>, String> {
    let inner = state.lock().await;
    Ok(inner.account.as_ref().map(account_info_of))
}

/// Account devices across platforms (§2); any device except the current one
/// may be revoked.
#[tauri::command]
pub async fn tono_devices(state: tauri::State<'_, Arc<TonoState>>) -> Result<Vec<TonoDevice>, String> {
    let client = { state.lock().await.client.clone() };
    let devices = client.devices().await.map_err(|err| err.to_string())?;
    Ok(devices
        .devices
        .into_iter()
        .map(|device| TonoDevice {
            id: device.id,
            name: device.name,
            created_at: device.created_at,
            current: device.current.unwrap_or(false),
        })
        .collect())
}

/// Revoke a device by UUID (§2).
#[tauri::command]
pub async fn tono_revoke_device(state: tauri::State<'_, Arc<TonoState>>, id: String) -> Result<(), String> {
    let client = { state.lock().await.client.clone() };
    client.revoke_device(&id).await.map_err(|err| err.to_string())?;
    state.audit().log(AuditEvent::RevokeDevice { id });
    Ok(())
}

/// Servers from the validated catalog, US/JP first, with the selection flag.
#[tauri::command]
pub async fn tono_servers(state: tauri::State<'_, Arc<TonoState>>) -> Result<Vec<TonoServer>, String> {
    let inner = state.lock().await;
    let order = catalog_sync::sort_server_names(&inner.nodes);
    Ok(order
        .into_iter()
        .filter_map(|name| {
            inner
                .nodes
                .iter()
                .find(|node| node.name == name)
                .map(|node| TonoServer {
                    name: node.name.clone(),
                    server: node.server.to_string(),
                    port: node.port,
                    selected: inner.selected_node.as_deref() == Some(node.name.as_str()),
                    available: !catalog_sync::is_exit_blocked(&node.name),
                })
        })
        .collect())
}

fn catalog_status_of(inner: &TonoInner) -> TonoCatalogStatus {
    let revision = inner.catalog_tracker.current_revision();
    TonoCatalogStatus {
        revision: (revision >= 0).then_some(revision),
        node_count: inner.nodes.len(),
        last_synced_at_ms: inner.catalog_last_synced_at_ms,
        error: inner.catalog_sync_error.clone(),
    }
}

#[tauri::command]
pub async fn tono_catalog_status(state: tauri::State<'_, Arc<TonoState>>) -> Result<TonoCatalogStatus, String> {
    let inner = state.lock().await;
    Ok(catalog_status_of(&inner))
}

/// User-initiated account-scoped refresh. This deliberately reuses catalog_sync's verified
/// fetch/install path; the command cannot install unverified bytes or bypass rollback checks.
#[tauri::command]
pub async fn tono_refresh_catalog(
    state: tauri::State<'_, Arc<TonoState>>,
    app: AppHandle,
) -> Result<TonoCatalogStatus, String> {
    let generation = {
        let inner = state.lock().await;
        if !matches!(inner.account_state, AccountState::Ready) {
            return Err("sign in before refreshing cloud servers".to_string());
        }
        inner.sign_in_generation
    };
    let result = catalog_sync::sync_with_retries_for_auth_generation(state.inner(), &app, generation).await;
    let inner = state.lock().await;
    if inner.sign_in_generation != generation {
        return Err("catalog refresh was superseded by an account change".to_string());
    }
    result?;
    Ok(catalog_status_of(&inner))
}

async fn test_server_endpoint(
    name: String,
    address: SocketAddr,
    cancellation: tokio_util::sync::CancellationToken,
) -> TonoServerTestResult {
    let started = std::time::Instant::now();
    let result = tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err("cancelled".to_string()),
        result = tokio::time::timeout(SERVER_TEST_TIMEOUT, tokio::net::TcpStream::connect(address)) => {
            match result {
                Ok(Ok(stream)) => {
                    drop(stream);
                    Ok(started.elapsed().as_millis().max(1).min(u64::MAX as u128) as u64)
                }
                Ok(Err(error)) => Err(error.to_string()),
                Err(_) => Err("timeout".to_string()),
            }
        }
    };
    match result {
        Ok(latency_ms) => TonoServerTestResult {
            name,
            latency_ms: Some(latency_ms),
            error: None,
        },
        Err(error) => TonoServerTestResult {
            name,
            latency_ms: None,
            error: Some(error),
        },
    }
}

/// Measure each usable catalog endpoint without selecting it. This is allowed only while fully
/// disconnected and unarmed: connected WFP intentionally permits only the selected endpoint,
/// and widening that permit for a UI test would weaken the connection safety contract.
#[tauri::command]
pub async fn tono_test_available_servers(
    state: tauri::State<'_, Arc<TonoState>>,
) -> Result<Vec<TonoServerTestResult>, String> {
    let (generation, auth_generation, catalog_revision, cancellation, nodes) = {
        let mut inner = state.lock().await;
        if !matches!(inner.account_state, AccountState::Ready) {
            return Err("sign in before testing servers".to_string());
        }
        if inner.fsm.status().is_connected || inner.fsm.status().is_connecting || inner.fsm.kill_switch_armed() {
            return Err("disconnect before testing all servers".to_string());
        }
        if inner.server_test_cancellation.is_some() {
            return Err("a server test is already running".to_string());
        }
        let nodes = inner
            .nodes
            .iter()
            .filter(|node| !catalog_sync::is_exit_blocked(&node.name))
            .map(|node| (node.name.clone(), SocketAddr::new(node.server.into(), node.port)))
            .collect::<Vec<_>>();
        inner.server_test_generation = inner.server_test_generation.wrapping_add(1);
        let generation = inner.server_test_generation;
        let cancellation = tokio_util::sync::CancellationToken::new();
        inner.server_test_cancellation = Some(cancellation.clone());
        (
            generation,
            inner.sign_in_generation,
            inner.catalog_tracker.current_revision(),
            cancellation,
            nodes,
        )
    };

    let mut results = stream::iter(nodes)
        .map(|(name, address)| test_server_endpoint(name, address, cancellation.clone()))
        .buffer_unordered(SERVER_TEST_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    results.sort_by(|left, right| left.name.cmp(&right.name));

    let mut inner = state.lock().await;
    let owns_slot = inner.server_test_generation == generation;
    let stale = cancellation.is_cancelled()
        || !owns_slot
        || inner.sign_in_generation != auth_generation
        || inner.catalog_tracker.current_revision() != catalog_revision;
    if owns_slot {
        inner.server_test_cancellation = None;
    }
    if stale {
        return Err("server test cancelled or superseded".to_string());
    }
    Ok(results)
}

#[tauri::command]
pub async fn tono_cancel_server_tests(state: tauri::State<'_, Arc<TonoState>>) -> Result<(), String> {
    let mut inner = state.lock().await;
    inner.cancel_server_tests();
    Ok(())
}

/// Select a server. Persists the choice (L4). What happens next is decided
/// by `connection::select_action` (H1): a same-node reselect with no
/// pending choice is a pure no-op; a real change while a tunnel is up
/// derives the §6 node switch as a registered task; a fresh pick in armed
/// Protected Offline (including after a catalog choice loss, M5) schedules
/// the protected reconnect. Generation, tasks, and the H-1 intent bit are
/// touched only when a transaction actually derives (M2).
#[tauri::command]
pub async fn tono_select_server(
    state: tauri::State<'_, Arc<TonoState>>,
    app: AppHandle,
    name: String,
) -> Result<(), String> {
    let action = {
        let mut inner = state.lock().await;
        if !inner.nodes.iter().any(|node| node.name == name) {
            return Err("unknown server".to_string());
        }
        if catalog_sync::is_exit_blocked(&name) {
            return Err("this server is currently unavailable (network blocked)".to_string());
        }
        let previous = inner.selected_node.clone();
        let changed = previous.as_deref() != Some(name.as_str());
        let cleared_choice = inner.catalog_requires_choice;
        let action = connection::select_action(
            changed,
            cleared_choice,
            inner.fsm.status(),
            inner.fsm.kill_switch_armed(),
        );
        if action == connection::SelectAction::Noop {
            return Ok(());
        }
        inner.selected_node = Some(name.clone());
        // A fresh user choice re-arms auto-reconnect (§3).
        inner.catalog_requires_choice = false;
        if matches!(
            action,
            connection::SelectAction::Switch | connection::SelectAction::Reconnect
        ) {
            // The switch/reconnect re-arms rather than releases (H-1 intent).
            inner.invalidate_connection(false);
        }
        let generation = inner.connect_generation;
        if let Err(err) = crate::tono::state::save_selection(&inner.catalog_dir, &name) {
            logging!(warn, Type::Service, "Tono: 选中节点持久化失败: {err}");
        }
        emit_status(&app, &status_of(&inner));
        // Spawned *and* registered under one guard. Registering after `drop(inner)` left a
        // window in which a concurrent `disconnect()` ran `abort_connection_tasks()` against an
        // empty switch slot and this line then installed a task nothing could abort — a node
        // switch surviving the disconnect that was supposed to cancel it, re-arming WFP behind
        // a completed release. The task's first act is to lock this same mutex, so it cannot
        // make progress before the guard is dropped below.
        if action == connection::SelectAction::Switch {
            let task_state = state.inner().clone();
            let task_app = app.clone();
            inner.tasks.switch = Some(AsyncHandler::spawn(move || async move {
                connection::switch_selected_node(task_state, task_app, generation).await;
            }));
        }
        drop(inner);
        if cleared_choice {
            state.audit().log(AuditEvent::RequiresChoiceCleared);
        }
        if action == connection::SelectAction::Switch
            && let Some(from) = previous
        {
            state.audit().log(AuditEvent::NodeSwitch { from, to: name.clone() });
        }
        action
    };

    match action {
        // Already spawned and registered above, under the guard.
        connection::SelectAction::Switch => {}
        connection::SelectAction::Reconnect => {
            connection::schedule_reconnect(&state, &app).await;
        }
        connection::SelectAction::Noop | connection::SelectAction::UpdateOnly => {}
    }
    Ok(())
}

/// Execute a fresh controller delay probe through the selected exit. This is intentionally
/// available only while Connected; cached legacy delay history is not presented as a new test.
#[tauri::command]
pub async fn tono_test_current_server(state: tauri::State<'_, Arc<TonoState>>) -> Result<u64, String> {
    connection::test_current_server(state.inner()).await
}

/// Run the §6 connect transaction.
#[tauri::command]
pub async fn tono_connect(state: tauri::State<'_, Arc<TonoState>>, app: AppHandle) -> Result<(), String> {
    connection::connect(state.inner().clone(), app).await
}

/// Explicit disconnect: restores DNS, then releases the kill switch (§6).
#[tauri::command]
pub async fn tono_disconnect(state: tauri::State<'_, Arc<TonoState>>, app: AppHandle) -> Result<(), String> {
    connection::disconnect(state.inner().clone(), app).await
}

/// F3 connect progress for the steps UI. Semantics: the *latest*
/// transaction's record — during an attempt it shows live step state; after
/// success all steps read completed; after a failure the failed step and
/// the sanitized error persist until the next attempt resets them; before
/// the first attempt all steps read pending.
///
/// TS: `interface TonoConnectStep { key: string; label: string; state: "pending" | "current" | "completed" | "failed"; elapsedMs: number | null }`
/// TS: `interface TonoConnectProgress { steps: TonoConnectStep[]; totalElapsedMs: number | null; failedStage: string | null; error: string | null; retryAttempt: number; nextRetryAtMs: number | null }`
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TonoConnectProgress {
    pub steps: Vec<crate::tono::steps::StepRecord>,
    pub total_elapsed_ms: Option<u64>,
    pub failed_stage: Option<String>,
    pub error: Option<String>,
    pub retry_attempt: u32,
    pub next_retry_at_ms: Option<i64>,
}

/// Connect progress (F3).
#[tauri::command]
pub async fn tono_connect_progress(state: tauri::State<'_, Arc<TonoState>>) -> Result<TonoConnectProgress, String> {
    let inner = state.lock().await;
    let current_elapsed_ms = inner
        .step_started_at
        .map(|started| started.elapsed().as_millis() as u64);
    let steps = crate::tono::steps::snapshot_with_current_elapsed(&inner.connect_steps, current_elapsed_ms);
    Ok(TonoConnectProgress {
        total_elapsed_ms: crate::tono::steps::total_elapsed_ms(&steps),
        steps,
        failed_stage: inner.failed_stage.map(str::to_string),
        error: inner.connect_error.clone(),
        retry_attempt: inner.retry_attempt,
        next_retry_at_ms: inner.next_retry_at_ms,
    })
}

/// F3: abort any scheduled reconnect and run one immediately (the normal
/// predicate still applies — armed + idle Protected Offline + no pending
/// catalog choice). Connected/Connecting is a success no-op.
#[tauri::command]
pub async fn tono_retry_now(state: tauri::State<'_, Arc<TonoState>>, app: AppHandle) -> Result<(), String> {
    retry_now(state.inner().clone(), app).await
}

/// Shared Protected Offline retry entry for IPC and native surfaces such as the tray. Keeping
/// this beside the command prevents either caller from bypassing the reconnect predicate.
pub async fn retry_now(state: Arc<TonoState>, app: AppHandle) -> Result<(), String> {
    {
        let mut inner = state.lock().await;
        if connection::retry_now_is_noop(inner.fsm.status()) {
            return Ok(());
        }
        inner.tasks.abort_reconnect();
    }
    connection::schedule_reconnect(&state, &app).await;
    Ok(())
}

/// Current product status (also pushed on `tono://status`).
#[tauri::command]
pub async fn tono_status(state: tauri::State<'_, Arc<TonoState>>) -> Result<TonoStatus, String> {
    note_frontend_ipc();
    if let Some(status) = STATUS_SNAPSHOT.load_full() {
        return Ok((*status).clone());
    }
    let inner = state.lock().await;
    Ok(status_of(&inner))
}

/// Close one connection only on the controller generation that supplied its row.
#[tauri::command]
pub async fn tono_close_connection(
    state: tauri::State<'_, Arc<TonoState>>,
    id: String,
    controller_generation: u64,
) -> Result<(), String> {
    connection::close_owned_controller_connection(&state, controller_generation, Some(&id)).await
}

/// Close all connections only on the controller generation represented by the Activity page.
#[tauri::command]
pub async fn tono_close_all_connections(
    state: tauri::State<'_, Arc<TonoState>>,
    controller_generation: u64,
) -> Result<(), String> {
    connection::close_owned_controller_connection(&state, controller_generation, None).await
}

/// How many times restore asks the Service about the stored barrier before giving up.
///
/// The Service restores WFP and reconciles its startup state *before* it begins serving IPC, so
/// on a BFE-dependent auto-start the pipe simply does not exist yet — and the app spawns restore
/// immediately at launch. One failed probe therefore means "not yet", not "no barrier".
const PROTECTION_PROBE_ATTEMPTS: usize = 5;
const PROTECTION_PROBE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// What the Service could tell restore about a stored kill switch.
///
/// The third case is the whole point. Collapsing an IPC failure into "no barrier" makes every
/// downstream branch treat it as *proven disarmed*: the signed-out path skipped the release and
/// reported SignedOut + `killSwitch: null` + `protectionBlocked: false` over a live WFP block,
/// Disconnect then became a silent success no-op, and Quit computed `protected == false` and
/// exited — leaving the machine blocked with no owner and a UI insisting all was well.
#[derive(Debug, Clone)]
enum StoredProtection {
    /// The Service answered and wants the barrier.
    Armed(Box<KillSwitchStatus>),
    /// The Service answered and wants no barrier. The only reading that proves absence.
    ProvenAbsent,
    /// The Service did not answer. Never treated as absence.
    Unknown(String),
}

/// Ask the Service about the stored barrier, retrying inside the restore budget.
async fn probe_stored_protection(deadline: tokio::time::Instant) -> StoredProtection {
    let mut last_error = "the Tono Service did not answer".to_string();
    for attempt in 0..PROTECTION_PROBE_ATTEMPTS {
        match tokio::time::timeout_at(deadline, service::tono_service_status_snapshot()).await {
            Ok(Ok(snapshot)) => {
                return match snapshot.kill_switch {
                    Some(status) if status.wanted => StoredProtection::Armed(Box::new(status)),
                    _ => StoredProtection::ProvenAbsent,
                };
            }
            Ok(Err(error)) => last_error = error.to_string(),
            Err(_elapsed) => {
                last_error = format!("status probe exceeded the {RESTORE_TRANSACTION_TIMEOUT:?} restore budget");
                break;
            }
        }
        if attempt + 1 < PROTECTION_PROBE_ATTEMPTS
            && tokio::time::timeout_at(deadline, tokio::time::sleep(PROTECTION_PROBE_INTERVAL))
                .await
                .is_err()
        {
            break;
        }
    }
    logging!(
        warn,
        Type::Service,
        "Tono: 无法读取 Service 的保护状态，按“未知（仍可能已封锁）”处理: {last_error}"
    );
    StoredProtection::Unknown(last_error)
}

/// Fold a protection reading into the FSM.
///
/// `Unknown` is recorded as armed but *not* session-verified. Of the two possible mistakes,
/// believing in a barrier that is already gone costs the user one Disconnect that succeeds
/// immediately; believing a live barrier is gone costs them their network with no way back.
/// Withholding `mark_session_verified` keeps auto-reconnect out of it — an unknown must unlock
/// the release paths, not start driving the machine.
fn apply_stored_protection(inner: &mut TonoInner, protection: &StoredProtection) {
    match protection {
        StoredProtection::Armed(status) => {
            if status.verified {
                inner.fsm.mark_session_verified();
            }
            inner.kill_switch = Some((**status).clone());
            inner.fsm.mark_kill_switch_armed();
        }
        StoredProtection::Unknown(_) => inner.fsm.mark_kill_switch_armed(),
        StoredProtection::ProvenAbsent => {}
    }
}

/// The single wording for "we could not read the barrier". It has to name the consequence and
/// the escape hatch, because the user may be looking at a machine with no network.
fn unknown_protection_message(reason: &str) -> String {
    format!(
        "protection state unknown — the Tono Service is not answering ({reason}). Network protection may still be blocking this machine: use Disconnect to release it, or run `tono-service.exe --emergency-disarm` as Administrator"
    )
}

/// Startup session restore (§2): load the persisted selection (L4), seed
/// the catalog from the verified cache, then refresh + `me()`. A 401 means
/// the session is dead (logout, disarm, clear); other errors keep the kill
/// switch armed and enter the error state. If the Service still wants the
/// kill switch, surface Protected Offline and wait for the user — never
/// auto-reconnect here.
pub async fn restore_session(app: AppHandle, state: Arc<TonoState>) {
    let restore_deadline = tokio::time::Instant::now() + RESTORE_TRANSACTION_TIMEOUT;
    let generation = {
        let mut inner = state.lock().await;
        // Restore is an authentication transaction too. A retry supersedes an older restore,
        // while sign-in/sign-out already bump the same generation.
        inner.sign_in_generation = inner.sign_in_generation.wrapping_add(1);
        if let Some(selected) = crate::tono::state::load_selection(&inner.catalog_dir) {
            inner.selected_node = Some(selected);
        }
        catalog_sync::seed_from_cache(&mut inner);
        crate::tono::policy_sync::seed_from_cache(&mut inner);
        emit_status(&app, &status_of(&inner));
        inner.sign_in_generation
    };

    // Three-valued on purpose: armed / proven absent / unknown. This used to be an
    // `Option<KillSwitchStatus>` where every failure mode became `None`, and `None` reads as
    // "there is no barrier" everywhere below.
    let protection = probe_stored_protection(restore_deadline).await;

    let (client, probe) = {
        let inner = state.lock().await;
        if inner.sign_in_generation != generation {
            return;
        }
        let refresh = inner.credentials.refresh_token().ok().flatten();
        let probe = token_probe(inner.credential_error.as_ref(), refresh.as_ref());
        (inner.client.clone(), probe)
    };

    // M1: a credential-store *error* is not a missing token — it enters the
    // error state (protection preserved), never SignedOut.
    match probe {
        TokenProbe::StoreError => {
            let mut inner = state.lock().await;
            if inner.sign_in_generation != generation {
                return;
            }
            apply_stored_protection(&mut inner, &protection);
            let detail = inner
                .credential_error
                .clone()
                .unwrap_or_else(|| "unknown credential error".to_string());
            inner.account_state = match &protection {
                // Two unknowns at once (a slow vault and a Service that is not up yet) is the
                // common boot case; report both rather than only the one we noticed first.
                StoredProtection::Unknown(reason) => AccountState::Error(format!(
                    "credential store unreadable: {detail}; {}",
                    unknown_protection_message(reason)
                )),
                _ => AccountState::Error(format!("credential store unreadable: {detail}")),
            };
            emit_status(&app, &status_of(&inner));
            return;
        }
        TokenProbe::NoToken => {
            if let StoredProtection::Unknown(reason) = &protection {
                // Never the silent signed-out path. Unknown here was the worst of the lot: it
                // skipped the release entirely and reported SignedOut over a possibly-live WFP
                // block, after which Disconnect was a success no-op and Quit exited computing
                // `protected == false`. Record it as armed so every release path stays
                // reachable, and say plainly that we do not know.
                let mut inner = state.lock().await;
                if inner.sign_in_generation != generation {
                    return;
                }
                apply_stored_protection(&mut inner, &protection);
                inner.account_state = AccountState::Error(unknown_protection_message(reason));
                emit_status(&app, &status_of(&inner));
                return;
            }
            if matches!(protection, StoredProtection::Armed(_)) {
                {
                    let mut inner = state.lock().await;
                    if inner.sign_in_generation != generation {
                        return;
                    }
                    apply_stored_protection(&mut inner, &protection);
                }
                if let Err(error) = connection::release_explicit(&state, &app).await {
                    let mut inner = state.lock().await;
                    if inner.sign_in_generation != generation {
                        return;
                    }
                    inner.account_state = AccountState::Error(format!(
                        "stored protection could not be released while signed out: {error}"
                    ));
                    emit_status(&app, &status_of(&inner));
                    return;
                }
                let mut inner = state.lock().await;
                // Generation first, like every sibling block: a user who signed in while the
                // startup release reconciled may already own a fresh connect transaction, and
                // `sign_out_or_quit` here would wipe its FSM mid-flight.
                if inner.sign_in_generation != generation {
                    return;
                }
                inner.fsm.sign_out_or_quit();
                inner.kill_switch = None;
            }
            let mut inner = state.lock().await;
            if inner.sign_in_generation != generation {
                return;
            }
            inner.account_state = AccountState::SignedOut;
            emit_status(&app, &status_of(&inner));
            return;
        }
        TokenProbe::HasToken => {}
    }

    {
        let mut inner = state.lock().await;
        if inner.sign_in_generation != generation {
            return;
        }
        inner.account_state = AccountState::Restoring;
        emit_status(&app, &status_of(&inner));
    }

    let account_result = match tokio::time::timeout_at(restore_deadline, client.me()).await {
        Ok(result) => result,
        Err(_) => {
            let mut inner = state.lock().await;
            if inner.sign_in_generation != generation {
                return;
            }
            apply_stored_protection(&mut inner, &protection);
            inner.account_state =
                AccountState::Error(format!("session restore exceeded {RESTORE_TRANSACTION_TIMEOUT:?}"));
            emit_status(&app, &status_of(&inner));
            return;
        }
    };

    match account_result {
        Ok(me) => {
            let info = account_info_of(&me.user);
            {
                let mut inner = state.lock().await;
                if inner.sign_in_generation != generation {
                    return;
                }
                inner.account = Some(me.user);
                inner.account_state = if info.suspended {
                    AccountState::Suspended
                } else {
                    AccountState::Ready
                };
                apply_stored_protection(&mut inner, &protection);
                emit_status(&app, &status_of(&inner));
            }
            if !info.suspended {
                match tokio::time::timeout_at(
                    restore_deadline,
                    catalog_sync::sync_with_retries_for_auth_generation(&state, &app, generation),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => logging!(warn, Type::Service, "Tono: 会话恢复后的目录同步失败: {err}"),
                    Err(_) => logging!(
                        warn,
                        Type::Service,
                        "Tono: 会话恢复目录同步达到 {RESTORE_TRANSACTION_TIMEOUT:?} 总预算；继续使用已验证缓存"
                    ),
                }
                if state.lock().await.sign_in_generation != generation {
                    return;
                }
                match tokio::time::timeout_at(
                    restore_deadline,
                    crate::tono::policy_sync::sync_with_retries_for_auth_generation(&state, &app, generation),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => logging!(warn, Type::Service, "Tono: 会话恢复后的策略同步失败: {err}"),
                    Err(_) => logging!(
                        warn,
                        Type::Service,
                        "Tono: 会话恢复策略同步达到 {RESTORE_TRANSACTION_TIMEOUT:?} 总预算；继续使用已验证缓存"
                    ),
                }
                if state.lock().await.sign_in_generation != generation {
                    return;
                }
                catalog_sync::spawn_periodic_for_auth_generation(&state, &app, generation).await;
            }
        }
        Err(ApiError::Unauthorized) => {
            // Dead session (§2): logout, disarm the kill switch, clear. The
            // release goes through the owner-gated route (C1); a failed
            // release keeps the system visibly armed and is logged loudly,
            // but the account is dead regardless and still clears.
            if state.lock().await.sign_in_generation != generation {
                return;
            }
            let release_error = connection::release_explicit(&state, &app).await.err();
            if let Some(err) = &release_error {
                logging!(
                    error,
                    Type::Service,
                    "Tono: 401 恢复时释放 Kill Switch 失败，系统仍受保护: {err}"
                );
            }
            if state.lock().await.sign_in_generation != generation {
                return;
            }
            client.logout().await;
            let mut inner = state.lock().await;
            if inner.sign_in_generation != generation {
                return;
            }
            inner.fsm.sign_out_or_quit();
            inner.account = None;
            inner.account_state = AccountState::SignedOut;
            if release_error.is_some() {
                inner.fsm.mark_kill_switch_armed();
            } else {
                inner.kill_switch = None;
            }
            emit_status(&app, &status_of(&inner));
            drop(inner);
            state.audit().log(AuditEvent::SignOut);
        }
        Err(err) => {
            // Flaky network must never drop protection (§2).
            let mut inner = state.lock().await;
            if inner.sign_in_generation != generation {
                return;
            }
            apply_stored_protection(&mut inner, &protection);
            inner.account_state = match &protection {
                StoredProtection::Unknown(reason) => {
                    AccountState::Error(format!("{err}; {}", unknown_protection_message(reason)))
                }
                _ => AccountState::Error(err.to_string()),
            };
            emit_status(&app, &status_of(&inner));
        }
    }
}

/// L2: retry entry for the `error` account state — re-runs the startup
/// restore flow (token probe → `me()` → catalog sync).
#[tauri::command]
pub async fn tono_retry_restore(state: tauri::State<'_, Arc<TonoState>>, app: AppHandle) -> Result<(), String> {
    state.audit().log(AuditEvent::RetryRestore);
    load_credentials(state.inner()).await;
    restore_session(app, state.inner().clone()).await;
    Ok(())
}

/// L7: the spawned restore must never die silently in `restoring` — a
/// panic lands the account in `error` (retryable) instead. The vault
/// hydrate runs first (bounded), so restore never touches the keyring
/// itself.
pub async fn restore_session_guarded(app: AppHandle, state: Arc<TonoState>) {
    use futures::FutureExt as _;

    load_credentials(&state).await;
    let outcome = std::panic::AssertUnwindSafe(restore_session(app.clone(), state.clone()))
        .catch_unwind()
        .await;
    if let Err(payload) = outcome {
        logging!(error, Type::Service, "Tono: 会话恢复任务 panic: {payload:?}");
        let mut inner = state.lock().await;
        // A superseding sign-in/sign-out owns any newer state. Only the restore state itself may
        // be converted into this error; a late panic must not overwrite an established session.
        if matches!(inner.account_state, AccountState::Restoring) {
            inner.account_state = AccountState::Error("session restore panicked".to_string());
            emit_status(&app, &status_of(&inner));
        }
    }
}

/// §8: whether the local traffic audit is enabled (default on).
#[tauri::command]
pub async fn tono_audit_enabled(state: tauri::State<'_, Arc<TonoState>>) -> Result<bool, String> {
    Ok(state.audit().enabled())
}

/// §8: toggle the local traffic audit; persisted atomically to
/// `tono/settings.json` (L3: a persistence failure surfaces as an error and
/// leaves the switch as it was).
#[tauri::command]
pub async fn tono_set_audit_enabled(state: tauri::State<'_, Arc<TonoState>>, enabled: bool) -> Result<(), String> {
    state.audit().set_enabled(enabled)
}

/// §8: the JSONL audit file info (for the settings page / support bundle).
///
/// TS: `interface TonoAuditLogInfo { path: string; droppedCount: number }`
/// NOTE: this replaces the previous plain-string return of this command
/// (L2: the drop count is now observable); the frontend consumer must be
/// updated in step.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TonoAuditLogInfo {
    pub path: String,
    pub dropped_count: u64,
}

/// §8: the JSONL audit file path plus the dropped-event counter.
#[tauri::command]
pub async fn tono_audit_log_path(state: tauri::State<'_, Arc<TonoState>>) -> Result<TonoAuditLogInfo, String> {
    Ok(TonoAuditLogInfo {
        path: state.audit().log_path().to_string_lossy().into_owned(),
        dropped_count: state.audit().dropped_count(),
    })
}

// ---- Diagnostics (user-initiated upload) ----

/// How long a single environment probe (Service protocol, DNS status) may
/// take before the report simply records "unknown" for it. Assembling
/// diagnostics must never hang the very UI the user reached for when
/// everything else is already broken.
const DIAGNOSTICS_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// The receipt the intake returns.
///
/// TS: `interface TonoDiagnosticsReceipt { referenceCode: string; receivedAt: number | null }`
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TonoDiagnosticsReceipt {
    pub reference_code: String,
    pub received_at: Option<i64>,
}

/// Assemble the whitelisted report (see `tono::diagnostics` for the privacy
/// contract). Shared by the preview command and the upload command so the
/// text the user is shown and the payload that is sent cannot drift.
async fn collect_diagnostics_report(
    state: &Arc<TonoState>,
    app: &AppHandle,
) -> crate::tono::diagnostics::DiagnosticsReport {
    // Probes first, with no product lock held: they talk to the Service.
    let protocol = tokio::time::timeout(DIAGNOSTICS_PROBE_TIMEOUT, clash_verge_service_ipc::get_version())
        .await
        .ok()
        .and_then(Result::ok)
        .filter(|response| response.code == 0)
        .and_then(|response| response.data);
    let dns = tokio::time::timeout(DIAGNOSTICS_PROBE_TIMEOUT, service::tono_protected_dns_status())
        .await
        .ok()
        .and_then(Result::ok);
    // sysinfo's adapter walk and OS query are blocking syscalls.
    let (os_version, adapters) = AsyncHandler::spawn_blocking(|| {
        (
            tauri_plugin_clash_verge_sysinfo::os_long_version(),
            tauri_plugin_clash_verge_sysinfo::list_network_interfaces(),
        )
    })
    .await
    .unwrap_or_else(|_| ("Unknown".to_string(), Vec::new()));

    let audit_log_path = state.audit().log_path().to_path_buf();
    let service_log_path = crate::tono::diagnostics::service_log_path();
    let home = crate::tono::diagnostics::home_dir();
    let app_version = app.package_info().version.to_string();

    let inner = state.lock().await;
    let status = inner.fsm.status();
    let current_elapsed_ms = inner
        .step_started_at
        .map(|started| started.elapsed().as_millis() as u64);
    let steps = crate::tono::steps::snapshot_with_current_elapsed(&inner.connect_steps, current_elapsed_ms);
    let revision = inner.catalog_tracker.current_revision();
    // The live secret values, handed to the scrubber to be *subtracted* from
    // free text (never emitted). Structural rules cover what is not here.
    let mut known_secrets: Vec<String> = Vec::new();
    if let Some(secret) = &inner.controller_secret {
        known_secrets.push(secret.clone());
    }
    for node in &inner.nodes {
        known_secrets.push(node.uuid.clone());
        known_secrets.push(node.reality_public_key.clone());
        known_secrets.push(node.reality_short_id.clone());
        known_secrets.push(node.server.to_string());
    }
    if let Ok(Some(token)) = inner.credentials.refresh_token() {
        known_secrets.push(token);
    }
    crate::tono::diagnostics::build_report(&crate::tono::diagnostics::DiagnosticsSources {
        app_version: &app_version,
        os_version: &os_version,
        os_arch: std::env::consts::ARCH,
        service_protocol: protocol.as_ref(),
        ui_state: ui_state_key(status.ui_state()),
        account_state: inner.account_state.key(),
        selected_server: inner.selected_node.as_deref(),
        catalog_revision: (revision >= 0).then_some(revision),
        kill_switch: inner.kill_switch.as_ref(),
        dns: dns.as_ref(),
        failed_stage: inner.failed_stage,
        connect_error: inner.connect_error.as_deref(),
        retry_attempt: inner.retry_attempt,
        steps: &steps,
        adapter_names: &adapters,
        known_secrets: &known_secrets,
        audit_log_path: &audit_log_path,
        service_log_path: &service_log_path,
        home_dir: home.as_deref(),
        reported_at_ms: epoch_millis(),
    })
}

/// The exact payload an upload would send, for the "what will be sent"
/// disclosure and for Copy details. Purely local — nothing leaves the
/// machine on this command.
///
/// TS: see `TonoDiagnosticsReport` in `services/tono.ts`; the field list is
/// `tono_core::auth::DiagnosticsReport`.
#[tauri::command]
pub async fn tono_diagnostics_report(
    state: tauri::State<'_, Arc<TonoState>>,
    app: AppHandle,
) -> Result<crate::tono::diagnostics::DiagnosticsReport, String> {
    Ok(collect_diagnostics_report(state.inner(), &app).await)
}

/// Upload one diagnostics report and return its support reference code.
///
/// **User-initiated only.** This is the sole upload path and it exists
/// behind an explicit confirmation in the UI; nothing in the app calls it on
/// a timer, on a crash, or on a failed connect.
///
/// The report is rebuilt here rather than accepted from the WebView: the
/// whitelist has to be enforced where the payload is constructed, or a
/// compromised renderer could post whatever it liked to the account's
/// diagnostics stream.
#[tauri::command]
pub async fn tono_upload_diagnostics(
    state: tauri::State<'_, Arc<TonoState>>,
    app: AppHandle,
) -> Result<TonoDiagnosticsReceipt, String> {
    let client = {
        let inner = state.lock().await;
        inner.client.clone()
    };
    let report = collect_diagnostics_report(state.inner(), &app).await;
    match client.upload_diagnostics_report(&report).await {
        Ok(receipt) => {
            state.audit().log(AuditEvent::DiagnosticsUploaded {
                reference: receipt.reference_code.clone(),
            });
            Ok(TonoDiagnosticsReceipt {
                reference_code: receipt.reference_code,
                received_at: receipt.received_at,
            })
        }
        Err(err) => {
            let message = diagnostics_upload_error(&err);
            state
                .audit()
                .log(AuditEvent::DiagnosticsUploadFail { error: err.to_string() });
            Err(message)
        }
    }
}

/// Classify an upload failure into a stable `TONO_DIAG_*` prefix the
/// frontend turns into actionable text (the same convention the connect
/// errors use, see `STABLE_ERROR_KEYS` in `services/tono.ts`).
fn diagnostics_upload_error(err: &ApiError) -> String {
    let prefix = match err {
        ApiError::Unauthorized => "TONO_DIAG_SIGNED_OUT",
        ApiError::RateLimited => "TONO_DIAG_RATE_LIMITED",
        ApiError::Transport { .. } => "TONO_DIAG_UNREACHABLE",
        // The intake is not deployed (or was withdrawn) — distinct from a
        // server fault, and there is nothing the user can do but copy the
        // details instead.
        ApiError::NotFound => "TONO_DIAG_UNAVAILABLE",
        _ => "TONO_DIAG_FAILED",
    };
    format!("{prefix}: {err}")
}

/// Explicit Quit/restart release (§6, L1): bump the generation, abort every task, then join the
/// single-flight explicit-release sequence. A preventable interactive exit is cancelled when
/// release cannot be proven; the unpreventable WM_ENDSESSION path applies its own short outer
/// budget in the run-event handler.
pub async fn quit_release(app: AppHandle) -> Result<(), String> {
    let Some(state) = app.try_state::<Arc<TonoState>>().map(|state| state.inner().clone()) else {
        return Ok(());
    };
    let protected = {
        let mut inner = state.lock().await;
        inner.invalidate_connection(true);
        inner.tasks.abort_catalog_sync();
        inner.fsm.kill_switch_armed()
            || inner.fsm.status().is_connected
            || inner.fsm.status().is_connecting
            || inner.fsm.status().is_protection_blocked
    };
    if protected {
        connection::release_explicit(&state, &app).await
    } else {
        Ok(())
    }
}

/// M3: exit is *committed* (RunEvent::Exit) — close the audit channel so
/// the writer drains, then wait for it (bounded). Kept strictly apart from
/// `quit_release`: a cancelled quit must not kill the audit trail.
pub async fn flush_audit_for_exit(app: &AppHandle) {
    let Some(state) = app.try_state::<Arc<TonoState>>().map(|state| state.inner().clone()) else {
        return;
    };
    state.audit().close_sender();
    if let Some(writer) = state.audit().take_writer() {
        let _ = tokio::time::timeout(AUDIT_FLUSH_BUDGET, writer).await;
    }
}

/// M3: the quit path was cancelled after `quit_release` already ran — the
/// barrier may really be gone while the FSM still claims protection.
/// Re-sync from the Service so the UI shows the truth.
pub async fn resync_after_cancelled_quit(app: AppHandle) {
    let Some(state) = app.try_state::<Arc<TonoState>>().map(|state| state.inner().clone()) else {
        return;
    };
    let kill_switch = service::tono_service_status_snapshot()
        .await
        .ok()
        .and_then(|snapshot| snapshot.kill_switch);
    let mut inner = state.lock().await;
    match kill_switch {
        Some(status) if status.wanted => {
            inner.cancel_server_tests();
            // Still armed (the release failed or never ran): reflect it.
            if status.verified {
                inner.fsm.mark_session_verified();
            }
            if !inner.fsm.kill_switch_armed() {
                inner.fsm.mark_kill_switch_armed();
            }
            inner.kill_switch = Some(status);
        }
        Some(_) => {
            // Verifiably disarmed: converge the FSM to released.
            inner.kill_switch = None;
            if inner.fsm.kill_switch_armed()
                || inner.fsm.status().is_connected
                || inner.fsm.status().is_protection_blocked
            {
                inner.fsm.sign_out_or_quit();
            }
        }
        None => {
            // No WFP answer (other platform or IPC down): keep the local
            // view and just re-emit below.
        }
    }
    emit_status(&app, &status_of(&inner));
}

#[cfg(test)]
mod tests {
    use super::{TokenProbe, stage_key, test_server_endpoint, token_probe, ui_state_key, unknown_protection_message};
    use tono_core::connection::{ConnectStage, UiState};

    #[test]
    fn stage_keys_cover_all_stages_in_order() {
        let keys: Vec<&str> = ConnectStage::ALL.iter().map(|stage| stage_key(*stage)).collect();
        assert_eq!(
            keys,
            [
                "preparing",
                "preparingService",
                "startingKillSwitch",
                "startingTunnel",
                "lockingTraffic",
                "applyingCloudPolicy",
                "securingDNS",
                "checkingExit",
                "verifyingTraffic",
            ]
        );
    }

    #[test]
    fn ui_state_keys_are_stable() {
        assert_eq!(ui_state_key(UiState::NotConnected), "notConnected");
        assert_eq!(ui_state_key(UiState::Connecting(ConnectStage::Preparing)), "connecting");
        assert_eq!(ui_state_key(UiState::Connected), "connected");
        assert_eq!(ui_state_key(UiState::ProtectedOffline), "protectedOffline");
        assert_eq!(ui_state_key(UiState::Disconnecting), "disconnecting");
    }

    #[test]
    fn an_unreadable_protection_state_is_reported_as_unknown_with_a_way_out() {
        let message = unknown_protection_message("pipe not found");
        // It must not read as "not protected", and it must carry both the cause and the
        // elevated command that restores connectivity if the app cannot release it.
        assert!(message.contains("unknown"), "{message}");
        assert!(message.contains("pipe not found"), "{message}");
        assert!(message.contains("emergency-disarm"), "{message}");
    }

    #[test]
    fn token_probe_decision_order() {
        let error = "keychain locked".to_string();
        let token = "rt-1".to_string();
        // A vault error wins over everything — it is the M1 error state,
        // never a mistaken signed-out.
        assert_eq!(token_probe(Some(&error), Some(&token)), TokenProbe::StoreError);
        assert_eq!(token_probe(Some(&error), None), TokenProbe::StoreError);
        assert_eq!(token_probe(None, Some(&token)), TokenProbe::HasToken);
        assert_eq!(token_probe(None, None), TokenProbe::NoToken);
    }

    #[tokio::test]
    async fn server_endpoint_test_reports_a_real_tcp_handshake() {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });

        let result = test_server_endpoint(
            "US Test".to_string(),
            address,
            tokio_util::sync::CancellationToken::new(),
        )
        .await;

        assert_eq!(result.name, "US Test");
        assert!(result.latency_ms.is_some());
        assert!(result.error.is_none());
        accept.await.unwrap();
    }

    #[tokio::test]
    async fn server_endpoint_test_honors_cancellation() {
        let cancellation = tokio_util::sync::CancellationToken::new();
        cancellation.cancel();
        let result = test_server_endpoint("JP Test".to_string(), "192.0.2.1:443".parse().unwrap(), cancellation).await;

        assert_eq!(result.latency_ms, None);
        assert_eq!(result.error.as_deref(), Some("cancelled"));
    }
}
