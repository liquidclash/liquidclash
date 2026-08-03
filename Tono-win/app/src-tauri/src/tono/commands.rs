//! Tauri commands for the Tono product layer. All errors are plain strings
//! for the frontend; status changes are pushed via the `tono://status`
//! event (Tauri Emitter).

use std::sync::Arc;

use arc_swap::ArcSwapOption;
use clash_verge_logging::{Type, logging};
use clash_verge_service_ipc::KillSwitchStatus;
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
/// TS: `interface TonoStatus { accountState: string; uiState: string; stage: string | null; stageLabel: string | null; selectedServer: string | null; protectionBlocked: boolean; killSwitch: KillSwitchStatus | null; catalogRevision: number | null; catalogRequiresChoice: boolean }`
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
}

/// Last published immutable UI snapshot. The status command reads this without joining the large
/// product-state mutex, so a slow credential-store or transition commit cannot make the WebView
/// lose all progress/diagnostics. Writers still publish only fully assembled states.
static STATUS_SNAPSHOT: Lazy<ArcSwapOption<TonoStatus>> = Lazy::new(ArcSwapOption::empty);

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

/// TS: `interface TonoServer { name: string; server: string; port: number; selected: boolean }`
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TonoServer {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub selected: bool,
}

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
    }
}

pub(crate) fn emit_status(app: &AppHandle, status: &TonoStatus) {
    STATUS_SNAPSHOT.store(Some(Arc::new(status.clone())));
    if let Err(err) = app.emit("tono://status", status) {
        logging!(warn, Type::Service, "Tono: 状态事件发送失败: {err}");
    }
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
    if let Ok((refresh, id)) = outcome {
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
    }
    // Timeout (or a completed load): either way the gate opens — "no
    // credentials" semantics, never a stalled startup.
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
                })
        })
        .collect())
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
    let (action, generation) = {
        let mut inner = state.lock().await;
        if !inner.nodes.iter().any(|node| node.name == name) {
            return Err("unknown server".to_string());
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
        drop(inner);
        if cleared_choice {
            state.audit().log(AuditEvent::RequiresChoiceCleared);
        }
        if action == connection::SelectAction::Switch
            && let Some(from) = previous
        {
            state.audit().log(AuditEvent::NodeSwitch { from, to: name.clone() });
        }
        (action, generation)
    };

    match action {
        connection::SelectAction::Switch => {
            let task_state = state.inner().clone();
            let handle = AsyncHandler::spawn(move || async move {
                connection::switch_selected_node(task_state, app, generation).await;
            });
            let mut inner = state.lock().await;
            inner.tasks.switch = Some(handle);
        }
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
    if let Some(status) = STATUS_SNAPSHOT.load_full() {
        return Ok((*status).clone());
    }
    let inner = state.lock().await;
    Ok(status_of(&inner))
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

    let wanted_kill_switch = tokio::time::timeout_at(restore_deadline, service::tono_service_status_snapshot())
        .await
        .ok()
        .and_then(Result::ok)
        .and_then(|snapshot| snapshot.kill_switch)
        .filter(|status| status.wanted);

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
            if let Some(status) = wanted_kill_switch {
                if status.verified {
                    inner.fsm.mark_session_verified();
                }
                inner.kill_switch = Some(status);
                inner.fsm.mark_kill_switch_armed();
            }
            let detail = inner
                .credential_error
                .clone()
                .unwrap_or_else(|| "unknown credential error".to_string());
            inner.account_state = AccountState::Error(format!("credential store unreadable: {detail}"));
            emit_status(&app, &status_of(&inner));
            return;
        }
        TokenProbe::NoToken => {
            if let Some(status) = wanted_kill_switch {
                {
                    let mut inner = state.lock().await;
                    if inner.sign_in_generation != generation {
                        return;
                    }
                    if status.verified {
                        inner.fsm.mark_session_verified();
                    }
                    inner.kill_switch = Some(status);
                    inner.fsm.mark_kill_switch_armed();
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
            if let Some(status) = wanted_kill_switch {
                if status.verified {
                    inner.fsm.mark_session_verified();
                }
                inner.kill_switch = Some(status);
                inner.fsm.mark_kill_switch_armed();
            }
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
                if let Some(status) = wanted_kill_switch {
                    if status.verified {
                        inner.fsm.mark_session_verified();
                    }
                    inner.kill_switch = Some(status);
                    inner.fsm.mark_kill_switch_armed();
                }
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
            if let Some(status) = wanted_kill_switch {
                if status.verified {
                    inner.fsm.mark_session_verified();
                }
                inner.kill_switch = Some(status);
                inner.fsm.mark_kill_switch_armed();
            }
            inner.account_state = AccountState::Error(err.to_string());
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
    use super::{TokenProbe, stage_key, token_probe, ui_state_key};
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
}
