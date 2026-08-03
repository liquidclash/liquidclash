//! Tono account API: wire models and client logic (product-contract.md §1/§2).
//!
//! The crate ships no HTTP stack: [`HttpTransport`] abstracts request →
//! response so the Windows app can plug in its own client (which must then
//! enforce §1's transport rules: https/443 only, no redirects, no cookies,
//! 2 MiB response cap, 30 s connect / 45 s total timeouts). Everything
//! above the wire — Bearer handling, 401 → refresh once + retry, refresh
//! coalescing, error-envelope mapping, and the bounded mainland-link
//! transport retry — lives here.

use async_trait::async_trait;
use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use uuid::Uuid;

use crate::catalog::ExitCatalogResponse;
use crate::credentials::{CredentialError, CredentialStore};

pub const DEFAULT_BASE_URL: &str = "https://api.afk.ccwu.cc";
pub const API_PREFIX: &str = "api/v1/";
pub const DEFAULT_DEVICE_NAME: &str = "Windows PC";
/// Default device allowance; the server may override per user (§2).
pub const DEFAULT_DEVICE_LIMIT: u32 = 2;

/// Endpoint paths relative to `/api/v1/` (§1).
pub mod endpoints {
    pub const AUTH_METHODS: &str = "auth/methods";
    pub const EMAIL_START: &str = "auth/email/start";
    pub const EMAIL_VERIFY: &str = "auth/email/verify";
    pub const REFRESH: &str = "auth/refresh";
    pub const LOGOUT: &str = "auth/logout";
    pub const ME: &str = "me";
    pub const DEVICES: &str = "devices";
    pub const EXIT_CATALOG: &str = "exit-catalog";
    pub const TRAFFIC_POLICY: &str = "traffic-policy";
    /// User-initiated diagnostics upload (never automatic; see
    /// [`super::DiagnosticsReport`]).
    pub const DIAGNOSTICS_REPORTS: &str = "diagnostics/reports";
    pub fn device(id: &str) -> String {
        format!("devices/{id}")
    }
}

/// Coarse classification of a control-plane transport failure, driving the
/// bounded retry policy (§1). The retryable kinds are exactly the ones
/// where the request provably never reached the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// Name resolution failed (provably never delivered).
    Dns,
    /// TCP connect failed. The reqwest classifier maps its `is_connect()`
    /// here, covering DNS resolution *and* TCP connect — no finer split is
    /// available, and in either phase HTTP bytes provably never went out.
    Connect,
    /// TLS handshake/validation failed (bytes may have flowed; never retry).
    Tls,
    /// Any timeout (may have been delivered; POSTs must never retry it).
    Timeout,
    /// Anything else.
    Other,
}

/// The bounded retry policy for the mainland link (§1): one retry per
/// logical request, only when the request provably never reached the
/// server. GET/HEAD retry on any transport kind (idempotent reads); POST
/// and DELETE retry only on Dns/Connect — a timeout or TLS failure may
/// already have delivered the bytes, and codes/tokens must never be sent
/// twice. Status responses (4xx/5xx), parse failures, and InvalidResponse
/// never reach this predicate.
pub fn should_retry_transport(method: HttpMethod, kind: TransportKind) -> bool {
    match method {
        HttpMethod::Get => true,
        HttpMethod::Post | HttpMethod::Delete => {
            matches!(kind, TransportKind::Dns | TransportKind::Connect)
        }
    }
}

/// Interval between a failed attempt and its single retry (500 ms; there
/// is no `waitsForConnectivity` equivalent — this partially covers it).
pub const TRANSPORT_RETRY_DELAY: Duration = Duration::from_millis(500);

/// Parity with the macOS `TonoAPIClient.APIError`, plus `InvalidInput` for
/// client-side validation and `Credentials` for store failures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ApiError {
    #[error("Tono service is not configured.")]
    InvalidConfiguration,
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("could not reach Tono: {message}")]
    Transport { kind: TransportKind, message: String },
    #[error("your session has expired; please sign in again")]
    Unauthorized,
    #[error("this account does not have permission for that action")]
    Forbidden,
    #[error("the requested item no longer exists")]
    NotFound,
    #[error("this Tono account has reached its device allowance; revoke another device first")]
    DeviceLimit,
    /// HTTP 429. Distinct from the generic `Server` bucket so a caller can
    /// say "wait and try again" instead of "something broke" — the
    /// diagnostics upload is the first endpoint the server rate-limits.
    #[error("too many requests; please wait and try again")]
    RateLimited,
    #[error("server error {status}: {message}")]
    Server { status: u16, message: String },
    #[error("Tono returned an invalid response")]
    InvalidResponse,
    #[error("credential store failed: {0}")]
    Credentials(String),
}

impl From<CredentialError> for ApiError {
    fn from(err: CredentialError) -> Self {
        ApiError::Credentials(err.to_string())
    }
}

// ---- Account rules (§2, parity with TonoAccountRules.swift) ----

/// Trim + lowercase.
pub fn normalize_email(raw: &str) -> String {
    raw.trim().to_lowercase()
}

/// Exactly one `@`, non-empty local part, a dot in the domain.
pub fn is_valid_email(raw: &str) -> bool {
    let normalized = normalize_email(raw);
    let parts: Vec<&str> = normalized.split('@').collect();
    parts.len() == 2 && !parts[0].is_empty() && parts[1].contains('.')
}

/// Trim; empty becomes the platform default; capped at 80 chars.
pub fn normalize_device_name(raw: &str) -> String {
    let trimmed = raw.trim();
    let base = if trimmed.is_empty() { DEFAULT_DEVICE_NAME } else { trimmed };
    base.chars().take(80).collect()
}

/// Lowercase canonical UUID. Generated on first run, then persisted (§2).
pub fn new_installation_id() -> String {
    Uuid::new_v4().to_string()
}

/// Validate and canonicalize an installation id (lowercase hyphenated UUID).
pub fn normalize_installation_id(raw: &str) -> Result<String, ApiError> {
    let lowered = raw.trim().to_lowercase();
    Uuid::parse_str(&lowered)
        .map(|uuid| uuid.to_string())
        .map_err(|_| ApiError::InvalidInput("installation id must be a UUID".to_string()))
}

// ---- Wire models (§1/§2; optional fields tolerate additive server changes) ----

/// Display-only timestamp fields arrive as epoch seconds (number or numeric
/// string); ISO strings the core cannot parse without a datetime crate are
/// dropped instead of failing the whole decode.
fn de_opt_epoch<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(value.and_then(|value| match value {
        serde_json::Value::Number(number) => number
            .as_i64()
            .or_else(|| number.as_f64().map(|float| float as i64)),
        serde_json::Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct User {
    pub id: String,
    pub email: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub plan: Option<String>,
    #[serde(rename = "deviceLimit", default)]
    pub device_limit: Option<i64>,
    #[serde(rename = "quotaBytes", default)]
    pub quota_bytes: Option<i64>,
    #[serde(rename = "usageBytes", default)]
    pub usage_bytes: Option<i64>,
    #[serde(rename = "expiresAt", default, deserialize_with = "de_opt_epoch")]
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub suspended: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Device {
    pub id: String,
    pub name: String,
    #[serde(rename = "installationId", default)]
    pub installation_id: Option<String>,
    #[serde(rename = "createdAt", default, deserialize_with = "de_opt_epoch")]
    pub created_at: Option<i64>,
    #[serde(rename = "lastSeenAt", default, deserialize_with = "de_opt_epoch")]
    pub last_seen_at: Option<i64>,
    #[serde(rename = "confirmedAt", default, deserialize_with = "de_opt_epoch")]
    pub confirmed_at: Option<i64>,
    #[serde(default)]
    pub current: Option<bool>,
    #[serde(default)]
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenResponse {
    #[serde(rename = "accessToken")]
    pub access_token: String,
    #[serde(rename = "refreshToken")]
    pub refresh_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthResponse {
    #[serde(rename = "accessToken")]
    pub access_token: String,
    #[serde(rename = "refreshToken", default)]
    pub refresh_token: Option<String>,
    pub user: User,
    #[serde(default)]
    pub device: Option<Device>,
}

/// The worker may wrap auth payloads as `{auth: ...}`; accept both that
/// envelope and the legacy unwrapped response (parity with
/// `TonoAuthEnvelope`).
pub fn decode_auth_response(body: &[u8]) -> Result<AuthResponse, ApiError> {
    #[derive(Deserialize)]
    struct Envelope {
        auth: Option<AuthResponse>,
    }
    if let Ok(envelope) = serde_json::from_slice::<Envelope>(body) {
        if let Some(auth) = envelope.auth {
            return Ok(auth);
        }
    }
    serde_json::from_slice::<AuthResponse>(body).map_err(|_| ApiError::InvalidResponse)
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EmailStartRequest {
    pub email: String,
    #[serde(rename = "deviceName")]
    pub device_name: String,
    #[serde(rename = "installationId")]
    pub installation_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmailChallengeResponse {
    #[serde(rename = "challengeId")]
    pub challenge_id: String,
    #[serde(rename = "expiresIn")]
    pub expires_in: i64,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EmailVerifyRequest {
    #[serde(rename = "challengeId")]
    pub challenge_id: String,
    pub code: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RefreshRequest {
    #[serde(rename = "refreshToken")]
    pub refresh_token: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LogoutRequest {
    // The server treats an explicit JSON `null` as a validation error (400)
    // rather than an omitted field, so None must skip serialization entirely.
    #[serde(rename = "refreshToken", skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct MeResponse {
    pub user: User,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct DevicesResponse {
    pub devices: Vec<Device>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthMethod {
    pub enabled: bool,
    #[serde(rename = "clientId", default)]
    pub client_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthMethodsResponse {
    pub email: AuthMethod,
    pub apple: AuthMethod,
    pub google: AuthMethod,
}

// ---- Diagnostics upload (user-initiated only) ----
//
// THE ONE PLACE the diagnostics wire contract is spelled. If the server's
// intake disagrees, change it *here* — nothing else declares these names.
//
// `POST /api/v1/diagnostics/reports`, Bearer-authorized (the report is tied
// to the signed-in account; that is stated in the UI before the upload).
//
// Request body:
//
// ```json
// {"report": {
//   "schemaVersion": 1,                       // number
//   "reportedAtMs": 1712345678901,            // number, epoch ms, client clock
//   "appVersion": "0.0.3",                    // string
//   "osVersion": "Windows 11 Pro 23H2",       // string
//   "osArch": "x86_64",                       // string
//   "serviceProtocol": "1.14",                // string "epoch.revision" | null
//   "serviceBuild": "2.6.2",                  // string | null
//   "uiState": "protectedOffline",            // string
//   "accountState": "ready",                  // string
//   "selectedServer": "US West 1",            // string (catalog display name) | null
//   "catalogRevision": 12,                    // number | null
//   "killSwitchMode": "blocked",              // string | null
//   "killSwitchWanted": true,                 // bool | null
//   "killSwitchLive": false,                  // bool | null
//   "killSwitchLastError": "…",               // string | null (redacted)
//   "dnsEnabled": true,                       // bool | null
//   "dnsLastError": "…",                      // string | null (redacted)
//   "failedStage": "securingDNS",             // string | null
//   "error": "…",                             // string | null (redacted)
//   "retryAttempt": 2,                        // number
//   "totalElapsedMs": 4600,                   // number | null
//   "steps": [                                // array
//     {"key": "preparing", "state": "completed", "elapsedMs": 1200}
//   ],
//   "virtualAdapters": ["hyperV", "wsl"],     // array of fixed class strings
//   "auditLogPath": "%USERPROFILE%\\…\\traffic-audit.jsonl",     // string
//   "serviceLogPath": "C:\\ProgramData\\Tono\\logs\\tono-service.log" // string
// }}
// ```
//
// Response body: `{"referenceCode": "TON-4F2K-9QX1", "receivedAt": 1712345678}`
// — `receivedAt` is optional and display-only; `referenceCode` is required
// and non-empty (an empty one is an [`ApiError::InvalidResponse`]).
//
// PRIVACY: every field is enumerated below by hand. The struct is a
// whitelist, never a projection of product state — adding a field here is
// the only way to add a field to the upload, and the app-side builder
// (`tono::diagnostics`) has the tests that prove it.

/// One connect step as uploaded (mirrors the UI's step record minus its
/// localized label, which the server has no use for).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticsStep {
    pub key: String,
    /// "pending" | "current" | "completed" | "failed".
    pub state: String,
    pub elapsed_ms: Option<u64>,
}

/// The whitelisted diagnostics payload. See the module comment above for the
/// exact JSON. NOTHING may be added here without also being added to the
/// app-side allow-list test.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticsReport {
    pub schema_version: u32,
    pub reported_at_ms: i64,
    pub app_version: String,
    pub os_version: String,
    pub os_arch: String,
    pub service_protocol: Option<String>,
    pub service_build: Option<String>,
    pub ui_state: String,
    pub account_state: String,
    pub selected_server: Option<String>,
    pub catalog_revision: Option<i64>,
    pub kill_switch_mode: Option<String>,
    pub kill_switch_wanted: Option<bool>,
    pub kill_switch_live: Option<bool>,
    pub kill_switch_last_error: Option<String>,
    pub dns_enabled: Option<bool>,
    pub dns_last_error: Option<String>,
    pub failed_stage: Option<String>,
    pub error: Option<String>,
    pub retry_attempt: u32,
    pub total_elapsed_ms: Option<u64>,
    pub steps: Vec<DiagnosticsStep>,
    pub virtual_adapters: Vec<String>,
    pub audit_log_path: String,
    pub service_log_path: String,
}

/// The current [`DiagnosticsReport`] schema. Bump when a field is added or
/// its meaning changes, so the intake can tell payload generations apart.
pub const DIAGNOSTICS_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize)]
struct DiagnosticsReportRequest<'a> {
    report: &'a DiagnosticsReport,
}

/// The intake's answer: a short human-readable code the user reads out to
/// support.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticsReceipt {
    pub reference_code: String,
    #[serde(default, deserialize_with = "de_opt_epoch")]
    pub received_at: Option<i64>,
}

/// Server error envelope `{error:{message,code}}` (§1).
#[derive(Debug, Clone, Deserialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Debug, Clone, Deserialize)]
struct ErrorBody {
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    code: Option<String>,
}

// ---- Transport abstraction ----

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Delete,
}

/// One control-plane request, fully built (URL = base + `/api/v1/` + path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiRequest {
    pub method: HttpMethod,
    pub url: String,
    pub bearer: Option<String>,
    pub json_body: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// The platform HTTP stack. Implementations must enforce §1's transport
/// rules (https/443, no redirects, no cookies, 2 MiB cap, timeouts).
#[async_trait]
pub trait HttpTransport: Send + Sync {
    async fn send(&self, request: ApiRequest) -> Result<ApiResponse, ApiError>;
}

/// Lets an `Arc<T>` serve as the transport so tests can share a mock.
#[async_trait]
impl<T: HttpTransport + ?Sized> HttpTransport for Arc<T> {
    async fn send(&self, request: ApiRequest) -> Result<ApiResponse, ApiError> {
        (**self).send(request).await
    }
}

// ---- Client ----

#[derive(Debug, Default)]
struct AuthState {
    access_token: Option<String>,
    /// Bumped on every successful refresh so a waiter can tell a fresh
    /// token from the one its request failed with.
    epoch: u64,
}

/// Account API client (§1): Bearer injection, one refresh-and-retry on 401,
/// and refresh coalescing — concurrent refreshes share a single in-flight
/// request (parity with the macOS shared `refreshTask`).
pub struct ApiClient<T: HttpTransport, S: CredentialStore> {
    transport: T,
    credentials: Arc<S>,
    base_url: String,
    state: tokio::sync::Mutex<AuthState>,
    refresh_lock: tokio::sync::Mutex<()>,
}

impl<T: HttpTransport, S: CredentialStore> ApiClient<T, S> {
    pub fn new(base_url: &str, transport: T, credentials: Arc<S>) -> Result<Self, ApiError> {
        Ok(Self {
            transport,
            credentials,
            base_url: validate_base_url(base_url)?,
            state: tokio::sync::Mutex::new(AuthState::default()),
            refresh_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// Install tokens from a completed sign-in (§2). The refresh token, when
    /// present, is persisted; the access token lives in memory only.
    pub async fn adopt(&self, auth: &AuthResponse) -> Result<(), ApiError> {
        if let Some(refresh) = &auth.refresh_token {
            self.credentials.set_refresh_token(refresh)?;
        }
        let mut state = self.state.lock().await;
        state.access_token = Some(auth.access_token.clone());
        state.epoch += 1;
        Ok(())
    }

    pub async fn auth_methods(&self) -> Result<AuthMethodsResponse, ApiError> {
        let body = self.call(HttpMethod::Get, endpoints::AUTH_METHODS, None, None).await?;
        decode_json(&body)
    }

    /// `POST auth/email/start` with normalized account fields (§2).
    pub async fn start_email_sign_in(
        &self,
        email: &str,
        device_name: &str,
        installation_id: &str,
    ) -> Result<EmailChallengeResponse, ApiError> {
        let email = normalize_email(email);
        if !is_valid_email(&email) {
            return Err(ApiError::InvalidInput("invalid email address".to_string()));
        }
        let request = EmailStartRequest {
            email,
            device_name: normalize_device_name(device_name),
            installation_id: normalize_installation_id(installation_id)?,
        };
        let body = serde_json::to_string(&request).map_err(|_| ApiError::InvalidResponse)?;
        let response = self.call(HttpMethod::Post, endpoints::EMAIL_START, Some(body), None).await?;
        decode_json(&response)
    }

    /// `POST auth/email/verify`; tolerates the `{auth: ...}` envelope.
    pub async fn verify_email_sign_in(
        &self,
        challenge_id: &str,
        code: &str,
    ) -> Result<AuthResponse, ApiError> {
        let request = EmailVerifyRequest {
            challenge_id: challenge_id.to_string(),
            code: code.to_string(),
        };
        let body = serde_json::to_string(&request).map_err(|_| ApiError::InvalidResponse)?;
        let response = self.call(HttpMethod::Post, endpoints::EMAIL_VERIFY, Some(body), None).await?;
        decode_auth_response(&response)
    }

    pub async fn me(&self) -> Result<MeResponse, ApiError> {
        let body = self.authorized(HttpMethod::Get, endpoints::ME, None).await?;
        decode_json(&body)
    }

    pub async fn devices(&self) -> Result<DevicesResponse, ApiError> {
        let body = self.authorized(HttpMethod::Get, endpoints::DEVICES, None).await?;
        decode_json(&body)
    }

    pub async fn exit_catalog(&self) -> Result<ExitCatalogResponse, ApiError> {
        let body = self.authorized(HttpMethod::Get, endpoints::EXIT_CATALOG, None).await?;
        decode_json(&body)
    }

    /// `GET traffic-policy`: the cloud WeChat-DIRECT routing policy (digest
    /// + revision semantics identical to the exit catalog).
    pub async fn traffic_policy(&self) -> Result<crate::policy::TonoTrafficPolicyResponse, ApiError> {
        let body = self.authorized(HttpMethod::Get, endpoints::TRAFFIC_POLICY, None).await?;
        decode_json(&body)
    }

    /// `POST diagnostics/reports`: upload one user-initiated diagnostics
    /// report and return its support reference code.
    ///
    /// This call exists *only* on a path the user explicitly took. There is
    /// no automatic, scheduled, or crash-triggered caller, and adding one
    /// would break the product's stated privacy posture.
    ///
    /// It rides the ordinary authorized transport on purpose: while the kill
    /// switch has the machine blocked, the WFP bootstrap policy still permits
    /// the pinned API IPs on TCP/443, so this upload works in exactly the
    /// situation ("no other connectivity") that produces the reports worth
    /// having. As a POST it inherits the Dns/Connect-only transport retry —
    /// a timeout is never resent, so a delivered report cannot be duplicated.
    pub async fn upload_diagnostics_report(
        &self,
        report: &DiagnosticsReport,
    ) -> Result<DiagnosticsReceipt, ApiError> {
        let body = serde_json::to_string(&DiagnosticsReportRequest { report })
            .map_err(|_| ApiError::InvalidResponse)?;
        let response = self
            .authorized(HttpMethod::Post, endpoints::DIAGNOSTICS_REPORTS, Some(body))
            .await?;
        let receipt: DiagnosticsReceipt = decode_json(&response)?;
        // A receipt with no code is useless to the user: they would be told
        // to quote nothing. Treat it as a malformed response.
        if receipt.reference_code.trim().is_empty() {
            return Err(ApiError::InvalidResponse);
        }
        Ok(receipt)
    }

    /// `DELETE devices/{uuid}`. Any device except the current one may be
    /// revoked (§2); the current-device check is the caller's policy.
    pub async fn revoke_device(&self, id: &str) -> Result<(), ApiError> {
        Uuid::parse_str(id)
            .map_err(|_| ApiError::InvalidInput("device id must be a UUID".to_string()))?;
        self.authorized(HttpMethod::Delete, &endpoints::device(id), None).await?;
        Ok(())
    }

    /// Best-effort server logout, then local token wipe (§2).
    pub async fn logout(&self) {
        // Gate on "a session exists", not on "an access token is cached". A process that
        // never completed an authorized call — offline at startup, or a refresh that failed
        // on transport — holds a valid refresh token and no access token, and the old gate
        // wiped that token locally while leaving it live on the server. `authorized` refreshes
        // first when the access token is missing, and `refresh_access_token` fails without a
        // network call when the store is empty, so the never-signed-in case stays a no-op.
        let has_session = self.credentials.refresh_token().ok().flatten().is_some()
            || self.state.lock().await.access_token.is_some();
        if has_session {
            // Read the refresh token immediately before the POST: reaching the server may go
            // through a refresh that rotates it, which would put a stale value in the body.
            let body = serde_json::to_string(&LogoutRequest {
                refresh_token: self.credentials.refresh_token().ok().flatten(),
            })
            .ok();
            let _ = self.authorized(HttpMethod::Post, endpoints::LOGOUT, body).await;
        }
        // Wipe the persisted token while the state lock is held. Releasing it first left a
        // window in which a refresh that started after the epoch bump could read the token
        // back off disk and resurrect the session the user just ended.
        {
            let mut state = self.state.lock().await;
            state.access_token = None;
            // Invalidate any in-flight refresh so its stale result is
            // discarded instead of resurrecting the wiped session (L3).
            state.epoch += 1;
            let _ = self.credentials.delete_refresh_token();
        }
    }

    /// Send with the current access token; on 401 refresh once and retry
    /// once (§1).
    async fn authorized(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<String>,
    ) -> Result<Vec<u8>, ApiError> {
        let (token, epoch) = {
            let state = self.state.lock().await;
            match &state.access_token {
                Some(token) => (token.clone(), state.epoch),
                None => {
                    let epoch = state.epoch;
                    drop(state);
                    let token = self.refresh_access_token(epoch).await?;
                    let epoch = self.state.lock().await.epoch;
                    (token, epoch)
                }
            }
        };
        match self.call(method, path, body.clone(), Some(&token)).await {
            Err(ApiError::Unauthorized) => {
                // Drop the stale token only if nobody refreshed meanwhile.
                let mut state = self.state.lock().await;
                if state.epoch == epoch {
                    state.access_token = None;
                }
                drop(state);
                let renewed = self.refresh_access_token(epoch).await?;
                // No transport retry on the replay: the refresh just proved
                // connectivity, and the budget is one retry per logical request.
                self.send(method, path, body, Some(&renewed)).await
            }
            result => result,
        }
    }

    /// Concurrent refreshes coalesce: the first caller through
    /// `refresh_lock` performs the one in-flight refresh; waiters observe
    /// the bumped epoch and reuse its token instead of refreshing again.
    async fn refresh_access_token(&self, stale_epoch: u64) -> Result<String, ApiError> {
        let _permit = self.refresh_lock.lock().await;
        {
            let state = self.state.lock().await;
            if state.epoch != stale_epoch {
                if let Some(token) = &state.access_token {
                    return Ok(token.clone());
                }
            }
        }
        let refresh = self.credentials.refresh_token()?.ok_or(ApiError::Unauthorized)?;
        let body = serde_json::to_string(&RefreshRequest {
            refresh_token: refresh,
        })
        .map_err(|_| ApiError::InvalidResponse)?;
        let response = self.call(HttpMethod::Post, endpoints::REFRESH, Some(body), None).await?;
        let tokens: TokenResponse = decode_json(&response)?;
        // Commit critical section: adopt()/logout() may have installed a new
        // session while this request was in flight (both bump the epoch).
        // A stale result is discarded, never written over the new
        // session's tokens (L3).
        let mut state = self.state.lock().await;
        if state.epoch != stale_epoch {
            return state.access_token.clone().ok_or(ApiError::Unauthorized);
        }
        // Rotate before exposing the new access token: the stored refresh
        // token is replaced atomically by the store implementation (§2).
        self.credentials.set_refresh_token(&tokens.refresh_token)?;
        state.access_token = Some(tokens.access_token.clone());
        state.epoch += 1;
        Ok(tokens.access_token)
    }

    /// One logical API call: the request plus at most one transport
    /// retry (the mainland-link policy, §1). The retry fires only when the
    /// first attempt failed in a way that provably never reached the
    /// server (see [`should_retry_transport`]); a failed retry propagates
    /// the *original* error, which is the more useful signal.
    ///
    /// Interaction with the 401 replay (an independent mechanism): this
    /// budget is per logical request, so the worst case is first attempt
    /// → transport retry → 401 → refresh → replay — one transport retry
    /// plus one 401 replay, never more. The replay itself does not
    /// transport-retry: the refresh just proved connectivity. There is no
    /// `waitsForConnectivity` equivalent here — the fixed 500 ms interval
    /// partially covers that semantic and is documented as such.
    async fn call(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<String>,
        bearer: Option<&str>,
    ) -> Result<Vec<u8>, ApiError> {
        let first = self.send(method, path, body.clone(), bearer).await;
        match first {
            Err(err) if matches!(err, ApiError::Transport { kind, .. } if should_retry_transport(method, kind)) => {
                tokio::time::sleep(TRANSPORT_RETRY_DELAY).await;
                match self.send(method, path, body, bearer).await {
                    Ok(response) => Ok(response),
                    // Propagate the original error: it is the more useful
                    // signal than a second, possibly different, failure.
                    Err(_) => Err(err),
                }
            }
            result => result,
        }
    }

    async fn send(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<String>,
        bearer: Option<&str>,
    ) -> Result<Vec<u8>, ApiError> {
        let request = ApiRequest {
            method,
            url: format!("{}/{API_PREFIX}{path}", self.base_url),
            bearer: bearer.map(str::to_string),
            json_body: body,
        };
        map_status(self.transport.send(request).await?)
    }
}

fn decode_json<R: DeserializeOwned>(body: &[u8]) -> Result<R, ApiError> {
    // Empty 2xx bodies decode as `{}` (macOS parity).
    let bytes = if body.is_empty() { b"{}".as_slice() } else { body };
    serde_json::from_slice(bytes).map_err(|_| ApiError::InvalidResponse)
}

fn map_status(response: ApiResponse) -> Result<Vec<u8>, ApiError> {
    if (200..300).contains(&response.status) {
        return Ok(response.body);
    }
    let envelope = serde_json::from_slice::<ErrorEnvelope>(&response.body).ok();
    let code = envelope.as_ref().and_then(|env| env.error.code.clone());
    let message = envelope.and_then(|env| env.error.message);
    match response.status {
        401 => Err(ApiError::Unauthorized),
        403 => Err(ApiError::Forbidden),
        404 => Err(ApiError::NotFound),
        409 if code.as_deref() == Some("DEVICE_LIMIT") => Err(ApiError::DeviceLimit),
        429 => Err(ApiError::RateLimited),
        status => Err(ApiError::Server {
            status,
            message: message.unwrap_or_else(|| format!("Tono request failed ({status}).")),
        }),
    }
}

/// §1 origin rules: https only, port 443 only, no userinfo, query, or path.
/// Debug builds additionally allow `http` to loopback hosts for local
/// development (parity with the macOS `#if DEBUG` allowance).
fn validate_base_url(raw: &str) -> Result<String, ApiError> {
    let invalid = || ApiError::InvalidConfiguration;
    let (scheme, rest) = raw.split_once("://").ok_or_else(invalid)?;
    let is_https = scheme.eq_ignore_ascii_case("https");
    let is_http = scheme.eq_ignore_ascii_case("http");
    if (!is_https && !is_http) || rest.is_empty() || rest.contains(['@', '?', '#']) {
        return Err(invalid());
    }
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    if authority.is_empty() || !path.is_empty() {
        return Err(invalid());
    }
    // Authority must be printable ASCII; spaces, controls, and non-ASCII
    // bytes would otherwise reach the transport (L4).
    if !authority.bytes().all(|byte| (0x21..=0x7E).contains(&byte)) {
        return Err(invalid());
    }
    let (host, port): (&str, Option<u16>) = if let Some(stripped) = authority.strip_prefix('[') {
        let end = stripped.find(']').ok_or_else(invalid)?;
        let tail = &stripped[end + 1..];
        let port = match tail.strip_prefix(':') {
            Some(text) => Some(text.parse().map_err(|_| invalid())?),
            None if tail.is_empty() => None,
            None => return Err(invalid()),
        };
        (&stripped[..end], port)
    } else if authority.matches(':').count() > 1 {
        return Err(invalid());
    } else {
        match authority.rsplit_once(':') {
            Some((host, text)) => (host, Some(text.parse().map_err(|_| invalid())?)),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return Err(invalid());
    }
    if is_https && port.is_some_and(|port| port != 443) {
        return Err(invalid());
    }
    if is_http {
        let loopback = matches!(host.to_ascii_lowercase().as_str(), "localhost" | "127.0.0.1" | "::1");
        if !(cfg!(debug_assertions) && loopback) {
            return Err(invalid());
        }
    }
    Ok(format!("{}://{}", scheme.to_ascii_lowercase(), authority))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::MemoryCredentialStore;
    use std::sync::Mutex;

    // ---- mock transport ----

    type Handler = Box<dyn FnMut(&ApiRequest) -> Result<ApiResponse, ApiError> + Send>;

    struct MockTransport {
        requests: Mutex<Vec<ApiRequest>>,
        handler: Mutex<Handler>,
    }

    impl MockTransport {
        fn new(
            handler: impl FnMut(&ApiRequest) -> Result<ApiResponse, ApiError> + Send + 'static,
        ) -> Arc<Self> {
            Arc::new(Self {
                requests: Mutex::new(Vec::new()),
                handler: Mutex::new(Box::new(handler)),
            })
        }

        fn count_to(&self, suffix: &str) -> usize {
            self.requests
                .lock()
                .unwrap()
                .iter()
                .filter(|request| request.url.ends_with(suffix))
                .count()
        }

        fn requests(&self) -> Vec<ApiRequest> {
            self.requests.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl HttpTransport for MockTransport {
        async fn send(&self, request: ApiRequest) -> Result<ApiResponse, ApiError> {
            self.requests.lock().unwrap().push(request.clone());
            (self.handler.lock().unwrap())(&request)
        }
    }

    fn json(status: u16, body: &str) -> Result<ApiResponse, ApiError> {
        Ok(ApiResponse {
            status,
            body: body.as_bytes().to_vec(),
        })
    }

    fn user_json() -> &'static str {
        r#"{"id":"u1","email":"user@example.com","deviceLimit":2,"suspended":false}"#
    }

    fn test_client(
        handler: impl FnMut(&ApiRequest) -> Result<ApiResponse, ApiError> + Send + 'static,
    ) -> (
        ApiClient<Arc<MockTransport>, MemoryCredentialStore>,
        Arc<MockTransport>,
        Arc<MemoryCredentialStore>,
    ) {
        let store = Arc::new(MemoryCredentialStore::new());
        let mock = MockTransport::new(handler);
        let client = ApiClient::new(DEFAULT_BASE_URL, mock.clone(), store.clone()).unwrap();
        (client, mock, store)
    }

    fn auth_response(access: &str, refresh: Option<&str>) -> AuthResponse {
        AuthResponse {
            access_token: access.to_string(),
            refresh_token: refresh.map(str::to_string),
            user: serde_json::from_str(user_json()).unwrap(),
            device: None,
        }
    }

    // ---- account rules ----

    #[test]
    fn email_normalization_and_validation() {
        assert_eq!(normalize_email("  User@Example.COM \n"), "user@example.com");
        assert!(is_valid_email("  a@b.co "));
        assert!(!is_valid_email("no-at-sign"));
        assert!(!is_valid_email("@domain.com"));
        assert!(!is_valid_email("a@nodot"));
        assert!(!is_valid_email("a@b@c.com"));
        assert!(!is_valid_email(""));
    }

    #[test]
    fn device_name_normalization() {
        assert_eq!(normalize_device_name("  My PC  "), "My PC");
        assert_eq!(normalize_device_name("   "), DEFAULT_DEVICE_NAME);
        assert_eq!(normalize_device_name(""), DEFAULT_DEVICE_NAME);
        let long = "x".repeat(100);
        assert_eq!(normalize_device_name(&long).chars().count(), 80);
        // Multibyte characters count as chars, never split a codepoint.
        let wide = "界".repeat(100);
        assert_eq!(normalize_device_name(&wide), "界".repeat(80));
    }

    #[test]
    fn installation_id_rules() {
        let id = new_installation_id();
        assert_eq!(id, id.to_lowercase());
        assert_eq!(normalize_installation_id(&id.to_uppercase()).unwrap(), id);
        assert_eq!(
            normalize_installation_id(&id).unwrap(),
            Uuid::parse_str(&id).unwrap().to_string()
        );
        assert!(matches!(
            normalize_installation_id("not-a-uuid"),
            Err(ApiError::InvalidInput(_))
        ));
    }

    // ---- base url validation ----

    #[test]
    fn base_url_origin_rules() {
        assert_eq!(
            validate_base_url(DEFAULT_BASE_URL).unwrap(),
            "https://api.afk.ccwu.cc"
        );
        assert_eq!(
            validate_base_url("https://api.afk.ccwu.cc/").unwrap(),
            "https://api.afk.ccwu.cc"
        );
        assert_eq!(
            validate_base_url("https://api.afk.ccwu.cc:443").unwrap(),
            "https://api.afk.ccwu.cc:443"
        );
        for bad in [
            "http://api.afk.ccwu.cc",            // release: https only
            "https://api.afk.ccwu.cc:444",       // 443 only
            "https://user@api.afk.ccwu.cc",      // no userinfo
            "https://api.afk.ccwu.cc/path",      // no path
            "https://api.afk.ccwu.cc?q=1",       // no query
            "https://api.afk.ccwu.cc/#frag",     // no fragment
            "api.afk.ccwu.cc",                   // scheme required
            "https://",                          // host required
        ] {
            assert_eq!(validate_base_url(bad), Err(ApiError::InvalidConfiguration), "{bad}");
        }
        // Debug builds allow loopback http for development.
        if cfg!(debug_assertions) {
            assert!(validate_base_url("http://127.0.0.1:8787").is_ok());
            assert!(validate_base_url("http://localhost").is_ok());
            assert!(validate_base_url("http://[::1]:8787").is_ok());
        }
        assert!(matches!(
            ApiClient::new(
                "http://evil.example.com",
                MockTransport::new(|_| unreachable!()),
                Arc::new(MemoryCredentialStore::new())
            ),
            Err(ApiError::InvalidConfiguration)
        ));
    }

    // ---- envelope & models ----

    #[test]
    fn auth_response_decodes_wrapped_and_unwrapped() {
        let user = user_json();
        let wrapped = format!(r#"{{"auth":{{"accessToken":"a1","refreshToken":"r1","user":{user}}}}}"#);
        let auth = decode_auth_response(wrapped.as_bytes()).unwrap();
        assert_eq!(auth.access_token, "a1");
        assert_eq!(auth.refresh_token.as_deref(), Some("r1"));

        let plain = format!(r#"{{"accessToken":"a2","user":{user}}}"#);
        let auth = decode_auth_response(plain.as_bytes()).unwrap();
        assert_eq!(auth.access_token, "a2");
        assert_eq!(auth.refresh_token, None);

        assert_eq!(
            decode_auth_response(b"{\"nope\":true}").unwrap_err(),
            ApiError::InvalidResponse
        );
    }

    #[test]
    fn user_model_tolerates_additive_and_partial_payloads() {
        let user: User = serde_json::from_str(
            r#"{"id":"u","email":"e@x.co","futureField":{"nested":1},"expiresAt":1700000000}"#,
        )
        .unwrap();
        assert_eq!(user.expires_at, Some(1_700_000_000));
        assert_eq!(user.device_limit, None);
        // Suspended accounts may be partially populated.
        let user: User = serde_json::from_str(r#"{"id":"u","email":"e@x.co","suspended":true}"#).unwrap();
        assert_eq!(user.suspended, Some(true));
        // Numeric-string and ISO-string timestamps degrade gracefully.
        let user: User =
            serde_json::from_str(r#"{"id":"u","email":"e@x.co","expiresAt":"1700000000"}"#).unwrap();
        assert_eq!(user.expires_at, Some(1_700_000_000));
        let user: User =
            serde_json::from_str(r#"{"id":"u","email":"e@x.co","expiresAt":"2026-01-01T00:00:00Z"}"#)
                .unwrap();
        assert_eq!(user.expires_at, None);
    }

    // ---- client behavior ----

    #[tokio::test]
    async fn email_start_sends_normalized_body() {
        let (client, mock, _store) = test_client(|request| {
            assert!(request.url.ends_with("api/v1/auth/email/start"));
            let body: serde_json::Value =
                serde_json::from_str(request.json_body.as_deref().unwrap()).unwrap();
            assert_eq!(body["email"], "user@example.com");
            assert_eq!(body["deviceName"], "Windows PC");
            assert_eq!(body["installationId"], "2f5b1f2a-0000-4c81-8d2b-3f2d0a1b2c3d");
            json(200, r#"{"challengeId":"c1","expiresIn":600,"message":"sent"}"#)
        });
        let challenge = client
            .start_email_sign_in("  User@Example.COM ", "  ", "2F5B1F2A-0000-4C81-8D2B-3F2D0A1B2C3D")
            .await
            .unwrap();
        assert_eq!(challenge.challenge_id, "c1");
        assert_eq!(mock.count_to("auth/email/start"), 1);
    }

    #[tokio::test]
    async fn email_start_rejects_invalid_email_client_side() {
        let (client, mock, _store) = test_client(|_| unreachable!());
        assert!(matches!(
            client.start_email_sign_in("nope", "pc", &new_installation_id()).await,
            Err(ApiError::InvalidInput(_))
        ));
        assert!(mock.requests().is_empty());
    }

    #[tokio::test]
    async fn verify_unwraps_auth_envelope() {
        let (client, _mock, _store) = test_client(|_| {
            json(
                200,
                r#"{"auth":{"accessToken":"a1","refreshToken":"r1","user":{"id":"u","email":"e@x.co"}}}"#,
            )
        });
        let auth = client.verify_email_sign_in("c1", "123456").await.unwrap();
        assert_eq!(auth.access_token, "a1");
    }

    #[tokio::test]
    async fn refresh_rotates_tokens_and_stores_new_refresh() {
        let (client, mock, store) = test_client(|request| {
            if request.url.ends_with("auth/refresh") {
                let body: serde_json::Value =
                    serde_json::from_str(request.json_body.as_deref().unwrap()).unwrap();
                assert_eq!(body["refreshToken"], "refresh-1");
                return json(200, r#"{"accessToken":"access-2","refreshToken":"refresh-2"}"#);
            }
            assert_eq!(request.bearer.as_deref(), Some("access-2"));
            json(200, r#"{"user":{"id":"u","email":"e@x.co"}}"#)
        });
        store.set_refresh_token("refresh-1").unwrap();
        let me = client.me().await.unwrap();
        assert_eq!(me.user.id, "u");
        assert_eq!(store.refresh_token().unwrap().as_deref(), Some("refresh-2"));
        assert_eq!(mock.count_to("auth/refresh"), 1);
        // The next authorized call uses the held access token directly.
        client.me().await.unwrap();
        assert_eq!(mock.count_to("auth/refresh"), 1);
        assert_eq!(mock.count_to("/me"), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_401s_coalesce_into_a_single_refresh() {
        let (client, mock, store) = test_client(|request| {
            if request.url.ends_with("auth/refresh") {
                return json(200, r#"{"accessToken":"access-2","refreshToken":"refresh-2"}"#);
            }
            match request.bearer.as_deref() {
                Some("access-2") => json(200, r#"{"user":{"id":"u","email":"e@x.co"}}"#),
                _ => json(401, r#"{"error":{"message":"expired","code":"UNAUTHORIZED"}}"#),
            }
        });
        store.set_refresh_token("refresh-1").unwrap();
        client.adopt(&auth_response("access-1", None)).await.unwrap();
        let client = Arc::new(client);
        let mut handles = Vec::new();
        for _ in 0..8 {
            let client = client.clone();
            handles.push(tokio::spawn(async move { client.me().await }));
        }
        for handle in handles {
            handle.await.unwrap().unwrap();
        }
        assert_eq!(mock.count_to("auth/refresh"), 1, "refreshes must coalesce");
        assert_eq!(store.refresh_token().unwrap().as_deref(), Some("refresh-2"));
    }

    #[tokio::test]
    async fn retries_once_after_401_then_surfaces_unauthorized() {
        let (client, mock, store) = test_client(|request| {
            if request.url.ends_with("auth/refresh") {
                return json(200, r#"{"accessToken":"access-2","refreshToken":"refresh-2"}"#);
            }
            let _ = request;
            json(401, r#"{"error":{"message":"expired","code":"UNAUTHORIZED"}}"#)
        });
        store.set_refresh_token("refresh-1").unwrap();
        client.adopt(&auth_response("access-1", None)).await.unwrap();
        assert_eq!(client.me().await.unwrap_err(), ApiError::Unauthorized);
        // Exactly one retry: /me with access-1, refresh, /me with access-2.
        assert_eq!(mock.count_to("/me"), 2);
        assert_eq!(mock.count_to("auth/refresh"), 1);
    }

    #[tokio::test]
    async fn missing_refresh_token_is_unauthorized() {
        let (client, _mock, _store) = test_client(|_| unreachable!());
        assert_eq!(client.me().await.unwrap_err(), ApiError::Unauthorized);
    }

    #[tokio::test]
    async fn device_limit_maps_to_dedicated_error() {
        let (client, _mock, _store) = test_client(|_| {
            json(409, r#"{"error":{"message":"device limit reached","code":"DEVICE_LIMIT"}}"#)
        });
        assert_eq!(
            client
                .start_email_sign_in("u@x.co", "pc", &new_installation_id())
                .await
                .unwrap_err(),
            ApiError::DeviceLimit
        );
    }

    #[tokio::test]
    async fn status_and_envelope_mapping() {
        // 409 with another code stays a generic server error.
        let (client, _mock, _store) = test_client(|_| {
            json(409, r#"{"error":{"message":"conflict","code":"OTHER"}}"#)
        });
        assert_eq!(
            client
                .start_email_sign_in("u@x.co", "pc", &new_installation_id())
                .await
                .unwrap_err(),
            ApiError::Server {
                status: 409,
                message: "conflict".to_string()
            }
        );

        let (client, _mock, store) = test_client(|request| {
            if request.url.ends_with("auth/refresh") {
                return json(200, r#"{"accessToken":"a","refreshToken":"r"}"#);
            }
            if request.url.ends_with("/me") {
                return json(403, r#"{"error":{"message":"forbidden"}}"#);
            }
            json(500, r#"{"error":{"message":"boom","code":"X"}}"#)
        });
        store.set_refresh_token("r0").unwrap();
        assert_eq!(client.me().await.unwrap_err(), ApiError::Forbidden);
        assert_eq!(
            client.devices().await.unwrap_err(),
            ApiError::Server {
                status: 500,
                message: "boom".to_string()
            }
        );

        let (client, _mock, store) = test_client(|_| json(404, "{}"));
        store.set_refresh_token("r0").unwrap();
        client.adopt(&auth_response("a", None)).await.unwrap();
        assert_eq!(
            client.revoke_device(&new_installation_id()).await.unwrap_err(),
            ApiError::NotFound
        );
    }

    #[tokio::test]
    async fn transport_failure_maps_to_transport_error() {
        let (client, mock, _store) = test_client(|_| {
            Err(ApiError::Transport {
                kind: TransportKind::Other,
                message: "dns".to_string(),
            })
        });
        // GET retries any transport kind once, so the mock sees two calls
        // and the *original* error propagates.
        assert_eq!(
            client.auth_methods().await.unwrap_err(),
            ApiError::Transport {
                kind: TransportKind::Other,
                message: "dns".to_string()
            }
        );
        assert_eq!(mock.count_to("auth/methods"), 2);
    }

    // ---- bounded transport retry (mainland link policy) ----

    fn fail_then_ok(
        kind: TransportKind,
        ok_status: u16,
        ok_body: &'static str,
    ) -> impl FnMut(&ApiRequest) -> Result<ApiResponse, ApiError> + Send {
        let mut calls = 0_usize;
        move |_request| {
            calls += 1;
            if calls == 1 {
                Err(ApiError::Transport {
                    kind,
                    message: kind_message(kind).to_string(),
                })
            } else {
                Ok(ApiResponse {
                    status: ok_status,
                    body: ok_body.as_bytes().to_vec(),
                })
            }
        }
    }

    fn kind_message(kind: TransportKind) -> &'static str {
        match kind {
            TransportKind::Dns => "dns",
            TransportKind::Connect => "connect",
            TransportKind::Tls => "tls",
            TransportKind::Timeout => "timeout",
            TransportKind::Other => "other",
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn get_retries_every_transport_kind_exactly_once() {
        for kind in [
            TransportKind::Dns,
            TransportKind::Connect,
            TransportKind::Tls,
            TransportKind::Timeout,
            TransportKind::Other,
        ] {
            let (client, mock, _store) = test_client(fail_then_ok(kind, 200, r#"{"email":{"enabled":true},"apple":{"enabled":false},"google":{"enabled":false}}"#));
            let methods = client.auth_methods().await.unwrap();
            assert!(methods.email.enabled, "{kind:?}");
            assert_eq!(mock.count_to("auth/methods"), 2, "{kind:?} must retry exactly once");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn get_retry_failure_propagates_the_original_error() {
        let (client, mock, _store) = test_client(|_| {
            Err(ApiError::Transport {
                kind: TransportKind::Connect,
                message: "connect refused".to_string(),
            })
        });
        let err = client.auth_methods().await.unwrap_err();
        assert_eq!(
            err,
            ApiError::Transport {
                kind: TransportKind::Connect,
                message: "connect refused".to_string()
            }
        );
        assert_eq!(mock.count_to("auth/methods"), 2, "one retry, no more");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn post_retries_only_dns_and_connect() {
        for (kind, expected_calls) in [
            (TransportKind::Dns, 2_usize),
            (TransportKind::Connect, 2),
            (TransportKind::Timeout, 1),
            (TransportKind::Tls, 1),
            (TransportKind::Other, 1),
        ] {
            let (client, mock, _store) = test_client(fail_then_ok(
                kind,
                200,
                r#"{"challengeId":"c1","expiresIn":600,"message":"sent"}"#,
            ));
            let outcome = client
                .start_email_sign_in("user@example.com", "pc", &new_installation_id())
                .await;
            if expected_calls == 2 {
                assert!(outcome.is_ok(), "{kind:?} must retry and succeed");
            } else {
                assert!(outcome.is_err(), "{kind:?} must not retry a POST");
            }
            assert_eq!(mock.count_to("auth/email/start"), expected_calls, "{kind:?}");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn status_and_parse_failures_never_retry() {
        // 500 with an error envelope: a status, not a transport failure.
        let (client, mock, _store) = test_client(|_| json(500, r#"{"error":{"message":"boom","code":"X"}}"#));
        assert!(client.auth_methods().await.is_err());
        assert_eq!(mock.count_to("auth/methods"), 1, "HTTP statuses never retry");

        // 200 with garbage: a parse failure, not a transport failure.
        let (client, mock, _store) = test_client(|_| json(200, "{not the schema"));
        assert!(client.auth_methods().await.is_err());
        assert_eq!(mock.count_to("auth/methods"), 1, "parse failures never retry");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn email_verify_post_never_retries_on_timeout() {
        let (client, mock, _store) = test_client(|_| {
            Err(ApiError::Transport {
                kind: TransportKind::Timeout,
                message: "timeout".to_string(),
            })
        });
        assert!(client.verify_email_sign_in("c1", "123456").await.is_err());
        assert_eq!(
            mock.count_to("auth/email/verify"),
            1,
            "a possibly-delivered code must never be sent twice"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refresh_post_never_retries_on_timeout() {
        // /me 401s → refresh (POST, Timeout) → must not be retried.
        let (client, mock, store) = test_client(|request| {
            if request.url.ends_with("auth/refresh") {
                return Err(ApiError::Transport {
                    kind: TransportKind::Timeout,
                    message: "timeout".to_string(),
                });
            }
            json(401, r#"{"error":{"message":"expired","code":"UNAUTHORIZED"}}"#)
        });
        store.set_refresh_token("refresh-1").unwrap();
        assert!(client.me().await.is_err());
        assert_eq!(mock.count_to("auth/refresh"), 1, "refresh POST must not retry a timeout");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn logout_post_never_retries_on_timeout() {
        let (client, mock, store) = test_client(|request| {
            if request.url.ends_with("auth/refresh") {
                return json(200, r#"{"accessToken":"access-2","refreshToken":"refresh-2"}"#);
            }
            if request.url.ends_with("auth/logout") {
                return Err(ApiError::Transport {
                    kind: TransportKind::Timeout,
                    message: "timeout".to_string(),
                });
            }
            json(200, r#"{"user":{"id":"u1","email":"e@x.co"}}"#)
        });
        store.set_refresh_token("refresh-1").unwrap();
        client.me().await.unwrap();
        client.logout().await;
        assert_eq!(mock.count_to("auth/logout"), 1, "logout must not retry a timeout");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn combined_retry_then_401_replay_bound() {
        // First GET: Connect failure → transport retry succeeds with 401 →
        // refresh → replay succeeds. Bounds: 2 calls for the first logical
        // send (attempt + retry), exactly 1 refresh, 1 replay.
        let (client, mock, store) = test_client(|request| {
            if request.url.ends_with("auth/refresh") {
                return json(200, r#"{"accessToken":"access-2","refreshToken":"refresh-2"}"#);
            }
            if request.url.ends_with("/me") {
                match request.bearer.as_deref() {
                    Some("access-2") => return json(200, r#"{"user":{"id":"u1","email":"e@x.co"}}"#),
                    Some("access-1") => return json(401, r#"{"error":{"message":"expired"}}"#),
                    _ => {}
                }
            }
            if request.url.ends_with("auth/methods") {
                static CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
                if CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) == 0 {
                    return Err(ApiError::Transport {
                        kind: TransportKind::Connect,
                        message: "connect".to_string(),
                    });
                }
                return json(200, r#"{"email":{"enabled":true},"apple":{"enabled":false},"google":{"enabled":false}}"#);
            }
            unreachable!()
        });
        store.set_refresh_token("refresh-1").unwrap();
        client.adopt(&auth_response("access-1", None)).await.unwrap();
        client.auth_methods().await.unwrap(); // transport fail → retry → ok
        assert_eq!(mock.count_to("auth/methods"), 2, "one transport retry");
        client.me().await.unwrap(); // 401 → refresh → replay ok
        assert_eq!(mock.count_to("auth/refresh"), 1, "one 401 replay");
    }

    // ---- diagnostics upload ----

    fn sample_report() -> DiagnosticsReport {
        DiagnosticsReport {
            schema_version: DIAGNOSTICS_SCHEMA_VERSION,
            reported_at_ms: 1_712_345_678_901,
            app_version: "0.0.3".to_string(),
            os_version: "Windows 11 Pro".to_string(),
            os_arch: "x86_64".to_string(),
            ui_state: "protectedOffline".to_string(),
            account_state: "ready".to_string(),
            retry_attempt: 2,
            steps: vec![DiagnosticsStep {
                key: "preparing".to_string(),
                state: "completed".to_string(),
                elapsed_ms: Some(1200),
            }],
            audit_log_path: "%USERPROFILE%/traffic-audit.jsonl".to_string(),
            service_log_path: r"C:\ProgramData\Tono\logs\tono-service.log".to_string(),
            ..DiagnosticsReport::default()
        }
    }

    #[tokio::test]
    async fn diagnostics_upload_posts_the_wrapped_report_and_returns_the_code() {
        let (client, mock, store) = test_client(|request| {
            assert!(request.url.ends_with("api/v1/diagnostics/reports"));
            assert_eq!(request.method, HttpMethod::Post);
            assert_eq!(request.bearer.as_deref(), Some("access-1"));
            let body: serde_json::Value =
                serde_json::from_str(request.json_body.as_deref().unwrap()).unwrap();
            // The payload is wrapped in `report` and camelCased.
            assert_eq!(body["report"]["schemaVersion"], 1);
            assert_eq!(body["report"]["uiState"], "protectedOffline");
            assert_eq!(body["report"]["steps"][0]["elapsedMs"], 1200);
            json(200, r#"{"referenceCode":"TON-4F2K-9QX1","receivedAt":1712345678}"#)
        });
        store.set_refresh_token("r0").unwrap();
        client.adopt(&auth_response("access-1", None)).await.unwrap();
        let receipt = client.upload_diagnostics_report(&sample_report()).await.unwrap();
        assert_eq!(receipt.reference_code, "TON-4F2K-9QX1");
        assert_eq!(receipt.received_at, Some(1_712_345_678));
        assert_eq!(mock.count_to("diagnostics/reports"), 1);
    }

    #[tokio::test]
    async fn diagnostics_upload_rejects_a_receipt_without_a_code() {
        let (client, _mock, store) = test_client(|_| json(200, r#"{"referenceCode":"   "}"#));
        store.set_refresh_token("r0").unwrap();
        client.adopt(&auth_response("access-1", None)).await.unwrap();
        assert_eq!(
            client.upload_diagnostics_report(&sample_report()).await.unwrap_err(),
            ApiError::InvalidResponse
        );
    }

    #[tokio::test]
    async fn rate_limited_uploads_map_to_their_own_error() {
        let (client, _mock, store) = test_client(|_| {
            json(429, r#"{"error":{"message":"slow down","code":"RATE_LIMITED"}}"#)
        });
        store.set_refresh_token("r0").unwrap();
        client.adopt(&auth_response("access-1", None)).await.unwrap();
        assert_eq!(
            client.upload_diagnostics_report(&sample_report()).await.unwrap_err(),
            ApiError::RateLimited
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn diagnostics_upload_never_retries_a_timeout() {
        let (client, mock, store) = test_client(|_| {
            Err(ApiError::Transport {
                kind: TransportKind::Timeout,
                message: "timeout".to_string(),
            })
        });
        store.set_refresh_token("r0").unwrap();
        client.adopt(&auth_response("access-1", None)).await.unwrap();
        assert!(client.upload_diagnostics_report(&sample_report()).await.is_err());
        assert_eq!(
            mock.count_to("diagnostics/reports"),
            1,
            "a possibly-delivered report must never be sent twice"
        );
    }

    #[test]
    fn diagnostics_report_serializes_exactly_the_whitelisted_keys() {
        // The wire contract, spelled out. A field added to the struct without
        // a deliberate update here fails this test — which is the point.
        let value = serde_json::to_value(sample_report()).unwrap();
        let mut keys: Vec<&str> = value.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "accountState",
                "appVersion",
                "auditLogPath",
                "catalogRevision",
                "dnsEnabled",
                "dnsLastError",
                "error",
                "failedStage",
                "killSwitchLastError",
                "killSwitchLive",
                "killSwitchMode",
                "killSwitchWanted",
                "osArch",
                "osVersion",
                "reportedAtMs",
                "retryAttempt",
                "schemaVersion",
                "selectedServer",
                "serviceBuild",
                "serviceLogPath",
                "serviceProtocol",
                "steps",
                "totalElapsedMs",
                "uiState",
                "virtualAdapters",
            ]
        );
        let step = value["steps"][0].as_object().unwrap();
        let mut step_keys: Vec<&str> = step.keys().map(String::as_str).collect();
        step_keys.sort_unstable();
        assert_eq!(step_keys, ["elapsedMs", "key", "state"]);
    }

    #[tokio::test]
    async fn revoke_device_validates_uuid() {
        let (client, mock, _store) = test_client(|_| unreachable!());
        assert!(matches!(
            client.revoke_device("not-a-uuid").await,
            Err(ApiError::InvalidInput(_))
        ));
        assert!(mock.requests().is_empty());
    }

    #[tokio::test]
    async fn logout_posts_refresh_token_and_wipes_local_state() {
        let (client, mock, store) = test_client(|request| {
            if request.url.ends_with("auth/logout") {
                let body: serde_json::Value =
                    serde_json::from_str(request.json_body.as_deref().unwrap()).unwrap();
                assert_eq!(body["refreshToken"], "refresh-1");
            }
            json(200, "{}")
        });
        store.set_refresh_token("refresh-1").unwrap();
        client.adopt(&auth_response("access-1", None)).await.unwrap();
        client.logout().await;
        assert_eq!(mock.count_to("auth/logout"), 1);
        assert_eq!(store.refresh_token().unwrap(), None);
        // Subsequent authorized calls cannot refresh anymore.
        assert_eq!(client.me().await.unwrap_err(), ApiError::Unauthorized);
    }

    #[test]
    fn logout_request_omits_null_refresh_token() {
        // The server 400s on an explicit JSON null (it is not `undefined`).
        let json = serde_json::to_value(LogoutRequest {
            refresh_token: None,
        })
        .unwrap();
        assert_eq!(json, serde_json::json!({}));
        let json = serde_json::to_value(LogoutRequest {
            refresh_token: Some("r".to_string()),
        })
        .unwrap();
        assert_eq!(json, serde_json::json!({"refreshToken": "r"}));
    }

    #[tokio::test]
    async fn adopt_persists_refresh_token_when_present() {
        let (client, _mock, store) = test_client(|_| unreachable!());
        client.adopt(&auth_response("a", Some("r-new"))).await.unwrap();
        assert_eq!(store.refresh_token().unwrap().as_deref(), Some("r-new"));
        // Without a refresh token the stored one survives.
        client.adopt(&auth_response("a2", None)).await.unwrap();
        assert_eq!(store.refresh_token().unwrap().as_deref(), Some("r-new"));
    }

    #[tokio::test]
    async fn exit_catalog_decodes_response() {
        let (client, _mock, store) = test_client(|_| {
            json(200, r#"{"revision":3,"yaml":"proxies: []","sha256":"x","updatedAt":42}"#)
        });
        store.set_refresh_token("r0").unwrap();
        client.adopt(&auth_response("a", None)).await.unwrap();
        let catalog = client.exit_catalog().await.unwrap();
        assert_eq!(catalog.revision, 3);
        assert_eq!(catalog.updated_at, Some(42));
    }

    #[test]
    fn base_url_rejects_non_printable_authority() {
        for bad in [
            "https://api afk.ccwu.cc",
            "https://api.afk.ccwu.c\ncc",
            "https://\tapi.afk.ccwu.cc",
            "https://api.afk.ccwü.cc",
            "https://user@api.afk.ccwu.cc",
        ] {
            assert_eq!(
                validate_base_url(bad),
                Err(ApiError::InvalidConfiguration),
                "{bad:?}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn in_flight_refresh_cannot_clobber_a_newer_session() {
        // The refresh response is held back until adopt() installs a new
        // session; the stale result must be discarded, never committed (L3).
        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        let started_tx = std::sync::Mutex::new(Some(started_tx));
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let (client, mock, store) = test_client(move |request| {
            if request.url.ends_with("auth/refresh") {
                if let Some(tx) = started_tx.lock().unwrap().take() {
                    let _ = tx.send(());
                }
                // Block until the test has run adopt().
                release_rx.recv().unwrap();
                return json(200, r#"{"accessToken":"access-old","refreshToken":"refresh-old"}"#);
            }
            assert_eq!(request.bearer.as_deref(), Some("access-new"));
            json(200, r#"{"user":{"id":"u","email":"e@x.co"}}"#)
        });
        store.set_refresh_token("refresh-1").unwrap();
        let client = Arc::new(client);
        let task_client = client.clone();
        let pending = tokio::spawn(async move { task_client.me().await });
        // The refresh request is now blocked inside the mock.
        started_rx.await.unwrap();
        client
            .adopt(&auth_response("access-new", Some("refresh-new")))
            .await
            .unwrap();
        release_tx.send(()).unwrap();
        let me = pending.await.unwrap().unwrap();
        assert_eq!(me.user.id, "u");
        assert_eq!(
            store.refresh_token().unwrap().as_deref(),
            Some("refresh-new"),
            "stale refresh must not overwrite the new session"
        );
        assert_eq!(mock.count_to("auth/refresh"), 1);
    }
}
