//! Connect state machine (product-contract.md §6/§7).
//!
//! Pure logic only: stages, UI state derivation, reconnect backoff, and the
//! failure decision table. An initial, not-yet-verified attempt is released
//! on failure; after a tunnel has been fully verified the logical session
//! remains fail-closed until explicit Disconnect, Sign Out, or Quit.

use std::time::Duration;

/// The connect-transaction stages, in order (§6). `PreparingService` is
/// the Windows rename of macOS `preparingHelper` (the privileged steps are
/// performed by the Windows service); `ApplyingCloudPolicy` applies the
/// cloud WeChat-DIRECT policy after the tunnel is locked (Mac Build 28
/// parity).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConnectStage {
    Preparing,
    PreparingService,
    StartingKillSwitch,
    StartingTunnel,
    LockingTraffic,
    ApplyingCloudPolicy,
    SecuringDns,
    CheckingExit,
    VerifyingTraffic,
}

impl ConnectStage {
    /// All stages in transaction order.
    pub const ALL: [ConnectStage; 9] = [
        ConnectStage::Preparing,
        ConnectStage::PreparingService,
        ConnectStage::StartingKillSwitch,
        ConnectStage::StartingTunnel,
        ConnectStage::LockingTraffic,
        ConnectStage::ApplyingCloudPolicy,
        ConnectStage::SecuringDns,
        ConnectStage::CheckingExit,
        ConnectStage::VerifyingTraffic,
    ];

    /// UI text, mirroring the macOS strings (§7).
    pub fn label(self) -> &'static str {
        match self {
            ConnectStage::Preparing => "Preparing protection…",
            ConnectStage::PreparingService => "Preparing secure service…",
            ConnectStage::StartingKillSwitch => "Starting Kill Switch…",
            ConnectStage::StartingTunnel => "Starting protected tunnel…",
            ConnectStage::LockingTraffic => "Locking traffic to tunnel…",
            ConnectStage::ApplyingCloudPolicy => "Applying cloud routing policy…",
            ConnectStage::SecuringDns => "Securing DNS…",
            ConnectStage::CheckingExit => "Checking secure exit…",
            ConnectStage::VerifyingTraffic => "Verifying traffic protection…",
        }
    }
}

/// Observable connection state (§7). Flag layout mirrors the macOS
/// AppState so UI bindings stay a mechanical port.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConnectionStatus {
    pub is_connected: bool,
    pub is_connecting: bool,
    pub is_disconnecting: bool,
    /// Kill switch armed while not connected: the fail-closed "blocked"
    /// state the UI shows as Protected Offline.
    pub is_protection_blocked: bool,
    pub stage: Option<ConnectStage>,
}

/// Top-level UI states (§7). "Recovering" is ProtectedOffline plus an
/// active backoff, not a separate state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiState {
    NotConnected,
    Connecting(ConnectStage),
    Connected,
    ProtectedOffline,
    Disconnecting,
}

impl ConnectionStatus {
    pub fn ui_state(&self) -> UiState {
        if self.is_disconnecting {
            UiState::Disconnecting
        } else if self.is_connecting {
            UiState::Connecting(self.stage.unwrap_or(ConnectStage::Preparing))
        } else if self.is_connected {
            UiState::Connected
        } else if self.is_protection_blocked {
            UiState::ProtectedOffline
        } else {
            UiState::NotConnected
        }
    }
}

/// Auto-reconnect backoff behind an armed kill switch: 2/5/10/20/30 s,
/// capped at 30 s (§6).
#[derive(Debug, Clone, Default)]
pub struct ReconnectBackoff {
    step: usize,
}

impl ReconnectBackoff {
    pub const DELAYS_SECS: [u64; 5] = [2, 5, 10, 20, 30];

    pub fn new() -> Self {
        Self::default()
    }

    pub fn next_delay(&mut self) -> Duration {
        let seconds = Self::DELAYS_SECS[self.step.min(Self::DELAYS_SECS.len() - 1)];
        self.step += 1;
        Duration::from_secs(seconds)
    }

    pub fn reset(&mut self) {
        self.step = 0;
    }
}

/// What a connect failure does to the kill switch (§6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureAction {
    /// Failure after the WFP policy exists: stop the core, keep blocking,
    /// enter Protected Offline, auto-reconnect with backoff.
    KeepBlockingAndReconnect,
    /// Failure before the WFP policy exists (e.g. elevation refused):
    /// full release.
    FullRelease,
}

/// Initial attempts release on failure; only a verified armed session reconnects fail-closed.
pub fn on_connect_failure(kill_switch_armed: bool, session_verified: bool) -> FailureAction {
    if kill_switch_armed && session_verified {
        FailureAction::KeepBlockingAndReconnect
    } else {
        FailureAction::FullRelease
    }
}

/// Everything that can end a session. Only Disconnect, SignOut, and Quit
/// may release the kill switch (§6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownCause {
    Disconnect,
    SignOut,
    Quit,
    Crash,
    Kill,
    Sleep,
    NetworkChange,
    CatalogFailure,
    ApiOutage,
}

impl ShutdownCause {
    pub fn releases_kill_switch(self) -> bool {
        matches!(
            self,
            ShutdownCause::Disconnect | ShutdownCause::SignOut | ShutdownCause::Quit
        )
    }
}

/// Refused state-machine transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectTransitionError {
    /// `Connected` requires an in-flight transaction and an armed kill
    /// switch; an unarmed Connected state is the one combination the
    /// fail-closed promise forbids (M2).
    InvalidSuccessPrecondition,
}

impl std::fmt::Display for ConnectTransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectTransitionError::InvalidSuccessPrecondition => f.write_str(
                "connect can only succeed while connecting with a verified armed kill switch",
            ),
        }
    }
}

impl std::error::Error for ConnectTransitionError {}

/// Pure connect-transaction state machine. Owns the flags, the armed
/// latch, and the backoff so every transition in §6 is testable without
/// I/O.
#[derive(Debug, Clone, Default)]
pub struct ConnectionFsm {
    status: ConnectionStatus,
    kill_switch_armed: bool,
    session_verified: bool,
    backoff: ReconnectBackoff,
}

impl ConnectionFsm {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn status(&self) -> &ConnectionStatus {
        &self.status
    }

    pub fn kill_switch_armed(&self) -> bool {
        self.kill_switch_armed
    }

    pub fn session_verified(&self) -> bool {
        self.session_verified
    }

    /// Record (or restore) that this logical protection session completed all checks.
    pub fn mark_session_verified(&mut self) {
        self.session_verified = true;
    }

    /// Step 1: begin a connect transaction.
    pub fn begin_connect(&mut self) {
        self.status.is_connecting = true;
        self.status.is_disconnecting = false;
        self.status.stage = Some(ConnectStage::Preparing);
    }

    /// Advance to `stage` (must be connecting; stages only move forward).
    pub fn advance_stage(&mut self, stage: ConnectStage) {
        debug_assert!(self.status.is_connecting);
        if let Some(current) = self.status.stage {
            debug_assert!(stage >= current);
        }
        self.status.stage = Some(stage);
    }

    /// Step 3 completes: the WFP bootstrap policy exists. From here on the
    /// machine is fail-closed.
    pub fn mark_kill_switch_armed(&mut self) {
        self.kill_switch_armed = true;
        self.status.is_protection_blocked = true;
    }

    /// Step 10: all checks passed. A transaction must be in flight, the kill
    /// switch armed, and the Service verification commit durable — an
    /// unverified or unarmed `Connected` must never exist.
    pub fn connect_succeeded(&mut self) -> Result<(), ConnectTransitionError> {
        if !self.status.is_connecting || !self.kill_switch_armed || !self.session_verified {
            return Err(ConnectTransitionError::InvalidSuccessPrecondition);
        }
        self.status.is_connected = true;
        self.status.is_connecting = false;
        self.status.is_disconnecting = false;
        self.status.is_protection_blocked = false;
        self.status.stage = None;
        self.backoff.reset();
        Ok(())
    }

    /// Connect transaction failed. A verified armed session stays blocked
    /// and reconnects; an initial attempt receives a full release.
    pub fn connect_failed(&mut self) -> FailureAction {
        match on_connect_failure(self.kill_switch_armed, self.session_verified) {
            FailureAction::KeepBlockingAndReconnect => {
                self.status.is_connected = false;
                self.status.is_connecting = false;
                self.status.is_disconnecting = false;
                self.status.is_protection_blocked = true;
                self.status.stage = None;
                FailureAction::KeepBlockingAndReconnect
            }
            FailureAction::FullRelease => {
                self.release();
                FailureAction::FullRelease
            }
        }
    }

    /// A required initial full release failed. Keep the real armed state visible and do not
    /// claim either network restoration or a reconnectable established session.
    pub fn initial_release_failed(&mut self) {
        self.status.is_connected = false;
        self.status.is_connecting = false;
        self.status.is_disconnecting = false;
        self.status.is_protection_blocked = self.kill_switch_armed;
        self.status.stage = None;
    }

    /// Mihomo crash or TUN disappearance at runtime: identical to a
    /// connect failure after arm (§6) — keep blocking, reconnect behind
    /// the barrier.
    pub fn tunnel_died(&mut self) -> FailureAction {
        debug_assert!(
            self.kill_switch_armed,
            "a live tunnel implies an armed kill switch"
        );
        debug_assert!(
            self.session_verified,
            "a live tunnel implies a verified session"
        );
        self.status.is_connected = false;
        self.status.is_connecting = false;
        self.status.stage = None;
        self.status.is_protection_blocked = self.kill_switch_armed;
        // Runtime tunnel loss is always fail-closed. Preserve (rather than manufacture) the
        // logical verification latch across the reconnect attempt.
        FailureAction::KeepBlockingAndReconnect
    }

    /// Delay before the next protected reconnect attempt. Handed out only
    /// while idle in Protected Offline — never while connected,
    /// disconnecting, or mid-transaction (M1).
    pub fn next_reconnect_delay(&mut self) -> Option<Duration> {
        if self.status.is_protection_blocked
            && self.session_verified
            && !self.status.is_connected
            && !self.status.is_disconnecting
            && !self.status.is_connecting
        {
            Some(self.backoff.next_delay())
        } else {
            None
        }
    }

    /// Explicit disconnect is allowed from Connected or Protected Offline
    /// and is one of the three causes that release the kill switch (§6).
    pub fn begin_disconnect(&mut self) {
        self.status.is_disconnecting = true;
        self.status.is_connecting = false;
        self.status.stage = None;
    }

    /// Disconnect finished (DNS restored *before* the kill switch was
    /// disarmed by the service — ordering enforced there, §6). Idempotent:
    /// a duplicate call (e.g. a raced disconnect and a failing connect
    /// transaction both converging the machine) is a no-op, never a panic.
    pub fn finish_disconnect(&mut self) {
        if !self.status.is_disconnecting {
            return;
        }
        self.release();
    }

    /// Sign out or quit: the other two releasing causes.
    pub fn sign_out_or_quit(&mut self) {
        self.release();
    }

    fn release(&mut self) {
        self.kill_switch_armed = false;
        self.session_verified = false;
        self.backoff.reset();
        self.status = ConnectionStatus::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stages_are_ordered_and_labelled() {
        assert_eq!(ConnectStage::ALL.len(), 9);
        assert!(ConnectStage::Preparing < ConnectStage::VerifyingTraffic);
        assert!(ConnectStage::LockingTraffic < ConnectStage::ApplyingCloudPolicy);
        assert!(ConnectStage::ApplyingCloudPolicy < ConnectStage::SecuringDns);
        let labels: Vec<&str> = ConnectStage::ALL.iter().map(|stage| stage.label()).collect();
        assert_eq!(
            labels,
            [
                "Preparing protection…",
                "Preparing secure service…",
                "Starting Kill Switch…",
                "Starting protected tunnel…",
                "Locking traffic to tunnel…",
                "Applying cloud routing policy…",
                "Securing DNS…",
                "Checking secure exit…",
                "Verifying traffic protection…",
            ]
        );
    }

    #[test]
    fn backoff_produces_capped_sequence() {
        let mut backoff = ReconnectBackoff::new();
        let delays: Vec<Duration> = (0..8).map(|_| backoff.next_delay()).collect();
        assert_eq!(
            delays,
            [2, 5, 10, 20, 30, 30, 30, 30]
                .map(Duration::from_secs)
                .to_vec()
        );
        backoff.reset();
        assert_eq!(backoff.next_delay(), Duration::from_secs(2));
    }

    #[test]
    fn ui_state_derivation() {
        let mut status = ConnectionStatus::default();
        assert_eq!(status.ui_state(), UiState::NotConnected);
        status.is_connecting = true;
        status.stage = Some(ConnectStage::SecuringDns);
        assert_eq!(status.ui_state(), UiState::Connecting(ConnectStage::SecuringDns));
        // Missing stage falls back to the first stage label.
        status.stage = None;
        assert_eq!(status.ui_state(), UiState::Connecting(ConnectStage::Preparing));
        status.is_connecting = false;
        status.is_connected = true;
        assert_eq!(status.ui_state(), UiState::Connected);
        status.is_connected = false;
        status.is_protection_blocked = true;
        assert_eq!(status.ui_state(), UiState::ProtectedOffline);
        status.is_disconnecting = true;
        assert_eq!(status.ui_state(), UiState::Disconnecting);
    }

    #[test]
    fn failure_decision_table() {
        assert_eq!(on_connect_failure(false, false), FailureAction::FullRelease);
        assert_eq!(on_connect_failure(true, false), FailureAction::FullRelease);
        assert_eq!(
            on_connect_failure(true, true),
            FailureAction::KeepBlockingAndReconnect
        );
    }

    #[test]
    fn only_disconnect_signout_quit_release() {
        for (cause, releases) in [
            (ShutdownCause::Disconnect, true),
            (ShutdownCause::SignOut, true),
            (ShutdownCause::Quit, true),
            (ShutdownCause::Crash, false),
            (ShutdownCause::Kill, false),
            (ShutdownCause::Sleep, false),
            (ShutdownCause::NetworkChange, false),
            (ShutdownCause::CatalogFailure, false),
            (ShutdownCause::ApiOutage, false),
        ] {
            assert_eq!(cause.releases_kill_switch(), releases, "{cause:?}");
        }
    }

    #[test]
    fn happy_path_connect_then_disconnect() {
        let mut fsm = ConnectionFsm::new();
        fsm.begin_connect();
        assert_eq!(fsm.status().ui_state(), UiState::Connecting(ConnectStage::Preparing));
        for stage in &ConnectStage::ALL[1..] {
            fsm.advance_stage(*stage);
            if *stage == ConnectStage::StartingTunnel {
                fsm.mark_kill_switch_armed();
            }
        }
        assert!(fsm.kill_switch_armed());
        fsm.mark_session_verified();
        fsm.connect_succeeded().unwrap();
        assert_eq!(fsm.status().ui_state(), UiState::Connected);
        assert!(fsm.kill_switch_armed(), "kill switch stays armed while connected");
        fsm.begin_disconnect();
        assert_eq!(fsm.status().ui_state(), UiState::Disconnecting);
        fsm.finish_disconnect();
        assert_eq!(fsm.status().ui_state(), UiState::NotConnected);
        assert!(!fsm.kill_switch_armed());
    }

    #[test]
    fn failure_before_arm_fully_releases() {
        let mut fsm = ConnectionFsm::new();
        fsm.begin_connect();
        fsm.advance_stage(ConnectStage::PreparingService);
        // Elevation refused: no WFP policy exists yet.
        assert_eq!(fsm.connect_failed(), FailureAction::FullRelease);
        assert_eq!(fsm.status().ui_state(), UiState::NotConnected);
        assert!(!fsm.kill_switch_armed());
        assert_eq!(fsm.next_reconnect_delay(), None, "no protected reconnect after release");
    }

    #[test]
    fn failure_after_verified_session_keeps_blocking_and_backs_off() {
        let mut fsm = ConnectionFsm::new();
        fsm.begin_connect();
        fsm.advance_stage(ConnectStage::StartingKillSwitch);
        fsm.mark_kill_switch_armed();
        fsm.mark_session_verified();
        fsm.advance_stage(ConnectStage::StartingTunnel);
        assert_eq!(
            fsm.connect_failed(),
            FailureAction::KeepBlockingAndReconnect
        );
        assert!(fsm.kill_switch_armed());
        assert_eq!(fsm.status().ui_state(), UiState::ProtectedOffline);
        // Protected Offline + active backoff == "Recovering" (§7).
        assert_eq!(fsm.next_reconnect_delay(), Some(Duration::from_secs(2)));
        assert_eq!(fsm.next_reconnect_delay(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn tunnel_death_at_runtime_keeps_blocking() {
        let mut fsm = ConnectionFsm::new();
        fsm.begin_connect();
        fsm.mark_kill_switch_armed();
        fsm.mark_session_verified();
        fsm.connect_succeeded().unwrap();
        assert_eq!(
            fsm.tunnel_died(),
            FailureAction::KeepBlockingAndReconnect
        );
        assert!(fsm.kill_switch_armed());
        assert_eq!(fsm.status().ui_state(), UiState::ProtectedOffline);
        assert!(!fsm.status().is_connected);
    }

    #[test]
    fn reconnect_after_failure_resets_backoff_on_success() {
        let mut fsm = ConnectionFsm::new();
        fsm.begin_connect();
        fsm.mark_kill_switch_armed();
        fsm.mark_session_verified();
        fsm.connect_failed();
        assert_eq!(fsm.next_reconnect_delay(), Some(Duration::from_secs(2)));
        // The protected reconnect run succeeds.
        fsm.begin_connect();
        fsm.connect_succeeded().unwrap();
        assert_eq!(fsm.next_reconnect_delay(), None);
        // A later failure starts the backoff from the top again.
        fsm.tunnel_died();
        assert_eq!(fsm.next_reconnect_delay(), Some(Duration::from_secs(2)));
    }

    #[test]
    fn disconnect_from_protected_offline_releases() {
        let mut fsm = ConnectionFsm::new();
        fsm.begin_connect();
        fsm.mark_kill_switch_armed();
        fsm.mark_session_verified();
        fsm.connect_failed();
        assert_eq!(fsm.status().ui_state(), UiState::ProtectedOffline);
        fsm.begin_disconnect();
        fsm.finish_disconnect();
        assert_eq!(fsm.status().ui_state(), UiState::NotConnected);
        assert!(!fsm.kill_switch_armed());
    }

    #[test]
    fn finish_disconnect_is_idempotent() {
        let mut fsm = ConnectionFsm::new();
        fsm.begin_connect();
        fsm.mark_kill_switch_armed();
        fsm.mark_session_verified();
        fsm.connect_succeeded().unwrap();
        fsm.begin_disconnect();
        fsm.finish_disconnect();
        // A raced second convergence must be a no-op, not a panic.
        fsm.finish_disconnect();
        assert_eq!(fsm.status().ui_state(), UiState::NotConnected);
        assert!(!fsm.kill_switch_armed());
        // Calling it on a fresh machine is equally inert.
        let mut fresh = ConnectionFsm::new();
        fresh.finish_disconnect();
        assert_eq!(fresh.status().ui_state(), UiState::NotConnected);
    }

    #[test]
    fn sign_out_releases_from_any_state() {
        let mut fsm = ConnectionFsm::new();
        fsm.begin_connect();
        fsm.mark_kill_switch_armed();
        fsm.mark_session_verified();
        fsm.connect_succeeded().unwrap();
        fsm.sign_out_or_quit();
        assert_eq!(fsm.status().ui_state(), UiState::NotConnected);
        assert!(!fsm.kill_switch_armed());
        assert_eq!(fsm.next_reconnect_delay(), None);
    }

    #[test]
    fn reconnect_predicate_stops_once_disconnect_begins() {
        // M1: explicit disconnect from Protected Offline is allowed (§6)
        // and must stop any further protected reconnects.
        let mut fsm = ConnectionFsm::new();
        fsm.begin_connect();
        fsm.mark_kill_switch_armed();
        fsm.mark_session_verified();
        fsm.connect_failed();
        assert_eq!(fsm.status().ui_state(), UiState::ProtectedOffline);
        assert!(fsm.next_reconnect_delay().is_some());
        fsm.begin_disconnect();
        assert_eq!(fsm.next_reconnect_delay(), None);
        fsm.finish_disconnect();
        assert_eq!(fsm.next_reconnect_delay(), None);
    }

    #[test]
    fn reconnect_predicate_pauses_during_reconnect_attempt() {
        // M1: while the reconnect transaction runs, no delay is handed out.
        let mut fsm = ConnectionFsm::new();
        fsm.begin_connect();
        fsm.mark_kill_switch_armed();
        fsm.mark_session_verified();
        fsm.connect_failed();
        assert!(fsm.next_reconnect_delay().is_some());
        fsm.begin_connect();
        assert_eq!(fsm.next_reconnect_delay(), None);
        fsm.advance_stage(ConnectStage::StartingKillSwitch);
        fsm.connect_succeeded().unwrap();
        assert_eq!(fsm.next_reconnect_delay(), None);
    }

    #[test]
    fn connect_succeeded_requires_verified_armed_connect_transaction() {
        // M2: fresh machine — no transaction, no arm. Success must be
        // refused, never producing an unarmed Connected state.
        let mut fsm = ConnectionFsm::new();
        assert_eq!(
            fsm.connect_succeeded(),
            Err(ConnectTransitionError::InvalidSuccessPrecondition)
        );
        assert!(!fsm.status().is_connected);
        // Armed but not connecting is still not a valid success.
        let mut fsm = ConnectionFsm::new();
        fsm.mark_kill_switch_armed();
        assert_eq!(
            fsm.connect_succeeded(),
            Err(ConnectTransitionError::InvalidSuccessPrecondition)
        );
        assert!(!fsm.status().is_connected);
        // Connecting but not yet armed (pre-WFP failure path) likewise.
        let mut fsm = ConnectionFsm::new();
        fsm.begin_connect();
        assert_eq!(
            fsm.connect_succeeded(),
            Err(ConnectTransitionError::InvalidSuccessPrecondition)
        );
        assert!(!fsm.status().is_connected);
        // Connecting and armed is still insufficient until the durable
        // verification commit succeeds.
        fsm.mark_kill_switch_armed();
        assert_eq!(
            fsm.connect_succeeded(),
            Err(ConnectTransitionError::InvalidSuccessPrecondition)
        );
        assert!(!fsm.status().is_connected);
    }
}
