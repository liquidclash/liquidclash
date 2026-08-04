import Foundation
import Observation

@MainActor @Observable
final class AccountSession {
    enum State: Equatable { case restoring, signedOut, authenticating, enrolling, ready, suspended, error(String) }
    private(set) var state: State = .restoring
    private(set) var user: TonoUser?
    private(set) var device: TonoDevice?
    private(set) var enrollment: TonoEnrollment?
    private(set) var devices: [TonoDevice] = []
    private(set) var authMethods: TonoAuthMethodsResponse?
    private(set) var emailChallenge: TonoEmailChallengeResponse?
    private var enrollmentAuthKey: String?
    private var enrollmentHostname: String?
    private let api: TonoAPIClient
    private let keychain: KeychainStore
    private let sidecar: TonoSidecarService
    private let descriptorConsumer: @MainActor (TonoTransportDescriptor?) async -> Void
    private let catalogConsumer: @MainActor (TonoExitCatalogResponse) async throws -> Void
    private let trafficPolicyConsumer: @MainActor (TonoTrafficPolicyResponse) async throws -> Void
    private let cloudFallbackPreferred: @MainActor () -> Bool
    private let cloudFallbackConsumer: @MainActor (Bool) throws -> Void
    private let killSwitchDisarmConsumer: @MainActor () async -> Void
    private let diagnosticSnapshotConsumer: @MainActor () -> TonoDiagnosticSnapshot
    private let claudeTrafficResearchConsumer:
        @MainActor () async -> TonoClaudeTrafficResearchSnapshot
    private let protectionBlockedConsumer: @MainActor () -> Bool
    private let protectedRetryConsumer: @MainActor () -> Void
    private let exitNode: String
    private var runtimeMonitor: Task<Void, Never>?
    private var catalogSyncTask: Task<Void, Never>?
    private var deviceRefreshTask: Task<Void, Never>?
    private var deviceActionTask: Task<Void, Never>?
    private var systemSleeping = false
    private var lastCatalogFailureMessage: String?
    private var lastTrafficPolicyFailureMessage: String?
    private var authMethodsLoading = false
    private var hasStartedRestore = false
    private var shouldResumeProtection = false

    var deviceLimit: Int { user?.deviceLimit ?? TonoAccountRules.maximumDevices }
    var isAtDeviceLimit: Bool { devices.count >= deviceLimit }
    var isReady: Bool { state == .ready }
    var catalogFailureMessage: String? { lastCatalogFailureMessage }
    /// A stale managed traffic policy silently degrades the WeChat direct
    /// route; without this accessor the stored failure was write-only and
    /// invisible to every UI and diagnostic surface.
    var trafficPolicyFailureMessage: String? { lastTrafficPolicyFailureMessage }

    init(api: TonoAPIClient = TonoAPIClient(), keychain: KeychainStore = KeychainStore(), sidecar: TonoSidecarService,
         exitNode: String = Bundle.main.object(forInfoDictionaryKey: "TonoExitNode") as? String ?? "",
         descriptorConsumer: @escaping @MainActor (TonoTransportDescriptor?) async -> Void,
         catalogConsumer: @escaping @MainActor (TonoExitCatalogResponse) async throws -> Void = { _ in },
         trafficPolicyConsumer: @escaping @MainActor (TonoTrafficPolicyResponse) async throws -> Void = { _ in },
         cloudFallbackPreferred: @escaping @MainActor () -> Bool = { false },
         cloudFallbackConsumer: @escaping @MainActor (Bool) throws -> Void = { _ in },
         killSwitchDisarmConsumer: @escaping @MainActor () async -> Void = {},
         diagnosticSnapshotConsumer: @escaping @MainActor () -> TonoDiagnosticSnapshot = {
             TonoDiagnosticSnapshot(
                 appVersion: "unknown", build: "unknown", connected: false,
                 connecting: false, disconnecting: false, protectionBlocked: false,
                 killSwitchArmed: false, utunPresent: false,
                 protectedDNSConfigured: false, selectedExit: "unknown",
                 connectionStage: "unknown", reconnectAttempt: 0,
                 lastErrorCategory: nil
             )
         },
         claudeTrafficResearchConsumer: @escaping
            @MainActor () async -> TonoClaudeTrafficResearchSnapshot = {
                TonoClaudeTrafficResearchSnapshot(
                    observedSince: 0,
                    droppedEndpointCount: 0,
                    observedConnectionCount: 0,
                    identifiedProcessConnectionCount: 0,
                    proxiedConnectionCount: 0,
                    directConnectionCount: 0,
                    blockedConnectionCount: 0,
                    directRouteAttemptCount: 0,
                    managedDirectRouteCount: 0,
                    unclassifiedRouteCount: 0,
                    unsafeProtectionObservationCount: 0,
                    webManagedDirectConnectionCount: 0,
                    weChatConnectionCount: 0,
                    weChatManagedDirectConnectionCount: 0,
                    weChatProxiedConnectionCount: 0,
                    weChatBlockedConnectionCount: 0,
                    weChatEndpointUnknownProcessConnectionCount: 0,
                    unknownManagedDirectConnectionCount: 0,
                    otherManagedDirectConnectionCount: 0,
                    protectedDirectConnectionCount: 0,
                    connectionLimitReached: false,
                    connected: false,
                    killSwitchArmed: false,
                    tunPresent: false,
                    protectedDNSConfigured: false,
                    exitIdentityConsistency: "INCONCLUSIVE",
                    physicalBypassProbe: "INCONCLUSIVE",
                    entries: []
                )
            },
         protectionBlockedConsumer: @escaping @MainActor () -> Bool = { false },
         protectedRetryConsumer: @escaping @MainActor () -> Void = {}) {
        self.api = api; self.keychain = keychain; self.sidecar = sidecar
        self.exitNode = exitNode
        self.descriptorConsumer = descriptorConsumer
        self.catalogConsumer = catalogConsumer
        self.trafficPolicyConsumer = trafficPolicyConsumer
        self.cloudFallbackPreferred = cloudFallbackPreferred
        self.cloudFallbackConsumer = cloudFallbackConsumer
        self.killSwitchDisarmConsumer = killSwitchDisarmConsumer
        self.diagnosticSnapshotConsumer = diagnosticSnapshotConsumer
        self.claudeTrafficResearchConsumer = claudeTrafficResearchConsumer
        self.protectionBlockedConsumer = protectionBlockedConsumer
        self.protectedRetryConsumer = protectedRetryConsumer
    }

    func restore() async {
        guard !hasStartedRestore else { return }
        hasStartedRestore = true
        state = .restoring
        do {
            // Crash recovery can invoke networksetup and helper IPC. Run it on
            // the serialized runtime actor so the first window paints
            // immediately instead of blocking AppKit's launch callback.
            shouldResumeProtection =
                try await RuntimeCleanup.cleanupStaleRuntime()
            guard try keychain.string(for: .refreshToken) != nil else {
                // Signed out: never leave a previous session's kill switch armed.
                if !AppProfile.homeExitEnabled {
                    // A force-quit of an older Home-US build may have left its
                    // child daemon behind. Cleanup is local-only and does not
                    // invoke the Tailscale CLI or contact its control plane.
                    try? await sidecar.prepareCloudOnly()
                }
                do {
                    try await PrivilegedRuntimeCoordinator.shared.disarmKillSwitch()
                } catch {
                    state = .error(
                        "Tono could not release a protection state left by an earlier session. "
                        + "Run the documented sudo emergency-disarm command, then reopen Tono. "
                        + error.localizedDescription
                    )
                    return
                }
                shouldResumeProtection = false
                state = .signedOut
                await loadAuthMethods()
                return
            }
            // A stale crash state has already been stopped and DNS-restored.
            // PF remains armed with only Tono's bounded control-plane recovery
            // path; protection resumes after the authenticated cached/cloud
            // exit is ready below.
            if !AppProfile.homeExitEnabled {
                // The cloud-only path does not need the device inventory to
                // establish a protected route. Validate the account first,
                // then populate device-management UI in parallel with local
                // runtime preparation instead of adding another round trip to
                // the first-screen critical path.
                user = try await api.me().user
                guard user?.suspended != true else {
                    state = .suspended
                    return
                }
                refreshDevicesInBackground()
                await startCloudOnlyRuntime()
                return
            }
            // These are independent authenticated reads. TonoAPIClient
            // coalesces their access-token refresh, so restoring them
            // concurrently removes one control-plane round trip.
            async let meResponse = api.me()
            async let devicesResponse = api.devices()
            let (restoredUser, restoredDevices) = try await (
                meResponse.user,
                devicesResponse.devices
            )
            user = restoredUser
            devices = restoredDevices
            guard user?.suspended != true else { state = .suspended; return }
            device = devices.first(where: { $0.current == true })
            await resumeOrEnrollRuntime()
        } catch is CancellationError {
            // The restore task is scoped to the SwiftUI window. Closing and
            // recreating that window must be allowed to start a fresh restore
            // instead of stranding the session behind hasStartedRestore.
            hasStartedRestore = false
        } catch {
            await fail(error, signsOutOnUnauthorized: true)
        }
    }

    func loadAuthMethods() async {
        guard user == nil, !authMethodsLoading else { return }
        authMethodsLoading = true
        defer { authMethodsLoading = false }
        do {
            authMethods = try await api.authMethods()
        } catch is CancellationError {
            // SwiftUI cancels view-scoped tasks during ordinary transitions.
            // Cancellation is not a control-plane outage and must not replace
            // the sign-in screen with an error that immediately retries.
            return
        } catch {
            authMethods = nil
            if state != .authenticating {
                state = .error(
                    (error as? LocalizedError)?.errorDescription
                        ?? "Tono sign-in is temporarily unavailable."
                )
            }
        }
    }

    /// Re-runs the complete token/account validation after a transient launch
    /// failure. Retrying only the sign-in-method request would leave an existing
    /// refresh token stranded behind the login screen.
    func retryRestore() async {
        guard case .error = state else { return }
        hasStartedRestore = false
        await restore()
    }

    func requestEmailCode(email: String, deviceName: String) async {
        guard TonoAccountRules.validEmail(email) else {
            state = .error("Enter a valid email address.")
            return
        }
        state = .authenticating
        do {
            emailChallenge = try await api.startEmailSignIn(TonoEmailStartRequest(
                email: TonoAccountRules.normalizedEmail(email),
                deviceName: TonoAccountRules.normalizedDeviceName(deviceName),
                installationId: try keychain.installationId()
            ))
            state = .signedOut
        } catch {
            await fail(error)
        }
    }

    func verifyEmailCode(_ code: String) async {
        let normalizedCode = code.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let emailChallenge,
              normalizedCode.count == 6,
              normalizedCode.unicodeScalars.allSatisfy({ (48...57).contains($0.value) })
        else {
            state = .error("Enter the six-digit code from your email.")
            return
        }
        await authenticate {
            try await self.api.verifyEmailSignIn(TonoEmailVerifyRequest(
                challengeId: emailChallenge.challengeId,
                code: normalizedCode
            ))
        }
    }

    #if DEBUG
    func signInWithApple(deviceName: String) async {
        guard authMethods?.apple.enabled == true else {
            state = .error("Sign in with Apple is not configured.")
            return
        }
        await authenticate {
            let challenge = try await self.api.oidcChallenge(TonoOIDCChallengeRequest(
                provider: "apple",
                deviceName: TonoAccountRules.normalizedDeviceName(deviceName),
                installationId: try self.keychain.installationId()
            ))
            let token = try await AppleSignInCoordinator().identityToken(
                nonce: challenge.nonce
            )
            return try await self.api.verifyOIDC(TonoOIDCVerifyRequest(
                provider: "apple",
                challengeId: challenge.challengeId,
                idToken: token
            ))
        }
    }

    func signInWithGoogle(deviceName: String) async {
        guard authMethods?.google.enabled == true,
              let advertisedClientID = authMethods?.google.clientId
        else {
            state = .error("Google sign-in is not configured.")
            return
        }
        await authenticate {
            let challenge = try await self.api.oidcChallenge(TonoOIDCChallengeRequest(
                provider: "google",
                deviceName: TonoAccountRules.normalizedDeviceName(deviceName),
                installationId: try self.keychain.installationId()
            ))
            guard challenge.audience == advertisedClientID else {
                throw TonoAPIClient.APIError.invalidResponse
            }
            let token = try await GoogleSignInCoordinator.identityToken(
                clientID: advertisedClientID,
                nonce: challenge.nonce
            )
            return try await self.api.verifyOIDC(TonoOIDCVerifyRequest(
                provider: "google",
                challengeId: challenge.challengeId,
                idToken: token
            ))
        }
    }
    #endif

    func logout() async {
        await stopRuntime(logOutIdentity: true, releaseKillSwitch: true)
        await api.logout(); clearAccount(); state = .signedOut
    }

    func retryRuntime() async {
        if !AppProfile.homeExitEnabled {
            await startCloudOnlyRuntime()
        } else if device?.status == "pending" {
            await beginEnrollment()
        } else {
            await resumeOrEnrollRuntime()
        }
    }

    @discardableResult
    func refreshManagedCatalog(attempts: Int = 1) async -> Bool {
        let boundedAttempts = min(max(attempts, 1), 3)
        for attempt in 0..<boundedAttempts {
            do {
                try await catalogConsumer(try await api.exitCatalog())
                lastCatalogFailureMessage = nil
                return true
            } catch {
                // Keep the last verified, mode-0600 cache. Catalog
                // availability must never turn a temporary control-plane
                // failure into a clearnet fallback or erase usable exits.
                lastCatalogFailureMessage =
                    (error as? LocalizedError)?.errorDescription
                    ?? error.localizedDescription
                if attempt + 1 < boundedAttempts {
                    try? await Task.sleep(for: .seconds(1))
                }
            }
        }
        return false
    }

    @discardableResult
    func refreshManagedTrafficPolicy(attempts: Int = 1) async -> Bool {
        let boundedAttempts = min(max(attempts, 1), 3)
        for attempt in 0..<boundedAttempts {
            do {
                try await trafficPolicyConsumer(try await api.trafficPolicy())
                lastTrafficPolicyFailureMessage = nil
                return true
            } catch {
                // Direct routing is optional. A failed refresh keeps the last
                // verified policy; an absent policy never becomes clearnet.
                lastTrafficPolicyFailureMessage =
                    (error as? LocalizedError)?.errorDescription
                    ?? error.localizedDescription
                if attempt + 1 < boundedAttempts {
                    try? await Task.sleep(for: .seconds(1))
                }
            }
        }
        return false
    }

    func reloadDevices() async throws { devices = try await api.devices().devices }

    func revoke(_ target: TonoDevice) async {
        guard target.id != device?.id && target.current != true else { state = .error("The current device cannot revoke itself."); return }
        do { try await api.revokeDevice(target.id); try await reloadDevices() }
        catch { await fail(error) }
    }

    /// Transfers the one-time enrollment material and immediately removes the
    /// only credential-bearing copies retained by AccountSession.
    private func consumeEnrollmentCredentials() -> (authKey: String, hostname: String)? {
        defer {
            enrollmentAuthKey = nil
            enrollmentHostname = nil
        }
        guard let authKey = enrollmentAuthKey, !authKey.isEmpty,
              let hostname = enrollmentHostname, !hostname.isEmpty else {
            return nil
        }
        return (authKey, hostname)
    }

    private func adoptEnrollment(_ value: TonoEnrollment?) {
        enrollmentAuthKey = value?.authKey
        enrollmentHostname = value?.hostname
        // Keep only non-secret status metadata for observation/UI.
        enrollment = value.map {
            TonoEnrollment(
                id: $0.id,
                authKey: nil,
                hostname: nil,
                expiresAt: $0.expiresAt,
                state: $0.state
            )
        }
    }

    func beginEnrollment() async {
        guard AppProfile.homeExitEnabled else {
            await startCloudOnlyRuntime()
            return
        }
        guard let device else { state = .error("No Tono device is available to enroll."); return }
        state = .enrolling
        do {
            let response = try await api.enrollment(deviceId: device.id, installationId: keychain.installationId())
            adoptEnrollment(response.enrollment)
            guard let credentials = consumeEnrollmentCredentials() else {
                throw TonoAPIClient.APIError.invalidResponse
            }
            try await startSidecar(
                authKey: credentials.authKey,
                enrollmentHostname: credentials.hostname,
                confirm: true
            )
        } catch { await fail(error) }
    }

    private func authenticate(_ operation: () async throws -> TonoAuthResponse) async {
        state = .authenticating
        do {
            let response = try await operation(); try await api.adopt(response)
            emailChallenge = nil
            user = response.user
            device = response.device
            adoptEnrollment(response.enrollment)
            try await reloadDevices()
            if response.user.suspended == true { state = .suspended; return }
            if !AppProfile.homeExitEnabled {
                // Managed Reality exits authenticate directly with the Tono
                // control plane. They never consume or wait for a Tailscale
                // enrollment credential.
                enrollmentAuthKey = nil
                enrollmentHostname = nil
                enrollment = nil
                await startCloudOnlyRuntime()
            } else if response.enrollment == nil {
                await resumeOrEnrollRuntime()
            } else {
                state = .enrolling
                guard let credentials = consumeEnrollmentCredentials() else {
                    throw TonoAPIClient.APIError.invalidResponse
                }
                try await startSidecar(
                    authKey: credentials.authKey,
                    enrollmentHostname: credentials.hostname,
                    confirm: true
                )
            }
        } catch { await fail(error) }
    }

    /// Stops transport. Kill switch is released only on intentional logout/user disconnect.
    func stopRuntime(logOutIdentity: Bool = false, releaseKillSwitch: Bool = false) async {
        runtimeMonitor?.cancel()
        runtimeMonitor = nil
        catalogSyncTask?.cancel()
        catalogSyncTask = nil
        deviceRefreshTask?.cancel()
        deviceRefreshTask = nil
        deviceActionTask?.cancel()
        deviceActionTask = nil
        // Clear descriptor first so Mihomo stops, while kill switch may remain armed.
        await descriptorConsumer(nil)
        if AppProfile.homeExitEnabled {
            if logOutIdentity { await sidecar.logoutAndStop() }
            else { await sidecar.stop() }
        } else {
            // The VLESS-only profile never logs into Tailscale. Also clean a
            // verified stale child daemon left behind by an older app process.
            try? await sidecar.prepareCloudOnly()
        }
        if releaseKillSwitch {
            await releaseNetworkProtection()
        }
    }

    /// Explicit user escape hatch for a fail-closed host while the session is
    /// NOT ready (crash recovery with an unreachable control plane). Without
    /// it the sign-in gate and menu bar offered no way to restore internet.
    func restoreDirectInternet() async {
        await releaseNetworkProtection()
    }

    private func releaseNetworkProtection() async {
        await killSwitchDisarmConsumer()
        // The app-state consumer performs the same ordered transaction and
        // surfaces any UI error. Keep an idempotent fallback here for
        // launch/termination paths where that consumer is unavailable:
        // DNS must be restored before PF is opened.
        do {
            _ = try await PrivilegedRuntimeCoordinator.shared
                .restoreProtectedDNSIfConfigured()
            try await PrivilegedRuntimeCoordinator.shared.disarmKillSwitch()
        } catch {
            // Retain fail-closed protection when recovery cannot be proven.
        }
    }

    private func startSidecar(
        authKey: String?,
        enrollmentHostname: String? = nil,
        confirm: Bool
    ) async throws {
        guard AppProfile.homeExitEnabled else {
            try await startCloudOnlyRuntimeThrowing()
            return
        }
        guard !exitNode.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw TonoSidecarService.Error.exitNodeUnavailable("Set TonoExitNode in the app Info.plist")
        }

        // Arm kill switch BEFORE establishing tunnel so a mid-setup failure cannot leak.
        let apiHost = (Bundle.main.object(forInfoDictionaryKey: "TonoAPIBaseURL") as? String)
            .flatMap { URL(string: $0)?.host }
        try await PrivilegedRuntimeCoordinator.shared.prepareHelper()
        let protectedDNSState =
            await PrivilegedRuntimeCoordinator.shared.protectedDNSStatus()
        try await PrivilegedRuntimeCoordinator.shared.armKillSwitch(
            apiHosts: [apiHost].compactMap { $0 },
            exitNodeHints: [exitNode],
            tunnelInterfaces: [],
            proxyEndpoints: [],
            tailscaleBootstrapEnabled: confirm || AppProfile.homeExitEnabled,
            allowSystemResolution:
                !KillSwitchService.isArmed
                    && protectedDNSState.available
                    && !protectedDNSState.configured
                    && !protectedDNSState.snapshotPresent,
            helperPrepared: true
        )

        if confirm {
            guard let device, let authKey, let enrollmentHostname else {
                throw TonoAPIClient.APIError.invalidResponse
            }
            let identity = try await sidecar.enroll(
                authKey: authKey,
                hostname: enrollmentHostname
            )
            self.device = try await api.confirm(deviceId: device.id, identity: identity).device
            try await reloadDevices()
        }
        // Pull the authenticated catalog before choosing a data path. A failed
        // fetch leaves the last verified mode-0600 cache untouched.
        async let trafficPolicyRefresh: Bool = refreshManagedTrafficPolicy()
        await refreshManagedCatalog()
        _ = await trafficPolicyRefresh
        if !AppProfile.homeExitEnabled || cloudFallbackPreferred() {
            // A persisted managed-cloud selection is independent of Home-US.
            // While Home-US is disabled, every production launch takes this
            // path and skips its daemon/exit/SOCKS timeout chain completely.
            try await sidecar.prepareCloudOnly()
            try await activateCloudFallback()
        } else {
            do {
                try await sidecar.start(exitNode: exitNode)
                await descriptorConsumer(try await sidecar.descriptor())
                startRuntimeMonitor()
            } catch TonoSidecarService.Error.socksUnavailable {
                // Enrollment and confirm are already authoritative. Home-US is
                // an optional data path, so a failed home SOCKS probe must not
                // strand every separately authenticated managed cloud exit.
                await sidecar.stop()
                try await activateCloudFallback()
            } catch TonoSidecarService.Error.exitNodeUnavailable(_) {
                await sidecar.stop()
                try await activateCloudFallback()
            }
        }
        state = .ready
        startCatalogSync()
    }

    /// Starts the production VLESS Reality path without creating a Tailscale
    /// process, requesting an auth key, or depending on a Home-US exit node.
    private func startCloudOnlyRuntime() async {
        do {
            try await startCloudOnlyRuntimeThrowing()
        } catch {
            await fail(error)
        }
    }

    private func startCloudOnlyRuntimeThrowing() async throws {
        runtimeMonitor?.cancel()
        runtimeMonitor = nil
        await descriptorConsumer(nil)

        // Terminate a verified legacy Tono sidecar, including one left by an
        // older app process. This starts no daemon and performs no Tailscale
        // CLI, API, enrollment, or network operation.
        try await sidecar.prepareCloudOnly()

        // A normal signed-in-but-disconnected launch must leave the host's
        // network usable. The last authenticated mode-0600 catalog cache is
        // sufficient to paint the first usable screen; refreshing it is not a
        // launch gate and happens immediately in the background below.
        try await activateCloudFallback()
        state = .ready
        startCatalogSync(refreshImmediately: true)
    }

    private func startRuntimeMonitor() {
        runtimeMonitor?.cancel()
        runtimeMonitor = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(10))
                guard let self, !Task.isCancelled else { return }
                if await sidecar.isHealthy(exitNode: exitNode) == false {
                    // Drop the failed Home-US path but KEEP the kill switch
                    // armed. A separately authenticated managed cloud exit
                    // must not depend on the optional home sidecar remaining
                    // healthy after startup.
                    await descriptorConsumer(nil)
                    await sidecar.stop()
                    do {
                        try await activateCloudFallback()
                        state = .ready
                    } catch {
                        state = .error(
                            "The Tono home transport stopped and no managed cloud exit is available. Internet remains blocked by the kill switch."
                        )
                    }
                    return
                }
            }
        }
    }

    /// Prefer the last verified cache, then retry the authenticated catalog
    /// after the failed Home-US sidecar is fully stopped. The first catalog
    /// request can otherwise reuse a control-plane connection invalidated when
    /// PF is armed and its previous states are flushed.
    private func activateCloudFallback() async throws {
        do {
            try cloudFallbackConsumer(shouldResumeProtection)
            shouldResumeProtection = false
            return
        } catch {
            guard await refreshManagedCatalog(attempts: 2) else {
                let detail = lastCatalogFailureMessage.map { " \($0)" } ?? ""
                throw TonoSidecarService.Error.commandFailed(
                    "Managed cloud catalog is unavailable.\(detail)"
                )
            }
            try cloudFallbackConsumer(shouldResumeProtection)
            shouldResumeProtection = false
        }
    }

    private func startCatalogSync(refreshImmediately: Bool = false) {
        guard !systemSleeping else { return }
        catalogSyncTask?.cancel()
        catalogSyncTask = Task { [weak self] in
            if refreshImmediately {
                guard let self, !Task.isCancelled, state == .ready else { return }
                async let catalog: Bool = refreshManagedCatalog()
                async let policy: Bool = refreshManagedTrafficPolicy()
                _ = await (catalog, policy)
            }
            while !Task.isCancelled {
                // Catalog changes are not part of the packet-level leak
                // boundary. Five-minute synchronization keeps normal node
                // additions/removals prompt without maintaining a push socket
                // or waking every signed-in Mac once per minute. Launch and
                // explicit recovery paths still refresh immediately.
                try? await Task.sleep(for: .seconds(300))
                guard let self, !Task.isCancelled, state == .ready else { return }
                async let catalog: Bool = refreshManagedCatalog()
                async let policy: Bool = refreshManagedTrafficPolicy()
                _ = await (catalog, policy)
            }
        }
        updateRemoteDiagnosticsPolling()
    }

    func remoteDiagnosticsSettingChanged() {
        updateRemoteDiagnosticsPolling()
    }

    func prepareForSystemSleep() {
        systemSleeping = true
        catalogSyncTask?.cancel(); catalogSyncTask = nil
        deviceActionTask?.cancel(); deviceActionTask = nil
    }

    func resumeAfterSystemWake() {
        systemSleeping = false
        guard state == .ready else { return }
        startCatalogSync(refreshImmediately: false)
        // startCatalogSync resumes opted-in actions immediately, while its
        // catalog request waits for the normal timer and cannot race wake protection.
    }

    private func updateRemoteDiagnosticsPolling() {
        deviceActionTask?.cancel()
        deviceActionTask = nil
        guard state == .ready, !systemSleeping,
              AppProfile.defaults.bool(forKey: SettingsKey.remoteDiagnosticsEnabled) else { return }
        deviceActionTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self, state == .ready, !systemSleeping else { return }
                await pollDeviceActions()
                do { try await Task.sleep(for: .seconds(15)) } catch { return }
            }
        }
    }

    private func pollDeviceActions() async {
        guard !systemSleeping else { return }
        do {
            for action in try await api.deviceActions().actions {
                guard !Task.isCancelled, !systemSleeping else { return }
                guard action.expiresAt > Int(Date().timeIntervalSince1970) else {
                    continue
                }
                let result: TonoDeviceActionResult
                switch action.action {
                case .diagnosticSnapshot:
                    result = TonoDeviceActionResult(
                        outcome: "succeeded", message: nil,
                        snapshot: diagnosticSnapshotConsumer(),
                        trafficResearch: nil
                    )
                case .claudeTrafficSnapshot:
                    guard AppProfile.defaults.bool(
                        forKey: SettingsKey.claudeTrafficResearchEnabled
                    ) else {
                        result = TonoDeviceActionResult(
                            outcome: "failed",
                            message: "Claude traffic research is not enabled.",
                            snapshot: nil,
                            trafficResearch: nil
                        )
                        break
                    }
                    result = TonoDeviceActionResult(
                        outcome: "succeeded", message: nil, snapshot: nil,
                        trafficResearch: await claudeTrafficResearchConsumer()
                    )
                case .refreshCatalog:
                    // Support's one remote repair lever must cover the traffic
                    // policy too: a stale policy (WeChat direct pins) was
                    // previously unrepairable remotely.
                    let catalogRefreshed = await refreshManagedCatalog()
                    let policyRefreshed = await refreshManagedTrafficPolicy()
                    let succeeded = catalogRefreshed && policyRefreshed
                    result = TonoDeviceActionResult(
                        outcome: succeeded ? "succeeded" : "failed",
                        message: succeeded ? nil : [
                            catalogRefreshed ? nil : "Managed catalog refresh failed.",
                            policyRefreshed ? nil : "Traffic policy refresh failed.",
                        ].compactMap { $0 }.joined(separator: " "),
                        snapshot: nil,
                        trafficResearch: nil
                    )
                case .retryProtection:
                    guard protectionBlockedConsumer() else {
                        result = TonoDeviceActionResult(
                            outcome: "failed",
                            message: "Protection is not in Protected Offline state.",
                            snapshot: nil,
                            trafficResearch: nil
                        )
                        break
                    }
                    protectedRetryConsumer()
                    result = TonoDeviceActionResult(
                        outcome: "succeeded",
                        message: "Protected retry requested.",
                        snapshot: nil,
                        trafficResearch: nil
                    )
                }
                try await api.submitDeviceActionResult(id: action.id, result: result)
            }
        } catch {
            // A transient control-plane failure is retried by the next pull;
            // delivered actions are replayed by the Worker until completion.
        }
    }

    private func refreshDevicesInBackground() {
        deviceRefreshTask?.cancel()
        deviceRefreshTask = Task { [weak self] in
            guard let self else { return }
            do {
                let refreshed = try await api.devices().devices
                guard !Task.isCancelled else { return }
                devices = refreshed
                device = refreshed.first(where: { $0.current == true })
            } catch {
                // Device management can be retried from account settings. A
                // transient inventory failure must not hold the dashboard.
            }
        }
    }

    private func resumeOrEnrollRuntime() async {
        if !AppProfile.homeExitEnabled {
            await startCloudOnlyRuntime()
            return
        }
        do {
            try await startSidecar(authKey: nil, confirm: false)
        } catch TonoSidecarService.Error.needsEnrollment {
            await beginEnrollment()
        } catch {
            await fail(error)
        }
    }

    private func fail(_ error: Error, signsOutOnUnauthorized: Bool = false) async {
        // Task cancellation is an ownership/lifecycle event, not an account or
        // control-plane failure. In particular, do not turn URLSession -999
        // into a login error or tear down an otherwise protected route.
        guard !(error is CancellationError) else { return }
        runtimeMonitor?.cancel()
        runtimeMonitor = nil
        catalogSyncTask?.cancel()
        catalogSyncTask = nil
        deviceRefreshTask?.cancel()
        deviceRefreshTask = nil
        deviceActionTask?.cancel()
        deviceActionTask = nil
        await descriptorConsumer(nil)
        // Health / runtime failures keep kill switch; only auth sign-out disarms.
        if signsOutOnUnauthorized, error as? TonoAPIClient.APIError == .unauthorized {
            await sidecar.stop()
            await releaseNetworkProtection()
            await api.logout(); clearAccount(); state = .signedOut
        } else {
            // Leave kill switch armed if it was armed — prevents IP leak on failed reconnect.
            state = .error((error as? LocalizedError)?.errorDescription ?? "Something went wrong. Please try again.")
        }
    }
    private func clearAccount() {
        shouldResumeProtection = false
        user = nil
        device = nil
        enrollment = nil
        devices = []
        enrollmentAuthKey = nil
        enrollmentHostname = nil
        emailChallenge = nil
    }
}
