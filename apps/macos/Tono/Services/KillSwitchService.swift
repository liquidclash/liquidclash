import Foundation

/// System-level fail-closed Kill Switch.
///
/// PF state is owned by the same signed native privileged helper that launches
/// Mihomo. The helper authenticates Tono's kernel audit token and code-signing
/// requirement before accepting any arm, disarm, status, or core command.
nonisolated enum KillSwitchService {
    enum Error: LocalizedError {
        case installFailed(String)
        case notInstalled
        case commandFailed(String)
        case helperRejected
        case userDenied

        var errorDescription: String? {
            switch self {
            case .installFailed(let message):
                "Kill Switch install failed: \(message)"
            case .notInstalled:
                "The authenticated network helper is unavailable."
            case .commandFailed(let message):
                "Kill Switch command failed: \(message)"
            case .helperRejected:
                "The installed network helper rejected this copy of Tono."
            case .userDenied:
                "Administrator privileges were denied for the Kill Switch."
            }
        }
    }

    /// An authenticated status response is authoritative, while transport
    /// failure and peer rejection must preserve the app's local fail-closed
    /// intent. Keep rejection distinct so the UI can stop retrying and offer a
    /// signed helper repair instead of treating it as weak-network noise.
    enum StatusObservation: Sendable, Equatable {
        case unavailable
        case rejected
        case confirmed(requiresProtectionRecovery: Bool)
    }

    private static let stateKey = "Tono_killSwitchArmed"

    /// Whether the product intends the host to be fail-closed right now.
    static var isArmed: Bool {
        get { AppProfile.defaults.bool(forKey: stateKey) }
        set { AppProfile.defaults.set(newValue, forKey: stateKey) }
    }

    static var isHelperInstalled: Bool {
        HelperManager.isHelperRunning()
    }

    static func arm(
        apiHosts: [String]? = nil,
        exitNodeHints: [String]? = nil,
        tunnelInterfaces: [String]? = nil,
        proxyEndpoints: [ConfigPipeline.DialEndpoint]? = nil,
        sessionDirectEndpoints: [ConfigPipeline.DirectEndpoint]? = nil,
        tailscaleBootstrapEnabled: Bool? = nil,
        allowSystemResolution: Bool = false,
        helperPrepared: Bool = false
    ) throws {
        // A connect transaction can prepare the helper once, then perform its
        // ordered PF/core/PF operations without repeating authenticated version
        // probes. Every other caller retains the safe install-if-needed default.
        if !helperPrepared {
            try installIfNeeded()
        }
        do {
            let bootstrapPins = configuredBootstrapPins(for: apiHosts)
            let status = try HelperManager.armKillSwitch(
                apiHosts: apiHosts,
                exitNodeHints: exitNodeHints,
                tunnelInterfaces: tunnelInterfaces,
                proxyEndpoints: proxyEndpoints,
                sessionDirectEndpoints: sessionDirectEndpoints,
                tailscaleBootstrapEnabled: tailscaleBootstrapEnabled,
                allowSystemResolution: allowSystemResolution,
                bootstrapPins: bootstrapPins
            )
            guard status.armed, status.wanted, status.live else {
                throw Error.commandFailed("The PF rules did not become active.")
            }
            isArmed = true
        } catch HelperIPCError.forbidden {
            throw Error.helperRejected
        } catch let error as Error {
            throw error
        } catch {
            // The helper persists armed intent before loading PF. If the IPC
            // reply is lost after that commit, retain the fail-closed intent
            // locally instead of presenting the transition as unarmed.
            if let status = try? HelperManager.killSwitchStatus(),
               status.wanted || status.armed {
                isArmed = true
                // This very probe can run the helper's !live heal, which
                // reinstalls PF without the session exceptions the failed arm
                // carried. Record that so the session owner re-arms.
                if status.healed { needsSessionExceptionReassert = true }
            }
            throw Error.commandFailed(error.localizedDescription)
        }
    }

    /// Build-pinned addresses allow a Build 26 fail-closed state, whose active
    /// state erased its old control-plane resolution, to migrate without using
    /// the physical network's DNS. The helper independently validates that all
    /// pins are public and belong to an explicitly activated API host.
    private static func configuredBootstrapPins(
        for apiHosts: [String]?
    ) -> [String: [String]] {
        guard let apiHosts, !apiHosts.isEmpty,
              let apiHost = (Bundle.main.object(
                forInfoDictionaryKey: "TonoAPIBaseURL"
              ) as? String).flatMap({ URL(string: $0)?.host?.lowercased() }),
              apiHosts.contains(where: { $0.lowercased() == apiHost }),
              let addresses = Bundle.main.object(
                forInfoDictionaryKey: "TonoAPIBootstrapAddresses"
              ) as? [String], !addresses.isEmpty else {
            return [:]
        }
        return [apiHost: addresses]
    }

    /// Explicit disconnect/logout/quit path. DNS recovery is an invariant of
    /// every PF release, even if a caller forgets to request it separately.
    /// Failure leaves local intent armed so an unreachable helper can never be
    /// mistaken for a successful disarm.
    static func disarm() throws {
        // Recovery must remain possible across helper-version upgrades. An
        // older authenticated helper may not satisfy the current feature
        // version, but its status/disarm contract is still the authoritative
        // way to remove PF state that it installed.
        //
        // A single 2s status probe can time out while the serialized helper
        // finishes a bounded arm, and a corrupt persisted state makes status
        // answer ok=false — in both cases the daemon is present and
        // /killswitch/disarm (which clears that very state) must still be
        // attempted. Only a socket nobody answers is treated as absent.
        var reachable = false
        for attempt in 0..<3 {
            if (try? HelperManager.killSwitchStatus()) != nil
                || HelperManager.daemonAnswersSocket() {
                reachable = true
                break
            }
            if attempt < 2 { usleep(500_000) }
        }
        guard reachable else {
            if isArmed { throw Error.notInstalled }
            return
        }
        do {
            _ = try HelperManager.restoreProtectedDNSIfConfigured()
            try HelperManager.disarmKillSwitch()
            isArmed = false
        } catch HelperIPCError.forbidden {
            throw Error.helperRejected
        } catch {
            throw Error.commandFailed(error.localizedDescription)
        }
    }

    /// Set when the helper reports it self-healed PF from persisted state,
    /// which deliberately omits session direct endpoints. The owner of the
    /// live session must re-arm with its exceptions and only then clear this.
    /// Written from the privileged coordinator's executor and consumed on the
    /// main actor, so access is lock-guarded.
    private static let reassertLock = NSLock()
    nonisolated(unsafe) private static var reassertNeeded = false
    static var needsSessionExceptionReassert: Bool {
        get { reassertLock.withLock { reassertNeeded } }
        set { reassertLock.withLock { reassertNeeded = newValue } }
    }

    /// Observes effective helper-owned protection without mutating local intent.
    /// AppState commits a confirmed result only after checking that no newer
    /// connect/disconnect operation raced this IPC round trip.
    static func refreshStatus() -> StatusObservation {
        do {
            let status = try HelperManager.killSwitchStatus()
            if status.healed { needsSessionExceptionReassert = true }
            return .confirmed(
                requiresProtectionRecovery: status.armed || status.wanted
            )
        } catch HelperIPCError.forbidden {
            return .rejected
        } catch {
            return .unavailable
        }
    }

    /// After an app crash, re-supply control-plane metadata while keeping the
    /// stored fail-closed intent. The helper itself also restores PF at boot.
    static func reassertIfNeeded() throws {
        guard isArmed else { return }
        let apiHost = (Bundle.main.object(forInfoDictionaryKey: "TonoAPIBaseURL") as? String)
            .flatMap { URL(string: $0)?.host }
        let exitNode = (Bundle.main.object(forInfoDictionaryKey: "TonoExitNode") as? String)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        try arm(
            // nil preserves a previously authenticated/persisted host if a
            // malformed bundle unexpectedly omits this metadata. An explicit
            // empty array would erase the only bounded recovery path.
            apiHosts: apiHost.map { [$0] },
            exitNodeHints: AppProfile.homeExitEnabled && !exitNode.isEmpty ? [exitNode] : [],
            tunnelInterfaces: [],
            proxyEndpoints: [],
            sessionDirectEndpoints: [],
            tailscaleBootstrapEnabled: AppProfile.homeExitEnabled,
            allowSystemResolution: false
        )
    }

    /// Remove tunnel and proxy exceptions while preserving the control plane.
    /// Tailscale bootstrap remains available only when Home-US is enabled.
    static func restrictToBootstrap() throws {
        guard isArmed else { return }
        let apiHost = (Bundle.main.object(forInfoDictionaryKey: "TonoAPIBaseURL") as? String)
            .flatMap { URL(string: $0)?.host }
        try arm(
            apiHosts: apiHost.map { [$0] },
            tunnelInterfaces: [],
            proxyEndpoints: [],
            sessionDirectEndpoints: [],
            tailscaleBootstrapEnabled: AppProfile.homeExitEnabled,
            allowSystemResolution: false
        )
    }

    static func interfaceExists(_ name: String) -> Bool {
        name.withCString { if_nametoindex($0) != 0 }
    }

    static func installIfNeeded() throws {
        do {
            try HelperManager.installIfNeeded()
        } catch HelperInstallError.userDenied {
            throw Error.userDenied
        } catch {
            throw Error.installFailed(error.localizedDescription)
        }
    }
}
