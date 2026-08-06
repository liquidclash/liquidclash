import Foundation

/// Serializes every blocking helper, PF, and system-network operation away
/// from the main actor. Besides keeping SwiftUI responsive, one queue prevents
/// a late "arm" reply from racing past an intentional disconnect/disarm.
actor PrivilegedRuntimeCoordinator {
    static let shared = PrivilegedRuntimeCoordinator()

    func prepareHelper() throws {
        try HelperManager.installIfNeeded()
    }

    func daemonRejectsClient() -> Bool {
        HelperManager.daemonRejectsClient()
    }

    /// Explicit user-requested release is the one safe place to prompt for a
    /// rejecting helper repair. The actor keeps the probe and possible install
    /// ordered before core stop, DNS restoration, and PF disarm.
    func repairRejectingHelperForExplicitReleaseIfNeeded() throws {
        guard HelperManager.daemonRejectsClient() else { return }
        try KillSwitchService.installIfNeeded()
    }

    func installAndStartCore(
        configDirectory: String,
        configSHA256: String,
        helperPrepared: Bool = false
    ) throws {
        if !helperPrepared {
            try HelperManager.installIfNeeded()
        }
        try HelperManager.startCore(
            configDir: configDirectory,
            configSHA256: configSHA256
        )
    }

    func stopCore() throws {
        try HelperManager.stopCore()
    }

    func syncCoreConfig(configDirectory: String, configSHA256: String) throws -> String {
        try HelperManager.syncCoreConfig(
            configDir: configDirectory,
            configSHA256: configSHA256
        )
    }

    func coreStatus() -> (running: Bool, pid: Int?, lastError: String?) {
        HelperManager.coreStatus()
    }

    func armKillSwitch(
        apiHosts: [String]? = nil,
        exitNodeHints: [String]? = nil,
        tunnelInterfaces: [String]? = nil,
        proxyEndpoints: [ConfigPipeline.DialEndpoint]? = nil,
        sessionDirectEndpoints: [ConfigPipeline.DirectEndpoint]? = nil,
        tailscaleBootstrapEnabled: Bool? = nil,
        allowSystemResolution: Bool = false,
        helperPrepared: Bool = false
    ) throws {
        try KillSwitchService.arm(
            apiHosts: apiHosts,
            exitNodeHints: exitNodeHints,
            tunnelInterfaces: tunnelInterfaces,
            proxyEndpoints: proxyEndpoints,
            sessionDirectEndpoints: sessionDirectEndpoints,
            tailscaleBootstrapEnabled: tailscaleBootstrapEnabled,
            allowSystemResolution: allowSystemResolution,
            helperPrepared: helperPrepared
        )
    }

    func disarmKillSwitch() throws {
        try KillSwitchService.disarm()
    }

    func restrictKillSwitchToBootstrap() throws {
        try KillSwitchService.restrictToBootstrap()
    }

    func reassertKillSwitchIfNeeded() throws {
        try KillSwitchService.reassertIfNeeded()
    }

    func refreshKillSwitchStatus() -> KillSwitchService.StatusObservation {
        KillSwitchService.refreshStatus()
    }

    func cleanupStaleSystemProxy() {
        SystemProxy.cleanupIfStale()
    }

    func primaryNetworkService() -> String? {
        SystemProxy.primaryNetworkService()
    }

    func primaryNetworkInterface() -> String? {
        SystemProxy.primaryNetworkInterface()
    }

    func enableProtectedDNS(service: String) throws {
        try HelperManager.enableProtectedDNS(service: service)
    }

    func restoreProtectedDNS() throws {
        try HelperManager.restoreProtectedDNS()
    }

    @discardableResult
    func restoreProtectedDNSIfConfigured() throws -> Bool {
        try HelperManager.restoreProtectedDNSIfConfigured()
    }

    func protectedDNSIsIntact(service: String) -> Bool {
        let status = HelperManager.protectedDNSStatus()
        return status.configured && status.service == service
    }

    func protectedDNSStatus() -> (
        available: Bool,
        configured: Bool,
        snapshotPresent: Bool,
        service: String?
    ) {
        HelperManager.protectedDNSStatus()
    }

    func disableSystemProxyIfNeeded() throws {
        guard SystemProxy.didSetProxy else { return }
        try SystemProxy.disable()
    }

    func enableSystemProxy(httpPort: Int, socksPort: Int) throws {
        try SystemProxy.enable(httpPort: httpPort, socksPort: socksPort)
    }

    func replaceSystemProxy(httpPort: Int, socksPort: Int) throws {
        if SystemProxy.didSetProxy {
            try SystemProxy.disable()
        }
        try SystemProxy.enable(httpPort: httpPort, socksPort: socksPort)
    }

    func systemProxyIsIntact() -> Bool {
        SystemProxy.verifyProxyIntact()
    }

    func reapplySystemProxy() throws {
        try SystemProxy.reapply()
    }
}
