import Foundation

// MARK: - System Proxy Error

enum SystemProxyError: LocalizedError {
    case noNetworkService
    case commandFailed(String)
    case privilegesDenied

    var errorDescription: String? {
        switch self {
        case .noNetworkService:
            "No active network service found."
        case .commandFailed(let detail):
            "System proxy command failed: \(detail)"
        case .privilegesDenied:
            "Administrator privileges were denied."
        }
    }
}

// MARK: - Saved Proxy State

/// Snapshot of the original system proxy settings before we modify them.
nonisolated private struct ProxySnapshot: Codable {
    var httpEnabled: Bool
    var httpServer: String
    var httpPort: Int
    var httpsEnabled: Bool
    var httpsServer: String
    var httpsPort: Int
    var socksEnabled: Bool
    var socksServer: String
    var socksPort: Int
}

// MARK: - System Proxy Manager

nonisolated struct SystemProxy {

    // MARK: UserDefaults Keys

    private static let didSetProxyKey = "Tono_didSetSystemProxy"
    private static let snapshotKey = "Tono_proxySnapshot"
    private static let activePortKey = "Tono_activeProxyPort"
    private static let activeSocksPortKey = "Tono_activeSocksPort"
    private static let activeServiceKey = "Tono_activeProxyService"

    /// Mark that we have set the system proxy
    private static func markProxySet() {
        AppProfile.defaults.set(true, forKey: didSetProxyKey)
    }

    /// Clear the marker and snapshot
    private static func clearProxyMark() {
        AppProfile.defaults.removeObject(forKey: didSetProxyKey)
        AppProfile.defaults.removeObject(forKey: snapshotKey)
        AppProfile.defaults.removeObject(forKey: activePortKey)
        AppProfile.defaults.removeObject(forKey: activeSocksPortKey)
        AppProfile.defaults.removeObject(forKey: activeServiceKey)
    }

    /// Check if we previously set the system proxy
    static var didSetProxy: Bool {
        AppProfile.defaults.bool(forKey: didSetProxyKey)
    }

    // MARK: - Read Current Proxy Settings

    /// Parse output of networksetup -getwebproxy / -getsecurewebproxy / -getsocksfirewallproxy
    private static func parseProxyInfo(_ arguments: [String]) -> (enabled: Bool, server: String, port: Int) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try? process.run()
        process.waitUntilExit()

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""

        var enabled = false
        var server = ""
        var port = 0

        for line in output.components(separatedBy: .newlines) {
            let parts = line.components(separatedBy: ": ")
            guard parts.count == 2 else { continue }
            let key = parts[0].trimmingCharacters(in: .whitespaces)
            let value = parts[1].trimmingCharacters(in: .whitespaces)
            switch key {
            case "Enabled": enabled = (value == "Yes")
            case "Server": server = value
            case "Port": port = Int(value) ?? 0
            default: break
            }
        }
        return (enabled, server, port)
    }

    /// Capture current proxy settings before we overwrite them.
    private static func snapshot(for service: String) -> ProxySnapshot {
        let http = parseProxyInfo(["-getwebproxy", service])
        let https = parseProxyInfo(["-getsecurewebproxy", service])
        let socks = parseProxyInfo(["-getsocksfirewallproxy", service])

        return ProxySnapshot(
            httpEnabled: http.enabled, httpServer: http.server, httpPort: http.port,
            httpsEnabled: https.enabled, httpsServer: https.server, httpsPort: https.port,
            socksEnabled: socks.enabled, socksServer: socks.server, socksPort: socks.port
        )
    }

    /// Save current proxy settings to UserDefaults before we overwrite them
    private static func saveSnapshot(service: String) {
        persistSnapshot(snapshot(for: service))
    }

    private static func persistSnapshot(_ snapshot: ProxySnapshot) {
        if let data = try? JSONEncoder().encode(snapshot) {
            AppProfile.defaults.set(data, forKey: snapshotKey)
        }
    }

    /// Load saved snapshot
    private static func loadSnapshot() -> ProxySnapshot? {
        guard let data = AppProfile.defaults.data(forKey: snapshotKey) else { return nil }
        return try? JSONDecoder().decode(ProxySnapshot.self, from: data)
    }

    /// List all available network service names
    private static func listNetworkServices() -> [String] {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
        process.arguments = ["-listallnetworkservices"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try? process.run()
        process.waitUntilExit()

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        guard let output = String(data: data, encoding: .utf8) else { return [] }

        return output.components(separatedBy: .newlines)
            .filter { !$0.isEmpty && !$0.contains("*") && !$0.contains("denotes") }
    }

    /// Get the BSD interface currently used by the default IPv4 route.
    static func primaryNetworkInterface() -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/sbin/route")
        process.arguments = ["-n", "get", "default"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try? process.run()
        process.waitUntilExit()

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        guard let output = String(data: data, encoding: .utf8) else { return nil }

        for line in output.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("interface:") else { continue }
            let interface = trimmed
                .replacingOccurrences(of: "interface:", with: "")
                .trimmingCharacters(in: .whitespaces)
            return interface.isEmpty ? nil : interface
        }

        return nil
    }

    /// Resolve a networksetup service name from a BSD interface such as en0.
    private static func networkService(for interface: String) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
        process.arguments = ["-listnetworkserviceorder"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try? process.run()
        process.waitUntilExit()

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        guard let output = String(data: data, encoding: .utf8) else { return nil }

        var currentService: String?
        for line in output.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("("), let end = trimmed.firstIndex(of: ")") {
                let service = trimmed[trimmed.index(after: end)...]
                    .trimmingCharacters(in: .whitespaces)
                currentService = service.hasPrefix("*")
                    ? String(service.dropFirst()).trimmingCharacters(in: .whitespaces)
                    : service
                continue
            }

            if let deviceRange = trimmed.range(of: "Device: ") {
                var device = String(trimmed[deviceRange.upperBound...])
                if let closingIndex = device.firstIndex(of: ")") {
                    device = String(device[..<closingIndex])
                }
                device = device.trimmingCharacters(in: .whitespaces)
                if device == interface, let currentService {
                    return currentService
                }
            }
        }

        return nil
    }

    /// Get the primary network service name (e.g. "Wi-Fi")
    static func primaryNetworkService() -> String? {
        if let interface = primaryNetworkInterface(),
           let service = networkService(for: interface) {
            return service
        }

        let services = listNetworkServices()
        if let wifi = services.first(where: { $0 == "Wi-Fi" || $0.hasPrefix("Wi-Fi ") }) {
            return wifi
        }

        for preferred in ["Wi-Fi", "Ethernet", "USB 10/100/1000 LAN"] {
            if services.contains(preferred) { return preferred }
        }
        return services.first
    }

    /// Resolve the saved service name, falling back to primary if the saved one no longer exists
    private static func savedOrPrimaryService() -> String? {
        if let saved = AppProfile.defaults.string(forKey: activeServiceKey) {
            if listNetworkServices().contains(saved) {
                return saved
            }
        }
        return primaryNetworkService()
    }

    // MARK: - Enable System Proxy

    static func enable(httpPort: Int, socksPort: Int, service: String? = nil) throws {
        guard let networkService = service ?? primaryNetworkService() else {
            throw SystemProxyError.noNetworkService
        }

        // Persist recovery state before the first networksetup mutation. If the
        // process is killed between commands, the next launch must still know
        // which service and snapshot to restore.
        saveSnapshot(service: networkService)
        AppProfile.defaults.set(networkService, forKey: activeServiceKey)
        AppProfile.defaults.set(httpPort, forKey: activePortKey)
        AppProfile.defaults.set(socksPort, forKey: activeSocksPortKey)
        markProxySet()

        let commands: [[String]] = [
            ["-setproxybypassdomains", networkService, "localhost", "127.0.0.1", "*.local"],
            ["-setwebproxy", networkService, "127.0.0.1", "\(httpPort)"],
            ["-setwebproxystate", networkService, "on"],
            ["-setsecurewebproxy", networkService, "127.0.0.1", "\(httpPort)"],
            ["-setsecurewebproxystate", networkService, "on"],
            ["-setsocksfirewallproxy", networkService, "127.0.0.1", "\(socksPort)"],
            ["-setsocksfirewallproxystate", networkService, "on"],
        ]

        do {
            do {
                for args in commands {
                    try runNetworkSetup(args)
                }
            } catch {
                try runNetworkSetupWithPrivileges(commands)
            }
        } catch {
            // A failed command sequence may have already changed one or more
            // proxy classes. Roll back immediately when possible; otherwise
            // retain the marker so cleanupIfStale() retries on next launch.
            do {
                try restoreOrTurnOffProxy(service: networkService)
                clearProxyMark()
            } catch {
                // Preserve the original failure while keeping recovery state.
            }
            throw error
        }
    }

    // MARK: - Disable / Restore System Proxy

    static func disable(service: String? = nil) throws {
        guard let networkService = service ?? savedOrPrimaryService() else {
            throw SystemProxyError.noNetworkService
        }

        try restoreOrTurnOffProxy(service: networkService)
        clearProxyMark()
    }

    /// Restore original settings if we have a snapshot, otherwise just turn off.
    private static func restoreOrTurnOffProxy(service: String) throws {
        if let snapshot = loadSnapshot() {
            try restore(snapshot, service: service)
        } else {
            try turnOffProxy(service: service)
        }
    }

    private static func turnOffProxy(service: String) throws {
        let commands: [[String]] = [
            ["-setwebproxystate", service, "off"],
            ["-setsecurewebproxystate", service, "off"],
            ["-setsocksfirewallproxystate", service, "off"],
        ]
        do {
            for args in commands { try runNetworkSetup(args) }
        } catch {
            try runNetworkSetupWithPrivileges(commands)
        }
    }

    /// Restore proxy settings from a snapshot
    private static func restore(_ snapshot: ProxySnapshot, service: String) throws {
        var commands: [[String]] = []

        if snapshot.httpEnabled && !snapshot.httpServer.isEmpty {
            commands.append(["-setwebproxy", service, snapshot.httpServer, "\(snapshot.httpPort)"])
            commands.append(["-setwebproxystate", service, "on"])
        } else {
            commands.append(["-setwebproxystate", service, "off"])
        }

        if snapshot.httpsEnabled && !snapshot.httpsServer.isEmpty {
            commands.append(["-setsecurewebproxy", service, snapshot.httpsServer, "\(snapshot.httpsPort)"])
            commands.append(["-setsecurewebproxystate", service, "on"])
        } else {
            commands.append(["-setsecurewebproxystate", service, "off"])
        }

        if snapshot.socksEnabled && !snapshot.socksServer.isEmpty {
            commands.append(["-setsocksfirewallproxy", service, snapshot.socksServer, "\(snapshot.socksPort)"])
            commands.append(["-setsocksfirewallproxystate", service, "on"])
        } else {
            commands.append(["-setsocksfirewallproxystate", service, "off"])
        }

        do {
            for args in commands { try runNetworkSetup(args) }
        } catch {
            try runNetworkSetupWithPrivileges(commands)
        }
    }

    // MARK: - Cleanup Stale Proxy

    /// Restore system proxy only if we previously set it (tracked via UserDefaults marker).
    /// Called on app launch to recover from crash/force-quit.
    static func cleanupIfStale() {
        guard didSetProxy else { return }
        guard primaryNetworkService() != nil else { return }

        try? disable()
    }

    // MARK: - Proxy Guard

    /// Check if system proxy still points to our ports. Returns false if tampered.
    static func verifyProxyIntact() -> Bool {
        guard didSetProxy else { return true }
        guard let service = primaryNetworkService() else { return true }

        let expectedPort = AppProfile.defaults.integer(forKey: activePortKey)
        let expectedSocks = AppProfile.defaults.integer(forKey: activeSocksPortKey)
        guard expectedPort > 0 else { return true }

        if let saved = AppProfile.defaults.string(forKey: activeServiceKey), saved != service {
            return false
        }

        let http = parseProxyInfo(["-getwebproxy", service])
        let socks = parseProxyInfo(["-getsocksfirewallproxy", service])

        return http.enabled && http.server == "127.0.0.1" && http.port == expectedPort
            && socks.enabled && socks.server == "127.0.0.1" && socks.port == expectedSocks
    }

    /// Re-apply our proxy settings (called by Proxy Guard when tampering detected)
    static func reapply() throws {
        let httpPort = AppProfile.defaults.integer(forKey: activePortKey)
        let socksPort = AppProfile.defaults.integer(forKey: activeSocksPortKey)
        guard httpPort > 0, socksPort > 0 else { return }
        guard let service = primaryNetworkService() else { return }

        let savedService = AppProfile.defaults.string(forKey: activeServiceKey)
        let replacementSnapshot: ProxySnapshot?
        if let savedService, savedService != service {
            try? restoreOrTurnOffProxy(service: savedService)
            replacementSnapshot = snapshot(for: service)
        } else if savedService == nil {
            replacementSnapshot = snapshot(for: service)
        } else {
            replacementSnapshot = nil
        }

        let commands: [[String]] = [
            ["-setwebproxy", service, "127.0.0.1", "\(httpPort)"],
            ["-setwebproxystate", service, "on"],
            ["-setsecurewebproxy", service, "127.0.0.1", "\(httpPort)"],
            ["-setsecurewebproxystate", service, "on"],
            ["-setsocksfirewallproxy", service, "127.0.0.1", "\(socksPort)"],
            ["-setsocksfirewallproxystate", service, "on"],
        ]

        do {
            for args in commands { try runNetworkSetup(args) }
        } catch {
            try runNetworkSetupWithPrivileges(commands)
        }

        if let replacementSnapshot {
            persistSnapshot(replacementSnapshot)
        }
        AppProfile.defaults.set(service, forKey: activeServiceKey)
        AppProfile.defaults.set(httpPort, forKey: activePortKey)
        AppProfile.defaults.set(socksPort, forKey: activeSocksPortKey)
        markProxySet()
    }

    // MARK: - Helpers

    /// Run networksetup and throw on failure
    private static func runNetworkSetup(_ arguments: [String]) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
        process.arguments = arguments
        let errPipe = Pipe()
        process.standardOutput = FileHandle.nullDevice
        process.standardError = errPipe
        try process.run()
        process.waitUntilExit()

        if process.terminationStatus != 0 {
            let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
            let errMsg = String(data: errData, encoding: .utf8) ?? "exit code \(process.terminationStatus)"
            throw SystemProxyError.commandFailed(errMsg.trimmingCharacters(in: .whitespacesAndNewlines))
        }
    }

    /// Run multiple networksetup commands with admin privileges via osascript
    private static func runNetworkSetupWithPrivileges(_ commands: [[String]]) throws {
        // Build a single shell script with all commands
        let shellCommands = commands.map { args in
            let escaped = args.map { "'\($0.replacingOccurrences(of: "'", with: "'\\''"))'" }
            return "/usr/sbin/networksetup " + escaped.joined(separator: " ")
        }.joined(separator: " && ")

        let script = "do shell script \"\(shellCommands.replacingOccurrences(of: "\"", with: "\\\""))\" with administrator privileges"

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", script]
        let errPipe = Pipe()
        process.standardOutput = FileHandle.nullDevice
        process.standardError = errPipe
        try process.run()
        process.waitUntilExit()

        if process.terminationStatus != 0 {
            let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
            let errMsg = String(data: errData, encoding: .utf8) ?? ""
            if errMsg.contains("canceled") || errMsg.contains("User canceled") {
                throw SystemProxyError.privilegesDenied
            }
            throw SystemProxyError.commandFailed(errMsg.trimmingCharacters(in: .whitespacesAndNewlines))
        }
    }
}
