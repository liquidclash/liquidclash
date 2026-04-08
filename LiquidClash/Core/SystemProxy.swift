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
private struct ProxySnapshot: Codable {
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

struct SystemProxy {

    // MARK: UserDefaults Keys

    private static let didSetProxyKey = "LiquidClash_didSetSystemProxy"
    private static let snapshotKey = "LiquidClash_proxySnapshot"
    private static let activePortKey = "LiquidClash_activeProxyPort"
    private static let activeSocksPortKey = "LiquidClash_activeSocksPort"

    /// Mark that we have set the system proxy
    private static func markProxySet() {
        UserDefaults.standard.set(true, forKey: didSetProxyKey)
    }

    /// Clear the marker and snapshot
    private static func clearProxyMark() {
        UserDefaults.standard.removeObject(forKey: didSetProxyKey)
        UserDefaults.standard.removeObject(forKey: snapshotKey)
        UserDefaults.standard.removeObject(forKey: activePortKey)
        UserDefaults.standard.removeObject(forKey: activeSocksPortKey)
    }

    /// Check if we previously set the system proxy
    static var didSetProxy: Bool {
        UserDefaults.standard.bool(forKey: didSetProxyKey)
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

    /// Save current proxy settings to UserDefaults before we overwrite them
    private static func saveSnapshot(service: String) {
        let http = parseProxyInfo(["-getwebproxy", service])
        let https = parseProxyInfo(["-getsecurewebproxy", service])
        let socks = parseProxyInfo(["-getsocksfirewallproxy", service])

        let snapshot = ProxySnapshot(
            httpEnabled: http.enabled, httpServer: http.server, httpPort: http.port,
            httpsEnabled: https.enabled, httpsServer: https.server, httpsPort: https.port,
            socksEnabled: socks.enabled, socksServer: socks.server, socksPort: socks.port
        )

        if let data = try? JSONEncoder().encode(snapshot) {
            UserDefaults.standard.set(data, forKey: snapshotKey)
        }
    }

    /// Load saved snapshot
    private static func loadSnapshot() -> ProxySnapshot? {
        guard let data = UserDefaults.standard.data(forKey: snapshotKey) else { return nil }
        return try? JSONDecoder().decode(ProxySnapshot.self, from: data)
    }

    /// Get the primary network service name (e.g. "Wi-Fi")
    static func primaryNetworkService() -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
        process.arguments = ["-listallnetworkservices"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try? process.run()
        process.waitUntilExit()

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        guard let output = String(data: data, encoding: .utf8) else { return nil }

        let services = output.components(separatedBy: .newlines)
            .filter { !$0.isEmpty && !$0.contains("*") && !$0.contains("denotes") }

        for preferred in ["Wi-Fi", "Ethernet", "USB 10/100/1000 LAN"] {
            if services.contains(preferred) { return preferred }
        }
        return services.first
    }

    // MARK: - Enable System Proxy

    static func enable(httpPort: Int, socksPort: Int, service: String? = nil) throws {
        guard let networkService = service ?? primaryNetworkService() else {
            throw SystemProxyError.noNetworkService
        }

        // Save original settings before overwriting
        saveSnapshot(service: networkService)

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
            for args in commands {
                try runNetworkSetup(args)
            }
        } catch {
            try runNetworkSetupWithPrivileges(commands)
        }

        // Remember which ports we set (for Proxy Guard verification)
        UserDefaults.standard.set(httpPort, forKey: activePortKey)
        UserDefaults.standard.set(socksPort, forKey: activeSocksPortKey)
        markProxySet()
    }

    // MARK: - Disable / Restore System Proxy

    static func disable(service: String? = nil) throws {
        guard let networkService = service ?? primaryNetworkService() else {
            throw SystemProxyError.noNetworkService
        }

        // Restore original settings if we have a snapshot, otherwise just turn off
        if let snapshot = loadSnapshot() {
            try restore(snapshot, service: networkService)
        } else {
            let commands: [[String]] = [
                ["-setwebproxystate", networkService, "off"],
                ["-setsecurewebproxystate", networkService, "off"],
                ["-setsocksfirewallproxystate", networkService, "off"],
            ]
            do {
                for args in commands { try runNetworkSetup(args) }
            } catch {
                try runNetworkSetupWithPrivileges(commands)
            }
        }

        clearProxyMark()
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

        let expectedPort = UserDefaults.standard.integer(forKey: activePortKey)
        let expectedSocks = UserDefaults.standard.integer(forKey: activeSocksPortKey)
        guard expectedPort > 0 else { return true }

        let http = parseProxyInfo(["-getwebproxy", service])
        let socks = parseProxyInfo(["-getsocksfirewallproxy", service])

        return http.enabled && http.server == "127.0.0.1" && http.port == expectedPort
            && socks.enabled && socks.server == "127.0.0.1" && socks.port == expectedSocks
    }

    /// Re-apply our proxy settings (called by Proxy Guard when tampering detected)
    static func reapply() throws {
        let httpPort = UserDefaults.standard.integer(forKey: activePortKey)
        let socksPort = UserDefaults.standard.integer(forKey: activeSocksPortKey)
        guard httpPort > 0, socksPort > 0 else { return }
        guard let service = primaryNetworkService() else { return }

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
