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

// MARK: - System Proxy Manager

struct SystemProxy {

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

        // Prefer Wi-Fi, then Ethernet
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

        let commands: [[String]] = [
            ["-setproxybypassdomains", networkService, "localhost", "127.0.0.1", "*.local"],
            ["-setwebproxy", networkService, "127.0.0.1", "\(httpPort)"],
            ["-setwebproxystate", networkService, "on"],
            ["-setsecurewebproxy", networkService, "127.0.0.1", "\(httpPort)"],
            ["-setsecurewebproxystate", networkService, "on"],
            ["-setsocksfirewallproxy", networkService, "127.0.0.1", "\(socksPort)"],
            ["-setsocksfirewallproxystate", networkService, "on"],
        ]

        // Try without privileges first
        do {
            for args in commands {
                try runNetworkSetup(args)
            }
        } catch {
            // Retry with admin privileges via osascript
            try runNetworkSetupWithPrivileges(commands)
        }
    }

    // MARK: - Disable System Proxy

    static func disable(service: String? = nil) throws {
        guard let networkService = service ?? primaryNetworkService() else {
            throw SystemProxyError.noNetworkService
        }

        let commands: [[String]] = [
            ["-setwebproxystate", networkService, "off"],
            ["-setsecurewebproxystate", networkService, "off"],
            ["-setsocksfirewallproxystate", networkService, "off"],
        ]

        do {
            for args in commands {
                try runNetworkSetup(args)
            }
        } catch {
            try runNetworkSetupWithPrivileges(commands)
        }
    }

    // MARK: - Cleanup Stale Proxy

    /// Check if system proxy is pointing to localhost (our proxy) and disable it.
    /// Called on app launch to clean up after crash/force-quit.
    static func cleanupIfStale() {
        guard let service = primaryNetworkService() else { return }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
        process.arguments = ["-getwebproxy", service]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try? process.run()
        process.waitUntilExit()

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""

        // If proxy is enabled and points to 127.0.0.1, it's ours — clean it up
        if output.contains("Enabled: Yes") && output.contains("Server: 127.0.0.1") {
            try? disable(service: service)
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
