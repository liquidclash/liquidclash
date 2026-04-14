import Foundation

/// Manages the privileged helper daemon (liquidclash-helper).
/// Handles installation via osascript and IPC via Unix socket HTTP.
struct HelperManager {

    static let socketPath = "/tmp/liquidclash/service.sock"
    private static let helperInstallPath = "/Library/PrivilegedHelperTools/liquidclash-helper"
    private static let mihomoInstallPath = "/Library/PrivilegedHelperTools/mihomo"
    private static let plistInstallPath = "/Library/LaunchDaemons/liquidclash.helper.plist"
    private static let plistLabel = "liquidclash.helper"

    // MARK: - Installation

    /// Install the helper daemon if not already running. Prompts for admin password once.
    static func installIfNeeded() throws {
        // Already running?
        if isHelperRunning() { return }

        guard let helperSource = Bundle.main.url(forResource: "liquidclash-helper", withExtension: nil),
              let mihomoSource = Bundle.main.url(forResource: "mihomo", withExtension: nil),
              let plistSource = Bundle.main.url(forResource: "liquidclash.helper", withExtension: "plist") else {
            throw HelperInstallError.resourceNotFound
        }

        let helperSrc = helperSource.path.shellEscaped
        let mihomoSrc = mihomoSource.path.shellEscaped
        let plistSrc = plistSource.path.shellEscaped

        // Build install script: copy binaries, set permissions, load daemon
        let script = """
        mkdir -p /Library/PrivilegedHelperTools && \
        mkdir -p /tmp/liquidclash && chmod 755 /tmp/liquidclash && \
        cp \(helperSrc) '\(helperInstallPath)' && \
        cp \(mihomoSrc) '\(mihomoInstallPath)' && \
        cp \(plistSrc) '\(plistInstallPath)' && \
        chmod 755 '\(helperInstallPath)' && \
        chmod 755 '\(mihomoInstallPath)' && \
        chown root:wheel '\(helperInstallPath)' '\(mihomoInstallPath)' && \
        chmod 644 '\(plistInstallPath)' && \
        chown root:wheel '\(plistInstallPath)' && \
        launchctl bootout system/\(plistLabel) 2>/dev/null; \
        launchctl bootstrap system '\(plistInstallPath)'
        """

        let prompt = "LiquidClash 需要安装辅助服务以管理代理核心"
        let osascript = "do shell script \"\(script.replacingOccurrences(of: "\"", with: "\\\""))\" with administrator privileges with prompt \"\(prompt)\""

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        proc.arguments = ["-e", osascript]
        let errPipe = Pipe()
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = errPipe
        try proc.run()
        proc.waitUntilExit()

        if proc.terminationStatus != 0 {
            let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
            let errMsg = String(data: errData, encoding: .utf8) ?? ""
            if errMsg.contains("canceled") || errMsg.contains("User canceled") {
                throw HelperInstallError.userDenied
            }
            throw HelperInstallError.installFailed(errMsg)
        }

        // Wait for helper to start listening
        for _ in 0..<20 {
            if isHelperRunning() { return }
            usleep(250_000)
        }
        throw HelperInstallError.installFailed("Helper did not start after installation")
    }

    /// Check if helper is responding on the socket.
    static func isHelperRunning() -> Bool {
        guard let resp = try? sendRequest(method: "GET", path: "/version"),
              resp.contains("version") else { return false }
        return true
    }

    // MARK: - Core Management

    static func startCore(configDir: String) throws {
        let body = """
        {"configDir":"\(configDir.replacingOccurrences(of: "\"", with: "\\\""))"}
        """
        let resp = try sendRequest(method: "POST", path: "/core/start", body: body)
        if resp.contains("\"500\"") || resp.contains("error") {
            throw HelperIPCError.startFailed(resp)
        }
    }

    static func stopCore() throws {
        let resp = try sendRequest(method: "DELETE", path: "/core/stop")
        if resp.contains("\"500\"") {
            throw HelperIPCError.stopFailed(resp)
        }
    }

    static func coreStatus() -> (running: Bool, pid: Int?) {
        guard let resp = try? sendRequest(method: "GET", path: "/core/status"),
              let data = resp.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return (false, nil)
        }
        let running = json["running"] as? Bool ?? false
        let pid = json["pid"] as? Int
        return (running, pid)
    }

    // MARK: - Unix Socket HTTP Client

    private static func sendRequest(method: String, path: String, body: String? = nil) throws -> String {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw HelperIPCError.socketFailed }
        defer { close(fd) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        socketPath.withCString { ptr in
            withUnsafeMutablePointer(to: &addr.sun_path) { sunPath in
                sunPath.withMemoryRebound(to: CChar.self, capacity: 104) { dest in
                    _ = strlcpy(dest, ptr, 104)
                }
            }
        }

        let connectResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                connect(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connectResult == 0 else { throw HelperIPCError.connectFailed }

        // Build HTTP request
        var httpReq = "\(method) \(path) HTTP/1.1\r\nHost: localhost\r\n"
        if let body {
            httpReq += "Content-Type: application/json\r\nContent-Length: \(body.utf8.count)\r\n\r\n\(body)"
        } else {
            httpReq += "\r\n"
        }

        _ = httpReq.withCString { ptr in write(fd, ptr, strlen(ptr)) }

        // Read response
        var buffer = [UInt8](repeating: 0, count: 65536)
        let n = read(fd, &buffer, buffer.count)
        guard n > 0 else { throw HelperIPCError.emptyResponse }

        let raw = String(bytes: buffer[0..<n], encoding: .utf8) ?? ""
        // Extract body from HTTP response
        if let bodyStart = raw.range(of: "\r\n\r\n") {
            return String(raw[bodyStart.upperBound...])
        }
        return raw
    }
}

// MARK: - Errors

enum HelperInstallError: LocalizedError {
    case resourceNotFound
    case userDenied
    case installFailed(String)

    var errorDescription: String? {
        switch self {
        case .resourceNotFound: "Helper binary not found in app bundle."
        case .userDenied: "Administrator privileges denied."
        case .installFailed(let msg): "Helper installation failed: \(msg)"
        }
    }
}

enum HelperIPCError: LocalizedError {
    case socketFailed
    case connectFailed
    case emptyResponse
    case startFailed(String)
    case stopFailed(String)

    var errorDescription: String? {
        switch self {
        case .socketFailed: "Failed to create socket."
        case .connectFailed: "Cannot connect to helper daemon."
        case .emptyResponse: "Empty response from helper."
        case .startFailed(let msg): "Failed to start core: \(msg)"
        case .stopFailed(let msg): "Failed to stop core: \(msg)"
        }
    }
}

// MARK: - String Extension

private extension String {
    var shellEscaped: String {
        "'" + replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
