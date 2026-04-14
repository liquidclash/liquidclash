import Foundation

// MARK: - LiquidClash Helper Daemon
// A lightweight root daemon that manages the mihomo process lifecycle.
// Listens on a Unix socket for HTTP commands from the LiquidClash app.

let version = "1.0.0"
let socketDir = "/tmp/liquidclash"
let socketPath = "\(socketDir)/service.sock"

// mihomo binary is stored alongside this helper at install time
let mihomoSearchPaths = [
    "/Library/PrivilegedHelperTools/mihomo",                          // installed alongside helper
    Bundle.main.bundlePath + "/../mihomo",                            // relative to helper binary
]

// MARK: - Process Manager

final class CoreManager {
    private var process: Process?
    private var logBuffer: [String] = []
    private let maxLogs = 500

    var isRunning: Bool { process?.isRunning ?? false }
    var pid: Int32? { process?.isRunning == true ? process!.processIdentifier : nil }

    func start(configDir: String) throws {
        if isRunning { try stop() }
        // Kill any stale mihomo processes not managed by us
        let pkill = Process()
        pkill.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
        pkill.arguments = ["-f", "mihomo"]
        pkill.standardOutput = FileHandle.nullDevice
        pkill.standardError = FileHandle.nullDevice
        try? pkill.run()
        pkill.waitUntilExit()
        usleep(500_000)

        guard let binary = findMihomo() else {
            throw HelperError.binaryNotFound
        }

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: binary)
        proc.arguments = ["-d", configDir]

        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = pipe

        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty, let line = String(data: data, encoding: .utf8) else { return }
            self?.appendLog(line)
        }

        proc.terminationHandler = { [weak self] _ in
            pipe.fileHandleForReading.readabilityHandler = nil
            self?.appendLog("[helper] mihomo exited")
        }

        try proc.run()
        process = proc
        appendLog("[helper] mihomo started, pid=\(proc.processIdentifier)")
    }

    func stop() throws {
        guard let proc = process, proc.isRunning else {
            process = nil
            return
        }
        proc.terminate()
        proc.waitUntilExit()
        process = nil
        appendLog("[helper] mihomo stopped")
    }

    func getLogs() -> [String] { logBuffer }

    private func appendLog(_ text: String) {
        let lines = text.components(separatedBy: .newlines).filter { !$0.isEmpty }
        logBuffer.append(contentsOf: lines)
        if logBuffer.count > maxLogs {
            logBuffer.removeFirst(logBuffer.count - maxLogs)
        }
    }

    private func findMihomo() -> String? {
        for path in mihomoSearchPaths {
            if FileManager.default.isExecutableFile(atPath: path) {
                return path
            }
        }
        return nil
    }
}

enum HelperError: Error {
    case binaryNotFound
}

// MARK: - HTTP over Unix Socket Server

final class SocketServer {
    let core = CoreManager()
    private var serverSocket: Int32 = -1
    private var running = true

    func start() {
        setupSocket()
        log("listening on \(socketPath)")

        // Handle SIGTERM/SIGINT gracefully — stop mihomo before exiting
        signal(SIGTERM) { _ in exit(0) }
        signal(SIGINT) { _ in exit(0) }
        atexit {
            // Kill managed mihomo process on exit
            let pkill = Process()
            pkill.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
            pkill.arguments = ["-f", "mihomo"]
            pkill.standardOutput = FileHandle.nullDevice
            pkill.standardError = FileHandle.nullDevice
            try? pkill.run()
            pkill.waitUntilExit()
            unlink(socketPath)
        }

        while running {
            let client = accept(serverSocket, nil, nil)
            guard client >= 0 else { continue }
            DispatchQueue.global().async { [weak self] in
                self?.handleClient(client)
                close(client)
            }
        }
    }

    private func setupSocket() {
        // Create socket directory with open permissions
        try? FileManager.default.createDirectory(atPath: socketDir, withIntermediateDirectories: true)
        chmod(socketDir, 0o755)

        // Remove stale socket
        unlink(socketPath)

        serverSocket = socket(AF_UNIX, SOCK_STREAM, 0)
        guard serverSocket >= 0 else { fatalError("socket() failed") }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        socketPath.withCString { ptr in
            withUnsafeMutablePointer(to: &addr.sun_path) { sunPath in
                let bound = sunPath.withMemoryRebound(to: CChar.self, capacity: 104) { dest in
                    strlcpy(dest, ptr, 104)
                }
                _ = bound
            }
        }

        let bindResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                bind(serverSocket, sockPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bindResult == 0 else { fatalError("bind() failed: \(errno)") }

        // Allow all local users to connect (like Verge)
        chmod(socketPath, 0o777)

        guard listen(serverSocket, 5) == 0 else { fatalError("listen() failed") }
    }

    // MARK: - Request Handling

    private func handleClient(_ fd: Int32) {
        var buffer = [UInt8](repeating: 0, count: 8192)
        let n = read(fd, &buffer, buffer.count)
        guard n > 0 else { return }

        let raw = String(bytes: buffer[0..<n], encoding: .utf8) ?? ""
        let (method, path, body) = parseHTTP(raw)

        let response: String
        switch (method, path) {
        case ("GET", "/version"):
            response = jsonResponse(200, ["version": version])

        case ("POST", "/core/start"):
            if let data = body.data(using: .utf8),
               let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let configDir = json["configDir"] as? String {
                do {
                    try core.start(configDir: configDir)
                    response = jsonResponse(200, ["message": "started"])
                } catch {
                    response = jsonResponse(500, ["message": error.localizedDescription])
                }
            } else {
                response = jsonResponse(400, ["message": "missing configDir"])
            }

        case ("DELETE", "/core/stop"):
            do {
                try core.stop()
                response = jsonResponse(200, ["message": "stopped"])
            } catch {
                response = jsonResponse(500, ["message": error.localizedDescription])
            }

        case ("GET", "/core/status"):
            let status: [String: Any] = [
                "running": core.isRunning,
                "pid": core.pid as Any
            ]
            response = jsonResponse(200, status)

        case ("GET", "/core/logs"):
            let logs = core.getLogs()
            if let data = try? JSONSerialization.data(withJSONObject: ["logs": logs]),
               let json = String(data: data, encoding: .utf8) {
                response = httpResponse(200, json)
            } else {
                response = jsonResponse(500, ["message": "log serialization failed"])
            }

        default:
            response = jsonResponse(404, ["message": "not found"])
        }

        _ = response.withCString { ptr in
            write(fd, ptr, strlen(ptr))
        }
    }

    // MARK: - HTTP Parsing (minimal)

    private func parseHTTP(_ raw: String) -> (method: String, path: String, body: String) {
        let parts = raw.components(separatedBy: "\r\n\r\n")
        let body = parts.count > 1 ? parts[1] : ""
        let firstLine = raw.components(separatedBy: "\r\n").first ?? ""
        let tokens = firstLine.split(separator: " ")
        let method = tokens.count > 0 ? String(tokens[0]) : ""
        let path = tokens.count > 1 ? String(tokens[1]) : ""
        return (method, path, body)
    }

    private func jsonResponse(_ code: Int, _ dict: [String: Any]) -> String {
        let data = (try? JSONSerialization.data(withJSONObject: dict)) ?? Data()
        let json = String(data: data, encoding: .utf8) ?? "{}"
        return httpResponse(code, json)
    }

    private func httpResponse(_ code: Int, _ body: String) -> String {
        "HTTP/1.1 \(code) OK\r\nContent-Type: application/json\r\nContent-Length: \(body.utf8.count)\r\n\r\n\(body)"
    }
}

// MARK: - Logging

func log(_ msg: String) {
    let df = DateFormatter()
    df.dateFormat = "HH:mm:ss"
    print("[\(df.string(from: Date()))] \(msg)")
}

// MARK: - Main

log("liquidclash-helper v\(version) starting")
let server = SocketServer()
server.start()
