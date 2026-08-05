import Foundation
import Network
import Darwin

nonisolated private final class TonoLockedBox<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Value
    init(_ value: Value) { self.value = value }
    func withLock<Result>(_ body: (inout Value) -> Result) -> Result {
        lock.lock(); defer { lock.unlock() }
        return body(&value)
    }
}

/// Runtime endpoint consumed by ConfigPipeline. It intentionally contains no auth key.
nonisolated struct TonoTransportDescriptor: Sendable, Equatable {
    let host: String
    let port: UInt16
    var username: String? = nil
    var password: String? = nil
    var udp: Bool = true

    init(host: String = "127.0.0.1", port: UInt16, username: String? = nil, password: String? = nil, udp: Bool = true) {
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.udp = udp
    }
}

actor TonoSidecarService {
    private static let maximumCLIOutputBytes = 8 * 1_024 * 1_024
    private static let maximumCLIErrorBytes = 64 * 1_024

    enum State: Sendable, Equatable {
        case stopped, starting, needsEnrollment, connecting, direct, relay(String), ready, offline, failed(String)
    }

    struct Peer: Sendable, Equatable {
        let stableID: String
        let hostName: String
        let addresses: [String]
        let online: Bool
        let exitNodeOption: Bool
        let currentAddress: String?
        let relayRegion: String?
        let publicKey: String?
    }

    struct Status: Sendable, Equatable {
        let backendState: String
        let selfPeer: Peer?
        let peers: [Peer]
        let relayRegion: String?
        let hasDirectPeer: Bool
        let selectedExitID: String?
        let selectedExitOnline: Bool
    }

    enum Error: LocalizedError {
        case unavailable, invalidStatus, needsEnrollment, exitNodeUnavailable(String), commandFailed(String), socksUnavailable
        var errorDescription: String? {
            switch self {
            case .unavailable: return "Tono is unavailable: bundled tailscaled/tailscale executables were not found."
            case .invalidStatus: return "tailscale returned an invalid status response."
            case .needsEnrollment: return "This Mac needs a new Tono device enrollment."
            case .exitNodeUnavailable(let value): return "Configured Mac Studio exit node is unavailable: \(value)"
            case .commandFailed(let value): return "tailscale command failed: \(value)"
            case .socksUnavailable: return "Tono SOCKS endpoint did not become healthy."
            }
        }
    }

    private(set) var state: State = .stopped
    private var daemon: Process?
    private var drainTasks: [Task<Void, Never>] = []
    private var port: UInt16?

    private let bundle: Bundle
    private let fm = FileManager.default
    private let root: URL
    private var socket: URL { root.appendingPathComponent("tailscaled.sock") }
    private var stateDirectory: URL { root.appendingPathComponent("state", isDirectory: true) }
    private var pidFile: URL { root.appendingPathComponent("tailscaled.pid") }

    init(bundle: Bundle = .main, applicationSupport: URL? = nil) {
        self.bundle = bundle
        let support = applicationSupport ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        root = support.appendingPathComponent("Tono/Sidecar", isDirectory: true)
    }

    /// Starts userspace networking and, when supplied, consumes the auth key exactly once.
    /// The key is passed directly to tailscale and is never retained or logged.
    func start(
        authKey: String? = nil,
        enrollmentHostname: String? = nil,
        exitNode: String
    ) async throws {
        do {
            let binaries = try Self.findBinaries(in: bundle)
            try await ensureDaemon(binaries)

            var status = try await fetchStatus(cli: binaries.cli)
            if let authKey, !authKey.isEmpty {
                guard let enrollmentHostname else { throw Error.invalidStatus }
                state = .connecting
                // A recovery enrollment replaces the server-side device. Explicitly log out
                // any stale local identity before consuming the one-time replacement key.
                _ = try? await runCLI(binaries.cli, arguments: ["--socket", socket.path, "logout"])
                _ = try await runCLI(
                    binaries.cli,
                    arguments: try Self.enrollmentArguments(
                        socket: socket,
                        hostname: enrollmentHostname
                    ),
                    standardInput: Data(authKey.utf8)
                )
                status = try await fetchStatus(cli: binaries.cli)
            } else if status.backendState == "NeedsLogin" {
                state = .needsEnrollment
                throw Error.needsEnrollment
            }
            status = try await waitForExitCandidate(exitNode, initialStatus: status, cli: binaries.cli)
            _ = try await runCLI(binaries.cli, arguments: Self.exitNodeArguments(socket: socket, identifier: exitNode))
            guard let selectedPort = port else { throw Error.socksUnavailable }
            let updated = try await waitForSelectedExit(exitNode, cli: binaries.cli)
            try await waitForHealthySOCKS(selectedPort)
            let peer = try Self.requireExitNode(exitNode, in: updated) // fail closed after selection too
            updateState(from: updated, exitPeer: peer)
        } catch {
            state = .failed(Self.redact(String(describing: error)))
            await stop(preserveFailure: true)
            throw error
        }
    }

    /// Joins the pending, restricted tailnet identity without attempting Internet egress.
    /// The control plane promotes the node tag only after validating this identity.
    func enroll(authKey: String, hostname: String) async throws -> TonoNodeIdentity {
        do {
            guard !authKey.isEmpty else { throw Error.needsEnrollment }
            let binaries = try Self.findBinaries(in: bundle)
            try await ensureDaemon(binaries)
            state = .connecting
            _ = try? await runCLI(binaries.cli, arguments: ["--socket", socket.path, "logout"])
            _ = try await runCLI(
                binaries.cli,
                arguments: try Self.enrollmentArguments(socket: socket, hostname: hostname),
                standardInput: Data(authKey.utf8)
            )
            let status = try await fetchStatus(cli: binaries.cli)
            guard status.backendState == "Running", let peer = status.selfPeer,
                  !peer.stableID.isEmpty, !peer.addresses.isEmpty,
                  let publicKey = peer.publicKey?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !publicKey.isEmpty else { throw Error.invalidStatus }
            return TonoNodeIdentity(
                stableNodeId: peer.stableID,
                nodeId: nil,
                publicKey: publicKey,
                tailscaleIPs: peer.addresses
            )
        } catch {
            state = .failed(Self.redact(String(describing: error)))
            await stop(preserveFailure: true)
            throw error
        }
    }

    func descriptor() async throws -> TonoTransportDescriptor {
        let isReady: Bool
        switch state { case .direct, .relay, .ready: isReady = true; default: isReady = false }
        guard isReady, let port else { throw Error.socksUnavailable }
        // Full SOCKS5 handshake + CONNECT; TCP accept alone is not health.
        guard await Self.probeSOCKS(port: port) else {
            state = .offline; throw Error.socksUnavailable
        }
        return TonoTransportDescriptor(port: port)
    }

    func identity() async throws -> TonoNodeIdentity {
        let binaries = try Self.findBinaries(in: bundle)
        guard let peer = try await fetchStatus(cli: binaries.cli).selfPeer,
              !peer.stableID.isEmpty, !peer.addresses.isEmpty,
              let publicKey = peer.publicKey?.trimmingCharacters(in: .whitespacesAndNewlines),
              !publicKey.isEmpty else { throw Error.invalidStatus }
        return TonoNodeIdentity(
            stableNodeId: peer.stableID,
            nodeId: nil,
            publicKey: publicKey,
            tailscaleIPs: peer.addresses
        )
    }

    func isHealthy(exitNode: String) async -> Bool {
        guard let port, let binaries = try? Self.findBinaries(in: bundle),
              let status = try? await fetchStatus(cli: binaries.cli),
              let peer = try? Self.requireExitNode(exitNode, in: status),
              status.backendState == "Running", status.selectedExitOnline,
              status.selectedExitID == peer.stableID else { return false }
        return await Self.probeSOCKS(port: port)
    }

    func stop() async { await stop(preserveFailure: false) }

    /// Leaves no userspace Tailscale process behind when the persisted
    /// selection is a managed cloud exit. This validates the pid-file target
    /// before terminating it; unrelated processes are never touched.
    func prepareCloudOnly() async throws {
        if daemon != nil {
            await stop(preserveFailure: false)
            return
        }
        // The production Reality-only path should not even resolve the legacy
        // sidecar binaries during a normal launch. Only inspect them when a PID
        // file proves that an older build may have left its owned daemon behind.
        if fm.fileExists(atPath: pidFile.path) {
            guard let resourceRoot = bundle.resourceURL else {
                throw Error.unavailable
            }
            // The Reality-only build intentionally does not embed Tailscale,
            // but the expected legacy path remains deterministic enough to
            // validate and stop an owned daemon from an in-place app upgrade.
            let legacyDaemon = resourceRoot.appendingPathComponent("tailscaled")
            try await terminateStaleDaemon(expectedExecutable: legacyDaemon)
        }
        try? fm.removeItem(at: socket)
        port = nil
        state = .stopped
    }

    func logoutAndStop() async {
        if let binaries = try? Self.findBinaries(in: bundle), daemon != nil {
            _ = try? await runCLI(binaries.cli, arguments: ["--socket", socket.path, "logout"])
        }
        await stop(preserveFailure: false)
    }

    private func stop(preserveFailure: Bool) async {
        if let daemon, daemon.isRunning {
            daemon.terminate()
            for _ in 0..<10 where daemon.isRunning { try? await Task.sleep(for: .milliseconds(100)) }
            if daemon.isRunning {
                kill(daemon.processIdentifier, SIGKILL)
                for _ in 0..<10 where daemon.isRunning { try? await Task.sleep(for: .milliseconds(50)) }
            }
        }
        daemon = nil; port = nil
        drainTasks.forEach { $0.cancel() }; drainTasks.removeAll()
        try? fm.removeItem(at: socket)
        try? fm.removeItem(at: pidFile)
        if !preserveFailure { state = .stopped }
    }

    private func ensureDaemon(_ binaries: (daemon: URL, cli: URL)) async throws {
        guard daemon == nil else { return }
        state = .starting
        try fm.createDirectory(at: stateDirectory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        for directory in [root, stateDirectory] {
            var metadata = stat()
            guard lstat(directory.path, &metadata) == 0,
                  metadata.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
                  metadata.st_uid == getuid(),
                  chmod(directory.path, 0o700) == 0 else {
                throw Error.commandFailed("sidecar state directory is unsafe")
            }
        }
        try await terminateStaleDaemon(expectedExecutable: binaries.daemon)
        try? fm.removeItem(at: socket)
        let selectedPort = try Self.reserveLoopbackPort()
        port = selectedPort

        let process = Process()
        process.executableURL = binaries.daemon
        process.arguments = Self.daemonArguments(stateDirectory: stateDirectory, socket: socket, port: selectedPort)
        process.environment = [
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LC_ALL": "C",
        ]
        process.standardInput = FileHandle.nullDevice
        let stdout = Pipe(), stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr
        process.terminationHandler = { [weak self] process in
            Task { await self?.processExited(process) }
        }
        try process.run()
        daemon = process
        try String(process.processIdentifier).write(to: pidFile, atomically: true, encoding: .utf8)
        try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: pidFile.path)
        drainTasks = [drain(stdout.fileHandleForReading), drain(stderr.fileHandleForReading)]
        try await waitForSocket()
    }

    private func processExited(_ process: Process) async {
        guard daemon === process else { return }
        daemon = nil; port = nil; try? fm.removeItem(at: socket)
        try? fm.removeItem(at: pidFile)
        if !Task.isCancelled { state = process.terminationStatus == 0 ? .offline : .failed("tailscaled exited (\(process.terminationStatus))") }
    }

    private func terminateStaleDaemon(expectedExecutable: URL) async throws {
        guard let value = try? String(contentsOf: pidFile, encoding: .utf8),
              let pid = Int32(value.trimmingCharacters(in: .whitespacesAndNewlines)), pid > 1 else {
            try? fm.removeItem(at: pidFile)
            return
        }
        guard Darwin.kill(pid, 0) == 0 else { try? fm.removeItem(at: pidFile); return }
        var buffer = [CChar](repeating: 0, count: 4_096)
        let count = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        let path = count > 0 ? String(cString: buffer) : ""
        guard URL(fileURLWithPath: path).standardizedFileURL == expectedExecutable.standardizedFileURL else {
            throw Error.commandFailed("refusing to terminate an unverified stale process")
        }
        Darwin.kill(pid, SIGTERM)
        for _ in 0..<20 where Darwin.kill(pid, 0) == 0 { try? await Task.sleep(for: .milliseconds(50)) }
        if Darwin.kill(pid, 0) == 0 { Darwin.kill(pid, SIGKILL) }
        for _ in 0..<20 where Darwin.kill(pid, 0) == 0 { try? await Task.sleep(for: .milliseconds(50)) }
        guard Darwin.kill(pid, 0) != 0 else { throw Error.commandFailed("stale tailscaled did not terminate") }
        try? fm.removeItem(at: pidFile)
    }

    private func drain(_ handle: FileHandle) -> Task<Void, Never> {
        // Always drain to prevent a full pipe deadlocking tailscaled. Integration UI may add a
        // bounded logger later; raw daemon output is deliberately discarded as potentially sensitive.
        Task.detached { while !Task.isCancelled && !(handle.availableData.isEmpty) {} }
    }

    private func waitForSocket() async throws {
        var delay = 100
        for _ in 0..<7 {
            if fm.fileExists(atPath: socket.path) { return }
            try await Task.sleep(for: .milliseconds(delay)); delay = min(delay * 2, 1_600)
        }
        throw Error.commandFailed("control socket timeout")
    }

    private func waitForHealthySOCKS(_ port: UInt16) async throws {
        var delay = 100
        for _ in 0..<7 {
            if await Self.probeSOCKS(port: port) { return }
            try await Task.sleep(for: .milliseconds(delay)); delay = min(delay * 2, 1_600)
        }
        throw Error.socksUnavailable
    }

    private func waitForSelectedExit(_ identifier: String, cli: URL) async throws -> Status {
        var delay = 100
        for _ in 0..<8 {
            let status = try await fetchStatus(cli: cli)
            if let peer = try? Self.requireExitNode(identifier, in: status),
               status.selectedExitOnline, status.selectedExitID == peer.stableID {
                return status
            }
            try await Task.sleep(for: .milliseconds(delay))
            delay = min(delay * 2, 1_600)
        }
        throw Error.exitNodeUnavailable(identifier)
    }

    private func waitForExitCandidate(_ identifier: String, initialStatus: Status, cli: URL) async throws -> Status {
        var status = initialStatus
        var delay = 100
        for _ in 0..<8 {
            if (try? Self.requireExitNode(identifier, in: status)) != nil { return status }
            try await Task.sleep(for: .milliseconds(delay))
            delay = min(delay * 2, 1_600)
            status = try await fetchStatus(cli: cli)
        }
        throw Error.exitNodeUnavailable(identifier)
    }

    private func fetchStatus(cli: URL) async throws -> Status {
        let data = try await runCLI(cli, arguments: ["--socket", socket.path, "status", "--json"])
        return try Self.parseStatusJSON(data)
    }

    private func runCLI(
        _ cli: URL,
        arguments: [String],
        standardInput: Data? = nil
    ) async throws -> Data {
        let process = Process(), output = Pipe(), errors = Pipe()
        process.executableURL = cli; process.arguments = arguments
        process.environment = [
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LC_ALL": "C",
        ]
        process.standardOutput = output; process.standardError = errors
        let input = standardInput.map { _ in Pipe() }
        if let input {
            process.standardInput = input
        } else {
            process.standardInput = FileHandle.nullDevice
        }
        let termination = Task<Int32, Never> {
            await withCheckedContinuation { continuation in
                process.terminationHandler = { continuation.resume(returning: $0.terminationStatus) }
                do {
                    try process.run()
                    if let input, let standardInput {
                        do {
                            try input.fileHandleForWriting.write(contentsOf: standardInput)
                            try input.fileHandleForWriting.close()
                        } catch {
                            try? input.fileHandleForWriting.close()
                            if process.isRunning { process.terminate() }
                        }
                    }
                } catch {
                    // A Process that fails before launch never takes ownership of
                    // the Pipe write ends. Close our copies so the bounded readers
                    // observe EOF instead of blocking forever on the error path.
                    try? output.fileHandleForWriting.close()
                    try? errors.fileHandleForWriting.close()
                    try? input?.fileHandleForWriting.close()
                    continuation.resume(returning: -1)
                }
            }
        }
        async let data = Self.readBounded(
            output.fileHandleForReading,
            maximumBytes: Self.maximumCLIOutputBytes
        )
        async let errorData = Self.readBounded(
            errors.fileHandleForReading,
            maximumBytes: Self.maximumCLIErrorBytes
        )
        let watchdog = Task {
            try? await Task.sleep(for: .seconds(15))
            if process.isRunning {
                process.terminate()
                try? await Task.sleep(for: .seconds(2))
                if process.isRunning { Darwin.kill(process.processIdentifier, SIGKILL) }
            }
        }
        let terminationStatus = await termination.value
        watchdog.cancel()
        let (capturedOutput, capturedError) = await (data, errorData)
        guard let capturedOutput, let capturedError else {
            throw Error.commandFailed("command output exceeded its safety limit")
        }
        guard terminationStatus == 0 else {
            throw Error.commandFailed(String(
                Self.redact(String(decoding: capturedError, as: UTF8.self)).prefix(1_024)
            ))
        }
        return capturedOutput
    }

    nonisolated private static func readBounded(
        _ handle: FileHandle,
        maximumBytes: Int
    ) -> Data? {
        var result = Data()
        do {
            while let chunk = try handle.read(upToCount: 64 * 1_024), !chunk.isEmpty {
                guard chunk.count <= maximumBytes - result.count else {
                    try? handle.close()
                    return nil
                }
                result.append(chunk)
            }
            return result
        } catch {
            return nil
        }
    }

    private func updateState(from status: Status, exitPeer: Peer) {
        if status.backendState != "Running" { state = status.backendState == "NeedsLogin" ? .needsEnrollment : .offline }
        else if exitPeer.currentAddress?.isEmpty == false { state = .direct }
        else if let region = exitPeer.relayRegion, !region.isEmpty { state = .relay(region) }
        else { state = .ready }
    }

    // MARK: Pure/test-friendly construction and parsing
    static func daemonArguments(stateDirectory: URL, socket: URL, port: UInt16) -> [String] {
        ["--tun=userspace-networking", "--statedir=\(stateDirectory.path)", "--socket=\(socket.path)", "--socks5-server=127.0.0.1:\(port)"]
    }
    static func enrollmentArguments(socket: URL, hostname: String) throws -> [String] {
        guard hostname.range(
            of: #"^tono-[a-f0-9]{32}$"#,
            options: .regularExpression
        ) != nil else {
            throw Error.invalidStatus
        }
        // `file:/dev/stdin` keeps the one-time key out of argv, environment,
        // shell history, and persistent files.
        return [
            "--socket", socket.path,
            "up",
            "--auth-key=file:/dev/stdin",
            "--hostname=\(hostname)",
            "--accept-routes=false",
            "--accept-dns=false",
            "--shields-up",
        ]
    }
    static func exitNodeArguments(socket: URL, identifier: String) -> [String] {
        ["--socket", socket.path, "set", "--exit-node", identifier, "--exit-node-allow-lan-access=false"]
    }

    static func parseStatusJSON(_ data: Data) throws -> Status {
        guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw Error.invalidStatus }
        func peer(_ value: Any) -> Peer? {
            guard let p = value as? [String: Any] else { return nil }
            // Self.ID / Peer.ID is StableNodeID — never treat as Device API management id.
            return Peer(stableID: p["ID"] as? String ?? p["StableID"] as? String ?? "",
                        hostName: p["HostName"] as? String ?? p["DNSName"] as? String ?? "",
                        addresses: p["TailscaleIPs"] as? [String] ?? [], online: p["Online"] as? Bool ?? false,
                        exitNodeOption: p["ExitNodeOption"] as? Bool ?? false,
                        currentAddress: p["CurAddr"] as? String,
                        relayRegion: p["Relay"] as? String,
                        publicKey: p["PublicKey"] as? String)
        }
        let peers = (root["Peer"] as? [String: Any] ?? [:]).values.compactMap(peer)
        let selfPeer = root["Self"].flatMap(peer)
        let relay = (root["Self"] as? [String: Any])?["Relay"] as? String
        let exit = root["ExitNodeStatus"] as? [String: Any]
        let direct = (root["Peer"] as? [String: Any] ?? [:]).values.contains {
            (($0 as? [String: Any])?["CurAddr"] as? String)?.isEmpty == false
        }
        return Status(backendState: root["BackendState"] as? String ?? "Unknown", selfPeer: selfPeer,
                      peers: peers, relayRegion: relay, hasDirectPeer: direct,
                      selectedExitID: exit?["ID"] as? String,
                      selectedExitOnline: exit?["Online"] as? Bool ?? false)
    }

    static func requireExitNode(_ identifier: String, in status: Status) throws -> Peer {
        let key = identifier.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        let match = status.peers.first { peer in
            peer.stableID.lowercased() == key || peer.addresses.contains(identifier) ||
            peer.hostName.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ".")) == key
        }
        guard let match, match.online, match.exitNodeOption else { throw Error.exitNodeUnavailable(identifier) }
        return match
    }

    static func redact(_ text: String) -> String {
        text.replacingOccurrences(of: #"(?i)(auth[-_ ]?key[=: ]+|tskey-[a-z]+-)[^\s\"']+"#,
                                  with: "$1<redacted>", options: .regularExpression)
    }

    private static func findBinaries(in bundle: Bundle) throws -> (daemon: URL, cli: URL) {
        let daemon = bundle.url(forResource: "tailscaled", withExtension: nil)
            ?? bundle.url(forResource: "tailscaled", withExtension: nil, subdirectory: "Resources")
        let cli = bundle.url(forResource: "tailscale", withExtension: nil)
            ?? bundle.url(forResource: "tailscale", withExtension: nil, subdirectory: "Resources")
        guard let daemon, let cli,
              FileManager.default.isExecutableFile(atPath: daemon.path), FileManager.default.isExecutableFile(atPath: cli.path)
        else { throw Error.unavailable }
        return (daemon, cli)
    }

    private static func reserveLoopbackPort() throws -> UInt16 {
        let fd = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw Error.socksUnavailable }
        defer { Darwin.close(fd) }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0 else { throw Error.socksUnavailable }
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let read = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.getsockname(fd, $0, &length)
            }
        }
        guard read == 0, address.sin_port != 0 else { throw Error.socksUnavailable }
        return UInt16(bigEndian: address.sin_port)
    }

    /// Probes the local SOCKS5 endpoint with a complete no-auth greeting and
    /// CONNECT to a controlled IP:port. A TCP accept or partial reply is never
    /// considered healthy.
    private static func probeSOCKS(port: UInt16) async -> Bool {
        await withCheckedContinuation { continuation in
            let connection = NWConnection(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!, using: .tcp)
            let completed = TonoLockedBox(false)
            @Sendable func finish(_ value: Bool) {
                let shouldFinish = completed.withLock { current in
                    guard !current else { return false }
                    current = true; return true
                }
                guard shouldFinish else { return }
                connection.cancel(); continuation.resume(returning: value)
            }
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    // SOCKS5 greeting: VER=5, NMETHODS=1, METHOD=0 (no auth)
                    connection.send(content: Data([0x05, 0x01, 0x00]), completion: .contentProcessed { error in
                        if error != nil { finish(false); return }
                        receiveExactly(connection, count: 2) { greeting in
                            guard let greeting, greeting == Data([0x05, 0x00]) else {
                                finish(false); return
                            }
                            // CONNECT 1.1.1.1:443 through the selected exit node.
                            let req = Data([0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0x01, 0xBB])
                            connection.send(content: req, completion: .contentProcessed { error in
                                if error != nil { finish(false); return }
                                receiveExactly(connection, count: 4) { header in
                                    guard let header, header[0] == 0x05,
                                          header[1] == 0x00, header[2] == 0x00 else {
                                        finish(false); return
                                    }
                                    switch header[3] {
                                    case 0x01:
                                        receiveExactly(connection, count: 6) { finish($0?.count == 6) }
                                    case 0x04:
                                        receiveExactly(connection, count: 18) { finish($0?.count == 18) }
                                    case 0x03:
                                        receiveExactly(connection, count: 1) { lengthData in
                                            guard let lengthData, let length = lengthData.first, length > 0 else {
                                                finish(false); return
                                            }
                                            receiveExactly(connection, count: Int(length) + 2) {
                                                finish($0?.count == Int(length) + 2)
                                            }
                                        }
                                    default:
                                        finish(false)
                                    }
                                }
                            })
                        }
                    })
                case .failed, .cancelled:
                    finish(false)
                default:
                    break
                }
            }
            connection.start(queue: .global())
            DispatchQueue.global().asyncAfter(deadline: .now() + 2.5) { finish(false) }
        }
    }

    private static func receiveExactly(
        _ connection: NWConnection,
        count: Int,
        accumulated: Data = Data(),
        completion: @escaping @Sendable (Data?) -> Void
    ) {
        guard count > 0, accumulated.count <= count else {
            completion(accumulated.count == count ? accumulated : nil)
            return
        }
        let remaining = count - accumulated.count
        connection.receive(minimumIncompleteLength: 1, maximumLength: remaining) {
            data, _, complete, error in
            guard error == nil, let data, !data.isEmpty else {
                completion(nil)
                return
            }
            var next = accumulated
            next.append(data)
            if next.count == count {
                completion(next)
            } else if complete || next.count > count {
                completion(nil)
            } else {
                receiveExactly(connection, count: count, accumulated: next, completion: completion)
            }
        }
    }
}
