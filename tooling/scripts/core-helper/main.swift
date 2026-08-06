import Foundation
import Darwin
import CryptoKit
import IOKit
import IOKit.pwr_mgt

let helperVersion = HelperProtocolVersion.current
private let socketDirectory = "/var/run/tono-core"
private let socketPath = "\(socketDirectory)/service.sock"
private let runtimeDirectory = "\(socketDirectory)/runtime"
private let runtimeConfigPath = "\(runtimeDirectory)/config.yaml"
private let pidPath = "\(socketDirectory)/mihomo.pid"
private let allowedUIDPath = "/Library/PrivilegedHelperTools/tono.allowed-uid"
private let mihomoPath = "/Library/PrivilegedHelperTools/tono-mihomo"
private let maximumRequestBytes = 16 * 1024
private let maximumHeaderBytes = 8 * 1024
private let maximumDiagnosticBytes = 32 * 1024
private var helperShutdownRequested: sig_atomic_t = 0
// IOKit power-message macros are not imported into Swift because they expand
// through unsupported C macros. These are the stable public IOMessage values.
private let tonoIOMessageCanSystemSleep: UInt32 = 0xe000_0270
private let tonoIOMessageSystemWillSleep: UInt32 = 0xe000_0280
private let tonoIOMessageSystemHasPoweredOn: UInt32 = 0xe000_0300
private let tonoIOMessageSystemWillPowerOn: UInt32 = 0xe000_0320
private let killSwitchArmFields = Set([
    "apiHosts",
    "exitHints",
    "tunnelInterfaces",
    "proxyEndpoints",
    "sessionDirectEndpoints",
    "tailscaleBootstrapEnabled",
    "allowSystemResolution",
    "bootstrapPins",
])

enum HelperFailure: Error {
    case invalid(String)
    case system(String)

    var message: String {
        switch self {
        case .invalid(let message), .system(let message): message
        }
    }
}

private func validateKillSwitchArmFields(_ object: [String: Any]) throws {
    guard Set(object.keys).isSubset(of: killSwitchArmFields) else {
        throw HelperFailure.invalid("Invalid Kill Switch arm request.")
    }
}

private func runRequestContractSelfTests() -> Bool {
    do {
        try validateKillSwitchArmFields([
            "apiHosts": [],
            "exitHints": [],
            "tunnelInterfaces": [],
            "proxyEndpoints": [],
            "sessionDirectEndpoints": [],
            "tailscaleBootstrapEnabled": false,
            "allowSystemResolution": false,
            "bootstrapPins": ["api.example.com": ["1.1.1.1"]],
        ])
        do {
            try validateKillSwitchArmFields(["unexpected": []])
            return false
        } catch {
            return true
        }
    } catch {
        return false
    }
}

private struct OwnedProcessIdentity {
    let pid: Int32
    let executablePath: String
    let uid: uid_t
}

private func staleOwnedCorePIDs(
    in processes: [OwnedProcessIdentity],
    expectedExecutablePath: String = mihomoPath
) -> [Int32] {
    processes.compactMap {
        guard $0.pid > 1, $0.uid == 0,
              $0.executablePath == expectedExecutablePath else { return nil }
        return $0.pid
    }.sorted()
}

private func runCoreLifecyclePolicySelfTests() -> Bool {
    staleOwnedCorePIDs(in: [
        .init(pid: 31, executablePath: mihomoPath, uid: 0),
        .init(pid: 32, executablePath: mihomoPath, uid: 501),
        .init(pid: 33, executablePath: "/tmp/tono-mihomo", uid: 0),
    ]) == [31]
}

private func ownedRuntimeConfigIsSafe(_ contents: String) -> Bool {
    contents.hasPrefix("# Tono owned runtime")
        && contents.contains("\nallow-lan: false\n")
        && contents.contains("\nipv6: false\n")
        && contents.contains("\nmode: rule\n")
        && contents.contains("\nexternal-controller: '127.0.0.1:")
        && contents.contains("\n  listen: \(ProtectedDNSContract.listener)\n")
        && contents.contains("\n  enhanced-mode: fake-ip\n")
        && contents.contains("\n  device: utun199\n")
        && contents.contains("\n  - MATCH,Tono-Exit")
}

private func runOwnedRuntimeContractSelfTests() -> Bool {
    let valid = """
    # Tono owned runtime
    allow-lan: false
    ipv6: false
    mode: rule
    external-controller: '127.0.0.1:9090'
    dns:
      listen: \(ProtectedDNSContract.listener)
      enhanced-mode: fake-ip
    tun:
      device: utun199
    rules:
      - MATCH,Tono-Exit
    """
    return ownedRuntimeConfigIsSafe(valid)
        && !ownedRuntimeConfigIsSafe(
            valid.replacingOccurrences(
                of: ProtectedDNSContract.listener,
                with: "198.18.0.2:53"
            )
        )
        && !ownedRuntimeConfigIsSafe(
            valid.replacingOccurrences(
                of: ProtectedDNSContract.listener,
                with: "0.0.0.0:53"
            )
        )
}

private func requestHelperShutdown(_ signal: Int32) {
    _ = signal
    helperShutdownRequested = 1
}

/// Last-resort recovery for a machine whose GUI cannot reconnect or quit
/// normally. This path is intentionally unavailable over the user socket and
/// requires an administrator to execute the installed, signed helper as root.
private func runEmergencyDisarm() -> Bool {
    guard geteuid() == 0 else {
        fputs("Tono emergency recovery must be run with sudo.\n", stderr)
        return false
    }
    do {
        let allowedUID = try readAllowedUID()
        // Initialization terminates a stale owned Mihomo process before PF is
        // opened, preventing a half-running privileged runtime after recovery.
        _ = try CoreManager(allowedUID: allowedUID)
        // Restore the user's DHCP/custom DNS before opening PF. If DNS recovery
        // fails, retain fail-closed protection instead of returning a machine
        // with direct egress but a dead resolver.
        _ = try ProtectedDNSManager().restore()
        let manager = try KillSwitchManager(allowedUID: allowedUID)
        _ = try manager.disarm()
        print("Tono network protection is disarmed.")
        return true
    } catch {
        fputs("Tono emergency recovery failed; PF remains fail-closed.\n", stderr)
        return false
    }
}

/// One-command recovery for a daemon that refuses its own GUI (a stale
/// incarnation, a mismatched allowed-uid record, or any Forbidden loop the
/// app cannot break over the socket). Disarms protection exactly like
/// --emergency-disarm, then removes this installation — daemon registration,
/// launchd plist, allowed-uid record, and the executables — so the next app
/// launch performs a clean authenticated reinstall.
private func runEmergencyReset() -> Bool {
    // Stop the daemon FIRST: with KeepAlive it can otherwise service a
    // concurrent GUI arm between this tool's disarm and the removal below,
    // re-writing PF state that then survives with no helper left installed —
    // a fail-closed machine with no owner.
    let bootout = Process()
    bootout.executableURL = URL(fileURLWithPath: "/bin/launchctl")
    bootout.arguments = ["bootout", "system/com.raydocs.tono.core-helper"]
    bootout.standardOutput = FileHandle.nullDevice
    bootout.standardError = FileHandle.nullDevice
    // A daemon that is not currently bootstrapped makes bootout fail; the
    // reset continues either way.
    try? bootout.run()
    bootout.waitUntilExit()

    guard runEmergencyDisarm() else {
        // Protection could not be released; removing the installation now
        // would strand the machine fail-closed with nothing able to enforce
        // or undo it. Put the daemon registration back and keep everything.
        let restore = Process()
        restore.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        restore.arguments = [
            "bootstrap", "system",
            "/Library/LaunchDaemons/com.raydocs.tono.core-helper.plist",
        ]
        restore.standardOutput = FileHandle.nullDevice
        restore.standardError = FileHandle.nullDevice
        try? restore.run()
        restore.waitUntilExit()
        fputs(
            "Tono emergency reset aborted: protection could not be released; "
            + "the installation was left in place.\n",
            stderr
        )
        return false
    }
    for path in [
        "/Library/LaunchDaemons/com.raydocs.tono.core-helper.plist",
        allowedUIDPath,
        mihomoPath,
        "/Library/PrivilegedHelperTools/tono-core-helper",
    ] {
        unlink(path)
    }
    print("Tono helper installation removed. Reopen Tono to reinstall it.")
    return true
}

private func fileType(_ value: stat) -> mode_t {
    value.st_mode & mode_t(S_IFMT)
}

private func secureMetadata(
    _ path: String,
    type: mode_t,
    owner: uid_t,
    allowOwner: uid_t? = nil,
    rejectWritableByGroupOrWorld: Bool = true
) throws -> stat {
    var metadata = stat()
    guard lstat(path, &metadata) == 0 else {
        throw HelperFailure.system("Required helper file is unavailable.")
    }
    guard fileType(metadata) == type,
          metadata.st_uid == owner || metadata.st_uid == allowOwner else {
        throw HelperFailure.invalid("Helper file ownership or type is invalid.")
    }
    if rejectWritableByGroupOrWorld, metadata.st_mode & 0o022 != 0 {
        throw HelperFailure.invalid("Helper file permissions are unsafe.")
    }
    return metadata
}

private func readAllowedUID() throws -> uid_t {
    _ = try secureMetadata(allowedUIDPath, type: mode_t(S_IFREG), owner: 0)
    let value = try String(contentsOfFile: allowedUIDPath, encoding: .utf8)
        .trimmingCharacters(in: .whitespacesAndNewlines)
    guard let parsed = UInt32(value), parsed > 0 else {
        throw HelperFailure.invalid("Allowed user configuration is invalid.")
    }
    return uid_t(parsed)
}

private func canonicalPath(_ path: String) -> String? {
    guard !path.utf8.contains(0), path.utf8.count < Int(PATH_MAX) else { return nil }
    var buffer = [CChar](repeating: 0, count: Int(PATH_MAX))
    return path.withCString { source in
        guard realpath(source, &buffer) != nil else { return nil }
        return String(cString: buffer)
    }
}

private func homeDirectory(for uid: uid_t) throws -> String {
    guard let record = getpwuid(uid), let directory = record.pointee.pw_dir else {
        throw HelperFailure.invalid("Allowed user has no home directory.")
    }
    return String(cString: directory)
}

private func allowedGroup(for uid: uid_t) throws -> gid_t {
    guard let record = getpwuid(uid) else {
        throw HelperFailure.invalid("Allowed user is unavailable.")
    }
    return record.pointee.pw_gid
}

private func ensureRootDirectory(_ path: String, permissions: mode_t) throws {
    var metadata = stat()
    if lstat(path, &metadata) != 0 {
        guard errno == ENOENT, mkdir(path, permissions) == 0 else {
            throw HelperFailure.system("Could not create helper runtime directory.")
        }
    } else {
        guard fileType(metadata) == mode_t(S_IFDIR), metadata.st_uid == 0,
              metadata.st_mode & 0o022 == 0 else {
            throw HelperFailure.invalid("Helper runtime directory is unsafe.")
        }
    }
    guard chown(path, 0, 0) == 0, chmod(path, permissions) == 0 else {
        throw HelperFailure.system("Could not secure helper runtime directory.")
    }
}

private func removeIfPresent(_ path: String, requiredType: mode_t, allowedOwner: uid_t) throws {
    var metadata = stat()
    guard lstat(path, &metadata) == 0 else {
        if errno == ENOENT { return }
        throw HelperFailure.system("Could not inspect stale helper state.")
    }
    guard fileType(metadata) == requiredType,
          metadata.st_uid == 0 || metadata.st_uid == allowedOwner else {
        throw HelperFailure.invalid("Refusing to replace unsafe helper state.")
    }
    guard unlink(path) == 0 else {
        throw HelperFailure.system("Could not remove stale helper state.")
    }
}

private func writeAll(_ fd: Int32, bytes: UnsafeRawPointer, count: Int) throws {
    var offset = 0
    while offset < count {
        let written = Darwin.write(fd, bytes.advanced(by: offset), count - offset)
        if written < 0 {
            if errno == EINTR { continue }
            throw HelperFailure.system("Write failed.")
        }
        guard written > 0 else { throw HelperFailure.system("Write failed.") }
        offset += written
    }
}

private func atomicCopy(
    source: String,
    destination: String,
    expectedOwner: uid_t,
    expectedSHA256: String,
    maximumBytes: Int64,
    required: Bool
) throws {
    guard expectedSHA256.range(
        of: #"^[0-9a-f]{64}$"#,
        options: .regularExpression
    ).map({ $0 == expectedSHA256.startIndex..<expectedSHA256.endIndex }) == true else {
        throw HelperFailure.invalid("Runtime input digest is invalid.")
    }
    let sourceFD = open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    if sourceFD < 0 {
        if !required, errno == ENOENT {
            var existing = stat()
            if lstat(destination, &existing) == 0 {
                guard fileType(existing) == mode_t(S_IFREG), existing.st_uid == 0,
                      unlink(destination) == 0 else {
                    throw HelperFailure.invalid("Could not remove a stale runtime file.")
                }
            }
            return
        }
        throw HelperFailure.invalid("Required Tono runtime input is unavailable.")
    }
    defer { close(sourceFD) }

    var metadata = stat()
    guard fstat(sourceFD, &metadata) == 0,
          fileType(metadata) == mode_t(S_IFREG),
          metadata.st_uid == expectedOwner,
          metadata.st_mode & 0o022 == 0,
          metadata.st_size >= 0,
          metadata.st_size <= maximumBytes else {
        throw HelperFailure.invalid("Tono runtime input failed ownership, type, or size checks.")
    }

    let temporary = "\(destination).new.\(UUID().uuidString)"
    let destinationFD = open(
        temporary,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
        0o600
    )
    guard destinationFD >= 0 else {
        throw HelperFailure.system("Could not create a runtime snapshot.")
    }
    var completed = false
    defer {
        close(destinationFD)
        if !completed { unlink(temporary) }
    }

    var buffer = [UInt8](repeating: 0, count: 64 * 1024)
    var copiedBytes: Int64 = 0
    var digest = SHA256()
    while true {
        let count = Darwin.read(sourceFD, &buffer, buffer.count)
        if count == 0 { break }
        if count < 0 {
            if errno == EINTR { continue }
            throw HelperFailure.system("Could not read a runtime input.")
        }
        copiedBytes += Int64(count)
        guard copiedBytes <= maximumBytes else {
            throw HelperFailure.invalid("Tono runtime input grew beyond its size limit.")
        }
        try buffer.withUnsafeBytes {
            guard let base = $0.baseAddress else { return }
            try writeAll(destinationFD, bytes: base, count: count)
            digest.update(bufferPointer: UnsafeRawBufferPointer(
                start: base,
                count: count
            ))
        }
    }
    let actualSHA256 = digest.finalize().map {
        String(format: "%02x", $0)
    }.joined()
    guard actualSHA256 == expectedSHA256 else {
        throw HelperFailure.invalid("Runtime input changed before its secure snapshot.")
    }
    guard fsync(destinationFD) == 0,
          fchown(destinationFD, 0, 0) == 0,
          fchmod(destinationFD, 0o600) == 0,
          rename(temporary, destination) == 0 else {
        throw HelperFailure.system("Could not commit the runtime snapshot.")
    }
    completed = true
}

private final class CoreManager {
    private let lock = NSLock()
    private let diagnosticLock = NSLock()
    private let allowedUID: uid_t
    private let allowedHome: String
    private var process: Process?
    private var diagnosticPipe: Pipe?
    private var diagnosticData = Data()
    private var lastFailure: String?

    init(allowedUID: uid_t) throws {
        self.allowedUID = allowedUID
        self.allowedHome = try homeDirectory(for: allowedUID)
        try ensureRootDirectory(runtimeDirectory, permissions: 0o700)
        try terminateStaleCore()
    }

    private func validateConfigDirectory(_ requested: String) throws -> String {
        guard let requestedPath = canonicalPath(requested) else {
            throw HelperFailure.invalid("Configuration directory does not exist.")
        }
        let candidates = ["Tono", "Tono-Dev"].compactMap {
            canonicalPath("\(allowedHome)/Library/Application Support/\($0)/config")
        }
        guard candidates.contains(requestedPath) else {
            throw HelperFailure.invalid("Configuration directory is outside Tono.")
        }
        let metadata = try secureMetadata(
            requestedPath,
            type: mode_t(S_IFDIR),
            owner: allowedUID
        )
        guard metadata.st_mode & 0o022 == 0 else {
            throw HelperFailure.invalid("Configuration directory permissions are unsafe.")
        }
        return requestedPath
    }

    private func snapshot(_ requested: String, expectedSHA256: String) throws -> String {
        let source = try validateConfigDirectory(requested)
        // The owned Tono runtime has no GEOIP/GEOSITE/MMDB references. Never copy
        // user-owned parser inputs into a root process merely because legacy
        // versions left them in the config directory.
        try atomicCopy(
            source: "\(source)/config.yaml",
            destination: runtimeConfigPath,
            expectedOwner: allowedUID,
            expectedSHA256: expectedSHA256,
            maximumBytes: 8 * 1024 * 1024,
            required: true
        )
        let contents = try String(contentsOfFile: runtimeConfigPath, encoding: .utf8)
        guard ownedRuntimeConfigIsSafe(contents) else {
            throw HelperFailure.invalid("Runtime config is not an owned Tono config.")
        }
        return runtimeConfigPath
    }

    func start(
        configDirectory: String,
        configSHA256: String,
        startAllowed: () -> Bool = { true }
    ) throws {
        lock.lock()
        defer { lock.unlock() }
        if process?.isRunning == true {
            throw HelperFailure.invalid("Mihomo is already running.")
        }
        _ = try secureMetadata(mihomoPath, type: mode_t(S_IFREG), owner: 0)
        let configPath = try snapshot(
            configDirectory,
            expectedSHA256: configSHA256
        )

        let child = Process()
        child.executableURL = URL(fileURLWithPath: mihomoPath)
        child.arguments = ["-d", runtimeDirectory, "-f", configPath]
        child.currentDirectoryURL = URL(fileURLWithPath: runtimeDirectory, isDirectory: true)
        child.environment = [
            // Never give a root process a user-writable HOME. Mihomo receives
            // all required inputs through its root-owned -d/-f paths.
            "HOME": runtimeDirectory,
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        ]
        resetDiagnostics()
        startDiagnosticCapture(for: child)
        do {
            guard startAllowed() else {
                stopDiagnosticCapture()
                throw HelperFailure.invalid(
                    "The system is entering sleep; network protection remains fail-closed."
                )
            }
            try child.run()
        } catch {
            stopDiagnosticCapture()
            throw error
        }
        process = child
        do {
            try writePID(child.processIdentifier)
        } catch {
            child.terminate()
            for _ in 0..<20 where child.isRunning { usleep(50_000) }
            if child.isRunning { kill(child.processIdentifier, SIGKILL) }
            process = nil
            stopDiagnosticCapture()
            throw error
        }

        // Most configuration/port failures terminate immediately. Catch them
        // here so the first start request returns a useful bounded diagnostic
        // instead of making the GUI poll an absent controller for seconds.
        for _ in 0..<3 where child.isRunning { usleep(50_000) }
        guard child.isRunning else {
            let failure = recordUnexpectedExit(child)
            process = nil
            try? removePIDFile()
            stopDiagnosticCapture()
            throw HelperFailure.system(failure)
        }
    }

    func sync(configDirectory: String, configSHA256: String) throws -> String {
        lock.lock()
        defer { lock.unlock() }
        guard process?.isRunning == true else {
            throw HelperFailure.invalid("Mihomo is not running.")
        }
        return try snapshot(
            configDirectory,
            expectedSHA256: configSHA256
        )
    }

    func stop() throws {
        lock.lock()
        defer { lock.unlock() }
        guard let child = process, child.isRunning else {
            process = nil
            try? removePIDFile()
            stopDiagnosticCapture()
            return
        }
        diagnosticLock.lock()
        lastFailure = nil
        diagnosticLock.unlock()
        child.terminate()
        for _ in 0..<30 where child.isRunning { usleep(100_000) }
        if child.isRunning {
            kill(child.processIdentifier, SIGKILL)
            for _ in 0..<20 where child.isRunning { usleep(50_000) }
        }
        guard !child.isRunning else {
            throw HelperFailure.system("Mihomo did not stop.")
        }
        process = nil
        try removePIDFile()
        stopDiagnosticCapture()
    }

    func status() -> (running: Bool, pid: Int32?, lastError: String?) {
        lock.lock()
        defer { lock.unlock() }
        guard let child = process else {
            return (false, nil, currentFailure())
        }
        guard child.isRunning else {
            let failure = recordUnexpectedExit(child)
            process = nil
            try? removePIDFile()
            stopDiagnosticCapture()
            return (false, nil, failure)
        }
        return (true, child.processIdentifier, nil)
    }

    private func resetDiagnostics() {
        diagnosticLock.lock()
        diagnosticData.removeAll(keepingCapacity: true)
        lastFailure = nil
        diagnosticLock.unlock()
    }

    private func startDiagnosticCapture(for child: Process) {
        let pipe = Pipe()
        diagnosticPipe = pipe
        child.standardOutput = pipe
        child.standardError = pipe
        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else {
                handle.readabilityHandler = nil
                return
            }
            self?.appendDiagnostic(data)
        }
    }

    private func stopDiagnosticCapture() {
        guard let pipe = diagnosticPipe else { return }
        pipe.fileHandleForReading.readabilityHandler = nil
        try? pipe.fileHandleForReading.close()
        try? pipe.fileHandleForWriting.close()
        diagnosticPipe = nil
    }

    private func appendDiagnostic(_ data: Data) {
        diagnosticLock.lock()
        defer { diagnosticLock.unlock() }
        if data.count >= maximumDiagnosticBytes {
            diagnosticData = Data(data.suffix(maximumDiagnosticBytes))
            return
        }
        let overflow = diagnosticData.count + data.count - maximumDiagnosticBytes
        if overflow > 0 {
            diagnosticData.removeFirst(overflow)
        }
        diagnosticData.append(data)
    }

    private func recordUnexpectedExit(_ child: Process) -> String {
        diagnosticLock.lock()
        defer { diagnosticLock.unlock() }
        if let lastFailure { return lastFailure }
        let detail = Self.sanitizedDiagnostic(diagnosticData)
        let prefix = "Mihomo exited during startup (status \(child.terminationStatus))."
        let failure = detail.isEmpty ? prefix : "\(prefix) \(detail)"
        lastFailure = failure
        return failure
    }

    private func currentFailure() -> String? {
        diagnosticLock.lock()
        defer { diagnosticLock.unlock() }
        return lastFailure
    }

    private static func sanitizedDiagnostic(_ data: Data) -> String {
        var text = String(decoding: data, as: UTF8.self)
        text = text.replacingOccurrences(of: "127.0.0.1", with: "<loopback>")
        text = text.replacingOccurrences(
            of: #"\b(?:\d{1,3}\.){3}\d{1,3}\b"#,
            with: "<ip>",
            options: .regularExpression
        )
        text = text.replacingOccurrences(of: "<loopback>", with: "127.0.0.1")
        text = text.replacingOccurrences(
            of: #"(?i)(vless|vmess|trojan|ss)://\S+"#,
            with: "$1://<redacted>",
            options: .regularExpression
        )
        text = text.replacingOccurrences(
            of: #"(?i)(uuid|password|token|secret|public-key|short-id)(\s*[:=]\s*)\S+"#,
            with: "$1$2<redacted>",
            options: .regularExpression
        )
        let lines = text.components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
            .suffix(6)
        return String(lines.joined(separator: " | ").prefix(600))
    }

    private func writePID(_ pid: Int32) throws {
        let data = Data("\(pid)\n".utf8)
        let temporary = "\(pidPath).new"
        let fd = open(temporary, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw HelperFailure.system("Could not persist Mihomo state.") }
        defer { close(fd) }
        try data.withUnsafeBytes {
            guard let base = $0.baseAddress else { return }
            try writeAll(fd, bytes: base, count: $0.count)
        }
        guard fsync(fd) == 0, fchown(fd, 0, 0) == 0, fchmod(fd, 0o600) == 0,
              rename(temporary, pidPath) == 0 else {
            unlink(temporary)
            throw HelperFailure.system("Could not persist Mihomo state.")
        }
    }

    private func removePIDFile() throws {
        var metadata = stat()
        guard lstat(pidPath, &metadata) == 0 else {
            if errno == ENOENT { return }
            throw HelperFailure.system("Could not inspect Mihomo state.")
        }
        guard fileType(metadata) == mode_t(S_IFREG), metadata.st_uid == 0,
              unlink(pidPath) == 0 else {
            throw HelperFailure.invalid("Mihomo state file is unsafe.")
        }
    }

    private func processIdentity(_ pid: Int32) -> OwnedProcessIdentity? {
        var buffer = [CChar](repeating: 0, count: Int(PATH_MAX) * 4)
        let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard length > 0 else { return nil }

        var info = proc_bsdinfo()
        let infoSize = withUnsafeMutablePointer(to: &info) {
            proc_pidinfo(
                pid,
                PROC_PIDTBSDINFO,
                0,
                $0,
                Int32(MemoryLayout<proc_bsdinfo>.size)
            )
        }
        guard infoSize == MemoryLayout<proc_bsdinfo>.size else { return nil }
        return .init(
            pid: pid,
            executablePath: String(cString: buffer),
            uid: info.pbi_uid
        )
    }

    private func runningProcessIdentities() -> [OwnedProcessIdentity] {
        let capacity = proc_listallpids(nil, 0)
        guard capacity > 0 else { return [] }
        var pids = [Int32](repeating: 0, count: Int(capacity) + 32)
        let count = pids.withUnsafeMutableBytes {
            proc_listallpids($0.baseAddress, Int32($0.count))
        }
        guard count > 0 else { return [] }
        return pids.prefix(Int(count)).compactMap(processIdentity)
    }

    private func terminateOwnedCore(_ pid: Int32) throws {
        guard kill(pid, 0) == 0 else { return }
        _ = kill(pid, SIGTERM)
        for _ in 0..<30 where kill(pid, 0) == 0 { usleep(100_000) }
        if kill(pid, 0) == 0 { _ = kill(pid, SIGKILL) }
        for _ in 0..<20 where kill(pid, 0) == 0 { usleep(50_000) }
        guard kill(pid, 0) != 0 else {
            throw HelperFailure.system("A stale Mihomo process could not be stopped.")
        }
    }

    private func terminateStaleCore() throws {
        var identities = runningProcessIdentities()
        if let raw = try? String(contentsOfFile: pidPath, encoding: .utf8),
           let recordedPID = Int32(raw.trimmingCharacters(in: .whitespacesAndNewlines)),
           let recordedIdentity = processIdentity(recordedPID),
           !identities.contains(where: { $0.pid == recordedPID }) {
            identities.append(recordedIdentity)
        }

        for pid in staleOwnedCorePIDs(in: identities) {
            try terminateOwnedCore(pid)
        }
        try? removePIDFile()
    }
}

private struct HTTPRequest {
    let method: String
    let path: String
    let body: Data
}

private func readRequest(_ fd: Int32) throws -> HTTPRequest {
    let delimiter = Data("\r\n\r\n".utf8)
    var data = Data()
    var expectedLength: Int?
    var headerRange: Range<Data.Index>?
    var buffer = [UInt8](repeating: 0, count: 2048)

    while data.count <= maximumRequestBytes {
        if let split = data.range(of: delimiter) {
            headerRange = split
            guard split.lowerBound <= maximumHeaderBytes,
                  let header = String(data: data[..<split.lowerBound], encoding: .utf8) else {
                throw HelperFailure.invalid("Invalid request headers.")
            }
            let lines = header.components(separatedBy: "\r\n")
            guard let requestLine = lines.first else {
                throw HelperFailure.invalid("Invalid request.")
            }
            var contentLength = 0
            var sawContentLength = false
            for line in lines.dropFirst() {
                let pair = line.split(separator: ":", maxSplits: 1)
                guard pair.count == 2 else { throw HelperFailure.invalid("Invalid request header.") }
                let name = pair[0].trimmingCharacters(in: .whitespaces).lowercased()
                let value = pair[1].trimmingCharacters(in: .whitespaces)
                if name == "transfer-encoding" {
                    throw HelperFailure.invalid("Transfer encoding is not accepted.")
                }
                if name == "content-length" {
                    guard !sawContentLength, let parsed = Int(value), parsed >= 0,
                          parsed <= maximumRequestBytes - split.upperBound else {
                        throw HelperFailure.invalid("Invalid content length.")
                    }
                    sawContentLength = true
                    contentLength = parsed
                }
            }
            expectedLength = split.upperBound + contentLength
            guard let total = expectedLength else {
                throw HelperFailure.invalid("Invalid request.")
            }
            if data.count >= total {
                guard data.count == total else {
                    throw HelperFailure.invalid("Unexpected bytes after request body.")
                }
                let fields = requestLine.split(separator: " ")
                guard fields.count == 3, fields[2] == "HTTP/1.1" else {
                    throw HelperFailure.invalid("Invalid request line.")
                }
                let body = Data(data[split.upperBound..<total])
                return HTTPRequest(method: String(fields[0]), path: String(fields[1]), body: body)
            }
        }

        let count = Darwin.read(fd, &buffer, buffer.count)
        if count < 0 {
            if errno == EINTR { continue }
            throw HelperFailure.invalid("Request timed out.")
        }
        guard count > 0 else { throw HelperFailure.invalid("Incomplete request.") }
        data.append(buffer, count: count)
        if headerRange == nil, data.count > maximumHeaderBytes {
            throw HelperFailure.invalid("Request headers are too large.")
        }
        if let total = expectedLength, data.count > total {
            throw HelperFailure.invalid("Unexpected bytes after request body.")
        }
    }
    throw HelperFailure.invalid("Request is too large.")
}

private func jsonObject(_ data: Data) throws -> [String: Any] {
    guard !data.isEmpty,
          let value = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw HelperFailure.invalid("A JSON object is required.")
    }
    return value
}

private func sendResponse(_ fd: Int32, status: Int, object: [String: Any]) {
    let reason: String
    switch status {
    case 200: reason = "OK"
    case 400: reason = "Bad Request"
    case 403: reason = "Forbidden"
    case 404: reason = "Not Found"
    case 409: reason = "Conflict"
    default: reason = "Internal Server Error"
    }
    let body = (try? JSONSerialization.data(withJSONObject: object)) ?? Data(#"{"ok":false,"error":"Internal error."}"#.utf8)
    var response = Data(
        "HTTP/1.1 \(status) \(reason)\r\nContent-Type: application/json\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n".utf8
    )
    response.append(body)
    try? response.withUnsafeBytes {
        guard let base = $0.baseAddress else { return }
        try writeAll(fd, bytes: base, count: $0.count)
    }
}

/// Serializes network-opening helper requests against the kernel power
/// transition. Once sleep begins, no late GUI request may replace the
/// emergency PF state or restart the owned core. Existing requests finish
/// before `beginSleep()` returns, after which the power callback installs the
/// all-block barrier and stops Mihomo.
private final class PowerTransitionGate: @unchecked Sendable {
    private let lock = NSLock()
    private var sleeping = false

    func whileAwake<T>(_ operation: () throws -> T) throws -> T {
        lock.lock()
        defer { lock.unlock() }
        guard !sleeping else {
            throw HelperFailure.invalid(
                "The system is entering sleep; network protection remains fail-closed."
            )
        }
        return try operation()
    }

    func isAwake() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return !sleeping
    }

    func beginSleep() {
        lock.lock()
        sleeping = true
        lock.unlock()
    }

    func finishWakeBarrier() {
        lock.lock()
        sleeping = false
        lock.unlock()
    }

    static func runSelfTests() -> Bool {
        let gate = PowerTransitionGate()
        guard (try? gate.whileAwake { 7 }) == 7 else { return false }
        gate.beginSleep()
        do {
            _ = try gate.whileAwake { 9 }
            return false
        } catch {
            gate.finishWakeBarrier()
            return (try? gate.whileAwake { 11 }) == 11
        }
    }
}

/// Installs the fail-closed barrier from the privileged process at the actual
/// macOS power event. On sleep it commits PF first, then stops the owned core;
/// on wake it reasserts the emergency block before the GUI can rebuild TUN and
/// DNS. Missing GUI notifications therefore affect recovery latency, not leak
/// safety.
private final class HelperPowerMonitor: @unchecked Sendable {
    private let killSwitch: KillSwitchManager
    private let core: CoreManager
    private let transitionGate: PowerTransitionGate
    private let queue = DispatchQueue(label: "com.raydocs.tono.helper-power")
    private var rootPort: io_connect_t = 0
    private var notifier: io_object_t = 0
    private var notificationPort: IONotificationPortRef?

    init(
        killSwitch: KillSwitchManager,
        core: CoreManager,
        transitionGate: PowerTransitionGate
    ) {
        self.killSwitch = killSwitch
        self.core = core
        self.transitionGate = transitionGate
    }

    func start() throws {
        guard rootPort == 0 else { return }
        let callback: IOServiceInterestCallback = {
            refcon, _, messageType, messageArgument in
            guard let refcon else { return }
            let monitor = Unmanaged<HelperPowerMonitor>
                .fromOpaque(refcon)
                .takeUnretainedValue()
            monitor.handle(messageType, argument: messageArgument)
        }
        let port = IORegisterForSystemPower(
            Unmanaged.passUnretained(self).toOpaque(),
            &notificationPort,
            callback,
            &notifier
        )
        guard port != 0, let notificationPort else {
            if let notificationPort {
                IONotificationPortDestroy(notificationPort)
                self.notificationPort = nil
            }
            throw HelperFailure.system(
                "Could not register the helper power-transition monitor."
            )
        }
        rootPort = port
        IONotificationPortSetDispatchQueue(notificationPort, queue)
    }

    private func handle(
        _ messageType: UInt32,
        argument: UnsafeMutableRawPointer?
    ) {
        switch messageType {
        case tonoIOMessageCanSystemSleep:
            IOAllowPowerChange(rootPort, Int(bitPattern: argument))
        case tonoIOMessageSystemWillSleep:
            // Wait for any already-authorized arm/start/disarm request, then
            // reject all later ones before committing the emergency barrier.
            transitionGate.beginSleep()
            let wasProtected = killSwitch.secureForPowerTransition()
            if wasProtected { try? core.stop() }
            IOAllowPowerChange(rootPort, Int(bitPattern: argument))
        case tonoIOMessageSystemWillPowerOn:
            // Keep the request gate closed while devices and routes are still
            // resuming. A second barrier at HasPoweredOn covers any stale state
            // the kernel restored with the physical interfaces.
            _ = killSwitch.secureForPowerTransition()
        case tonoIOMessageSystemHasPoweredOn:
            _ = killSwitch.secureForPowerTransition()
            // GUI recovery may proceed only after emergency PF is reasserted.
            transitionGate.finishWakeBarrier()
        default:
            break
        }
    }

    func stop() {
        if let notificationPort {
            IONotificationPortSetDispatchQueue(notificationPort, nil)
        }
        if notifier != 0 {
            IODeregisterForSystemPower(&notifier)
            notifier = 0
        }
        if rootPort != 0 {
            IOServiceClose(rootPort)
            rootPort = 0
        }
        if let notificationPort {
            IONotificationPortDestroy(notificationPort)
            self.notificationPort = nil
        }
    }

    deinit {
        stop()
    }
}

private final class SocketServer {
    private let allowedUID: uid_t
    private let allowedGID: gid_t
    private let authorizer: TonoPeerAuthorizer
    private let core: CoreManager
    private let killSwitch: KillSwitchManager
    private let protectedDNS: ProtectedDNSManager
    private let transitionGate: PowerTransitionGate
    private let powerMonitor: HelperPowerMonitor
    private var serverFD: Int32 = -1

    init() throws {
        guard geteuid() == 0 else {
            throw HelperFailure.invalid("The helper must run as root.")
        }
        allowedUID = try readAllowedUID()
        allowedGID = try allowedGroup(for: allowedUID)
        authorizer = try TonoPeerAuthorizer(allowedUID: allowedUID)
        try ensureRootDirectory(socketDirectory, permissions: 0o755)
        core = try CoreManager(allowedUID: allowedUID)
        killSwitch = try KillSwitchManager(allowedUID: allowedUID)
        protectedDNS = try ProtectedDNSManager()
        transitionGate = PowerTransitionGate()
        powerMonitor = HelperPowerMonitor(
            killSwitch: killSwitch,
            core: core,
            transitionGate: transitionGate
        )
        try setupSocket()
        try powerMonitor.start()
    }

    deinit {
        if serverFD >= 0 { close(serverFD) }
    }

    private func setupSocket() throws {
        try removeIfPresent(socketPath, requiredType: mode_t(S_IFSOCK), allowedOwner: allowedUID)
        serverFD = socket(AF_UNIX, SOCK_STREAM, 0)
        guard serverFD >= 0 else { throw HelperFailure.system("Could not create helper socket.") }
        _ = fcntl(serverFD, F_SETFD, FD_CLOEXEC)

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let copied = socketPath.withCString { source in
            withUnsafeMutablePointer(to: &address.sun_path) { tuple in
                tuple.withMemoryRebound(to: CChar.self, capacity: 104) {
                    strlcpy($0, source, 104)
                }
            }
        }
        guard copied < 104 else { throw HelperFailure.invalid("Helper socket path is too long.") }
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(serverFD, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bound == 0,
              chown(socketPath, allowedUID, allowedGID) == 0,
              chmod(socketPath, 0o600) == 0,
              listen(serverFD, 8) == 0 else {
            throw HelperFailure.system("Could not secure helper socket.")
        }
    }

    func run() {
        while helperShutdownRequested == 0 {
            var descriptor = pollfd(
                fd: serverFD,
                events: Int16(POLLIN),
                revents: 0
            )
            // IPC wakes poll immediately. A one-second timeout exists only to
            // observe the signal flag and avoids four idle helper wakeups/sec.
            let ready = poll(&descriptor, 1, 1_000)
            if ready == 0 { continue }
            if ready < 0 {
                if errno == EINTR { continue }
                usleep(100_000)
                continue
            }
            guard descriptor.revents & Int16(POLLIN) != 0 else { continue }
            let client = accept(serverFD, nil, nil)
            if client < 0 {
                if errno == EINTR { continue }
                usleep(100_000)
                continue
            }
            handle(client)
            close(client)
        }
        // launchd replacement/bootout is a normal lifecycle event. Reap the
        // owned child before this helper exits so the next version never races
        // an orphaned controller or TUN.
        try? core.stop()
    }

    private func handle(_ client: Int32) {
        _ = fcntl(client, F_SETFD, FD_CLOEXEC)
        var timeout = timeval(tv_sec: 3, tv_usec: 0)
        _ = withUnsafePointer(to: &timeout) {
            setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, $0, socklen_t(MemoryLayout<timeval>.size))
        }
        _ = withUnsafePointer(to: &timeout) {
            setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, $0, socklen_t(MemoryLayout<timeval>.size))
        }

        guard authorizer.accepts(socket: client) else {
            sendResponse(client, status: 403, object: ["ok": false, "error": "Forbidden."])
            return
        }

        do {
            let request = try readRequest(client)
            switch (request.method, request.path) {
            case ("GET", "/version"):
                guard request.body.isEmpty else { throw HelperFailure.invalid("Unexpected request body.") }
                sendResponse(client, status: 200, object: ["ok": true, "version": helperVersion])
            case ("GET", "/core/status"):
                guard request.body.isEmpty else { throw HelperFailure.invalid("Unexpected request body.") }
                let status = core.status()
                var object: [String: Any] = ["ok": true, "running": status.running]
                if let pid = status.pid { object["pid"] = Int(pid) }
                if let lastError = status.lastError {
                    object["lastError"] = String(lastError.prefix(600))
                }
                sendResponse(client, status: 200, object: object)
            case ("POST", "/core/start"):
                let object = try jsonObject(request.body)
                guard object.count == 2,
                      let directory = object["configDir"] as? String,
                      let digest = object["configSHA256"] as? String else {
                    throw HelperFailure.invalid("Invalid start request.")
                }
                try core.start(
                    configDirectory: directory,
                    configSHA256: digest,
                    startAllowed: { transitionGate.isAwake() }
                )
                sendResponse(client, status: 200, object: ["ok": true])
            case ("POST", "/core/sync"):
                let object = try jsonObject(request.body)
                guard object.count == 2,
                      let directory = object["configDir"] as? String,
                      let digest = object["configSHA256"] as? String else {
                    throw HelperFailure.invalid("Invalid sync request.")
                }
                let path = try core.sync(
                    configDirectory: directory,
                    configSHA256: digest
                )
                sendResponse(client, status: 200, object: ["ok": true, "configPath": path])
            case ("DELETE", "/core/stop"):
                guard request.body.isEmpty else { throw HelperFailure.invalid("Unexpected request body.") }
                try core.stop()
                sendResponse(client, status: 200, object: ["ok": true])
            case ("GET", "/killswitch/status"):
                guard request.body.isEmpty else { throw HelperFailure.invalid("Unexpected request body.") }
                sendResponse(client, status: 200, object: killSwitch.status())
            case ("POST", "/killswitch/arm"):
                let object = try jsonObject(request.body)
                try validateKillSwitchArmFields(object)
                let response = try killSwitch.arm(
                    object,
                    commitAllowed: { transitionGate.isAwake() }
                )
                sendResponse(client, status: 200, object: response)
            case ("POST", "/killswitch/disarm"):
                guard request.body.isEmpty else { throw HelperFailure.invalid("Unexpected request body.") }
                let response = try transitionGate.whileAwake {
                    try killSwitch.disarm()
                }
                sendResponse(client, status: 200, object: response)
            case ("GET", "/dns/status"):
                guard request.body.isEmpty else { throw HelperFailure.invalid("Unexpected request body.") }
                sendResponse(client, status: 200, object: protectedDNS.status())
            case ("POST", "/dns/enable"):
                let object = try jsonObject(request.body)
                guard object.count == 1,
                      let service = object["service"] as? String else {
                    throw HelperFailure.invalid("Invalid protected DNS request.")
                }
                sendResponse(
                    client,
                    status: 200,
                    object: try protectedDNS.enable(service: service)
                )
            case ("POST", "/dns/restore"):
                guard request.body.isEmpty else { throw HelperFailure.invalid("Unexpected request body.") }
                sendResponse(client, status: 200, object: try protectedDNS.restore())
            default:
                sendResponse(client, status: 404, object: ["ok": false, "error": "Not found."])
            }
        } catch let failure as HelperFailure {
            let status = failure.message.contains("already running") ? 409 : 400
            sendResponse(client, status: status, object: ["ok": false, "error": failure.message])
        } catch {
            sendResponse(client, status: 500, object: ["ok": false, "error": "Internal helper error."])
        }
    }
}

signal(SIGPIPE, SIG_IGN)
signal(SIGTERM, requestHelperShutdown)
signal(SIGINT, requestHelperShutdown)
umask(0o077)
if CommandLine.arguments.dropFirst() == ["--version"] {
    print(helperVersion)
    exit(0)
}
if CommandLine.arguments.dropFirst() == ["--self-test"] {
    exit(
        KillSwitchManager.runSelfTests()
            && ProtectedDNSManager.runSelfTests()
            && runRequestContractSelfTests()
            && runCoreLifecyclePolicySelfTests()
            && runOwnedRuntimeContractSelfTests()
            && PowerTransitionGate.runSelfTests()
            ? 0 : 1
    )
}
if CommandLine.arguments.dropFirst() == ["--network-self-test"] {
    exit(KillSwitchManager.runNetworkSelfTest() ? 0 : 1)
}
if CommandLine.arguments.dropFirst() == ["--emergency-disarm"] {
    exit(runEmergencyDisarm() ? 0 : 1)
}
if CommandLine.arguments.dropFirst() == ["--emergency-reset"] {
    exit(runEmergencyReset() ? 0 : 1)
}
do {
    let server = try SocketServer()
    server.run()
} catch {
    exit(1)
}
