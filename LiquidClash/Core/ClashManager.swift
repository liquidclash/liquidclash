import Foundation
import Observation

// MARK: - Clash Manager

@Observable
final class ClashManager {
    var isRunning = false
    var logOutput: [String] = []

    private var process: Process?
    private var outputPipe: Pipe?
    private var privilegedMode = false
    private var privilegedPID: Int32?

    /// Possible binary locations (checked in order)
    private var binarySearchPaths: [URL] {
        let appSupport = ConfigStorage.shared.appSupportDirectory
        var paths = [
            appSupport.appendingPathComponent("bin/mihomo"),
            appSupport.appendingPathComponent("bin/clash"),
        ]
        // Also check in app bundle
        if let bundled = Bundle.main.url(forResource: "mihomo", withExtension: nil) {
            paths.insert(bundled, at: 0)
        }
        if let bundled = Bundle.main.url(forResource: "clash", withExtension: nil) {
            paths.insert(bundled, at: 1)
        }
        // Check /usr/local/bin as fallback
        paths.append(URL(fileURLWithPath: "/usr/local/bin/mihomo"))
        paths.append(URL(fileURLWithPath: "/usr/local/bin/clash"))
        return paths
    }

    /// Find the mihomo/clash binary
    func findBinary() -> URL? {
        let fm = FileManager.default
        for path in binarySearchPaths {
            if fm.isExecutableFile(atPath: path.path) {
                return path
            }
        }
        return nil
    }

    /// Config directory for mihomo
    var configDirectory: URL {
        let dir = ConfigStorage.shared.appSupportDirectory.appendingPathComponent("config", isDirectory: true)
        if !FileManager.default.fileExists(atPath: dir.path) {
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        }
        return dir
    }

    /// Main config file path
    var configFilePath: URL {
        configDirectory.appendingPathComponent("config.yaml")
    }

    // MARK: - Geodata

    /// Copy bundled geodata files (MMDB, geoip.dat, geosite.dat) to config directory
    /// so mihomo doesn't need to download them on first launch.
    private func ensureGeodataFiles() {
        let fm = FileManager.default
        let geodataFiles = ["country.mmdb", "geoip.dat", "geosite.dat"]
        for filename in geodataFiles {
            let dest = configDirectory.appendingPathComponent(filename)
            guard !fm.fileExists(atPath: dest.path) else { continue }
            if let bundled = Bundle.main.url(forResource: filename.components(separatedBy: ".").first,
                                              withExtension: filename.components(separatedBy: ".").last) {
                try? fm.copyItem(at: bundled, to: dest)
            }
        }
    }

    // MARK: - Write Runtime Config

    /// Write runtime config using ConfigPipeline
    func writeRuntimeConfig(subscriptionYAML: String, overlay: ConfigPipeline.OverlayConfig, customNodes: [ProxyNode] = []) throws {
        try ConfigPipeline.generateRuntime(
            subscriptionYAML: subscriptionYAML,
            overlay: overlay,
            customNodes: customNodes,
            outputPath: configFilePath
        )
    }

    // MARK: - Start

    /// Start mihomo with subscription YAML + overlay
    func start(subscriptionYAML: String, overlay: ConfigPipeline.OverlayConfig, customNodes: [ProxyNode] = []) throws {
        guard !isRunning else { return }

        guard let binary = findBinary() else {
            throw ClashError.binaryNotFound
        }

        ensureGeodataFiles()
        try writeRuntimeConfig(subscriptionYAML: subscriptionYAML, overlay: overlay, customNodes: customNodes)

        let proc = Process()
        proc.executableURL = binary
        proc.arguments = ["-d", configDirectory.path]

        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = pipe

        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty, let line = String(data: data, encoding: .utf8) else { return }
            DispatchQueue.main.async {
                self?.logOutput.append(contentsOf: line.components(separatedBy: .newlines).filter { !$0.isEmpty })
                // Keep only last 500 lines
                if let count = self?.logOutput.count, count > 500 {
                    self?.logOutput.removeFirst(count - 500)
                }
            }
        }

        proc.terminationHandler = { [weak self] _ in
            DispatchQueue.main.async {
                self?.isRunning = false
                self?.process = nil
            }
        }

        try proc.run()
        process = proc
        outputPipe = pipe
        isRunning = true
    }

    // MARK: - Start with Privileges (for TUN mode)

    /// Start mihomo with root privileges via osascript (required for TUN)
    func startWithPrivileges(subscriptionYAML: String, overlay: ConfigPipeline.OverlayConfig, customNodes: [ProxyNode] = []) throws {
        guard !isRunning else { return }

        guard let binary = findBinary() else {
            throw ClashError.binaryNotFound
        }

        ensureGeodataFiles()

        // Write config file with TUN enabled overlay
        var tunOverlay = overlay
        tunOverlay.tunEnabled = true
        try writeRuntimeConfig(subscriptionYAML: subscriptionYAML, overlay: tunOverlay, customNodes: customNodes)

        // Launch with admin privileges via osascript
        let binaryPath = binary.path.replacingOccurrences(of: "'", with: "'\\''")
        let configDir = configDirectory.path.replacingOccurrences(of: "'", with: "'\\''")
        let shellCmd = "'\(binaryPath)' -d '\(configDir)' &> /dev/null & echo $!"

        let script = "do shell script \"\(shellCmd.replacingOccurrences(of: "\"", with: "\\\""))\" with administrator privileges"

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        proc.arguments = ["-e", script]
        let outPipe = Pipe()
        let errPipe = Pipe()
        proc.standardOutput = outPipe
        proc.standardError = errPipe
        try proc.run()
        proc.waitUntilExit()

        if proc.terminationStatus != 0 {
            let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
            let errMsg = String(data: errData, encoding: .utf8) ?? ""
            if errMsg.contains("canceled") || errMsg.contains("User canceled") {
                throw ClashError.startFailed("Administrator privileges denied")
            }
            throw ClashError.startFailed(errMsg.trimmingCharacters(in: .whitespacesAndNewlines))
        }

        // Read the PID from osascript output (from "echo $!")
        let pidData = outPipe.fileHandleForReading.readDataToEndOfFile()
        if let pidStr = String(data: pidData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
           let pid = Int32(pidStr) {
            privilegedPID = pid
        }

        privilegedMode = true
        isRunning = true
    }

    // MARK: - Stop

    func stop() {
        if privilegedMode {
            // TUN mode: process runs as root, kill by PID or fallback to pkill
            if let pid = privilegedPID {
                kill(pid, SIGTERM)
                // Brief wait for graceful shutdown
                usleep(500_000)
                // Force kill if still alive
                kill(pid, SIGKILL)
            } else {
                // Fallback: pkill (less precise)
                let proc = Process()
                proc.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
                proc.arguments = ["-f", "mihomo"]
                proc.standardOutput = FileHandle.nullDevice
                proc.standardError = FileHandle.nullDevice
                try? proc.run()
                proc.waitUntilExit()
            }
            privilegedPID = nil
            privilegedMode = false
        } else if let proc = process {
            proc.terminate()
            proc.waitUntilExit()
        }
        outputPipe?.fileHandleForReading.readabilityHandler = nil
        process = nil
        outputPipe = nil
        isRunning = false
    }

    // MARK: - Rewrite Config (for hot reload without restarting process)

    /// Rewrite config.yaml on disk without restarting the process.
    /// Used together with ClashAPI.reloadConfig() for hot reloading.
    func rewriteConfig(subscriptionYAML: String, overlay: ConfigPipeline.OverlayConfig, customNodes: [ProxyNode] = []) throws {
        try writeRuntimeConfig(subscriptionYAML: subscriptionYAML, overlay: overlay, customNodes: customNodes)
    }

}

// MARK: - Clash Error

enum ClashError: LocalizedError {
    case binaryNotFound
    case configWriteFailed
    case startFailed(String)

    var errorDescription: String? {
        switch self {
        case .binaryNotFound:
            "找不到 mihomo 核心文件"
        case .configWriteFailed:
            "配置文件写入失败"
        case .startFailed(let msg):
            "核心启动失败：\(msg)"
        }
    }
}
