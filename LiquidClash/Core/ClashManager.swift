import Foundation
import Observation

// MARK: - Clash Manager

@Observable
final class ClashManager {
    var isRunning = false
    var logOutput: [String] = []

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

    /// Find the mihomo binary (for non-helper fallback checks)
    func findBinary() -> URL? {
        let paths: [URL] = [
            Bundle.main.url(forResource: "mihomo", withExtension: nil),
            ConfigStorage.shared.appSupportDirectory.appendingPathComponent("bin/mihomo"),
            URL(fileURLWithPath: "/usr/local/bin/mihomo"),
        ].compactMap { $0 }
        return paths.first { FileManager.default.isExecutableFile(atPath: $0.path) }
    }

    // MARK: - Geodata

    private func ensureGeodataFiles() {
        let fm = FileManager.default
        for filename in ["country.mmdb", "geoip.dat", "geosite.dat"] {
            let dest = configDirectory.appendingPathComponent(filename)
            guard !fm.fileExists(atPath: dest.path) else { continue }
            if let bundled = Bundle.main.url(forResource: filename.components(separatedBy: ".").first,
                                              withExtension: filename.components(separatedBy: ".").last) {
                try? fm.copyItem(at: bundled, to: dest)
            }
        }
    }

    // MARK: - Write Runtime Config

    func writeRuntimeConfig(subscriptionYAML: String, overlay: ConfigPipeline.OverlayConfig, customNodes: [ProxyNode] = []) throws {
        try ConfigPipeline.generateRuntime(
            subscriptionYAML: subscriptionYAML,
            overlay: overlay,
            customNodes: customNodes,
            outputPath: configFilePath
        )
    }

    // MARK: - Start (via Helper Daemon)

    func start(subscriptionYAML: String, overlay: ConfigPipeline.OverlayConfig, customNodes: [ProxyNode] = []) throws {
        guard !isRunning else { return }

        ensureGeodataFiles()
        try writeRuntimeConfig(subscriptionYAML: subscriptionYAML, overlay: overlay, customNodes: customNodes)

        // Ensure helper daemon is installed and running
        try HelperManager.installIfNeeded()

        // Tell helper to start mihomo with our config directory
        try HelperManager.startCore(configDir: configDirectory.path)
        isRunning = true
    }

    // MARK: - Stop (via Helper Daemon)

    func stop() {
        do {
            try HelperManager.stopCore()
        } catch {
            print("[ClashManager] stop failed: \(error)")
        }
        isRunning = false
    }

    // MARK: - Rewrite Config (for hot reload without restarting process)

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
