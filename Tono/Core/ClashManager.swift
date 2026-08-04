import Foundation
import Observation

/// Serializes runtime-config reads, validation, YAML generation, hashing, and
/// atomic disk writes away from the main actor. Catalogs are intentionally
/// bounded, but even a valid large YAML file must not stall SwiftUI while the
/// connect button is animating.
private actor RuntimeConfigWriter {
    func write(
        overlay: ConfigPipeline.OverlayConfig,
        customNodes: [ProxyNode],
        directPolicy: ConfigPipeline.ManagedDirectRuntimePolicy?,
        outputPath: URL
    ) throws -> String {
        try ConfigPipeline.generateRuntime(
            subscriptionYAML: ConfigStorage.shared.loadSubscriptionYAML() ?? "",
            overlay: overlay,
            customNodes: customNodes,
            directPolicy: directPolicy,
            outputPath: outputPath
        )
    }
}

// MARK: - Clash Manager

@Observable
final class ClashManager {
    var isRunning = false
    var logOutput: [String] = []
    private(set) var runtimeConfigSHA256: String?
    private let configWriter = RuntimeConfigWriter()

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

    @discardableResult
    func writeRuntimeConfig(
        overlay: ConfigPipeline.OverlayConfig,
        customNodes: [ProxyNode] = [],
        directPolicy: ConfigPipeline.ManagedDirectRuntimePolicy? = nil
    ) async throws -> String {
        let digest = try await configWriter.write(
            overlay: overlay,
            customNodes: customNodes,
            directPolicy: directPolicy,
            outputPath: configFilePath
        )
        runtimeConfigSHA256 = digest
        return digest
    }

    // MARK: - Start (via Helper Daemon)

    func start(
        overlay: ConfigPipeline.OverlayConfig,
        customNodes: [ProxyNode] = [],
        directPolicy: ConfigPipeline.ManagedDirectRuntimePolicy? = nil,
        helperPrepared: Bool = false
    ) async throws {
        guard !isRunning else { return }

        // The owned Tono runtime intentionally has no GEOIP/GEOSITE/MMDB rules.
        // Legacy non-Tono development configs may still opt into those assets.
        if overlay.tonoTransport == nil &&
            overlay.selectedNodeName == ConfigPipeline.homeNodeName {
            ensureGeodataFiles()
        }
        let digest = try await writeRuntimeConfig(
            overlay: overlay,
            customNodes: customNodes,
            directPolicy: directPolicy
        )

        // Helper installation, launchd replacement, and Unix-socket IPC are
        // serialized off the main actor so the connection animation stays
        // responsive even when macOS displays an administrator prompt.
        try await PrivilegedRuntimeCoordinator.shared.installAndStartCore(
            configDirectory: configDirectory.path,
            configSHA256: digest,
            helperPrepared: helperPrepared
        )
        isRunning = true
    }

    // MARK: - Stop (via Helper Daemon)

    @discardableResult
    func stop() -> Bool {
        do {
            try HelperManager.stopCore()
        } catch {
            print("[ClashManager] stop failed: \(error)")
            isRunning = false
            return false
        }
        isRunning = false
        return true
    }

    @discardableResult
    func stopAsync() async -> Bool {
        do {
            try await PrivilegedRuntimeCoordinator.shared.stopCore()
        } catch {
            print("[ClashManager] stop failed: \(error)")
            isRunning = false
            return false
        }
        isRunning = false
        return true
    }

    // MARK: - Rewrite Config (for hot reload without restarting process)

    func rewriteConfig(
        overlay: ConfigPipeline.OverlayConfig,
        customNodes: [ProxyNode] = [],
        directPolicy: ConfigPipeline.ManagedDirectRuntimePolicy? = nil
    ) async throws {
        try await writeRuntimeConfig(
            overlay: overlay,
            customNodes: customNodes,
            directPolicy: directPolicy
        )
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
