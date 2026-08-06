import Foundation
import Darwin

// MARK: - Config Storage

nonisolated final class ConfigStorage: @unchecked Sendable {
    static let shared = ConfigStorage()

    private let fileManager: FileManager

    /// ~/Library/Application Support/Tono/
    let appSupportDirectory: URL

    private init(fileManager: FileManager = .default) {
        self.fileManager = fileManager
        let base = fileManager.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first ?? URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true)
            .appendingPathComponent(
                "Library/Application Support",
                isDirectory: true
            )
        let url = base
            .appendingPathComponent(AppProfile.appSupportDirectoryName, isDirectory: true)
        if !fileManager.fileExists(atPath: url.path) {
            try? fileManager.createDirectory(
                at: url,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        }
        try? fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
        appSupportDirectory = url
    }

    /// Config file path
    var configFilePath: URL {
        appSupportDirectory.appendingPathComponent("config.json")
    }

    // MARK: - Config

    func saveConfig(_ config: ClashConfig) {
        var persisted = config
        // The local controller credential is per-process and must never survive
        // a restart or be exposed in the preferences file.
        persisted.secret = ""
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(persisted) else { return }
        try? writeSensitive(data, to: configFilePath)
    }

    func loadConfig() -> ClashConfig? {
        guard let data = try? Data(contentsOf: configFilePath) else { return nil }
        return try? JSONDecoder().decode(ClashConfig.self, from: data)
    }

    // MARK: - Proxy Regions

    func saveProxyRegions(_ regions: [ProxyRegion]) {
        let container = RegionContainer(regions: regions.map { region in
            RegionContainer.Region(
                id: region.id,
                name: region.name,
                nodes: region.nodes,
                isExpanded: region.isExpanded
            )
        })
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        guard let data = try? encoder.encode(container) else { return }
        let url = appSupportDirectory.appendingPathComponent("regions.json")
        try? writeSensitive(data, to: url)
    }

    func loadProxyRegions() -> [ProxyRegion]? {
        let url = appSupportDirectory.appendingPathComponent("regions.json")
        guard let data = try? Data(contentsOf: url) else { return nil }
        guard let container = try? JSONDecoder().decode(RegionContainer.self, from: data) else { return nil }
        return container.regions.map { region in
            ProxyRegion(id: region.id, name: region.name, nodes: region.nodes, isExpanded: region.isExpanded)
        }
    }

    // MARK: - Runtime Config Path

    var runtimeConfigPath: URL {
        appSupportDirectory.appendingPathComponent("config", isDirectory: true)
            .appendingPathComponent("config.yaml")
    }

    // MARK: - Subscription YAML (immutable, stored as-is)

    var subscriptionYAMLPath: URL {
        appSupportDirectory.appendingPathComponent("subscription_raw.yaml")
    }

    func saveSubscriptionYAML(_ yaml: String) {
        if let data = yaml.data(using: .utf8) {
            try? writeSensitive(data, to: subscriptionYAMLPath)
        }
    }

    func loadSubscriptionYAML() -> String? {
        try? String(contentsOf: subscriptionYAMLPath, encoding: .utf8)
    }

    /// Legacy aliases for compatibility during migration
    func saveRawSubscriptionYAML(_ yaml: String) { saveSubscriptionYAML(yaml) }
    func loadRawSubscriptionYAML() -> String? { loadSubscriptionYAML() }

    // MARK: - Managed exit catalog

    private var managedExitCatalogPath: URL {
        appSupportDirectory.appendingPathComponent("managed-exit-catalog.json")
    }

    func saveManagedExitCatalog(_ catalog: ManagedExitCatalogCache) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try writeSensitive(encoder.encode(catalog), to: managedExitCatalogPath)
    }

    func loadManagedExitCatalog() -> ManagedExitCatalogCache? {
        guard let attributes = try? fileManager.attributesOfItem(
            atPath: managedExitCatalogPath.path
        ),
              let permissions = (attributes[.posixPermissions] as? NSNumber)?.uint16Value,
              permissions & 0o077 == 0,
              let owner = (attributes[.ownerAccountID] as? NSNumber)?.uint32Value,
              owner == getuid()
        else { return nil }
        guard let values = try? managedExitCatalogPath.resourceValues(forKeys: [
            .isRegularFileKey,
            .isSymbolicLinkKey,
            .fileSizeKey,
        ]),
              values.isRegularFile == true,
              values.isSymbolicLink != true,
              let size = values.fileSize,
              size > 0,
              size <= 2 * 1024 * 1024,
              let data = try? Data(contentsOf: managedExitCatalogPath, options: .mappedIfSafe)
        else { return nil }
        return try? JSONDecoder().decode(ManagedExitCatalogCache.self, from: data)
    }

    // MARK: - Managed traffic policy

    private var managedTrafficPolicyPath: URL {
        appSupportDirectory.appendingPathComponent("managed-traffic-policy.json")
    }

    func saveManagedTrafficPolicy(_ policy: ManagedTrafficPolicyCache) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try writeSensitive(encoder.encode(policy), to: managedTrafficPolicyPath)
    }

    func loadManagedTrafficPolicy() -> ManagedTrafficPolicyCache? {
        guard let attributes = try? fileManager.attributesOfItem(
            atPath: managedTrafficPolicyPath.path
        ),
              let permissions = (attributes[.posixPermissions] as? NSNumber)?.uint16Value,
              permissions & 0o077 == 0,
              let owner = (attributes[.ownerAccountID] as? NSNumber)?.uint32Value,
              owner == getuid()
        else { return nil }
        guard let values = try? managedTrafficPolicyPath.resourceValues(forKeys: [
            .isRegularFileKey,
            .isSymbolicLinkKey,
            .fileSizeKey,
        ]),
              values.isRegularFile == true,
              values.isSymbolicLink != true,
              let size = values.fileSize,
              size > 0,
              size <= 128 * 1024,
              let data = try? Data(
                contentsOf: managedTrafficPolicyPath,
                options: .mappedIfSafe
              )
        else { return nil }
        return try? JSONDecoder().decode(ManagedTrafficPolicyCache.self, from: data)
    }

    // MARK: - Rules

    func saveRules(_ rules: [RuleItem]) {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        guard let data = try? encoder.encode(rules) else { return }
        let url = appSupportDirectory.appendingPathComponent("rules.json")
        try? writeSensitive(data, to: url)
    }

    func loadRules() -> [RuleItem]? {
        let url = appSupportDirectory.appendingPathComponent("rules.json")
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode([RuleItem].self, from: data)
    }

    func writeSensitive(_ data: Data, to url: URL) throws {
        try data.write(to: url, options: .atomic)
        try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}

nonisolated struct ManagedExitCatalogCache: Codable, Sendable, Equatable {
    let revision: Int
    let yaml: String
    let sha256: String
    let updatedAt: Int?
}

nonisolated struct ManagedTrafficPolicyCache: Codable, Sendable, Equatable {
    let revision: Int
    let json: String
    let sha256: String
    let updatedAt: Int?
}

// MARK: - Region Container (Codable wrapper)

nonisolated private struct RegionContainer: Codable {
    nonisolated struct Region: Codable {
        let id: String
        let name: String
        let nodes: [ProxyNode]
        let isExpanded: Bool
    }
    let regions: [Region]
}
