import Foundation

// MARK: - Config Storage

final class ConfigStorage {
    static let shared = ConfigStorage()

    private let fileManager = FileManager.default

    /// ~/Library/Application Support/LiquidClash/
    var appSupportDirectory: URL {
        let url = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
            .appendingPathComponent("LiquidClash", isDirectory: true)
        if !fileManager.fileExists(atPath: url.path) {
            try? fileManager.createDirectory(at: url, withIntermediateDirectories: true)
        }
        return url
    }

    /// Config file path
    var configFilePath: URL {
        appSupportDirectory.appendingPathComponent("config.json")
    }

    // MARK: - Config

    func saveConfig(_ config: ClashConfig) {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(config) else { return }
        try? data.write(to: configFilePath, options: .atomic)
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
        try? data.write(to: url, options: .atomic)
    }

    func loadProxyRegions() -> [ProxyRegion]? {
        let url = appSupportDirectory.appendingPathComponent("regions.json")
        guard let data = try? Data(contentsOf: url) else { return nil }
        guard let container = try? JSONDecoder().decode(RegionContainer.self, from: data) else { return nil }
        return container.regions.map { region in
            ProxyRegion(id: region.id, name: region.name, nodes: region.nodes, isExpanded: region.isExpanded)
        }
    }

    // MARK: - Raw Subscription YAML

    /// Save the raw YAML content downloaded from subscriptions for mihomo to use directly
    func saveRawSubscriptionYAML(_ yaml: String) {
        let url = appSupportDirectory.appendingPathComponent("subscription_raw.yaml")
        try? yaml.write(to: url, atomically: true, encoding: .utf8)
    }

    func loadRawSubscriptionYAML() -> String? {
        let url = appSupportDirectory.appendingPathComponent("subscription_raw.yaml")
        return try? String(contentsOf: url, encoding: .utf8)
    }

    // MARK: - Rules

    func saveRules(_ rules: [RuleItem]) {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        guard let data = try? encoder.encode(rules) else { return }
        let url = appSupportDirectory.appendingPathComponent("rules.json")
        try? data.write(to: url, options: .atomic)
    }

    func loadRules() -> [RuleItem]? {
        let url = appSupportDirectory.appendingPathComponent("rules.json")
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode([RuleItem].self, from: data)
    }
}

// MARK: - Region Container (Codable wrapper)

private struct RegionContainer: Codable {
    struct Region: Codable {
        let id: String
        let name: String
        let nodes: [ProxyNode]
        let isExpanded: Bool
    }
    let regions: [Region]
}
