import SwiftUI
import Observation

// MARK: - Network Info

struct NetworkInfo {
    var ip: String = "--"
    var networkType: String = "--"
    var location: String = "--"
}

// MARK: - Traffic Stats

struct TrafficStats {
    var uploadSpeed: Int64 = 0
    var downloadSpeed: Int64 = 0
    var totalUpload: Int64 = 0
    var totalDownload: Int64 = 0
    var activeConnections: Int = 0
}

// MARK: - App State

@Observable
final class AppState {
    // Navigation
    var selectedPage: AppPage = .dashboard

    // Dashboard
    var isConnected: Bool = false
    var isConnecting: Bool = false
    var proxyMode: ProxyMode = .rule
    var activeNode: ProxyNode? = nil
    var networkInfo: NetworkInfo = NetworkInfo()
    var trafficStats: TrafficStats = TrafficStats()
    var errorMessage: String? = nil

    // Proxies
    var proxyRegions: [ProxyRegion] = []
    var selectedNodeId: String? = nil

    // Rules
    var rules: [RuleItem] = []

    // Activity
    var connections: [ConnectionEntry] = []

    // Logs
    var logEntries: [LogEntry] = []
    var logLevel: String = "info"

    // Subscriptions
    var subscriptions: [SubscriptionInfo] = []
    private var autoUpdateTimer: Timer?
    private var proxyGuardTimer: Timer?

    // Clash config
    var config: ClashConfig = ClashConfig()

    // Core components
    let clashManager = ClashManager()
    let subscriptionManager = SubscriptionManager()
    private var clashAPI: ClashAPI?
    private var webSocket: ClashWebSocket?
    private var connectTask: Task<Void, Never>?

    // MARK: - Init

    init() {}

    // Computed
    var totalNodes: Int {
        proxyRegions.flatMap(\.nodes).count
    }

    var isCoreAvailable: Bool {
        clashManager.findBinary() != nil
    }

    // MARK: - Connection Control

    func connect() {
        guard !isConnected && !isConnecting else { return }
        guard !proxyRegions.isEmpty else {
            errorMessage = "没有可用的代理节点，请先导入订阅"
            return
        }
        isConnecting = true
        errorMessage = nil

        // Sync settings from UserDefaults to config
        let portString = UserDefaults.standard.string(forKey: SettingsKey.mixedPort) ?? "7890"
        let port = Int(portString) ?? 7890
        config.mixedPort = port
        config.port = port
        config.socksPort = port
        config.tunEnabled = UserDefaults.standard.bool(forKey: SettingsKey.tunMode)
        config.allowLan = config.tunEnabled && UserDefaults.standard.bool(forKey: SettingsKey.allowLAN)

        // Populate proxies from regions
        let allNodes = proxyRegions.flatMap(\.nodes)
        config.proxies = allNodes

        // Build proxy groups
        let nodeNames = allNodes.map(\.name)
        let proxyGroup = ProxyGroup(name: "Proxy", type: .select, proxies: nodeNames + ["DIRECT"])
        config.proxyGroups = [
            ProxyGroup(name: "GLOBAL", type: .select, proxies: ["Proxy", "DIRECT"] + nodeNames),
            proxyGroup,
        ]

        // Build config rules from current rules
        config.rules = rules.map { $0.clashString }
        // Ensure a final catch-all rule exists — use Proxy so traffic actually goes through proxy
        if !config.rules.contains(where: { $0.hasPrefix("MATCH,") }) {
            config.rules.append("MATCH,Proxy")
        }
        config.mode = proxyMode.rawValue.lowercased()

        // Load raw subscription YAML — only use if it's actual Clash YAML (contains "proxies:")
        // URI-format subscriptions (trojan://, vmess://) are parsed into structured nodes instead
        let rawYAML = ConfigStorage.shared.loadRawSubscriptionYAML()
        let validRawYAML = rawYAML.flatMap { $0.contains("proxies:") ? $0 : nil }

        do {
            if config.tunEnabled {
                try clashManager.startWithPrivileges(config: config, rawSubscriptionYAML: validRawYAML)
            } else {
                try clashManager.start(config: config, rawSubscriptionYAML: validRawYAML)
            }
        } catch {
            isConnecting = false
            errorMessage = error.localizedDescription
            return
        }

        // Health-check: poll /version until mihomo is ready
        let apiPort = config.externalController.split(separator: ":").last.flatMap { Int($0) } ?? 9090
        let api = ClashAPI(port: apiPort, secret: config.secret)

        connectTask = Task { [clashManager] in
            do {
                try await api.waitUntilReady()
                await MainActor.run {
                    self.isConnecting = false
                    self.onCoreStarted(api: api)
                }
            } catch {
                await MainActor.run {
                    self.isConnecting = false
                    // Show mihomo log for diagnosis
                    let logs = clashManager.logOutput.suffix(5).joined(separator: "\n")
                    if !logs.isEmpty {
                        self.errorMessage = "核心启动失败：\n\(logs)"
                    } else if !clashManager.isRunning {
                        self.errorMessage = "核心进程已退出，请检查端口是否被占用（7890/9090）"
                    } else {
                        self.errorMessage = "核心启动失败：\(error.localizedDescription)"
                    }
                    clashManager.stop()
                }
            }
        }
    }

    func disconnect() {
        // Cancel any in-progress connect Task
        connectTask?.cancel()
        connectTask = nil
        isConnecting = false

        // Stop WebSocket streams
        webSocket?.stopAll()
        webSocket = nil
        clashAPI = nil

        // Stop core
        clashManager.stop()

        // Stop proxy guard and restore system proxy
        stopProxyGuard()
        if SystemProxy.didSetProxy {
            do {
                try SystemProxy.disable()
            } catch {
                errorMessage = "系统代理关闭失败，请在系统设置 > 网络中手动关闭代理"
            }
        }

        // Reset state
        isConnected = false
        networkInfo = NetworkInfo()
        trafficStats = TrafficStats()
        connections = []
        logEntries = []
    }

    private func onCoreStarted(api: ClashAPI) {
        clashAPI = api

        // Auto-enable system proxy (skip for TUN mode — TUN handles routing itself)
        if !config.tunEnabled {
            do {
                try SystemProxy.enable(httpPort: config.mixedPort, socksPort: config.mixedPort)
                startProxyGuard()
            } catch {
                errorMessage = "System proxy: \(error.localizedDescription)"
            }
        }

        isConnected = true
        let port = config.externalController.split(separator: ":").last.flatMap { Int($0) } ?? 9090

        // Start WebSocket streams
        let ws = ClashWebSocket(port: port, secret: config.secret)
        webSocket = ws

        ws.onTraffic = { [weak self] traffic in
            DispatchQueue.main.async {
                self?.trafficStats.uploadSpeed = traffic.up
                self?.trafficStats.downloadSpeed = traffic.down
            }
        }

        ws.onConnections = { [weak self] response in
            DispatchQueue.main.async {
                self?.trafficStats.totalUpload = response.uploadTotal
                self?.trafficStats.totalDownload = response.downloadTotal
                self?.trafficStats.activeConnections = response.connections?.count ?? 0
                self?.updateConnections(from: response)
            }
        }

        ws.onLog = { [weak self] level, message in
            DispatchQueue.main.async {
                let logsEnabled = UserDefaults.standard.object(forKey: SettingsKey.logsEnabled) as? Bool ?? true
                guard logsEnabled else { return }

                let entry = LogEntry(level: level, message: message, timestamp: Date())
                self?.logEntries.append(entry)
                // Keep last 500 logs
                if (self?.logEntries.count ?? 0) > 500 {
                    self?.logEntries.removeFirst((self?.logEntries.count ?? 500) - 500)
                }
            }
        }

        ws.startTrafficStream()
        ws.startConnectionsStream()
        ws.startLogsStream(level: logLevel)

        // Fetch initial data from API
        Task { await fetchProxiesFromAPI() }
        Task { await fetchNetworkInfo() }

        // Set the active proxy in mihomo if a node is selected
        if let node = activeNode {
            Task {
                try? await api.selectProxy(group: "GLOBAL", proxy: "Proxy")
                try? await api.selectProxy(group: "Proxy", proxy: node.name)
            }
        }

        // Auto-retry subscriptions that have 0 nodes (likely failed due to needing proxy)
        let failedSubs = subscriptions.filter { $0.nodeCount == 0 && $0.isEnabled }
        if !failedSubs.isEmpty {
            Task {
                // Wait a moment for the proxy to be fully ready
                try? await Task.sleep(for: .seconds(2))
                try? await updateAllSubscriptions()
            }
        }
    }

    // MARK: - Proxy Management

    func selectNode(_ nodeId: String) {
        selectedNodeId = nodeId
        for region in proxyRegions {
            if let node = region.nodes.first(where: { $0.id == nodeId }) {
                activeNode = node

                // If connected, tell mihomo to switch
                if isConnected, let api = clashAPI {
                    Task {
                        try? await api.selectProxy(group: "GLOBAL", proxy: node.name)
                    }
                }
                break
            }
        }
    }

    func toggleRegion(_ regionId: String) {
        if let idx = proxyRegions.firstIndex(where: { $0.id == regionId }) {
            proxyRegions[idx].isExpanded.toggle()
        }
    }

    // MARK: - Mode

    func setProxyMode(_ mode: ProxyMode) {
        proxyMode = mode
        if isConnected, let api = clashAPI {
            Task {
                try? await api.updateMode(mode.rawValue.lowercased())
            }
        }
    }

    // MARK: - Node Management

    func addNode(_ node: ProxyNode) {
        // Place in matching region or create "CUSTOM" region
        let flag = node.flag.isEmpty ? "🌐" : node.flag
        var nodeWithFlag = node
        nodeWithFlag.flag = flag

        let regionId = "custom"
        if let idx = proxyRegions.firstIndex(where: { $0.id == regionId }) {
            proxyRegions[idx].nodes.append(nodeWithFlag)
        } else {
            let region = ProxyRegion(id: regionId, name: "CUSTOM NODES", nodes: [nodeWithFlag])
            proxyRegions.append(region)
        }
        saveState()
    }

    func deleteNode(_ nodeId: String) {
        for i in proxyRegions.indices {
            proxyRegions[i].nodes.removeAll { $0.id == nodeId }
        }
        proxyRegions.removeAll { $0.nodes.isEmpty }
        if selectedNodeId == nodeId {
            selectedNodeId = proxyRegions.first?.nodes.first?.id
            activeNode = proxyRegions.first?.nodes.first
        }
        saveState()
    }

    func clearAllNodes() {
        proxyRegions.removeAll()
        selectedNodeId = nil
        activeNode = nil
        saveState()
    }

    // MARK: - Rules

    func addRule(_ rule: RuleItem) {
        rules.append(rule)
        saveState()
        if isConnected { reloadCoreConfig() }
    }

    func deleteRule(_ ruleId: String) {
        rules.removeAll { $0.id == ruleId }
        saveState()
        if isConnected { reloadCoreConfig() }
    }

    func moveRule(from source: IndexSet, to destination: Int) {
        rules.move(fromOffsets: source, toOffset: destination)
        saveState()
        if isConnected { reloadCoreConfig() }
    }

    /// Rewrite config on disk and tell mihomo to reload it
    func reloadCoreConfig() {
        // Rebuild rules in config
        config.rules = rules.map { $0.clashString }
        if !config.rules.contains(where: { $0.hasPrefix("MATCH,") }) {
            config.rules.append("MATCH,Proxy")
        }

        // Rewrite config file — only use raw YAML if it's actual Clash config
        let rawYAML = ConfigStorage.shared.loadRawSubscriptionYAML()
        let validRawYAML = rawYAML.flatMap { $0.contains("proxies:") ? $0 : nil }
        do {
            try clashManager.rewriteConfig(config: config, rawSubscriptionYAML: validRawYAML)
        } catch {
            print("Warning: Failed to rewrite config: \(error)")
            return
        }

        // Tell mihomo to reload
        guard let api = clashAPI else { return }
        let configPath = clashManager.configFilePath.path
        Task {
            do {
                try await api.reloadConfig(path: configPath)
            } catch {
                print("Warning: Failed to reload config in mihomo: \(error)")
            }
        }
    }

    // MARK: - Connection Management

    func closeConnection(_ connectionId: String) async {
        guard let api = clashAPI else { return }
        do {
            try await api.closeConnection(id: connectionId)
            await MainActor.run {
                connections.removeAll { $0.id == connectionId }
            }
        } catch { }
    }

    func clearLogs() {
        logEntries.removeAll()
    }

    func closeAllConnections() async {
        guard let api = clashAPI else { return }
        do {
            try await api.closeAllConnections()
            await MainActor.run {
                connections.removeAll()
                trafficStats.activeConnections = 0
            }
        } catch { }
    }

    // MARK: - Latency Testing

    func testNodeLatency(_ nodeId: String) async {
        guard let api = clashAPI else { return }

        // Find node name
        var nodeName: String?
        for region in proxyRegions {
            if let node = region.nodes.first(where: { $0.id == nodeId }) {
                nodeName = node.name
                break
            }
        }
        guard let name = nodeName else { return }

        do {
            let result = try await api.testProxyDelay(name: name)
            if let delay = result.delay {
                await MainActor.run {
                    updateNodeLatency(nodeId: nodeId, latency: delay)
                }
            }
        } catch {
            // Node unreachable
        }
    }

    func testAllLatency() async {
        guard let api = clashAPI else { return }
        let allNodes = proxyRegions.flatMap(\.nodes)

        await withTaskGroup(of: Void.self) { group in
            for node in allNodes {
                group.addTask {
                    do {
                        let result = try await api.testProxyDelay(name: node.name)
                        if let delay = result.delay {
                            await MainActor.run {
                                self.updateNodeLatency(nodeId: node.id, latency: delay)
                            }
                        }
                    } catch { }
                }
            }
        }
    }

    private func updateNodeLatency(nodeId: String, latency: Int) {
        for i in proxyRegions.indices {
            if let j = proxyRegions[i].nodes.firstIndex(where: { $0.id == nodeId }) {
                proxyRegions[i].nodes[j].latency = latency
            }
        }
        // Update active node if needed
        if activeNode?.id == nodeId {
            activeNode?.latency = latency
        }
    }

    // MARK: - Subscription

    /// Proxy port to use for subscription downloads (when mihomo is running)
    private var activeProxyPort: Int? {
        isConnected ? config.mixedPort : nil
    }

    func updateSubscription(url: String) async throws {
        let (regions, rawYAML, _) = try await subscriptionManager.fetchAndOrganize(url: url, proxyPort: activeProxyPort)
        await MainActor.run {
            self.proxyRegions = regions
            self.selectedNodeId = regions.first?.nodes.first?.id
            self.activeNode = regions.first?.nodes.first
            // Merge rules: keep user rules, replace subscription rules
            if rawYAML.contains("rules:") {
                let parsedRules = ConfigParser.parseClashYAMLRules(rawYAML, source: .subscription)
                if !parsedRules.isEmpty {
                    let userRules = self.rules.filter { $0.source == .user }
                    self.rules = userRules + parsedRules
                }
            }
            self.saveState()
        }

        // Save raw YAML for mihomo to use directly
        ConfigStorage.shared.saveRawSubscriptionYAML(rawYAML)

        // Save subscription info
        await subscriptionManager.saveSubscriptionInfo(
            SubscriptionInfo(
                url: url,
                name: "Default",
                lastUpdate: Date(),
                nodeCount: regions.flatMap(\.nodes).count
            )
        )
    }

    func addSubscription(url: String, name: String) {
        let displayName = name.isEmpty ? Self.extractSubscriptionName(from: url) : name
        let sub = SubscriptionInfo(url: url, name: displayName)
        subscriptions.append(sub)
        Task { await subscriptionManager.saveSubscriptions(subscriptions) }
    }

    func removeSubscription(_ id: String) {
        subscriptions.removeAll { $0.id == id }
        Task { await subscriptionManager.saveSubscriptions(subscriptions) }
    }

    func renameSubscription(_ id: String, name: String) {
        guard let idx = subscriptions.firstIndex(where: { $0.id == id }) else { return }
        subscriptions[idx].name = name.trimmingCharacters(in: .whitespaces)
        Task { await subscriptionManager.saveSubscriptions(subscriptions) }
    }

    /// Extract a human-readable name from a subscription URL.
    /// e.g. "https://api.wd-blue.com/sub?target=clash&..." → "api.wd-blue.com"
    /// e.g. "https://example.com/clash/config.yaml" → "example.com"
    private static func extractSubscriptionName(from urlString: String) -> String {
        guard let url = URL(string: urlString),
              let host = url.host else {
            return "Subscription"
        }
        // Remove common prefixes
        var name = host
        for prefix in ["api.", "sub.", "www.", "subscribe."] {
            if name.hasPrefix(prefix) && name.count > prefix.count + 3 {
                name = String(name.dropFirst(prefix.count))
                break
            }
        }
        return name
    }

    func updateAllSubscriptions() async throws {
        let (regions, updatedSubs, rawYAML) = try await subscriptionManager.fetchAllAndOrganize(subscriptions, proxyPort: activeProxyPort)
        await MainActor.run {
            self.subscriptions = updatedSubs
            self.proxyRegions = regions
            self.selectedNodeId = regions.first?.nodes.first?.id
            self.activeNode = regions.first?.nodes.first
            // Merge rules: keep user rules, replace subscription rules
            if rawYAML.contains("rules:") {
                let parsedRules = ConfigParser.parseClashYAMLRules(rawYAML, source: .subscription)
                if !parsedRules.isEmpty {
                    let userRules = self.rules.filter { $0.source == .user }
                    self.rules = userRules + parsedRules
                }
            }
            self.saveState()
        }
        await subscriptionManager.saveSubscriptions(updatedSubs)

        if !rawYAML.isEmpty {
            ConfigStorage.shared.saveRawSubscriptionYAML(rawYAML)
        }
    }

    func startAutoUpdate(intervalHours: Int = 6) {
        stopAutoUpdate()
        let interval = TimeInterval(intervalHours * 3600)
        autoUpdateTimer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
            Task { [weak self] in
                try? await self?.updateAllSubscriptions()
            }
        }
    }

    func stopAutoUpdate() {
        autoUpdateTimer?.invalidate()
        autoUpdateTimer = nil
    }

    // MARK: - Proxy Guard

    /// Periodically verify system proxy hasn't been tampered with by other software.
    private func startProxyGuard() {
        stopProxyGuard()
        proxyGuardTimer = Timer.scheduledTimer(withTimeInterval: 10, repeats: true) { [weak self] _ in
            guard self?.isConnected == true, SystemProxy.didSetProxy else { return }
            if !SystemProxy.verifyProxyIntact() {
                try? SystemProxy.reapply()
            }
        }
    }

    private func stopProxyGuard() {
        proxyGuardTimer?.invalidate()
        proxyGuardTimer = nil
    }

    // MARK: - Apply Setting Changes at Runtime

    /// Dynamically apply a setting change via PATCH /configs without reconnecting.
    func applySettingChange(key: String, value: Any) {
        guard isConnected, let api = clashAPI else { return }

        Task {
            do {
                try await api.patchConfig([key: value])

                // If port changed, re-configure system proxy with new port
                if key == "mixed-port" || key == "port" || key == "socks-port" {
                    await MainActor.run {
                        if let port = value as? Int {
                            config.mixedPort = port
                            config.port = port
                            config.socksPort = port
                        }
                        if !config.tunEnabled {
                            do {
                                try SystemProxy.disable()
                                try SystemProxy.enable(httpPort: config.mixedPort, socksPort: config.mixedPort)
                            } catch {
                                self.errorMessage = "System proxy: \(error.localizedDescription)"
                            }
                        }
                    }
                }

                if key == "allow-lan", let val = value as? Bool {
                    await MainActor.run { config.allowLan = val }
                }
            } catch {
                print("Warning: Failed to apply setting \(key): \(error)")
            }
        }
    }

    // MARK: - API Data Fetching

    private func fetchProxiesFromAPI() async {
        guard let api = clashAPI else { return }
        do {
            let response = try await api.getProxies()
            await MainActor.run {
                // Update latencies from API data
                for (name, proxy) in response.proxies {
                    if let delay = proxy.history?.last?.delay, delay > 0 {
                        for i in proxyRegions.indices {
                            if let j = proxyRegions[i].nodes.firstIndex(where: { $0.name == name }) {
                                proxyRegions[i].nodes[j].latency = delay
                            }
                        }
                    }
                }
            }
        } catch { }
    }

    private func fetchNetworkInfo() async {
        // Simple IP detection via httpbin
        do {
            let url = URL(string: "https://httpbin.org/ip")!
            let (data, _) = try await URLSession.shared.data(from: url)
            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: String],
               let ip = json["origin"] {
                await MainActor.run {
                    self.networkInfo.ip = ip
                    self.networkInfo.networkType = "Proxy"
                    if let node = self.activeNode {
                        self.networkInfo.location = node.name
                    }
                }
            }
        } catch { }
    }

    // MARK: - Update Connections from WebSocket

    private func updateConnections(from response: APIConnectionsResponse) {
        guard let apiConnections = response.connections else { return }

        connections = apiConnections.prefix(50).map { conn in
            let type: ConnectionType
            if conn.chains.contains("REJECT") || conn.rule == "REJECT" {
                type = .rejected
            } else if conn.chains.contains("DIRECT") || conn.rule == "DIRECT" {
                type = .direct
            } else {
                type = .proxied
            }

            let chainNode = conn.chains.first ?? "Direct"
            let flag = ConfigParser.guessFlag(from: chainNode)

            let formatter = DateFormatter()
            formatter.dateFormat = "HH:mm:ss"
            let timestamp = formatter.string(from: Date())

            return ConnectionEntry(
                id: conn.id,
                domain: conn.metadata.host.isEmpty ? (conn.metadata.destinationIP ?? "unknown") : conn.metadata.host,
                protocolName: conn.metadata.type,
                rule: "\(conn.rule)\(conn.rulePayload.map { " (\($0))" } ?? "")",
                nodeFlag: flag,
                nodeName: chainNode,
                latency: nil,
                dataSize: formatBytes(conn.download + conn.upload),
                dataLabel: "Traffic",
                timestamp: timestamp,
                type: type
            )
        }
    }

    // MARK: - Region Organization (for re-parsing from raw YAML)

    private func organizeIntoRegions(_ nodes: [ProxyNode]) -> [ProxyRegion] {
        var regionMap: [String: (name: String, nodes: [ProxyNode])] = [:]

        let regionMapping: [(flags: Set<String>, id: String, name: String)] = [
            (["🇯🇵", "🇸🇬", "🇭🇰", "🇹🇼", "🇰🇷", "🇮🇳", "🇦🇺"], "ap", "ASIA PACIFIC"),
            (["🇺🇸", "🇨🇦", "🇧🇷"], "am", "AMERICAS"),
            (["🇬🇧", "🇩🇪", "🇫🇷", "🇳🇱", "🇷🇺"], "eu", "EUROPE"),
        ]

        for node in nodes {
            var placed = false
            for region in regionMapping {
                if region.flags.contains(node.flag) {
                    var existing = regionMap[region.id] ?? (name: region.name, nodes: [])
                    existing.nodes.append(node)
                    regionMap[region.id] = existing
                    placed = true
                    break
                }
            }
            if !placed {
                var other = regionMap["other"] ?? (name: "OTHER", nodes: [])
                other.nodes.append(node)
                regionMap["other"] = other
            }
        }

        let order = ["ap", "am", "eu", "other"]
        return order.compactMap { id in
            guard let region = regionMap[id], !region.nodes.isEmpty else { return nil }
            return ProxyRegion(id: id, name: region.name, nodes: region.nodes)
        }
    }

    // MARK: - Persistence

    func loadInitialData() {
        let storage = ConfigStorage.shared

        proxyRegions = storage.loadProxyRegions() ?? []
        rules = storage.loadRules() ?? []

        // Re-parse from subscription YAML if data is missing on disk
        let rawYAML = storage.loadRawSubscriptionYAML()

        // Re-parse regions from raw YAML if regions.json is empty
        if proxyRegions.isEmpty, let yaml = rawYAML, yaml.contains("proxies:") {
            let nodes = ConfigParser.parseClashYAMLProxies(yaml)
            if !nodes.isEmpty {
                proxyRegions = organizeIntoRegions(nodes)
                storage.saveProxyRegions(proxyRegions)
            }
        }

        // Re-parse rules from subscription YAML if rules are empty or missing policyName
        let needsReParse = rules.isEmpty || rules.contains(where: { $0.policyName == nil && $0.policy == .proxy })
        if needsReParse, let yaml = rawYAML, yaml.contains("rules:") {
            let parsed = ConfigParser.parseClashYAMLRules(yaml, source: .subscription)
            if !parsed.isEmpty {
                let userRules = rules.filter { $0.source == .user }
                rules = userRules + parsed
                storage.saveRules(rules)
            }
        }

        selectedNodeId = proxyRegions.first?.nodes.first?.id
        activeNode = proxyRegions.first?.nodes.first

        if let savedConfig = storage.loadConfig() {
            config = savedConfig
        }

        // Load subscriptions async
        Task {
            subscriptions = await subscriptionManager.loadSubscriptions()
            startAutoUpdate()
        }
    }

    /// Load mock data for previews only
    func loadMockData() {
        proxyRegions = mockProxyRegions
        rules = mockRules
        connections = mockConnections
        selectedNodeId = proxyRegions.first?.nodes.first?.id
        activeNode = proxyRegions.first?.nodes.first
    }

    func saveState() {
        let storage = ConfigStorage.shared
        storage.saveProxyRegions(proxyRegions)
        storage.saveRules(rules)
        storage.saveConfig(config)
    }
}

// MARK: - Helpers

private func formatBytes(_ bytes: Int64) -> String {
    if bytes < 1024 { return "\(bytes) B" }
    let kb = Double(bytes) / 1024
    if kb < 1024 { return String(format: "%.1f KB", kb) }
    let mb = kb / 1024
    if mb < 1024 { return String(format: "%.1f MB", mb) }
    let gb = mb / 1024
    return String(format: "%.2f GB", gb)
}
