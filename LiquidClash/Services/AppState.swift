import SwiftUI
import Observation

// MARK: - Network Info

struct NetworkInfo {
    var ip: String = "--"
    var asType: String = "--"
    var city: String = "--"
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
    var activeRules: [APIRule] = []
    var ruleProviders: [String: APIRuleProvider] = [:]
    /// Cached provider rules for search (lazy-loaded on first search)
    var providerRulesCache: [APIRule] = []
    var isLoadingProviderRules = false
    var providerRulesLoaded = false

    /// Total rule count: inline rules + all provider rules
    var totalRuleCount: Int {
        let inline = isConnected && !activeRules.isEmpty
            ? activeRules.count
            : rules.count
        let providerTotal = ruleProviders.values.reduce(0) { $0 + $1.ruleCount }
        return inline + providerTotal
    }

    /// All searchable rules: inline active rules + cached provider rules
    var allSearchableRules: [APIRule] {
        activeRules + providerRulesCache
    }

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
    let proxyService = ProxyService()
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
        isConnecting = true
        errorMessage = nil

        // Sync settings from UserDefaults to config
        let portString = UserDefaults.standard.string(forKey: SettingsKey.mixedPort) ?? "7890"
        let port = Int(portString) ?? 7890
        config.mixedPort = port
        config.tunEnabled = UserDefaults.standard.bool(forKey: SettingsKey.tunMode)
        config.allowLan = config.tunEnabled && UserDefaults.standard.bool(forKey: SettingsKey.allowLAN)
        config.mode = proxyMode.rawValue.lowercased()

        // Load subscription YAML (single source of truth)
        guard let subscriptionYAML = ConfigStorage.shared.loadSubscriptionYAML(),
              !subscriptionYAML.isEmpty else {
            isConnecting = false
            errorMessage = "没有可用的订阅配置，请先导入订阅"
            return
        }

        let overlay = ConfigPipeline.OverlayConfig(
            mixedPort: port,
            mode: proxyMode.rawValue.lowercased(),
            logLevel: "info",
            allowLan: config.tunEnabled && UserDefaults.standard.bool(forKey: SettingsKey.allowLAN),
            tunEnabled: config.tunEnabled
        )

        do {
            if config.tunEnabled {
                try clashManager.startWithPrivileges(subscriptionYAML: subscriptionYAML, overlay: overlay)
            } else {
                try clashManager.start(subscriptionYAML: subscriptionYAML, overlay: overlay)
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
        activeRules = []
        ruleProviders = [:]
        providerRulesCache = []
        providerRulesLoaded = false
        isLoadingProviderRules = false
    }

    private func onCoreStarted(api: ClashAPI) {
        clashAPI = api
        proxyService.setAPI(api)

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

        // Fetch proxy data from mihomo API (single source of truth)
        Task {
            await proxyService.refresh()
            await fetchNetworkInfo()
        }
        Task { await fetchActiveRules() }

        // Auto-retry subscriptions that have 0 nodes (likely failed due to needing proxy)
        let failedSubs = subscriptions.filter { $0.nodeCount == 0 && $0.isEnabled }
        if !failedSubs.isEmpty {
            Task {
                try? await Task.sleep(for: .seconds(2))
                try? await updateAllSubscriptions()
            }
        }
    }

    // MARK: - Proxy Management

    /// Select a node/group by name. Uses ProxyService to interact with mihomo directly.
    func selectNode(_ nodeName: String) {
        guard isConnected else { return }
        Task {
            // Find which Selector group contains this node/group name and switch
            for group in proxyService.groups where group.isSelector && group.all.contains(nodeName) {
                await proxyService.selectProxy(group: group.name, proxy: nodeName)
            }
            // Refresh IP after switch
            await MainActor.run { self.networkInfo = NetworkInfo() }
            await fetchNetworkInfo()
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

    func updateNode(_ node: ProxyNode) {
        for i in proxyRegions.indices {
            if let j = proxyRegions[i].nodes.firstIndex(where: { $0.id == node.id }) {
                proxyRegions[i].nodes[j] = node
                if selectedNodeId == node.id { activeNode = node }
                saveState()
                return
            }
        }
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
        guard let subscriptionYAML = ConfigStorage.shared.loadSubscriptionYAML(),
              !subscriptionYAML.isEmpty else { return }

        let portString = UserDefaults.standard.string(forKey: SettingsKey.mixedPort) ?? "7890"
        let port = Int(portString) ?? 7890
        let overlay = ConfigPipeline.OverlayConfig(
            mixedPort: port,
            mode: config.mode,
            logLevel: config.logLevel,
            allowLan: config.allowLan,
            tunEnabled: config.tunEnabled
        )

        do {
            try clashManager.rewriteConfig(subscriptionYAML: subscriptionYAML, overlay: overlay)
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

    func testNodeLatency(_ name: String) async {
        _ = await proxyService.testLatency(name: name)
    }

    func testAllLatency() async {
        guard !proxyService.nodes.isEmpty else { return }

        // If not connected, temporarily start mihomo just for latency testing
        let needsTempCore = clashAPI == nil

        if needsTempCore {
            do {
                let api = try await startTemporaryCore()
                proxyService.setAPI(api)
                await proxyService.refresh()
            } catch {
                print("[LiquidClash] Failed to start temp core for testing: \(error)")
                return
            }
        }

        await proxyService.testAllLatency()

        if needsTempCore {
            clashManager.stop()
            proxyService.setAPI(nil)
        }
    }

    /// Start mihomo temporarily (no system proxy) for latency testing
    private func startTemporaryCore() async throws -> ClashAPI {
        let portString = UserDefaults.standard.string(forKey: SettingsKey.mixedPort) ?? "7890"
        let port = Int(portString) ?? 7890

        guard let subscriptionYAML = ConfigStorage.shared.loadSubscriptionYAML(),
              !subscriptionYAML.isEmpty else {
            throw ClashError.configWriteFailed
        }

        let overlay = ConfigPipeline.OverlayConfig(
            mixedPort: port,
            mode: "rule",
            logLevel: "info"
        )

        try clashManager.start(subscriptionYAML: subscriptionYAML, overlay: overlay)

        let apiPort = config.externalController.split(separator: ":").last.flatMap { Int($0) } ?? 9090
        let api = ClashAPI(port: apiPort, secret: config.secret)
        try await api.waitUntilReady()
        return api
    }


    // MARK: - Subscription

    /// Proxy port to use for subscription downloads (when mihomo is running)
    private var activeProxyPort: Int? {
        isConnected ? config.mixedPort : nil
    }

    func updateSubscription(url: String) async throws {
        let (regions, rawYAML, userInfo) = try await subscriptionManager.fetchAndOrganize(url: url, proxyPort: activeProxyPort)
        await MainActor.run {
            let customRegions = self.proxyRegions.filter { $0.id == "custom" }
            self.proxyRegions = regions + customRegions
            self.selectedNodeId = regions.first?.nodes.first?.id
            self.activeNode = regions.first?.nodes.first
            // Merge rules: keep user rules, replace subscription rules
            let hasRules = rawYAML.components(separatedBy: .newlines)
                .contains { $0.trimmingCharacters(in: .whitespaces) == "rules:" }
            if hasRules {
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

        // Save subscription info with traffic data
        await subscriptionManager.saveSubscriptionInfo(
            SubscriptionInfo(
                url: url,
                name: "Default",
                lastUpdate: Date(),
                nodeCount: regions.flatMap(\.nodes).count,
                upload: userInfo?.upload,
                download: userInfo?.download,
                total: userInfo?.total,
                expire: userInfo?.expire
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
            // Preserve custom nodes across subscription updates
            let customRegions = self.proxyRegions.filter { $0.id == "custom" }
            self.proxyRegions = regions + customRegions
            self.selectedNodeId = regions.first?.nodes.first?.id
            self.activeNode = regions.first?.nodes.first
            // Merge rules: keep user rules, replace subscription rules
            let hasRulesSection = rawYAML.components(separatedBy: .newlines)
                .contains { $0.trimmingCharacters(in: .whitespaces) == "rules:" }
            if hasRulesSection {
                let parsedRules = ConfigParser.parseClashYAMLRules(rawYAML, source: .subscription)
                print("[LiquidClash] Parsed \(parsedRules.count) rules from subscription YAML (\(rawYAML.count) chars)")
                if !parsedRules.isEmpty {
                    let userRules = self.rules.filter { $0.source == .user }
                    self.rules = userRules + parsedRules
                }
            } else {
                print("[LiquidClash] No standalone 'rules:' line in YAML (\(rawYAML.count) chars, contains 'rules:': \(rawYAML.contains("rules:")))")
                // Preview first 200 chars of rawYAML for debugging
                print("[LiquidClash] YAML preview: \(String(rawYAML.prefix(200)))")
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


    private func fetchActiveRules() async {
        guard let api = clashAPI else {
            print("[LiquidClash]","fetchActiveRules: no API")
            return
        }
        for delay in [3, 8, 15] {
            try? await Task.sleep(for: .seconds(delay))
            guard isConnected else { return }
            do {
                let rulesResponse = try await api.getRules()
                let providersResponse = try? await api.getRuleProviders()
                let providerTotal = providersResponse?.providers.values.reduce(0) { $0 + $1.ruleCount } ?? 0
                print("[LiquidClash]","fetchActiveRules: \(rulesResponse.rules.count) inline rules, \(providersResponse?.providers.count ?? 0) providers (\(providerTotal) total)")
                await MainActor.run {
                    self.activeRules = rulesResponse.rules
                    self.ruleProviders = providersResponse?.providers ?? [:]
                }
                if providerTotal > 0 { return }
            } catch {
                print("[LiquidClash]","fetchActiveRules failed: \(error)")
            }
        }
    }

    /// Load all provider rules for search by reading local cache files.
    /// mihomo API doesn't expose provider rule contents, so we read the YAML files directly.
    func loadProviderRulesForSearch() {
        guard isConnected, !providerRulesLoaded, !isLoadingProviderRules else { return }
        isLoadingProviderRules = true

        Task {
            var allRules: [APIRule] = []
            let providers = await MainActor.run { self.ruleProviders }
            let inlineRules = await MainActor.run { self.activeRules }

            // Build provider→proxy mapping from inline RULE-SET rules
            var providerProxyMap: [String: String] = [:]
            for rule in inlineRules where rule.type == "RuleSet" || rule.type == "RULE-SET" {
                providerProxyMap[rule.payload] = rule.proxy
            }

            let rulesetDir = clashManager.configDirectory.appendingPathComponent("ruleset")
            print("[LiquidClash]","Loading provider rules from \(rulesetDir.path) (\(providers.count) providers)")

            for (name, provider) in providers {
                let proxyTarget = providerProxyMap[name] ?? name
                let filePath = rulesetDir.appendingPathComponent("\(name).yaml")

                guard let content = try? String(contentsOf: filePath, encoding: .utf8) else {
                    print("[LiquidClash]","Provider '\(name)': file not found at \(filePath.path)")
                    continue
                }

                // Parse YAML payload list: "payload:\n  - value\n  - value\n"
                let defaultType: String
                let behavior = provider.behavior.lowercased()
                if behavior == "ipcidr" {
                    defaultType = "IP-CIDR"
                } else {
                    defaultType = "DOMAIN"
                }

                var count = 0
                for line in content.components(separatedBy: .newlines) {
                    let trimmed = line.trimmingCharacters(in: .whitespaces)
                    guard trimmed.hasPrefix("- ") else { continue }
                    let value = String(trimmed.dropFirst(2)).trimmingCharacters(in: CharacterSet(charactersIn: "'\""))
                    guard !value.isEmpty else { continue }

                    if behavior == "classical" {
                        // Classical: "TYPE,payload" format
                        let parts = value.split(separator: ",", maxSplits: 1)
                        if parts.count == 2 {
                            allRules.append(APIRule(type: String(parts[0]), payload: String(parts[1]), proxy: proxyTarget))
                        } else {
                            allRules.append(APIRule(type: defaultType, payload: value, proxy: proxyTarget))
                        }
                    } else {
                        // Domain prefix: strip leading '+.' for cleaner display
                        let cleanValue = value.hasPrefix("+.") ? String(value.dropFirst(2)) : value
                        allRules.append(APIRule(type: defaultType, payload: cleanValue, proxy: proxyTarget))
                    }
                    count += 1
                }
                print("[LiquidClash]","Provider '\(name)': loaded \(count) rules from file")
            }

            await MainActor.run {
                self.providerRulesCache = allRules
                self.providerRulesLoaded = true
                self.isLoadingProviderRules = false
            }
            print("[LiquidClash]","Total provider rules loaded: \(allRules.count)")
        }
    }

    private func fetchNetworkInfo() async {
        // Wait for proxy to initialize
        try? await Task.sleep(for: .seconds(2))
        guard isConnected, !Task.isCancelled else { return }

        // Use curl through mihomo proxy to get IP (URLSession proxy config is unreliable)
        let port = config.mixedPort
        var ip = ""
        var city = "--"
        var country = ""
        var asType = "--"

        // Helper: run curl through proxy and parse JSON
        func curlJSON(_ urlString: String) -> [String: Any]? {
            let proc = Process()
            proc.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
            proc.arguments = ["-s", "--max-time", "5", "-x", "http://127.0.0.1:\(port)", urlString]
            let pipe = Pipe()
            proc.standardOutput = pipe
            proc.standardError = FileHandle.nullDevice
            do {
                try proc.run()
                proc.waitUntilExit()
                guard proc.terminationStatus == 0 else { return nil }
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                return try JSONSerialization.jsonObject(with: data) as? [String: Any]
            } catch { return nil }
        }

        // Step 1: Get IP + city from ip.sb (no rate limit)
        if let json = curlJSON("https://api.ip.sb/geoip"),
           let fetchedIP = json["ip"] as? String, !fetchedIP.isEmpty {
            ip = fetchedIP
            city = json["city"] as? String ?? "--"
            country = json["country_code"] as? String ?? ""
            asType = json["organization"] as? String ?? "--"
            print("[LiquidClash]","IP fetch OK via ip.sb: \(ip) \(city), \(country)")
        } else if let json = curlJSON("https://ipwho.is/"),
                  let fetchedIP = json["ip"] as? String, !fetchedIP.isEmpty {
            ip = fetchedIP
            city = json["city"] as? String ?? "--"
            country = json["country_code"] as? String ?? ""
            let conn = json["connection"] as? [String: Any]
            asType = conn?["org"] as? String ?? "--"
            print("[LiquidClash]","IP fetch OK via ipwho.is: \(ip) \(city), \(country)")
        }

        guard !ip.isEmpty, isConnected, !Task.isCancelled else {
            print("[LiquidClash]","Failed to get IP from all sources")
            return
        }

        let cityDisplay = country.isEmpty ? city : "\(city), \(country)"
        await MainActor.run {
            self.networkInfo.ip = ip
            self.networkInfo.city = cityDisplay
        }

        // Step 2: Get actual AS type from ipapi.is
        if let json = curlJSON("https://api.ipapi.is/?q=\(ip)"),
           let asnObj = json["asn"] as? [String: Any],
           let type = asnObj["type"] as? String, !type.isEmpty {
            await MainActor.run {
                self.networkInfo.asType = type.uppercased()
            }
        } else {
            await MainActor.run {
                self.networkInfo.asType = asType.uppercased()
            }
        }
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

    // MARK: - Persistence

    func loadInitialData() {
        let storage = ConfigStorage.shared

        proxyRegions = storage.loadProxyRegions() ?? []
        rules = storage.loadRules() ?? []
        print("[LiquidClash] loadInitialData: \(proxyRegions.count) regions, \(rules.count) rules from disk")

        // Re-parse rules from subscription YAML if rules are empty or missing policyName
        let rawYAML = storage.loadRawSubscriptionYAML()
        let needsReParse = rules.isEmpty || rules.contains(where: { $0.policyName == nil && $0.policy == .proxy })
        let yamlHasRules = rawYAML.map { yaml in
            yaml.components(separatedBy: .newlines).contains { $0.trimmingCharacters(in: .whitespaces) == "rules:" }
        } ?? false
        if needsReParse, let yaml = rawYAML, yamlHasRules {
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

        // Load subscriptions and refresh traffic data on launch
        Task {
            subscriptions = await subscriptionManager.loadSubscriptions()
            startAutoUpdate()
            // Auto-refresh subscriptions on launch to get latest traffic info
            if !subscriptions.isEmpty {
                try? await updateAllSubscriptions()
            }
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
