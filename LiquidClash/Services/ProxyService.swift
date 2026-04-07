import Foundation

/// All proxy/group data from mihomo API. Single source of truth.
/// No local YAML parsing — everything comes from the running mihomo instance.
@Observable
final class ProxyService {
    /// All proxy groups from mihomo (Selector, URLTest, Fallback, etc.)
    var groups: [MihomoGroup] = []
    /// All individual proxy nodes from mihomo
    var nodes: [MihomoNode] = []
    /// Currently selected main group and node
    var activeGroupName: String?
    var activeNodeName: String?

    private var api: ClashAPI?

    struct MihomoGroup: Identifiable {
        let id: String  // group name
        let name: String
        let type: String  // Selector, URLTest, Fallback, etc.
        var now: String?
        var all: [String]
        var latency: Int

        var isSelector: Bool { type == "Selector" }
    }

    struct MihomoNode: Identifiable {
        let id: String  // node name (used as ID since mihomo names are unique)
        let name: String
        let type: String  // Trojan, Shadowsocks, VMess, etc.
        var latency: Int
        var flag: String
    }

    func setAPI(_ api: ClashAPI?) {
        self.api = api
    }

    /// Fetch all proxies and groups from mihomo API. Call after core starts.
    func refresh() async {
        guard let api else { return }
        do {
            let response = try await api.getProxies()
            let skipNames: Set<String> = ["DIRECT", "REJECT", "COMPATIBLE", "PASS", "REJECT-DROP"]
            let groupTypes: Set<String> = ["Selector", "URLTest", "Fallback", "LoadBalance", "Relay"]

            var fetchedGroups: [MihomoGroup] = []
            var fetchedNodes: [MihomoNode] = []

            for (name, proxy) in response.proxies {
                guard !skipNames.contains(name) else { continue }
                let latency = proxy.history?.last?.delay ?? 0

                if groupTypes.contains(proxy.type), let members = proxy.all {
                    fetchedGroups.append(MihomoGroup(
                        id: name, name: name, type: proxy.type,
                        now: proxy.now, all: members, latency: latency
                    ))
                } else if proxy.all == nil {
                    // Skip info nodes
                    let lower = name.lowercased()
                    if lower.contains("traffic:") || lower.contains("expire:") { continue }

                    let (flag, _) = ConfigParser.extractFlag(from: name)
                    fetchedNodes.append(MihomoNode(
                        id: name, name: name, type: proxy.type,
                        latency: latency, flag: flag
                    ))
                }
            }

            await MainActor.run {
                self.groups = fetchedGroups.sorted { $0.name < $1.name }
                self.nodes = fetchedNodes.sorted { $0.name < $1.name }
                // Find main proxy group (usually "Proxies" or "PROXY")
                if let main = fetchedGroups.first(where: { $0.name == "Proxies" })
                    ?? fetchedGroups.first(where: { $0.name == "PROXY" })
                    ?? fetchedGroups.first(where: { $0.isSelector }) {
                    self.activeGroupName = main.name
                    self.activeNodeName = main.now
                }
            }
        } catch {
            print("[ProxyService] refresh failed: \(error)")
        }
    }

    /// Select a proxy in a specific group. Direct mihomo API call — no name mapping needed.
    func selectProxy(group: String, proxy: String) async {
        guard let api else { return }
        do {
            try await api.selectProxy(group: group, proxy: proxy)
            try await api.closeAllConnections()
            await refresh()
        } catch {
            print("[ProxyService] selectProxy failed: \(error)")
        }
    }

    private static let testURL = "http://cp.cloudflare.com/generate_204"
    private static let testTimeout = 3000

    /// Test latency for a specific proxy. Returns delay in ms, 0 = timeout.
    func testLatency(name: String) async -> Int {
        guard let api else { return 0 }
        let result = await api.testProxyDelay(name: name, url: Self.testURL, timeout: Self.testTimeout)
        let delay = result.delay ?? 0
        await MainActor.run {
            if let idx = nodes.firstIndex(where: { $0.id == name }) {
                nodes[idx].latency = delay
            }
        }
        return delay
    }

    /// Test latency for all nodes with limited concurrency (like Verge: max 10).
    func testAllLatency() async {
        guard api != nil else { return }
        let maxConcurrent = 10
        await withTaskGroup(of: Void.self) { group in
            var running = 0
            for node in nodes {
                if running >= maxConcurrent {
                    await group.next()
                    running -= 1
                }
                group.addTask {
                    _ = await self.testLatency(name: node.name)
                }
                running += 1
            }
        }
    }
}
