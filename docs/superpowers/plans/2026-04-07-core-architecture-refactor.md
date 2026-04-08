# Core Architecture Refactor: Verge-Style Config Pipeline

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor LiquidClash to use mihomo API as single source of truth, with a proper config pipeline that respects subscription YAML and only overlays minimal control fields.

**Architecture:** Subscription YAML is stored immutably. A thin overlay (port/controller/secret/dns-fallback) is applied to produce `runtime.yaml` for mihomo. All proxy/node/group/rule data is read exclusively from mihomo's REST API after core starts. No app-level YAML parsing for node display.

**Tech Stack:** Swift, SwiftUI, mihomo REST API, Process management

---

## Design Principles

1. **Subscription YAML is immutable** — never modify it, store as-is
2. **Overlay, don't replace** — only override fields needed for local control
3. **mihomo API is the single source of truth** — UI reads proxies, groups, rules, connections from API
4. **No YAML parsing for display** — ConfigParser is only used for URI→YAML generation, not for node display
5. **Respect the config** — DNS, rules, proxy-groups from subscription are used as-is

## File Structure

### Files to CREATE:
- `LiquidClash/Core/ConfigPipeline.swift` — Overlay logic: subscription.yaml + overlay → runtime.yaml
- `LiquidClash/Services/ProxyService.swift` — All proxy/group data from mihomo API (replaces proxy-related code in AppState)

### Files to MODIFY:
- `LiquidClash/Core/ClashManager.swift` — Remove writeConfigFromRawYAML/writeConfigYAML, use ConfigPipeline
- `LiquidClash/Services/AppState.swift` — Remove dual data source, delegate proxy data to ProxyService
- `LiquidClash/Services/ConfigStorage.swift` — Store subscription YAML + overlay separately
- `LiquidClash/Views/ProxiesView.swift` — Read from ProxyService, not proxyRegions
- `LiquidClash/Views/DashboardView.swift` — Active node from ProxyService
- `LiquidClash/Views/MenuBarView.swift` — Node selector from ProxyService
- `LiquidClash/Services/ConfigParser.swift` — Keep only URI→YAML generation, remove node display parsing

### Files to REMOVE (functionality absorbed elsewhere):
- Nothing deleted, but large sections of AppState (fetchProxiesFromAPI, selectProxyInMihomo, stripEmoji, resolveMihomoName) will be replaced.

---

### Task 1: ConfigPipeline — Overlay subscription YAML to produce runtime.yaml

**Files:**
- Create: `LiquidClash/Core/ConfigPipeline.swift`
- Modify: `LiquidClash/Services/ConfigStorage.swift`

This replaces `ClashManager.writeConfigFromRawYAML()` and `writeConfigYAML()` with a clean pipeline.

The overlay strategy (matching Verge's HANDLE_FIELDS concept):
- **Always override:** `mixed-port`, `external-controller`, `secret`, `port: 0`, `socks-port: 0`
- **Override if missing:** `dns` (with fake-ip config), `mode`
- **Never touch:** `proxies`, `proxy-groups`, `rules`, `rule-providers`, everything else

- [ ] **Step 1: Create ConfigPipeline.swift**

```swift
// LiquidClash/Core/ConfigPipeline.swift
import Foundation

/// Produces runtime.yaml from subscription YAML + minimal overlay.
/// Follows Verge's principle: subscription config is immutable, overlay only control fields.
struct ConfigPipeline {

    struct OverlayConfig {
        var mixedPort: Int = 7890
        var externalController: String = "127.0.0.1:9090"
        var secret: String = ""
        var mode: String = "rule"
        var logLevel: String = "info"
        var allowLan: Bool = false
        var tunEnabled: Bool = false
    }

    /// Default DNS config injected when subscription YAML has no dns: section.
    /// Without this, system DNS is used → DNS pollution → wrong GeoIP → all traffic DIRECT.
    private static let defaultDNS = """
    dns:
      enable: true
      enhanced-mode: fake-ip
      fake-ip-range: 198.18.0.1/16
      nameserver:
        - https://dns.alidns.com/dns-query
        - https://doh.pub/dns-query
      fallback:
        - https://dns.google/dns-query
        - https://cloudflare-dns.com/dns-query
      fallback-filter:
        geoip: true
        geoip-code: CN
    """

    /// Default TUN config.
    private static let defaultTUN = """
    tun:
      enable: true
      stack: system
      auto-route: true
      auto-detect-interface: true
    """

    /// Generate runtime.yaml from subscription YAML + overlay config.
    static func generateRuntime(subscriptionYAML: String, overlay: OverlayConfig, outputPath: URL) throws {
        var lines = subscriptionYAML.components(separatedBy: .newlines)

        // Fields we ALWAYS override (control fields only)
        let forceOverrides: [(key: String, value: String)] = [
            ("port", "0"),
            ("socks-port", "0"),
            ("redir-port", "0"),
            ("mixed-port", "\(overlay.mixedPort)"),
            ("external-controller", "'\(overlay.externalController)'"),
            ("secret", "''"),
            ("allow-lan", "\(overlay.allowLan)"),
            ("mode", overlay.mode),
            ("log-level", overlay.logLevel),
        ]

        // Replace existing top-level keys
        var appliedKeys: Set<String> = []
        for i in lines.indices {
            let line = lines[i]
            guard !line.isEmpty, !line.hasPrefix(" "), !line.hasPrefix("\t"), !line.hasPrefix("#") else { continue }
            for (key, value) in forceOverrides {
                if line.hasPrefix("\(key):") {
                    lines[i] = "\(key): \(value)"
                    appliedKeys.insert(key)
                }
            }
        }

        // Prepend any missing override keys
        var header = "# LiquidClash runtime config\n"
        for (key, value) in forceOverrides where !appliedKeys.contains(key) {
            header += "\(key): \(value)\n"
        }

        // Add DNS config only if subscription doesn't have one
        let hasDNS = lines.contains { $0.hasPrefix("dns:") && !$0.hasPrefix(" ") }
        if !hasDNS {
            header += "\n" + defaultDNS + "\n"
        }

        // Add TUN config if enabled and not present
        if overlay.tunEnabled && !lines.contains(where: { $0.hasPrefix("tun:") && !$0.hasPrefix(" ") }) {
            header += "\n" + defaultTUN + "\n"
        }

        let finalYAML = header + "\n" + lines.joined(separator: "\n")
        try finalYAML.write(to: outputPath, atomically: true, encoding: .utf8)
    }
}
```

- [ ] **Step 2: Update ConfigStorage to store subscription and overlay separately**

Add to `ConfigStorage.swift`:

```swift
// Add these properties and methods:

var runtimeConfigPath: URL {
    appSupportDirectory.appendingPathComponent("config", isDirectory: true)
        .appendingPathComponent("config.yaml")
}

var subscriptionYAMLPath: URL {
    appSupportDirectory.appendingPathComponent("subscription_raw.yaml")
}

func loadSubscriptionYAML() -> String? {
    try? String(contentsOf: subscriptionYAMLPath, encoding: .utf8)
}

func saveSubscriptionYAML(_ yaml: String) {
    try? yaml.write(to: subscriptionYAMLPath, atomically: true, encoding: .utf8)
}
```

- [ ] **Step 3: Build and verify compilation**

Run: `xcodebuild -scheme LiquidClash -configuration Debug build 2>&1 | grep "BUILD"`
Expected: BUILD SUCCEEDED

- [ ] **Step 4: Commit**

```bash
git add LiquidClash/Core/ConfigPipeline.swift LiquidClash/Services/ConfigStorage.swift
git commit -m "feat: add ConfigPipeline for clean YAML overlay"
```

---

### Task 2: ProxyService — Single source of truth from mihomo API

**Files:**
- Create: `LiquidClash/Services/ProxyService.swift`

This replaces all proxy-related code scattered in AppState (fetchProxiesFromAPI, selectProxyInMihomo, testNodeLatency, etc.) with a focused service that reads everything from mihomo API.

- [ ] **Step 1: Create ProxyService.swift**

```swift
// LiquidClash/Services/ProxyService.swift
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

    /// Test latency for a specific proxy. Uses mihomo name directly.
    func testLatency(name: String) async -> Int? {
        guard let api else { return nil }
        do {
            let result = try await api.testProxyDelay(name: name)
            if let delay = result.delay {
                await MainActor.run {
                    if let idx = nodes.firstIndex(where: { $0.id == name }) {
                        nodes[idx].latency = delay
                    }
                }
                return delay
            }
        } catch { }
        return nil
    }

    /// Test latency for all nodes.
    func testAllLatency() async {
        guard let api else { return }
        await withTaskGroup(of: Void.self) { group in
            for node in nodes {
                group.addTask {
                    _ = await self.testLatency(name: node.name)
                }
            }
        }
    }
}
```

- [ ] **Step 2: Build and verify**

Run: `xcodebuild -scheme LiquidClash -configuration Debug build 2>&1 | grep "BUILD"`
Expected: BUILD SUCCEEDED

- [ ] **Step 3: Commit**

```bash
git add LiquidClash/Services/ProxyService.swift
git commit -m "feat: add ProxyService as single source of truth from mihomo API"
```

---

### Task 3: Rewire ClashManager to use ConfigPipeline

**Files:**
- Modify: `LiquidClash/Core/ClashManager.swift`

Replace `writeConfigFromRawYAML()` and `writeConfigYAML()` with a single method that uses `ConfigPipeline`.

- [ ] **Step 1: Replace config writing methods in ClashManager**

Remove `writeConfigFromRawYAML()` and `writeConfigYAML()` entirely. Replace with:

```swift
/// Write runtime config using ConfigPipeline
func writeRuntimeConfig(subscriptionYAML: String, overlay: ConfigPipeline.OverlayConfig) throws {
    try ConfigPipeline.generateRuntime(
        subscriptionYAML: subscriptionYAML,
        overlay: overlay,
        outputPath: configFilePath
    )
}
```

Update `start()` and `startWithPrivileges()` to accept `subscriptionYAML: String` and `overlay: ConfigPipeline.OverlayConfig` instead of `config: ClashConfig, rawSubscriptionYAML: String?`.

- [ ] **Step 2: Update AppState.connect() to use new ClashManager API**

In `AppState.connect()`, replace the config building logic with:

```swift
let overlay = ConfigPipeline.OverlayConfig(
    mixedPort: port,
    mode: proxyMode.rawValue.lowercased(),
    logLevel: "info",
    allowLan: config.tunEnabled && UserDefaults.standard.bool(forKey: SettingsKey.allowLAN),
    tunEnabled: config.tunEnabled
)

guard let subscriptionYAML = ConfigStorage.shared.loadSubscriptionYAML() else {
    errorMessage = "No subscription config found"
    return
}

try clashManager.writeRuntimeConfig(subscriptionYAML: subscriptionYAML, overlay: overlay)
```

- [ ] **Step 3: Build and verify**

Run: `xcodebuild -scheme LiquidClash -configuration Debug build 2>&1 | grep "BUILD"`
Expected: BUILD SUCCEEDED

- [ ] **Step 4: Commit**

```bash
git add LiquidClash/Core/ClashManager.swift LiquidClash/Services/AppState.swift
git commit -m "refactor: ClashManager uses ConfigPipeline, remove string-level YAML hacking"
```

---

### Task 4: Rewire AppState to use ProxyService

**Files:**
- Modify: `LiquidClash/Services/AppState.swift`

Remove all proxy-related code from AppState and delegate to ProxyService. AppState becomes a thin coordinator.

- [ ] **Step 1: Add ProxyService to AppState**

```swift
// In AppState properties:
let proxyService = ProxyService()
```

- [ ] **Step 2: Remove from AppState**

Delete these methods/properties (now handled by ProxyService):
- `fetchProxiesFromAPI()` (entire method)
- `selectProxyInMihomo()` (entire method)
- `stripEmoji()` / `resolveMihomoName()` (if still present)
- `testNodeLatency()` / `testAllLatency()` (delegate to ProxyService)
- `selectorGroupNames` property
- `networkInfoTask` handling in `selectNode()` — simplify to just call ProxyService

- [ ] **Step 3: Update onCoreStarted()**

```swift
private func onCoreStarted(api: ClashAPI) {
    clashAPI = api
    proxyService.setAPI(api)

    // System proxy
    if !config.tunEnabled {
        do {
            try SystemProxy.enable(httpPort: config.mixedPort, socksPort: config.mixedPort)
            startProxyGuard()
        } catch {
            errorMessage = "System proxy: \(error.localizedDescription)"
        }
    }

    isConnected = true

    // WebSocket streams (unchanged)
    // ...

    // Fetch proxy data from mihomo API (single source of truth)
    Task {
        await proxyService.refresh()
        await fetchNetworkInfo()
    }
    Task { await fetchActiveRules() }
}
```

- [ ] **Step 4: Simplify selectNode()**

```swift
func selectNode(_ nodeName: String) {
    guard isConnected else { return }
    // Find which Selector group contains this node/group name
    Task {
        // If it's a group name, select it in parent Selectors
        // If it's a node name, select it directly
        for group in proxyService.groups where group.isSelector && group.all.contains(nodeName) {
            await proxyService.selectProxy(group: group.name, proxy: nodeName)
        }
        // Refresh IP after switch
        networkInfo = NetworkInfo()
        await fetchNetworkInfo()
    }
}
```

- [ ] **Step 5: Build and verify**

Run: `xcodebuild -scheme LiquidClash -configuration Debug build 2>&1 | grep "BUILD"`
Expected: BUILD SUCCEEDED

- [ ] **Step 6: Commit**

```bash
git add LiquidClash/Services/AppState.swift
git commit -m "refactor: AppState delegates proxy operations to ProxyService"
```

---

### Task 5: Update Views to use ProxyService

**Files:**
- Modify: `LiquidClash/Views/ProxiesView.swift`
- Modify: `LiquidClash/Views/DashboardView.swift`
- Modify: `LiquidClash/Views/MenuBarView.swift`
- Modify: `LiquidClash/Views/RegionGroupView.swift`

ProxiesView now reads from `proxyService.groups` and `proxyService.nodes` instead of `proxyRegions`.

- [ ] **Step 1: Redesign ProxiesView layout**

The view should show:
1. **Subscription panel** (existing, keep)
2. **Proxy Groups** — from `proxyService.groups`, shown as compact tags (service groups + region groups)
3. **Proxy Nodes** — from `proxyService.nodes`, organized by geographic region using flag emoji

Groups are shown at the top. Clicking a Selector group shows its members; clicking a member selects it.
Nodes below are organized by region (reuse existing RegionGroupView but feed it API data).

- [ ] **Step 2: Update DashboardView active node card**

Read from `proxyService.activeNodeName` instead of `appState.activeNode`.

- [ ] **Step 3: Update MenuBarView node selector**

Read from `proxyService.nodes` and `proxyService.groups`.

- [ ] **Step 4: Build and verify**

Run: `xcodebuild -scheme LiquidClash -configuration Debug build 2>&1 | grep "BUILD"`
Expected: BUILD SUCCEEDED

- [ ] **Step 5: Deploy and test on Mac mini**

```bash
xcodebuild -scheme LiquidClash -configuration Release build
sshpass -p 'hesong' scp -o StrictHostKeyChecking=no -r ~/Library/Developer/Xcode/DerivedData/LiquidClash-*/Build/Products/Release/LiquidClash.app hs@192.168.110.45:~/Desktop/
```

Verify:
- Proxy groups (YouTube, Netflix, HK, JP etc.) appear
- Nodes appear with correct names (matching mihomo)
- Node switching works (IP changes)
- Latency testing works
- IP/city/AS type displays correctly

- [ ] **Step 6: Commit**

```bash
git add LiquidClash/Views/
git commit -m "refactor: Views read from ProxyService (mihomo API), not local parsing"
```

---

### Task 6: Clean up dead code

**Files:**
- Modify: `LiquidClash/Services/AppState.swift` — remove dead properties/methods
- Modify: `LiquidClash/Services/ConfigParser.swift` — keep only URI→YAML generation + extractFlag
- Modify: `LiquidClash/Models/ClashConfig.swift` — simplify (remove proxies/proxyGroups/rules fields)

- [ ] **Step 1: Remove from AppState**

- `proxyRegions` property (replaced by ProxyService)
- `selectedNodeId` / `activeNode` (replaced by ProxyService)
- `selectorGroupNames` (never used)
- `debugLog()` method (replace with os.Logger or #if DEBUG)
- `organizeIntoRegions()` (no longer needed)

- [ ] **Step 2: Simplify ConfigParser**

Keep only:
- `parseSubscription()` — for initial URI→node parsing
- `generateClashYAML()` — for generating YAML from URI subscriptions
- `extractFlag()` / `guessFlag()` — for flag extraction
- `escapeYAML()` — helper

Remove:
- `parseClashYAMLProxies()` — no longer needed (mihomo API provides nodes)
- `parseClashYAMLRules()` — rules come from mihomo API
- `buildNodeFromDict()` / `parseInlineProxy()` — not needed for API-based flow

Actually, keep `parseClashYAMLProxies` for now — it's used by `generateClashYAML` flow when subscription returns URI format. But it's no longer the source of truth for UI display.

- [ ] **Step 3: Build and verify**

Run: `xcodebuild -scheme LiquidClash -configuration Release build 2>&1 | grep "BUILD"`
Expected: BUILD SUCCEEDED

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "chore: remove dead code from architecture refactor"
```

---

## Execution Notes

- **Test after each task** by building and deploying to Mac mini
- **Don't break existing features** — subscription download, WebSocket streams, system proxy, TUN should all continue working
- **The key insight**: after this refactor, there is NO name mapping anywhere. mihomo names ARE the UI names. `selectProxy("YouTube", "JP")` just works because both strings come from the same API response.
