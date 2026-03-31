import Foundation

// MARK: - ProxyMode

enum ProxyMode: String, CaseIterable {
    case rule   = "Rule"
    case global = "Global"
    case direct = "Direct"
}

// MARK: - AppPage

enum AppPage: String, CaseIterable, Identifiable {
    case dashboard = "Dashboard"
    case proxies   = "Proxies"
    case rules     = "Rules"
    case activity  = "Activity"
    case settings  = "Settings"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .dashboard: return "house"
        case .proxies:   return "network"
        case .rules:     return "list.bullet.rectangle"
        case .activity:  return "clock.arrow.circlepath"
        case .settings:  return "gearshape.fill"
        }
    }
}

// MARK: - MockNode (Dashboard 用)

struct MockNode {
    let flag: String
    let name: String
    let ping: Int
    let type: String
}

let mockActiveNode = MockNode(
    flag: "🇯🇵",
    name: "Tokyo - Premium Edge 01",
    ping: 42,
    type: "Trojan"
)

// MARK: - ProxyNode (Proxies 页面用)

struct ProxyNode: Identifiable, Hashable {
    let id: String
    let flag: String
    let name: String
    let protocolType: String
    let relay: String
    let latency: Int
    var isActive: Bool = false

    var latencyColor: LatencyLevel {
        if latency <= 100 { return .low }
        else if latency <= 150 { return .mid }
        else { return .high }
    }
}

enum LatencyLevel {
    case low, mid, high

    var color: String {
        switch self {
        case .low:  return "30D158"
        case .mid:  return "B29500"
        case .high: return "FF453A"
        }
    }

    var bgColor: String {
        switch self {
        case .low:  return "30D158"
        case .mid:  return "FFD60A"
        case .high: return "FF453A"
        }
    }
}

struct ProxyRegion: Identifiable {
    let id: String
    let name: String
    var nodes: [ProxyNode]
    var isExpanded: Bool = true
}

// MARK: - Mock Proxy Data

let mockProxyRegions: [ProxyRegion] = [
    ProxyRegion(id: "ap", name: "ASIA PACIFIC", nodes: [
        ProxyNode(id: "ap1", flag: "🇯🇵", name: "Tokyo - Edge 01", protocolType: "Trojan", relay: "HKG Relay", latency: 42, isActive: true),
        ProxyNode(id: "ap2", flag: "🇸🇬", name: "Singapore - SG-4", protocolType: "Vmess", relay: "Core", latency: 65),
        ProxyNode(id: "ap3", flag: "🇭🇰", name: "Hong Kong - HKT", protocolType: "SS", relay: "Direct", latency: 98),
        ProxyNode(id: "ap4", flag: "🇰🇷", name: "Seoul - KIX 02", protocolType: "Trojan", relay: "Oracle", latency: 54),
    ]),
    ProxyRegion(id: "am", name: "AMERICAS", nodes: [
        ProxyNode(id: "am1", flag: "🇺🇸", name: "Los Angeles - LAX", protocolType: "Trojan", relay: "Premium", latency: 145),
        ProxyNode(id: "am2", flag: "🇺🇸", name: "San Jose - SJ-1", protocolType: "Vmess", relay: "BGP", latency: 168),
        ProxyNode(id: "am3", flag: "🇨🇦", name: "Toronto - CN-01", protocolType: "SS", relay: "Digital Ocean", latency: 210),
    ]),
    ProxyRegion(id: "eu", name: "EUROPE", nodes: [
        ProxyNode(id: "eu1", flag: "🇬🇧", name: "London - LHR-2", protocolType: "Trojan", relay: "Linode", latency: 240),
        ProxyNode(id: "eu2", flag: "🇩🇪", name: "Frankfurt - FRA", protocolType: "Vmess", relay: "Hetzner", latency: 285),
    ]),
]

// MARK: - RuleItem (Rules 页面用)

enum RulePolicy: String {
    case proxy  = "Proxy"
    case direct = "Direct"
    case reject = "Reject"

    var dotColor: String {
        switch self {
        case .proxy:  return "4B6EFF"
        case .direct: return "30D158"
        case .reject: return "FF6E52"
        }
    }
}

struct RuleItem: Identifiable {
    let id: String
    let type: String
    let value: String
    let policy: RulePolicy
}

let mockRules: [RuleItem] = [
    RuleItem(id: "r1", type: "DOMAIN-SUFFIX", value: "google.com", policy: .proxy),
    RuleItem(id: "r2", type: "DOMAIN-SUFFIX", value: "netflix.com", policy: .proxy),
    RuleItem(id: "r3", type: "IP-CIDR", value: "192.168.0.0/16", policy: .direct),
    RuleItem(id: "r4", type: "GEOIP", value: "CN", policy: .direct),
    RuleItem(id: "r5", type: "MATCH", value: "Remaining Traffic", policy: .proxy),
]

// MARK: - ConnectionEntry (Activity 页面用)

enum ConnectionType: String {
    case proxied  = "Proxied"
    case direct   = "Direct"
    case rejected = "Rejected"
}

struct ConnectionEntry: Identifiable {
    let id: String
    let domain: String
    let protocolName: String
    let rule: String
    let nodeFlag: String
    let nodeName: String
    let latency: Int?
    let dataSize: String
    let dataLabel: String
    let timestamp: String
    let type: ConnectionType
}

let mockConnections: [ConnectionEntry] = [
    ConnectionEntry(id: "c1", domain: "api.github.com", protocolName: "HTTPS", rule: "global-proxy", nodeFlag: "🇺🇸", nodeName: "San Jose 04", latency: 42, dataSize: "124.5 KB", dataLabel: "Download", timestamp: "14:22:05", type: .proxied),
    ConnectionEntry(id: "c2", domain: "static.google.com", protocolName: "HTTPS", rule: "final", nodeFlag: "🇯🇵", nodeName: "Tokyo Edge 02", latency: 156, dataSize: "2.4 MB", dataLabel: "Download", timestamp: "14:21:58", type: .proxied),
    ConnectionEntry(id: "c3", domain: "tracker.baidu.com", protocolName: "HTTP", rule: "mainland-direct", nodeFlag: "🇨🇳", nodeName: "Direct", latency: 12, dataSize: "8.2 KB", dataLabel: "Upload", timestamp: "14:21:42", type: .direct),
    ConnectionEntry(id: "c4", domain: "telemetry.msn.com", protocolName: "QUIC", rule: "ad-block", nodeFlag: "🚫", nodeName: "Rejected", latency: nil, dataSize: "0 B", dataLabel: "Traffic", timestamp: "14:21:30", type: .rejected),
    ConnectionEntry(id: "c5", domain: "discord.gg", protocolName: "Websocket", rule: "chat-group", nodeFlag: "🇸🇬", nodeName: "Singapore Premium", latency: 89, dataSize: "542 KB", dataLabel: "Stream", timestamp: "14:21:15", type: .proxied),
    ConnectionEntry(id: "c6", domain: "upload.wikimedia.org", protocolName: "HTTPS", rule: "global-proxy", nodeFlag: "🇺🇸", nodeName: "San Jose 04", latency: 312, dataSize: "1.8 MB", dataLabel: "Download", timestamp: "14:20:52", type: .proxied),
]
