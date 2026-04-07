import SwiftUI

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
    case logs      = "Logs"
    case settings  = "Settings"

    var id: String { rawValue }

    var displayName: String {
        String(localized: String.LocalizationValue(rawValue))
    }

    var icon: String {
        switch self {
        case .dashboard: return "house"
        case .proxies:   return "globe"
        case .rules:     return "list.bullet"
        case .activity:  return "arrow.up.arrow.down"
        case .logs:      return "doc.text"
        case .settings:  return "gearshape"
        }
    }

    var iconColor: Color {
        switch self {
        case .dashboard: return Color(hex: "007AFF")
        case .proxies:   return Color(hex: "32ADE6")
        case .rules:     return Color(hex: "5856D6")
        case .activity:  return Color(hex: "007AFF")
        case .logs:      return Color(hex: "8E8E93")
        case .settings:  return Color(hex: "8E8E93")
        }
    }
}

// MARK: - Mock Data (Preview & initial data, replaced by real data in Phase 2)

let mockProxyRegions: [ProxyRegion] = [
    ProxyRegion(id: "ap", name: "ASIA PACIFIC", nodes: [
        ProxyNode(id: "ap1", flag: "🇯🇵", name: "Tokyo - Edge 01", type: .trojan, relay: "HKG Relay", latency: 42, isActive: true),
        ProxyNode(id: "ap2", flag: "🇸🇬", name: "Singapore - SG-4", type: .vmess, relay: "Core", latency: 65),
        ProxyNode(id: "ap3", flag: "🇭🇰", name: "Hong Kong - HKT", type: .shadowsocks, relay: "Direct", latency: 98),
        ProxyNode(id: "ap4", flag: "🇰🇷", name: "Seoul - KIX 02", type: .trojan, relay: "Oracle", latency: 54),
    ]),
    ProxyRegion(id: "am", name: "AMERICAS", nodes: [
        ProxyNode(id: "am1", flag: "🇺🇸", name: "Los Angeles - LAX", type: .trojan, relay: "Premium", latency: 145),
        ProxyNode(id: "am2", flag: "🇺🇸", name: "San Jose - SJ-1", type: .vmess, relay: "BGP", latency: 168),
        ProxyNode(id: "am3", flag: "🇨🇦", name: "Toronto - CN-01", type: .shadowsocks, relay: "Digital Ocean", latency: 210),
    ]),
    ProxyRegion(id: "eu", name: "EUROPE", nodes: [
        ProxyNode(id: "eu1", flag: "🇬🇧", name: "London - LHR-2", type: .trojan, relay: "Linode", latency: 240),
        ProxyNode(id: "eu2", flag: "🇩🇪", name: "Frankfurt - FRA", type: .vmess, relay: "Hetzner", latency: 285),
    ]),
]

let mockRules: [RuleItem] = [
    RuleItem(id: "r1", type: "DOMAIN-SUFFIX", value: "google.com", policy: .proxy),
    RuleItem(id: "r2", type: "DOMAIN-SUFFIX", value: "netflix.com", policy: .proxy),
    RuleItem(id: "r3", type: "IP-CIDR", value: "192.168.0.0/16", policy: .direct),
    RuleItem(id: "r4", type: "GEOIP", value: "CN", policy: .direct),
    RuleItem(id: "r5", type: "MATCH", value: "Remaining Traffic", policy: .proxy),
]

let mockConnections: [ConnectionEntry] = [
    ConnectionEntry(id: "c1", domain: "api.github.com", protocolName: "HTTPS", rule: "global-proxy", nodeFlag: "🇺🇸", nodeName: "San Jose 04", latency: 42, dataSize: "124.5 KB", dataLabel: "Download", timestamp: "14:22:05", type: .proxied),
    ConnectionEntry(id: "c2", domain: "static.google.com", protocolName: "HTTPS", rule: "final", nodeFlag: "🇯🇵", nodeName: "Tokyo Edge 02", latency: 156, dataSize: "2.4 MB", dataLabel: "Download", timestamp: "14:21:58", type: .proxied),
    ConnectionEntry(id: "c3", domain: "tracker.baidu.com", protocolName: "HTTP", rule: "mainland-direct", nodeFlag: "🇨🇳", nodeName: "Direct", latency: 12, dataSize: "8.2 KB", dataLabel: "Upload", timestamp: "14:21:42", type: .direct),
    ConnectionEntry(id: "c4", domain: "telemetry.msn.com", protocolName: "QUIC", rule: "ad-block", nodeFlag: "🚫", nodeName: "Rejected", latency: nil, dataSize: "0 B", dataLabel: "Traffic", timestamp: "14:21:30", type: .rejected),
    ConnectionEntry(id: "c5", domain: "discord.gg", protocolName: "Websocket", rule: "chat-group", nodeFlag: "🇸🇬", nodeName: "Singapore Premium", latency: 89, dataSize: "542 KB", dataLabel: "Stream", timestamp: "14:21:15", type: .proxied),
    ConnectionEntry(id: "c6", domain: "upload.wikimedia.org", protocolName: "HTTPS", rule: "global-proxy", nodeFlag: "🇺🇸", nodeName: "San Jose 04", latency: 312, dataSize: "1.8 MB", dataLabel: "Download", timestamp: "14:20:52", type: .proxied),
]
