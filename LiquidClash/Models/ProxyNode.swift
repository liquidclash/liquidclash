import Foundation

// MARK: - Proxy Protocol Type

enum ProxyType: String, Codable, CaseIterable, Hashable {
    case trojan
    case vmess
    case shadowsocks = "ss"
    case socks5
    case http
    case hysteria2
    case vless

    var displayName: String {
        switch self {
        case .trojan: "Trojan"
        case .vmess: "VMess"
        case .shadowsocks: "SS"
        case .socks5: "SOCKS5"
        case .http: "HTTP"
        case .hysteria2: "Hysteria2"
        case .vless: "VLESS"
        }
    }
}

// MARK: - Latency Level

enum LatencyLevel {
    case low, mid, high

    var color: String {
        switch self {
        case .low:  "30D158"
        case .mid:  "B29500"
        case .high: "FF453A"
        }
    }

    var bgColor: String {
        switch self {
        case .low:  "30D158"
        case .mid:  "FFD60A"
        case .high: "FF453A"
        }
    }
}

// MARK: - Proxy Node

struct ProxyNode: Identifiable, Codable, Hashable {
    var id: String = UUID().uuidString
    var flag: String = ""
    var name: String
    var type: ProxyType = .trojan
    var server: String = ""
    var port: Int = 443
    var relay: String = ""
    var latency: Int = 0
    var isActive: Bool = false

    // Connection parameters
    var username: String?
    var password: String?
    var uuid: String?
    var cipher: String?
    var udp: Bool = true

    // TLS / transport parameters (critical for mihomo config generation)
    var sni: String?
    var skipCertVerify: Bool?
    var network: String?       // tcp, ws, grpc, h2
    var wsPath: String?
    var wsHost: String?
    var tls: Bool?
    var alterId: Int?          // vmess

    // Display helpers
    var protocolType: String { type.displayName }
    var ping: Int { latency }

    var latencyColor: LatencyLevel {
        if latency <= 100 { return .low }
        else if latency <= 150 { return .mid }
        else { return .high }
    }

    enum CodingKeys: String, CodingKey {
        case id, flag, name, type, server, port, relay, latency, isActive
        case username, password, uuid, cipher, udp
        case sni, skipCertVerify, network, wsPath, wsHost, tls, alterId
    }
}
