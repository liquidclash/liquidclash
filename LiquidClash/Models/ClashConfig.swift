import Foundation

// MARK: - Clash Configuration

struct ClashConfig: Codable {
    var port: Int = 7890
    var socksPort: Int = 7891
    var mixedPort: Int = 7890
    var allowLan: Bool = false
    var mode: String = "rule"
    var logLevel: String = "info"
    var externalController: String = "127.0.0.1:9090"
    var secret: String = ""

    // TUN
    var tunEnabled: Bool = false

    // DNS
    var dnsEnabled: Bool = true
    var dnsListen: String = "0.0.0.0:53"

    // Proxies & Groups & Rules (stored separately for easier management)
    var proxies: [ProxyNode] = []
    var proxyGroups: [ProxyGroup] = []
    var rules: [String] = []

    enum CodingKeys: String, CodingKey {
        case port
        case socksPort = "socks-port"
        case mixedPort = "mixed-port"
        case allowLan = "allow-lan"
        case mode
        case logLevel = "log-level"
        case externalController = "external-controller"
        case secret
        case tunEnabled
        case dnsEnabled
        case dnsListen
        case proxies
        case proxyGroups = "proxy-groups"
        case rules
    }
}
