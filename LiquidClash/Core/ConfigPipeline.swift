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

    /// All proxy names found in the subscription YAML (for resolving dialer-proxy names)
    private static func extractProxyNames(from lines: [String]) -> [String] {
        var names: [String] = []
        var inProxies = false
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed == "proxies:" { inProxies = true; continue }
            if inProxies && !line.isEmpty && !line.hasPrefix(" ") && !line.hasPrefix("\t") && !trimmed.hasPrefix("-") && !trimmed.hasPrefix("#") {
                inProxies = false
            }
            guard inProxies else { continue }
            // Multi-line format: "- name: xxx"
            if trimmed.hasPrefix("- name:") {
                let name = trimmed.replacingOccurrences(of: "- name:", with: "")
                    .trimmingCharacters(in: .whitespaces)
                    .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
                if !name.isEmpty { names.append(name) }
            }
            // Inline format: "- {name: xxx, ...}"
            if trimmed.hasPrefix("- {") && trimmed.contains("name:") {
                if let nameStart = trimmed.range(of: "name:") {
                    let afterName = trimmed[nameStart.upperBound...].trimmingCharacters(in: .whitespaces)
                    let nameValue = afterName.prefix(while: { $0 != "," && $0 != "}" })
                        .trimmingCharacters(in: .whitespaces)
                        .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
                    if !nameValue.isEmpty { names.append(String(nameValue)) }
                }
            }
        }
        return names
    }

    /// Generate runtime.yaml from subscription YAML + overlay config + optional custom nodes.
    static func generateRuntime(subscriptionYAML: String, overlay: OverlayConfig, customNodes: [ProxyNode] = [], outputPath: URL) throws {
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

        // Inject custom nodes into proxies section and first Selector group
        if !customNodes.isEmpty {
            let proxyNames = extractProxyNames(from: lines)
            let insertion = customNodes.map { nodeToYAML($0, knownNames: proxyNames) }.joined()
            if let proxiesIdx = lines.firstIndex(where: { $0.hasPrefix("proxies:") }) {
                lines.insert(insertion, at: proxiesIdx + 1)
            } else {
                lines.append("proxies:")
                lines.append(insertion)
            }

            // Add custom node names to Selector groups so mihomo can select them
            let customNames = customNodes.map { $0.name }
            let nameEntries = customNames.map { "      - \"\($0)\"" }.joined(separator: "\n")
            if let groupsIdx = lines.firstIndex(where: { $0.hasPrefix("proxy-groups:") }) {
                var i = groupsIdx + 1
                var foundTarget = false
                while i < lines.count {
                    let line = lines[i]
                    if !line.isEmpty && !line.hasPrefix(" ") && !line.hasPrefix("\t") && !line.hasPrefix("-") && !line.hasPrefix("#") {
                        break
                    }
                    // Look for "- name: Proxies" or "- name: PROXY" group
                    let trimmed = line.trimmingCharacters(in: .whitespaces)
                    if trimmed.contains("name:") && (trimmed.contains("Proxies") || trimmed.contains("PROXY")) {
                        foundTarget = true
                    }
                    // Insert after the "proxies:" line of the target group
                    if foundTarget && trimmed == "proxies:" {
                        lines.insert(nameEntries, at: i + 1)
                        break
                    }
                    i += 1
                }
            }
        }

        let finalYAML = header + "\n" + lines.joined(separator: "\n")
        try finalYAML.write(to: outputPath, atomically: true, encoding: .utf8)
    }

    /// Convert a ProxyNode to mihomo YAML proxy entry.
    private static func nodeToYAML(_ node: ProxyNode, knownNames: [String] = []) -> String {
        var y = "  - name: \"\(node.name)\"\n"
        y += "    type: \(node.type.rawValue)\n"
        y += "    server: \(node.server)\n"
        y += "    port: \(node.port)\n"
        if let user = node.username, !user.isEmpty { y += "    username: \"\(user)\"\n" }
        if let pw = node.password, !pw.isEmpty { y += "    password: \"\(pw)\"\n" }
        if let uuid = node.uuid, !uuid.isEmpty { y += "    uuid: \(uuid)\n" }
        if let cipher = node.cipher, !cipher.isEmpty { y += "    cipher: \(cipher)\n" }
        if let aid = node.alterId { y += "    alterId: \(aid)\n" }
        y += "    udp: \(node.udp)\n"
        if !node.relay.isEmpty && node.relay != "Direct" {
            // Resolve dialer-proxy name: match against known proxy names (with emoji)
            let relay = node.relay
            let resolved = knownNames.first(where: { $0 == relay })  // exact match first
                ?? knownNames.first(where: { $0.contains(relay) })   // fuzzy: "Japan | 01" matches "🇯🇵 Japan | 01"
                ?? relay
            y += "    dialer-proxy: \"\(resolved)\"\n"
        }
        if let sni = node.sni, !sni.isEmpty { y += "    sni: \(sni)\n" }
        if let scv = node.skipCertVerify, scv { y += "    skip-cert-verify: true\n" }
        if let tls = node.tls, tls { y += "    tls: true\n" }
        if let net = node.network, !net.isEmpty {
            y += "    network: \(net)\n"
            if net == "ws" {
                y += "    ws-opts:\n"
                if let path = node.wsPath, !path.isEmpty { y += "      path: \"\(path)\"\n" }
                if let host = node.wsHost, !host.isEmpty { y += "      headers:\n        Host: \(host)\n" }
            }
        }
        return y
    }
}
