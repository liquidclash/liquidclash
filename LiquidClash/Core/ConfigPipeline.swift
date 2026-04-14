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
      default-nameserver:
        - 223.5.5.5
        - 119.29.29.29
      proxy-server-nameserver:
        - 223.5.5.5
        - 119.29.29.29
      nameserver:
        - 223.5.5.5
        - 119.29.29.29
      fallback:
        - 1.1.1.1
        - 8.8.8.8
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

    /// All proxy server hostnames found in the subscription YAML (for fake-ip-filter)
    private static func extractProxyServerHosts(from lines: [String]) -> [String] {
        var hosts: Set<String> = []
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            // Match "server: hostname" in both multi-line and inline formats
            guard let range = trimmed.range(of: "server:") else { continue }
            var value = trimmed[range.upperBound...]
                .trimmingCharacters(in: .whitespaces)
            // Remove trailing comma or brace for inline format
            if let commaIdx = value.firstIndex(of: ",") { value = String(value[..<commaIdx]) }
            if let braceIdx = value.firstIndex(of: "}") { value = String(value[..<braceIdx]) }
            value = value.trimmingCharacters(in: .whitespaces)
                .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
            // Skip IPs and empty values
            if value.isEmpty { continue }
            if value.allSatisfy({ $0.isNumber || $0 == "." || $0 == ":" }) { continue }
            hosts.insert(value)
        }
        return Array(hosts)
    }

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

        // DNS handling: use subscription DNS if present, inject defaults if missing.
        // Always ensure critical fields (default-nameserver, proxy-server-nameserver,
        // fake-ip-filter) are present so TUN mode works correctly.
        let hasDNS = lines.contains { $0.hasPrefix("dns:") && !$0.hasPrefix(" ") }
        if !hasDNS {
            var dnsConfig = defaultDNS
            let proxyHosts = extractProxyServerHosts(from: lines)
            if !proxyHosts.isEmpty {
                let filterEntries = proxyHosts.map { "        - \"+.\($0)\"" }.joined(separator: "\n")
                dnsConfig += "\n      fake-ip-filter:\n" + filterEntries
            }
            header += "\n" + dnsConfig + "\n"
        } else {
            // Subscription has DNS — patch in missing critical fields (2-space indent under dns:)
            let proxyHosts = extractProxyServerHosts(from: lines)
            var patches: [String] = []
            let dnsContent = lines.joined(separator: "\n")
            if !dnsContent.contains("default-nameserver") {
                patches.append("  default-nameserver:\n    - 223.5.5.5\n    - 119.29.29.29")
            }
            if !dnsContent.contains("proxy-server-nameserver") {
                patches.append("  proxy-server-nameserver:\n    - 223.5.5.5\n    - 119.29.29.29")
            }
            if !dnsContent.contains("fake-ip-filter") && !proxyHosts.isEmpty {
                let filterEntries = proxyHosts.map { "    - \"+.\($0)\"" }.joined(separator: "\n")
                patches.append("  fake-ip-filter:\n" + filterEntries)
            }
            if !patches.isEmpty, let dnsIdx = lines.firstIndex(where: { $0.hasPrefix("dns:") }) {
                lines.insert(patches.joined(separator: "\n"), at: dnsIdx + 1)
            }
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
            // Resolve dialer-proxy name: match against actual proxy names in config
            let relay = node.relay
            let resolved = knownNames.first(where: { $0 == relay })  // exact match first
                ?? knownNames.first(where: { relay.contains($0) })   // relay "🇯🇵 Japan | 01" contains config name "Japan | 01"
                ?? knownNames.first(where: { $0.contains(relay) })   // config name contains relay
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
