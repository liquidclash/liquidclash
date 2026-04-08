import Foundation

// MARK: - Config Parser

struct ConfigParser {

    // MARK: - Parse Subscription Content

    /// Auto-detect format and parse proxy nodes
    static func parseSubscription(_ content: String) -> [ProxyNode] {
        // Strip BOM and whitespace
        var trimmed = content.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("\u{FEFF}") {
            trimmed = String(trimmed.dropFirst())
        }

        // 1. If content looks like Clash YAML (contains "proxies:"), parse as YAML first
        if trimmed.contains("proxies:") {
            let yamlNodes = parseClashYAMLProxies(trimmed)
            if !yamlNodes.isEmpty { return yamlNodes }
        }

        // 2. Try as direct proxy URL lines (trojan://, vmess://, ss://, etc.)
        let lines = trimmed.components(separatedBy: .newlines).filter { !$0.isEmpty }
        let urlNodes = lines.compactMap { parseProxyURL($0) }
        if !urlNodes.isEmpty {
            return urlNodes
        }

        // 3. Try Base64 decode, then try all formats on decoded content
        if let decoded = decodeBase64(trimmed) {
            // 3a. Decoded might be Clash YAML
            if decoded.contains("proxies:") {
                let yamlNodes = parseClashYAMLProxies(decoded)
                if !yamlNodes.isEmpty { return yamlNodes }
            }
            // 3b. Decoded might be proxy URL lines
            let decodedLines = decoded.components(separatedBy: .newlines).filter { !$0.isEmpty }
            let decodedNodes = decodedLines.compactMap { parseProxyURL($0) }
            if !decodedNodes.isEmpty { return decodedNodes }
        }

        return []
    }

    // MARK: - Parse Proxy URLs

    static func parseProxyURL(_ url: String) -> ProxyNode? {
        let trimmed = url.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("trojan://") { return parseTrojanURL(trimmed) }
        if trimmed.hasPrefix("vmess://") { return parseVMessURL(trimmed) }
        if trimmed.hasPrefix("ss://") { return parseShadowsocksURL(trimmed) }
        if trimmed.hasPrefix("hysteria2://") || trimmed.hasPrefix("hy2://") { return parseHysteria2URL(trimmed) }
        if trimmed.hasPrefix("vless://") { return parseVLessURL(trimmed) }
        return nil
    }

    // MARK: - Trojan URL: trojan://password@server:port?params#name

    private static func parseTrojanURL(_ url: String) -> ProxyNode? {
        guard let parsed = URLComponents(string: url) else { return nil }
        let password = parsed.user ?? ""
        let server = parsed.host ?? ""
        let port = parsed.port ?? 443
        let rawName = parsed.fragment?.removingPercentEncoding ?? "\(server):\(port)"
        let (flag, name) = extractFlag(from: rawName)

        let params = queryParams(from: parsed)

        var node = ProxyNode(
            flag: flag, name: name, type: .trojan,
            server: server, port: port,
            password: password
        )
        node.sni = params["sni"] ?? params["peer"]
        if let insecure = params["allowInsecure"] ?? params["insecure"],
           insecure == "1" || insecure == "true" {
            node.skipCertVerify = true
        }
        if let net = params["type"], net != "tcp" { node.network = net }
        node.wsPath = params["path"]
        node.wsHost = params["host"]
        return node
    }

    // MARK: - VMess URL: vmess://base64(json)

    private static func parseVMessURL(_ url: String) -> ProxyNode? {
        let encoded = String(url.dropFirst("vmess://".count))
        guard let data = decodeBase64(encoded)?.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }

        let rawName = json["ps"] as? String ?? json["remarks"] as? String ?? ""
        let (flag, name) = extractFlag(from: rawName)
        let server = json["add"] as? String ?? ""
        let port = (json["port"] as? Int) ?? Int(json["port"] as? String ?? "") ?? 443
        let uuid = json["id"] as? String ?? ""
        let cipher = json["scy"] as? String ?? "auto"

        var node = ProxyNode(
            flag: flag, name: name, type: .vmess,
            server: server, port: port,
            uuid: uuid, cipher: cipher
        )
        let aid = (json["aid"] as? Int) ?? Int(json["aid"] as? String ?? "")
        node.alterId = aid ?? 0
        if let net = json["net"] as? String, net != "tcp" { node.network = net }
        if let tlsStr = json["tls"] as? String, !tlsStr.isEmpty { node.tls = true }
        node.sni = json["sni"] as? String
        node.wsPath = json["path"] as? String
        node.wsHost = json["host"] as? String
        if let scv = json["skip-cert-verify"] as? Bool, scv { node.skipCertVerify = true }
        return node
    }

    // MARK: - Shadowsocks URL: ss://base64(method:password)@server:port#name

    private static func parseShadowsocksURL(_ url: String) -> ProxyNode? {
        var working = String(url.dropFirst("ss://".count))
        var name = ""

        // Extract fragment (name)
        if let hashIdx = working.lastIndex(of: "#") {
            name = String(working[working.index(after: hashIdx)...]).removingPercentEncoding ?? ""
            working = String(working[..<hashIdx])
        }

        // Try SIP002 format: base64(method:password)@server:port
        if let atIdx = working.lastIndex(of: "@") {
            let userInfo = String(working[..<atIdx])
            let hostPort = String(working[working.index(after: atIdx)...])

            let decoded = decodeBase64(userInfo) ?? userInfo
            let parts = decoded.split(separator: ":", maxSplits: 1).map(String.init)
            let cipher = parts.first ?? "aes-256-gcm"
            let password = parts.count > 1 ? parts[1] : ""

            let hostParts = hostPort.split(separator: ":").map(String.init)
            let server = hostParts.first ?? ""
            let port = hostParts.count > 1 ? Int(hostParts[1]) ?? 443 : 443

            if name.isEmpty { name = "\(server):\(port)" }
            let (flag, cleanName) = extractFlag(from: name); name = cleanName

            return ProxyNode(
                flag: flag, name: name, type: .shadowsocks,
                server: server, port: port,
                password: password, cipher: cipher
            )
        }

        // Legacy format: base64(method:password@server:port)
        if let decoded = decodeBase64(working) {
            let parts = decoded.split(separator: "@", maxSplits: 1).map(String.init)
            guard parts.count == 2 else { return nil }
            let methodPassword = parts[0].split(separator: ":", maxSplits: 1).map(String.init)
            let hostPort = parts[1].split(separator: ":").map(String.init)

            let cipher = methodPassword.first ?? "aes-256-gcm"
            let password = methodPassword.count > 1 ? methodPassword[1] : ""
            let server = hostPort.first ?? ""
            let port = hostPort.count > 1 ? Int(hostPort[1]) ?? 443 : 443

            if name.isEmpty { name = "\(server):\(port)" }
            let (flag, cleanName) = extractFlag(from: name); name = cleanName

            return ProxyNode(
                flag: flag, name: name, type: .shadowsocks,
                server: server, port: port,
                password: password, cipher: cipher
            )
        }

        return nil
    }

    // MARK: - Hysteria2 URL

    private static func parseHysteria2URL(_ url: String) -> ProxyNode? {
        guard let parsed = URLComponents(string: url) else { return nil }
        let password = parsed.user ?? ""
        let server = parsed.host ?? ""
        let port = parsed.port ?? 443
        let rawName = parsed.fragment?.removingPercentEncoding ?? "\(server):\(port)"
        let (flag, name) = extractFlag(from: rawName)

        return ProxyNode(
            flag: flag, name: name, type: .hysteria2,
            server: server, port: port,
            password: password
        )
    }

    // MARK: - VLESS URL

    private static func parseVLessURL(_ url: String) -> ProxyNode? {
        guard let parsed = URLComponents(string: url) else { return nil }
        let uuid = parsed.user ?? ""
        let server = parsed.host ?? ""
        let port = parsed.port ?? 443
        let rawName = parsed.fragment?.removingPercentEncoding ?? "\(server):\(port)"
        let (flag, name) = extractFlag(from: rawName)

        return ProxyNode(
            flag: flag, name: name, type: .vless,
            server: server, port: port,
            uuid: uuid
        )
    }

    // MARK: - Simple Clash YAML Proxy Parser

    static func parseClashYAMLProxies(_ yaml: String) -> [ProxyNode] {
        let lines = yaml.components(separatedBy: .newlines)
        var nodes: [ProxyNode] = []
        var inProxies = false
        var currentNode: [String: String] = [:]

        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)

            // Detect proxies section
            if trimmed == "proxies:" || trimmed == "proxies: " {
                inProxies = true
                continue
            }

            // New top-level section ends proxies
            // But lines starting with "- " are proxy entries even without indentation (SubConverter format)
            if inProxies && !line.hasPrefix(" ") && !line.hasPrefix("\t") && !trimmed.isEmpty
                && !trimmed.hasPrefix("- ") {
                // Save last node
                if let node = buildNodeFromDict(currentNode) {
                    nodes.append(node)
                }
                currentNode = [:]
                inProxies = false
                continue
            }

            guard inProxies else { continue }

            // New proxy entry
            if trimmed.hasPrefix("- name:") || trimmed.hasPrefix("-  name:") {
                // Save previous node
                if let node = buildNodeFromDict(currentNode) {
                    nodes.append(node)
                }
                currentNode = [:]
                let value = extractYAMLValue(trimmed, prefix: "- name:")
                currentNode["name"] = value
            } else if trimmed.hasPrefix("- {") {
                // Inline format: - {name: xxx, type: trojan, ...}
                if let node = parseInlineProxy(trimmed) {
                    nodes.append(node)
                }
            } else if !trimmed.isEmpty && !trimmed.hasPrefix("#") {
                // Property line: "    key: value"
                let parts = trimmed.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
                if parts.count == 2 {
                    currentNode[parts[0]] = parts[1].trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
                }
            }
        }

        // Save last node
        if let node = buildNodeFromDict(currentNode) {
            nodes.append(node)
        }

        return nodes
    }

    /// Extract leading emoji flag from name if present, return (flag, cleanName)
    /// Only strips actual emoji (flags, symbols), not CJK/Hangul/other scripts.
    static func extractFlag(from name: String) -> (flag: String, cleanName: String) {
        var scalars = name.unicodeScalars[...]
        var emojiEnd = scalars.startIndex

        while emojiEnd < scalars.endIndex {
            let s = scalars[emojiEnd]
            if s.isASCII { break }
            // Regional Indicator Symbols (flags): U+1F1E6..U+1F1FF
            let isRegionalIndicator = (0x1F1E6...0x1F1FF).contains(s.value)
            // Variation selectors, zero-width joiners (emoji modifiers)
            let isModifier = s.value == 0xFE0F || s.value == 0x200D
            // Only treat as emoji if Unicode says so AND it's not a letter/number
            let isEmoji = (s.properties.isEmojiPresentation || isRegionalIndicator || isModifier)
                          && !s.properties.isAlphabetic
            if isEmoji {
                emojiEnd = scalars.index(after: emojiEnd)
            } else {
                break
            }
        }

        if emojiEnd > scalars.startIndex {
            let flag = String(scalars[scalars.startIndex..<emojiEnd])
            let rest = String(scalars[emojiEnd...]).trimmingCharacters(in: .whitespaces)
            if !rest.isEmpty {
                return (flag, rest)
            }
        }
        return (guessFlag(from: name), name)
    }

    private static func buildNodeFromDict(_ dict: [String: String]) -> ProxyNode? {
        guard let rawName = dict["name"], !rawName.isEmpty else { return nil }
        let (flag, name) = extractFlag(from: rawName)
        let typeStr = dict["type"] ?? "trojan"
        let type = ProxyType(rawValue: typeStr) ?? .trojan
        let server = dict["server"] ?? ""
        let port = Int(dict["port"] ?? "443") ?? 443

        var node = ProxyNode(
            flag: flag, name: name, type: type,
            server: server, port: port,
            password: dict["password"],
            uuid: dict["uuid"],
            cipher: dict["cipher"]
        )
        node.sni = dict["sni"] ?? dict["servername"]
        if let scv = dict["skip-cert-verify"], scv == "true" { node.skipCertVerify = true }
        if let net = dict["network"], net != "tcp" { node.network = net }
        if let tls = dict["tls"], tls == "true" { node.tls = true }
        if let aid = dict["alterId"] { node.alterId = Int(aid) }
        if let path = dict["ws-path"] { node.wsPath = path }
        return node
    }

    private static func parseInlineProxy(_ line: String) -> ProxyNode? {
        // - {name: xxx, type: trojan, server: xxx, port: 443, ...}
        var content = line.trimmingCharacters(in: .whitespaces)
        content = content.replacingOccurrences(of: "- {", with: "")
        content = content.replacingOccurrences(of: "}", with: "")

        // Smart split: split by ", key:" pattern to handle commas in quoted values
        var dict: [String: String] = [:]
        let knownKeys = ["name", "type", "server", "port", "password", "uuid", "cipher",
                         "udp", "sni", "skip-cert-verify", "network", "ws-opts",
                         "ws-path", "ws-headers", "alpn", "fingerprint",
                         "client-fingerprint", "tls", "servername", "flow",
                         "up", "down", "obfs", "obfs-password", "auth", "auth-str",
                         "ca", "ca-str", "recv-window-conn", "recv-window",
                         "disable-mtu-discovery", "plugin", "plugin-opts"]

        // First try: split by comma, then validate
        let pairs = smartSplitInlineYAML(content, knownKeys: knownKeys)
        for pair in pairs {
            let kv = pair.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            if kv.count == 2 {
                dict[kv[0]] = kv[1].trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
            }
        }
        return buildNodeFromDict(dict)
    }

    /// Split inline YAML respecting quoted values that may contain commas
    private static func smartSplitInlineYAML(_ content: String, knownKeys: [String]) -> [String] {
        var results: [String] = []
        var current = ""
        var inQuote: Character? = nil

        for char in content {
            if let q = inQuote {
                current.append(char)
                if char == q { inQuote = nil }
            } else if char == "\"" || char == "'" {
                current.append(char)
                inQuote = char
            } else if char == "," {
                // Check if next segment starts with a known key
                let trimmedCurrent = current.trimmingCharacters(in: .whitespaces)
                if !trimmedCurrent.isEmpty {
                    results.append(trimmedCurrent)
                }
                current = ""
            } else {
                current.append(char)
            }
        }
        let trimmedCurrent = current.trimmingCharacters(in: .whitespaces)
        if !trimmedCurrent.isEmpty {
            results.append(trimmedCurrent)
        }

        // Merge segments that don't start with "knownKey:" back into previous
        var merged: [String] = []
        for segment in results {
            let key = segment.split(separator: ":", maxSplits: 1).first.map(String.init) ?? ""
            if knownKeys.contains(key.trimmingCharacters(in: .whitespaces)) {
                merged.append(segment)
            } else if !merged.isEmpty {
                // This segment is a continuation (comma was inside a value)
                merged[merged.count - 1] += ", " + segment
            } else {
                merged.append(segment)
            }
        }

        return merged
    }

    // MARK: - Parse Clash YAML Rules

    static func parseClashYAMLRules(_ yaml: String, source: RuleSource = .subscription) -> [RuleItem] {
        let lines = yaml.components(separatedBy: .newlines)
        var rules: [RuleItem] = []
        var inRules = false

        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)

            if trimmed == "rules:" {
                inRules = true
                continue
            }

            if inRules && !line.hasPrefix(" ") && !line.hasPrefix("\t") && !trimmed.isEmpty
                && !trimmed.hasPrefix("- ") {
                break
            }

            guard inRules, trimmed.hasPrefix("- ") else { continue }
            var ruleStr = String(trimmed.dropFirst(2))
            // Strip YAML single/double quotes: - 'DOMAIN,example.com,Proxy' → DOMAIN,example.com,Proxy
            if (ruleStr.hasPrefix("'") && ruleStr.hasSuffix("'")) ||
               (ruleStr.hasPrefix("\"") && ruleStr.hasSuffix("\"")) {
                ruleStr = String(ruleStr.dropFirst().dropLast())
            }
            if let rule = RuleItem.from(clashString: ruleStr, source: source) {
                rules.append(rule)
            }
        }

        return rules
    }

    // MARK: - URI Query Params Helper

    private static func queryParams(from components: URLComponents) -> [String: String] {
        var dict: [String: String] = [:]
        for item in components.queryItems ?? [] {
            if let value = item.value { dict[item.name] = value }
        }
        return dict
    }

    // MARK: - Helpers

    static func decodeBase64(_ string: String) -> String? {
        // Try standard base64
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        // Pad if needed
        let remainder = base64.count % 4
        if remainder > 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }
        guard let data = Data(base64Encoded: base64) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private static func extractYAMLValue(_ line: String, prefix: String) -> String {
        let value = line.replacingOccurrences(of: "- name:", with: "")
            .trimmingCharacters(in: .whitespaces)
            .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
        return value
    }

    /// Guess country flag from node name
    static func guessFlag(from name: String) -> String {
        let lower = name.lowercased()
        let flagMap: [(keywords: [String], flag: String)] = [
            (["japan", "tokyo", "osaka", "jp", "🇯🇵"], "🇯🇵"),
            (["singapore", "sg", "🇸🇬"], "🇸🇬"),
            (["hong kong", "hk", "hongkong", "🇭🇰"], "🇭🇰"),
            (["taiwan", "tw", "taipei", "🇹🇼"], "🇨🇳"),
            (["korea", "seoul", "kr", "🇰🇷"], "🇰🇷"),
            (["us", "united states", "los angeles", "san jose", "lax", "sjc", "america", "🇺🇸"], "🇺🇸"),
            (["uk", "london", "united kingdom", "gb", "🇬🇧"], "🇬🇧"),
            (["germany", "frankfurt", "de", "🇩🇪"], "🇩🇪"),
            (["france", "paris", "fr", "🇫🇷"], "🇫🇷"),
            (["canada", "toronto", "ca", "🇨🇦"], "🇨🇦"),
            (["australia", "sydney", "au", "🇦🇺"], "🇦🇺"),
            (["india", "mumbai", "in", "🇮🇳"], "🇮🇳"),
            (["russia", "moscow", "ru", "🇷🇺"], "🇷🇺"),
            (["brazil", "sao paulo", "br", "🇧🇷"], "🇧🇷"),
            (["netherlands", "amsterdam", "nl", "🇳🇱"], "🇳🇱"),
        ]
        for entry in flagMap {
            for keyword in entry.keywords {
                if lower.contains(keyword) { return entry.flag }
            }
        }
        return "🌐"
    }

    // MARK: - Generate Clash YAML from Nodes

    /// Convert parsed ProxyNode array to complete Clash YAML config.
    /// Used when the subscription backend returns base64/URI format instead of YAML.
    /// Generates proxies, proxy-groups, and comprehensive rules using mihomo's geosite/geoip.
    static func generateClashYAML(from nodes: [ProxyNode]) -> String {
        var yaml = """
        # Generated by LiquidClash from subscription nodes
        mixed-port: 7890
        allow-lan: false
        mode: rule
        log-level: info
        external-controller: '127.0.0.1:9090'

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

        // Proxies
        yaml += "\nproxies:\n"
        for node in nodes {
            yaml += "  - name: \"\(escapeYAML(node.name))\"\n"
            yaml += "    type: \(node.type.rawValue)\n"
            yaml += "    server: \(node.server)\n"
            yaml += "    port: \(node.port)\n"
            if let password = node.password, !password.isEmpty {
                yaml += "    password: \"\(escapeYAML(password))\"\n"
            }
            if let uuid = node.uuid, !uuid.isEmpty {
                yaml += "    uuid: \(uuid)\n"
            }
            if let cipher = node.cipher, !cipher.isEmpty {
                yaml += "    cipher: \(cipher)\n"
            }
            if let alterId = node.alterId {
                yaml += "    alterId: \(alterId)\n"
            }
            yaml += "    udp: \(node.udp)\n"
            if let sni = node.sni, !sni.isEmpty {
                yaml += "    sni: \(sni)\n"
            }
            if let scv = node.skipCertVerify, scv {
                yaml += "    skip-cert-verify: true\n"
            }
            if let tls = node.tls, tls {
                yaml += "    tls: true\n"
            }
            if let net = node.network, !net.isEmpty {
                yaml += "    network: \(net)\n"
                if net == "ws" {
                    yaml += "    ws-opts:\n"
                    if let path = node.wsPath, !path.isEmpty {
                        yaml += "      path: \"\(path)\"\n"
                    }
                    if let host = node.wsHost, !host.isEmpty {
                        yaml += "      headers:\n"
                        yaml += "        Host: \(host)\n"
                    }
                }
            }
        }

        // Proxy Groups
        let nodeNames = nodes.map { "\"\(escapeYAML($0.name))\"" }

        // Build region-based sub-groups from node flags
        let regionKeywords: [(keywords: [String], id: String, name: String)] = [
            (["hong kong", "hk", "hongkong"], "HK", "HK"),
            (["japan", "tokyo", "osaka", "jp"], "JP", "JP"),
            (["singapore", "sg"], "SG", "SG"),
            (["taiwan", "tw", "taipei"], "TW", "TW"),
            (["united states", "us", "los angeles", "lax", "san jose", "sjc", "america"], "US", "US"),
        ]
        var regionNodes: [(id: String, name: String, members: [String])] = []
        for region in regionKeywords {
            let members = nodes.filter { node in
                let lower = node.name.lowercased()
                return region.keywords.contains { lower.contains($0) }
            }.map { "\"\(escapeYAML($0.name))\"" }
            if !members.isEmpty {
                regionNodes.append((id: region.id, name: region.name, members: members))
            }
        }

        yaml += "\nproxy-groups:\n"

        // Main select group — includes Auto Select, region groups, service groups, and all nodes
        yaml += "  - name: \"PROXY\"\n"
        yaml += "    type: select\n"
        yaml += "    proxies:\n"
        yaml += "      - \"Auto Select\"\n"
        for rg in regionNodes {
            yaml += "      - \"\(rg.name)\"\n"
        }
        for name in nodeNames {
            yaml += "      - \(name)\n"
        }

        // Auto select (url-test)
        yaml += "  - name: \"Auto Select\"\n"
        yaml += "    type: url-test\n"
        yaml += "    url: \"http://www.gstatic.com/generate_204\"\n"
        yaml += "    interval: 300\n"
        yaml += "    tolerance: 50\n"
        yaml += "    proxies:\n"
        for name in nodeNames {
            yaml += "      - \(name)\n"
        }

        // Region sub-groups (url-test within each region)
        for rg in regionNodes {
            yaml += "  - name: \"\(rg.name)\"\n"
            yaml += "    type: url-test\n"
            yaml += "    url: \"http://www.gstatic.com/generate_204\"\n"
            yaml += "    interval: 300\n"
            yaml += "    tolerance: 50\n"
            yaml += "    proxies:\n"
            for member in rg.members {
                yaml += "      - \(member)\n"
            }
        }

        // Service-specific select groups — each defaults to PROXY
        let serviceGroups = ["YouTube", "Netflix", "Disney", "Spotify", "Telegram", "Google", "OpenAI", "Apple", "Microsoft", "Steam"]
        for svc in serviceGroups {
            yaml += "  - name: \"\(svc)\"\n"
            yaml += "    type: select\n"
            yaml += "    proxies:\n"
            yaml += "      - \"PROXY\"\n"
            yaml += "      - \"Auto Select\"\n"
            yaml += "      - \"DIRECT\"\n"
            for rg in regionNodes {
                yaml += "      - \"\(rg.name)\"\n"
            }
            for name in nodeNames {
                yaml += "      - \(name)\n"
            }
        }

        // Fallback group
        yaml += "  - name: \"Fallback\"\n"
        yaml += "    type: fallback\n"
        yaml += "    url: \"http://www.gstatic.com/generate_204\"\n"
        yaml += "    interval: 300\n"
        yaml += "    proxies:\n"
        for name in nodeNames {
            yaml += "      - \(name)\n"
        }

        // Rule Providers
        yaml += """

        rule-providers:
          reject:
            type: http
            behavior: domain
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt"
            path: ./ruleset/reject.yaml
            interval: 86400
          proxy:
            type: http
            behavior: domain
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt"
            path: ./ruleset/proxy.yaml
            interval: 86400
          direct:
            type: http
            behavior: domain
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt"
            path: ./ruleset/direct.yaml
            interval: 86400
          private:
            type: http
            behavior: domain
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/private.txt"
            path: ./ruleset/private.yaml
            interval: 86400
          gfw:
            type: http
            behavior: domain
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/gfw.txt"
            path: ./ruleset/gfw.yaml
            interval: 86400
          tld-not-cn:
            type: http
            behavior: domain
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/tld-not-cn.txt"
            path: ./ruleset/tld-not-cn.yaml
            interval: 86400
          telegramcidr:
            type: http
            behavior: ipcidr
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/telegramcidr.txt"
            path: ./ruleset/telegramcidr.yaml
            interval: 86400
          cncidr:
            type: http
            behavior: ipcidr
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt"
            path: ./ruleset/cncidr.yaml
            interval: 86400
          lancidr:
            type: http
            behavior: ipcidr
            url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt"
            path: ./ruleset/lancidr.yaml
            interval: 86400

        rules:
          - RULE-SET,private,DIRECT
          - RULE-SET,reject,REJECT
          - GEOSITE,youtube,YouTube
          - GEOSITE,netflix,Netflix
          - GEOSITE,disney,Disney
          - GEOSITE,spotify,Spotify
          - GEOSITE,telegram,Telegram
          - RULE-SET,telegramcidr,Telegram,no-resolve
          - GEOSITE,google,Google
          - GEOSITE,openai,OpenAI
          - GEOSITE,apple,Apple
          - GEOSITE,microsoft,Microsoft
          - GEOSITE,steam,Steam
          - RULE-SET,tld-not-cn,PROXY
          - RULE-SET,gfw,PROXY
          - RULE-SET,proxy,PROXY
          - RULE-SET,direct,DIRECT
          - RULE-SET,cncidr,DIRECT,no-resolve
          - RULE-SET,lancidr,DIRECT,no-resolve
          - GEOSITE,category-ads-all,REJECT
          - GEOSITE,cn,DIRECT
          - GEOSITE,geolocation-!cn,PROXY
          - GEOIP,private,DIRECT,no-resolve
          - GEOIP,CN,DIRECT,no-resolve
          - MATCH,PROXY
        """

        return yaml
    }

    /// Escape special characters for YAML string values
    private static func escapeYAML(_ s: String) -> String {
        s.replacingOccurrences(of: "\\", with: "\\\\")
         .replacingOccurrences(of: "\"", with: "\\\"")
    }
}
