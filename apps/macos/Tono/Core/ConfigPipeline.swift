import Foundation
import CryptoKit
import Darwin
import AppKit

/// Produces runtime.yaml from subscription YAML + minimal overlay.
/// Follows Verge's principle: subscription config is immutable, overlay only control fields.
nonisolated struct ConfigPipeline {
    /// Mihomo is the only process allowed to create this interface. The kill
    /// switch validates that this exact interface exists before exempting it.
    static let tonoTunInterface = "utun199"

    struct OverlayConfig: Sendable {
        var mixedPort: Int = 7890
        var externalController: String = "127.0.0.1:9090"
        var secret: String = ""
        var mode: String = "rule"
        var logLevel: String = "info"
        var allowLan: Bool = false
        var tunEnabled: Bool = false
        /// `Home-US` or the exact name of one sanitized imported node.
        var selectedNodeName: String = "Home-US"
        /// Present only after Tono reports a healthy, exit-node-pinned SOCKS endpoint.
        var tonoTransport: TonoTransportDescriptor? = nil
    }

    struct DialEndpoint: Equatable, Sendable {
        let host: String
        let port: UInt16
        let transport: String
    }

    struct DirectEndpoint: Hashable, Equatable, Sendable {
        let address: String
        let port: UInt16
        let transport: String
    }

    struct DirectDomainPin: Equatable, Sendable {
        let host: String
        let addresses: [String]
        let ports: [UInt16]
    }

    /// One exact WeChat hostname/port route with its own reachability decision.
    /// Keeping this descriptor in ConfigPipeline gives runtime generation and
    /// tests one canonical mapping from a validated pin to its fallback group.
    struct ManagedDirectFallbackTarget: Equatable, Sendable {
        let host: String
        let port: UInt16
        let groupName: String
        let testURL: String
    }

    struct ManagedDirectRuntimePolicy: Equatable, Sendable {
        let physicalInterface: String
        let domainPins: [DirectDomainPin]
        let webDomainPins: [DirectDomainPin]
        let mediaEndpoints: [DirectEndpoint]
        /// Policy hostnames (pre-resolution) that must resolve through the
        /// interface-bound direct outbound via the China DoH resolvers, so the
        /// pinned answers are region-correct instead of exit-geolocated.
        let directResolverHosts: [String]

        init(
            physicalInterface: String,
            domainPins: [DirectDomainPin],
            webDomainPins: [DirectDomainPin] = [],
            mediaEndpoints: [DirectEndpoint],
            directResolverHosts: [String] = []
        ) {
            self.physicalInterface = physicalInterface
            self.domainPins = domainPins
            self.webDomainPins = webDomainPins
            self.mediaEndpoints = mediaEndpoints
            self.directResolverHosts = directResolverHosts
        }

        var sessionEndpoints: [DirectEndpoint] {
            let domainEndpoints = (domainPins + webDomainPins).flatMap { pin in
                pin.addresses.flatMap { address in
                    pin.ports.map {
                        DirectEndpoint(
                            address: address,
                            port: $0,
                            transport: "tcp"
                        )
                    }
                }
            }
            // The China DoH resolvers must be PF-permitted whenever managed
            // domains need region-correct resolution through the direct path.
            let resolverEndpoints = directResolverHosts.isEmpty
                ? []
                : ConfigPipeline.managedDirectResolverEndpoints
            return Array(Set(
                domainEndpoints + mediaEndpoints + resolverEndpoints
            )).sorted {
                ($0.transport, $0.port, $0.address)
                    < ($1.transport, $1.port, $1.address)
            }
        }

        var isEmpty: Bool {
            domainPins.isEmpty && webDomainPins.isEmpty
                && mediaEndpoints.isEmpty && directResolverHosts.isEmpty
        }
    }

    static let homeNodeName = "Home-US"
    static let exitGroupName = "Tono-Exit"
    static let directProxyName = "Tono-China-Direct"
    static let webDirectProxyName = "Tono-China-Web-Direct"
    static let managedDirectFallbackGroupPrefix = "Tono-WeChat-TCP-"
    static let managedDirectHealthIntervalSeconds = 60
    static let managedDirectHealthTimeoutMilliseconds = 3_500
    /// AliDNS DoH over TCP/443 with IP-literal certificates. Managed-direct
    /// domains resolve through these upstreams via the interface-bound direct
    /// outbound (nameserver-policy `#Tono-China-Direct`), which keeps pinned
    /// answers region-correct. TCP/443 stays inside the helper's session
    /// endpoint contract, and TLS server authentication protects the answers
    /// that feed the hosts pins and the PF allowlist.
    static let managedDirectResolverURLs = [
        "https://223.5.5.5/dns-query",
        "https://223.6.6.6/dns-query",
    ]
    static let managedDirectResolverEndpoints = [
        DirectEndpoint(address: "223.5.5.5", port: 443, transport: "tcp"),
        DirectEndpoint(address: "223.6.6.6", port: 443, transport: "tcp"),
    ]
    /// WeChat 4.x performs image/media/CDN transfer in helper executables that
    /// live inside the app bundle but are not the main binary (WeChatAppEx, its
    /// dedicated NetworkService helper, WeChatHelper, wxplayer, wxocr). Process
    /// matching therefore covers the whole reviewed bundle prefix, not one
    /// exact executable path. The standard install location is always present;
    /// a Launch Services lookup adds the real install path (e.g. under
    /// ~/Applications) so a non-standard install keeps routing and audit
    /// attribution. Dynamic entries are validated before adoption: they must
    /// still be a WeChat.app bundle and must be safe to embed in a Mihomo
    /// rule payload (no comma or parenthesis, printable ASCII only).
    static let managedDirectProcessBundlePaths: [String] = {
        var paths = ["/Applications/WeChat.app/"]
        let discovered = NSWorkspace.shared.urlsForApplications(
            withBundleIdentifier: "com.tencent.xinWeChat"
        )
        for url in discovered {
            let path = url.standardizedFileURL.resolvingSymlinksInPath().path + "/"
            guard path.hasSuffix("/WeChat.app/"),
                  !path.contains(","), !path.contains("("), !path.contains(")"),
                  path.unicodeScalars.allSatisfy({
                      $0.isASCII && $0.value > 0x20 && $0.value < 0x7F
                  }),
                  !paths.contains(path) else { continue }
            paths.append(path)
        }
        return paths
    }()

    /// Anchored RE2 patterns for Mihomo PROCESS-PATH-REGEX sub-rules, derived
    /// from the reviewed bundle prefixes so the two can never drift apart.
    static var managedDirectProcessPathRegexes: [String] {
        managedDirectProcessBundlePaths.map {
            let pattern = "^" + NSRegularExpression.escapedPattern(for: $0)
            // Commas separate AND sub-rules and parentheses delimit them, so
            // either character (even backslash-escaped) would corrupt the
            // emitted rule payload. Bundle paths must never contain them.
            precondition(
                !pattern.contains(",") && !pattern.contains("(")
                    && !pattern.contains(")"),
                "managed direct bundle path unsafe for rule emission"
            )
            return pattern
        }
    }

    /// Deterministic, bounded group names avoid exposing long policy hostnames
    /// as Mihomo object identifiers. A separate group per port ensures an HTTPS
    /// success cannot incorrectly mark TCP/80 direct as usable (or vice versa).
    static func managedDirectFallbackTargets(
        for policy: ManagedDirectRuntimePolicy?
    ) -> [ManagedDirectFallbackTarget] {
        guard let policy else { return [] }
        return policy.domainPins.flatMap { pin in
            pin.ports.map { port in
                let identity = "\(pin.host):\(port)"
                let digest = SHA256.hash(data: Data(identity.utf8))
                    .prefix(8)
                    .map { String(format: "%02x", $0) }
                    .joined()
                let scheme = port == 443 ? "https" : "http"
                return ManagedDirectFallbackTarget(
                    host: pin.host,
                    port: port,
                    groupName: managedDirectFallbackGroupPrefix + digest,
                    testURL: "\(scheme)://\(pin.host)/"
                )
            }
        }.sorted {
            ($0.host, $0.port) < ($1.host, $1.port)
        }
    }

    /// Finds the product-default cloud exit without depending on one exact
    /// catalog spelling. For example, `US Reality`, `US-VLESS-Reality`, and a
    /// flag-prefixed equivalent all resolve to the US Reality preference.
    static func preferredCloudExit(
        in nodes: [ProxyNode],
        named preferredName: String
    ) -> ProxyNode? {
        guard !nodes.isEmpty else { return nil }
        let preferredCompact = compactCloudExitName(preferredName)
        if let exact = nodes.first(where: {
            compactCloudExitName($0.name) == preferredCompact
                || compactCloudExitName($0.id) == preferredCompact
        }) {
            return exact
        }

        let preferredWords = cloudExitWords(preferredName)
        let wantsUS = preferredWords.contains("US")
            || (preferredWords.contains("UNITED") && preferredWords.contains("STATES"))
        let wantsJP = preferredWords.contains("JP")
            || preferredWords.contains("JAPAN")
            || preferredWords.contains("JAPANESE")
        let wantsReality = preferredWords.contains("REALITY")
        if wantsUS || wantsJP,
           let regional = nodes.first(where: { node in
               let words = cloudExitWords(node.name)
               let isUS = node.flag == "🇺🇸"
                   || words.contains("US")
                   || (words.contains("UNITED") && words.contains("STATES"))
               let isJP = node.flag == "🇯🇵"
                   || words.contains("JP")
                   || words.contains("JAPAN")
                   || words.contains("JAPANESE")
               let isRequestedRegion = (wantsUS && isUS) || (wantsJP && isJP)
               return isRequestedRegion && (!wantsReality || words.contains("REALITY"))
           }) {
            return regional
        }
        return nodes.first
    }

    static func orderedCloudExits(
        _ nodes: [ProxyNode],
        preferredName: String
    ) -> [ProxyNode] {
        guard let preferred = preferredCloudExit(in: nodes, named: preferredName),
              let index = nodes.firstIndex(where: { $0.id == preferred.id }) else {
            return nodes
        }
        var ordered = nodes
        ordered.remove(at: index)
        ordered.insert(preferred, at: 0)
        return ordered
    }

    private static func compactCloudExitName(_ value: String) -> String {
        String(value.uppercased().unicodeScalars.filter {
            CharacterSet.alphanumerics.contains($0)
        })
    }

    private static func cloudExitWords(_ value: String) -> Set<String> {
        let separated = String(value.uppercased().unicodeScalars.map {
            CharacterSet.alphanumerics.contains($0) ? Character(String($0)) : " "
        })
        return Set(separated.split(whereSeparator: \.isWhitespace).map(String.init))
    }

    /// Default DNS config injected when subscription YAML has no dns: section.
    /// Without this, system DNS is used → DNS pollution → wrong GeoIP → all traffic DIRECT.
    private static let defaultDNS = """
    dns:
      enable: true
      listen: \(ProtectedDNSContract.listener)
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

    /// Tono resolves through the pinned home route. IP-literal DoH endpoints avoid
    /// a bootstrap DNS query outside Home-US.
    private static let tonoDNS = """
    dns:
      enable: true
      listen: \(ProtectedDNSContract.listener)
      enhanced-mode: fake-ip
      fake-ip-range: 198.18.0.1/16
      use-hosts: true
      respect-rules: true
      proxy-server-nameserver:
        - https://1.1.1.1/dns-query#Tono-Exit
        - https://8.8.8.8/dns-query#Tono-Exit
      nameserver:
        - https://1.1.1.1/dns-query#Tono-Exit
        - https://8.8.8.8/dns-query#Tono-Exit
    """

    /// Default TUN config. Every validated catalog endpoint is excluded from
    /// the TUN route so changing the selector never requires rebuilding the
    /// interface. This does not grant direct egress: PF still permits only the
    /// root-owned core to the exact currently selected IP/port.
    private static func tunYAML(routeExclusions: [String] = []) -> String {
        var yaml = """
        tun:
          enable: true
          stack: gvisor
          device: \(tonoTunInterface)
          auto-route: true
          auto-detect-interface: true
          strict-route: true
          # Mihomo's gVisor ICMP path bypasses normal MATCH rules and otherwise
          # opens a host-direct ICMP socket. PF blocks it, but disable the path
          # at its source so ping can never attempt physical direct egress.
          disable-icmp-forwarding: true
          dns-hijack:
            - any:53
            - tcp://any:53
        """
        if !routeExclusions.isEmpty {
            yaml += "\n  route-exclude-address:\n"
            for address in routeExclusions {
                yaml += "    - \"\(address)/32\"\n"
            }
            yaml.removeLast()
        }
        return yaml
    }

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
    @discardableResult
    static func generateRuntime(
        subscriptionYAML: String,
        overlay: OverlayConfig,
        customNodes: [ProxyNode] = [],
        directPolicy: ManagedDirectRuntimePolicy? = nil,
        outputPath: URL
    ) throws -> String {
        // Tono mode: never text-delete sections from subscription YAML. Build a fully owned
        // runtime and import only proxy definitions (no rules/dns/tun/proxy-groups from sub).
        if overlay.tonoTransport != nil || overlay.selectedNodeName != homeNodeName {
            let owned = try buildOwnedTonoRuntime(
                subscriptionYAML: subscriptionYAML,
                overlay: overlay,
                transport: overlay.tonoTransport,
                customNodes: customNodes,
                directPolicy: directPolicy
            )
            return try secureWrite(owned, to: outputPath)
        }

        var lines = subscriptionYAML.components(separatedBy: .newlines)

        // Fields we ALWAYS override (control fields only)
        let forceOverrides: [(key: String, value: String)] = [
            ("port", "0"),
            ("socks-port", "0"),
            ("redir-port", "0"),
            ("mixed-port", "\(overlay.mixedPort)"),
            ("external-controller", "'\(overlay.externalController)'"),
            ("secret", "\"\(yamlScalar(overlay.secret))\""),
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
        var header = "# Tono runtime config\n"
        for (key, value) in forceOverrides where !appliedKeys.contains(key) {
            header += "\(key): \(value)\n"
        }

        // DNS handling: use subscription DNS if present, inject defaults if missing.
        let hasDNS = lines.contains { $0.hasPrefix("dns:") && !$0.hasPrefix(" ") }
        if !hasDNS {
            var dnsConfig = defaultDNS
            let proxyHosts = extractProxyServerHosts(from: lines)
            if !proxyHosts.isEmpty {
                let filterEntries = proxyHosts.map { "    - \"+.\($0)\"" }.joined(separator: "\n")
                dnsConfig += "\n  fake-ip-filter:\n" + filterEntries
            }
            header += "\n" + dnsConfig + "\n"
        } else {
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
            header += "\n" + tunYAML() + "\n"
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
        return try secureWrite(finalYAML, to: outputPath)
    }

    enum TonoInjectionError: LocalizedError {
        case unsafeDescriptor, unsafeOverlay, unsafeNode(String), duplicateNode(String), missingSelection
        var errorDescription: String? {
            switch self {
            case .unsafeDescriptor: return "Tono descriptor must use loopback and a non-zero port."
            case .unsafeOverlay: return "Tono runtime control settings are invalid."
            case .unsafeNode(let name): return "Proxy node \(name) contains unsupported or unsafe fields."
            case .duplicateNode(let name): return "Proxy node name \(name) is duplicated or reserved."
            case .missingSelection: return "The selected proxy node is unavailable."
            }
        }
    }

    /// Fully owned Tono runtime. Imported YAML is never copied into the runtime.
    /// Only validated ProxyNode fields are re-serialized below.
    static func buildOwnedTonoRuntime(
        subscriptionYAML: String,
        overlay: OverlayConfig,
        transport: TonoTransportDescriptor?,
        customNodes: [ProxyNode],
        directPolicy: ManagedDirectRuntimePolicy? = nil
    ) throws -> String {
        if let transport {
            guard transport.host == "127.0.0.1", transport.port != 0 else {
                throw TonoInjectionError.unsafeDescriptor
            }
        }
        let controllerParts = overlay.externalController.split(separator: ":", omittingEmptySubsequences: false)
        guard overlay.mixedPort > 0, overlay.mixedPort <= 65_535,
              controllerParts.count == 2, controllerParts[0] == "127.0.0.1",
              let controllerPort = Int(controllerParts[1]), controllerPort > 0, controllerPort <= 65_535,
              ["debug", "info", "warning", "error", "silent"].contains(overlay.logLevel)
        else {
            throw TonoInjectionError.unsafeOverlay
        }
        _ = subscriptionYAML

        let nodes = try validatedOwnedNodes(customNodes)
        let directPolicy = try validatedManagedDirectPolicy(
            directPolicy,
            excluding: Set(nodes.map(\.server))
        )
        let selected = overlay.selectedNodeName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (selected == homeNodeName && transport != nil) ||
                nodes.contains(where: { $0.name == selected }) else {
            throw TonoInjectionError.missingSelection
        }

        var proxyBlock = "proxies:\n"
        if let transport {
            proxyBlock += "  - name: \"\(homeNodeName)\"\n    type: socks5\n    server: 127.0.0.1\n    port: \(transport.port)\n    udp: \(transport.udp)\n"
            if let username = transport.username {
                proxyBlock += "    username: \"\(yamlScalar(username))\"\n"
            }
            if let password = transport.password {
                proxyBlock += "    password: \"\(yamlScalar(password))\"\n"
            }
        }
        for node in nodes {
            proxyBlock += try ownedNodeYAML(node)
        }
        if let directPolicy,
           !directPolicy.domainPins.isEmpty
            || !directPolicy.mediaEndpoints.isEmpty
            || !directPolicy.directResolverHosts.isEmpty {
            proxyBlock += """
              - name: "\(directProxyName)"
                type: direct
                interface-name: "\(yamlScalar(directPolicy.physicalInterface))"
                ip-version: ipv4-only

            """
        }
        if let directPolicy, !directPolicy.webDomainPins.isEmpty {
            proxyBlock += """
              - name: "\(webDirectProxyName)"
                type: direct
                interface-name: "\(yamlScalar(directPolicy.physicalInterface))"
                ip-version: ipv4-only

            """
        }

        var choices = (transport == nil ? [] : [homeNodeName]) + nodes.map(\.name)
        if let index = choices.firstIndex(of: selected) {
            choices.remove(at: index)
            choices.insert(selected, at: 0)
        }
        let choiceLines = choices.map { "      - \"\(yamlScalar($0))\"" }
            .joined(separator: "\n")

        var yaml = """
        # Tono owned runtime — imported YAML is parsed, validated, and re-serialized
        port: 0
        socks-port: 0
        redir-port: 0
        mixed-port: \(overlay.mixedPort)
        external-controller: '\(overlay.externalController)'
        secret: "\(yamlScalar(overlay.secret))"
        allow-lan: false
        ipv6: false
        mode: rule
        log-level: \(overlay.logLevel)
        unified-delay: true
        find-process-mode: strict
        profile:
          # Runtime config order is the committed selection. Never let a stale
          # cache.db choice override it after a protected config reload.
          store-selected: false

        """
        if let directPolicy,
           !directPolicy.domainPins.isEmpty
            || !directPolicy.webDomainPins.isEmpty {
            yaml += "hosts:\n"
            for pin in (directPolicy.domainPins + directPolicy.webDomainPins)
                .sorted(by: { $0.host < $1.host }) {
                yaml += "  \"\(yamlScalar(pin.host))\":\n"
                for address in pin.addresses {
                    yaml += "    - \"\(address)\"\n"
                }
            }
            yaml += "\n"
        }
        yaml += tonoDNS + "\n"
        if let directPolicy, !directPolicy.directResolverHosts.isEmpty {
            // Managed-direct hostnames resolve via China DoH through the
            // interface-bound direct outbound so /dns/query returns
            // region-correct answers for pinning. Client-facing answers for
            // already-pinned hosts still come from hosts: (use-hosts wins).
            let upstreams = managedDirectResolverURLs
                .map { "\"\($0)#\(directProxyName)\"" }
                .joined(separator: ", ")
            yaml += "  nameserver-policy:\n"
            for host in directPolicy.directResolverHosts.sorted() {
                yaml += "    \"\(yamlScalar(host))\": [\(upstreams)]\n"
            }
        }
        if let directPolicy,
           !directPolicy.domainPins.isEmpty
            || !directPolicy.webDomainPins.isEmpty {
            // WeChat's HTTPDNS hands its helpers raw CDN IPs; without a Host
            // those flows can never match the pinned DOMAIN rules and fall to
            // the exit. Sniff TLS on 443 and override the destination ONLY
            // for the reviewed pinned hosts (force-domain with global
            // override off), which re-routes exactly those dials through the
            // hosts:/PF-bounded pins while every other flow keeps its
            // original metadata and routing.
            yaml += "\nsniffer:\n"
            yaml += "  enable: true\n"
            yaml += "  parse-pure-ip: true\n"
            yaml += "  override-destination: false\n"
            yaml += "  sniff:\n"
            yaml += "    TLS:\n"
            yaml += "      ports: [443]\n"
            yaml += "  force-domain:\n"
            for pin in (directPolicy.domainPins + directPolicy.webDomainPins)
                .sorted(by: { $0.host < $1.host }) {
                yaml += "    - \"\(yamlScalar(pin.host))\"\n"
            }
        }
        if overlay.tunEnabled {
            // Keep the route fingerprint independent of the selected proxy.
            // A selector-only switch can then preserve gVisor/TUN state while
            // PF remains the authoritative, exact endpoint boundary.
            let routeExclusions = Array(Set(nodes.map(\.server))).sorted()
            yaml += "\n" + tunYAML(routeExclusions: routeExclusions) + "\n"
        }
        yaml += "\n" + proxyBlock + "\n"
        yaml += """
        proxy-groups:
          - name: "\(exitGroupName)"
            type: select
            proxies:
        \(choiceLines)

        """
        // Each exact WeChat host/port gets an independent DIRECT → protected
        // exit decision. REJECT is deliberately first: Mihomo fallback groups
        // choose their first member before the initial health result and when
        // every member is down. The sentinel turns both windows into a fast,
        // fail-closed error; after the immediate check it is unhealthy, so a
        // reachable China DIRECT path wins and Tono-Exit is the safe fallback.
        let directFallbackTargets = managedDirectFallbackTargets(for: directPolicy)
        precondition(
            Set(directFallbackTargets.map(\.groupName)).count
                == directFallbackTargets.count,
            "managed direct fallback group collision"
        )
        let directFallbackGroups = Dictionary(uniqueKeysWithValues:
            directFallbackTargets.map {
                ("\($0.host):\($0.port)", $0.groupName)
            }
        )
        for target in directFallbackTargets {
            yaml += """
              - name: "\(target.groupName)"
                type: fallback
                proxies:
                  - REJECT
                  - "\(directProxyName)"
                  - "\(exitGroupName)"
                url: "\(yamlScalar(target.testURL))"
                interval: \(managedDirectHealthIntervalSeconds)
                timeout: \(managedDirectHealthTimeoutMilliseconds)
                lazy: false
                hidden: true

            """
        }
        yaml += "\nrules:\n"
        // Claude App/Code are permanently protected before every trial
        // exception. The native WeChat rules below additionally require an
        // executable inside the reviewed /Applications/WeChat.app bundle; the
        // separate web rules remain bounded to an exact reviewed hostname and
        // TCP/443. Neither rule family carries an IP-CIDR sub-rule: under
        // fake-ip DNS Mihomo strips DstIP whenever Host is known (and vice
        // versa for IP-literal dials), so DOMAIN+IP-CIDR can never match
        // together. The pinned addresses still bound egress via the hosts:
        // entries (use-hosts resolves the direct dial to exactly those IPs)
        // and the PF session allowlist.
        yaml += "  - PROCESS-NAME,Claude,\(exitGroupName)\n"
        yaml += "  - PROCESS-NAME,claude,\(exitGroupName)\n"
        // The npm-distributed Claude Code launcher is observed as claude.exe
        // even on macOS. Mihomo matches the complete basename and does not
        // strip that suffix, so keep it explicit before every direct rule.
        yaml += "  - PROCESS-NAME,claude.exe,\(exitGroupName)\n"
        if transport != nil {
            yaml += "  - PROCESS-NAME,tailscaled,DIRECT\n"
            yaml += "  - PROCESS-NAME,tailscale,DIRECT\n"
        }
        if let directPolicy {
            for processPathRegex in managedDirectProcessPathRegexes {
                for pin in directPolicy.domainPins {
                    for port in pin.ports {
                        guard let groupName = directFallbackGroups[
                            "\(pin.host):\(port)"
                        ] else {
                            preconditionFailure(
                                "managed direct fallback target missing"
                            )
                        }
                        yaml += "  - AND,((NETWORK,TCP),(DST-PORT,\(port)),(DOMAIN,\(pin.host)),(PROCESS-PATH-REGEX,\(processPathRegex))),\(groupName)\n"
                    }
                }
                // UDP media dials are raw-IP (no DNS step), so DstIP survives
                // fake-ip preprocessing and the exact endpoint pin stays valid.
                for endpoint in directPolicy.mediaEndpoints {
                    yaml += "  - AND,((NETWORK,UDP),(DST-PORT,\(endpoint.port)),(IP-CIDR,\(endpoint.address)/32,no-resolve),(PROCESS-PATH-REGEX,\(processPathRegex))),\(directProxyName)\n"
                }
            }
            // Browser video acceleration is intentionally narrower than a
            // China/GEOIP bypass: an exact cloud-reviewed host, TCP/443, and
            // no suffix or process fallback. The pinned IPv4 answers still
            // constrain the dial through hosts: and the PF session allowlist.
            // Claude's own process-name rules above still win first.
            for pin in directPolicy.webDomainPins {
                for port in pin.ports {
                    yaml += "  - AND,((NETWORK,TCP),(DST-PORT,\(port)),(DOMAIN,\(pin.host))),\(webDirectProxyName)\n"
                }
            }
        }
        yaml += """
          - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
          - IP-CIDR6,::1/128,DIRECT,no-resolve
          - MATCH,\(exitGroupName)
        """
        return yaml
    }

    static func dialEndpoints(for node: ProxyNode?) throws -> [DialEndpoint] {
        guard let node else { return [] }
        let validated = try validatedOwnedNode(node)
        return [
            .init(host: validated.server, port: UInt16(validated.port), transport: "tcp"),
        ]
    }

    static func validatedOwnedNodes(_ nodes: [ProxyNode]) throws -> [ProxyNode] {
        guard nodes.count <= 200 else {
            throw TonoInjectionError.unsafeNode("node list")
        }
        var names = Set([
            homeNodeName,
            exitGroupName,
            directProxyName,
            webDirectProxyName,
            "__tono_tailnet",
            // Mihomo installs these adapters before parsing user proxies. A
            // catalog collision would invalidate the entire owned runtime and
            // can also corrupt the managed WeChat fallback member references.
            "DIRECT",
            "REJECT",
            "REJECT-DROP",
            "COMPATIBLE",
            "PASS",
            "PASS-RULE",
        ])
        var result: [ProxyNode] = []
        for node in nodes {
            let validated = try validatedOwnedNode(node)
            guard !validated.name.hasPrefix(managedDirectFallbackGroupPrefix) else {
                throw TonoInjectionError.duplicateNode(validated.name)
            }
            guard names.insert(validated.name).inserted else {
                throw TonoInjectionError.duplicateNode(validated.name)
            }
            result.append(validated)
        }
        return result
    }

    static func validatedOwnedNode(_ node: ProxyNode) throws -> ProxyNode {
        var value = node
        // Protected multi-exit mode deliberately starts with one audited
        // contract: VLESS over authenticated TLS/Reality and a TCP carrier.
        // Other protocols must not silently widen the root PF allowlist.
        guard node.type == .vless, node.tls == true,
              node.uuid?.isEmpty == false else {
            throw TonoInjectionError.unsafeNode(node.name)
        }
        value.name = try safeScalar(node.name, maximum: 128, field: node.name)
        value.server = try normalizedServerAddress(node.server, field: node.name)
        guard (1...65_535).contains(node.port), node.skipCertVerify != true else {
            throw TonoInjectionError.unsafeNode(node.name)
        }
        value.password = try optionalScalar(node.password, maximum: 1_024, field: node.name)
        value.username = try optionalScalar(node.username, maximum: 256, field: node.name)
        value.uuid = try optionalScalar(node.uuid, maximum: 128, field: node.name)
        value.cipher = try optionalScalar(node.cipher, maximum: 128, field: node.name)
        value.sni = try optionalHost(node.sni, field: node.name)
        value.wsHost = try optionalHost(node.wsHost, field: node.name)
        value.wsPath = try optionalScalar(node.wsPath, maximum: 2_048, field: node.name)
        value.grpcServiceName = try optionalScalar(node.grpcServiceName, maximum: 256, field: node.name)
        value.flow = try optionalScalar(node.flow, maximum: 128, field: node.name)
        value.clientFingerprint = try optionalScalar(node.clientFingerprint, maximum: 64, field: node.name)
        value.realityPublicKey = try optionalScalar(node.realityPublicKey, maximum: 256, field: node.name)
        value.realityShortId = try optionalScalar(node.realityShortId, maximum: 64, field: node.name)
        if let network = node.network?.lowercased(), network != "tcp" {
            throw TonoInjectionError.unsafeNode(node.name)
        }
        value.network = node.network?.lowercased()
        guard let uuid = value.uuid, UUID(uuidString: uuid) != nil else {
            throw TonoInjectionError.unsafeNode(node.name)
        }
        // Production is deliberately Reality-only. Plain VLESS-over-TLS must
        // not silently widen the catalog contract or reach Mihomo as a route
        // that has never been covered by the endpoint/fail-closed tests.
        guard let publicKey = value.realityPublicKey,
              publicKey.utf8.count == 43,
              publicKey.unicodeScalars.allSatisfy({
                  $0.isASCII
                      && ($0.properties.isAlphabetic
                          || CharacterSet.decimalDigits.contains($0)
                          || $0 == "-"
                          || $0 == "_")
              }),
              value.sni != nil,
              let shortID = value.realityShortId,
              !shortID.isEmpty,
              shortID.utf8.count <= 16,
              shortID.utf8.count.isMultiple(of: 2),
              shortID.unicodeScalars.allSatisfy({
                  CharacterSet(charactersIn: "0123456789abcdefABCDEF")
                      .contains($0)
              })
        else {
            throw TonoInjectionError.unsafeNode(node.name)
        }
        if let flow = value.flow, flow != "xtls-rprx-vision" {
            throw TonoInjectionError.unsafeNode(node.name)
        }
        return value
    }

    private static func ownedNodeYAML(_ node: ProxyNode) throws -> String {
        let value = try validatedOwnedNode(node)
        var yaml = """
          - name: "\(yamlScalar(value.name))"
            type: \(value.type.rawValue)
            server: "\(yamlScalar(value.server))"
            port: \(value.port)
            udp: \(value.udp)

        """
        func append(_ key: String, _ scalar: String?) {
            guard let scalar, !scalar.isEmpty else { return }
            yaml += "    \(key): \"\(yamlScalar(scalar))\"\n"
        }
        append("username", value.username)
        append("password", value.password)
        append("uuid", value.uuid)
        append("cipher", value.cipher)
        // Mihomo's VLESS schema uses `servername`. Emitting the generic
        // `sni` alias is accepted syntactically but ignored by Reality, which
        // makes the server reject the handshake with `tls: internal error`.
        append("servername", value.sni)
        append("flow", value.flow)
        append("client-fingerprint", value.clientFingerprint)
        if let alterId = value.alterId {
            guard (0...65_535).contains(alterId) else {
                throw TonoInjectionError.unsafeNode(value.name)
            }
            yaml += "    alterId: \(alterId)\n"
        }
        if value.tls == true { yaml += "    tls: true\n" }
        if let network = value.network {
            yaml += "    network: \(network)\n"
            if network == "ws" {
                yaml += "    ws-opts:\n"
                appendIndented("path", value.wsPath, into: &yaml, spaces: 6)
                if let host = value.wsHost {
                    yaml += "      headers:\n"
                    appendIndented("Host", host, into: &yaml, spaces: 8)
                }
            } else if network == "grpc" {
                yaml += "    grpc-opts:\n"
                appendIndented("grpc-service-name", value.grpcServiceName, into: &yaml, spaces: 6)
            }
        }
        if let publicKey = value.realityPublicKey, let shortId = value.realityShortId {
            yaml += "    reality-opts:\n"
            appendIndented("public-key", publicKey, into: &yaml, spaces: 6)
            appendIndented("short-id", shortId, into: &yaml, spaces: 6)
        }
        return yaml
    }

    private static func appendIndented(
        _ key: String,
        _ value: String?,
        into yaml: inout String,
        spaces: Int
    ) {
        guard let value, !value.isEmpty else { return }
        yaml += String(repeating: " ", count: spaces) +
            "\(key): \"\(yamlScalar(value))\"\n"
    }

    private static func safeScalar(
        _ raw: String,
        maximum: Int,
        field: String
    ) throws -> String {
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty, value.utf8.count <= maximum,
              !value.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7F }) else {
            throw TonoInjectionError.unsafeNode(field)
        }
        return value
    }

    private static func optionalScalar(
        _ raw: String?,
        maximum: Int,
        field: String
    ) throws -> String? {
        guard let raw else { return nil }
        return try safeScalar(raw, maximum: maximum, field: field)
    }

    private static func optionalHost(_ raw: String?, field: String) throws -> String? {
        guard let raw else { return nil }
        return try normalizedHost(raw, field: field)
    }

    private static func normalizedServerAddress(_ raw: String, field: String) throws -> String {
        let value = try normalizedHost(raw, field: field)
        var ipv4 = in_addr()
        guard inet_pton(AF_INET, value, &ipv4) == 1,
              isPublicIPv4(ipv4) else {
            // Hostname bootstrap would require a separate authenticated DoH
            // contract. Protected multi-exit mode accepts public IP literals
            // only, rejects private/reserved ranges before import, and
            // currently limits proxy egress to IPv4. SNI/Reality server names
            // remain supported separately.
            throw TonoInjectionError.unsafeNode(field)
        }
        return value
    }

    static func validatedPublicIPv4(_ raw: String, field: String) throws -> String {
        try normalizedServerAddress(raw, field: field)
    }

    static func validatedManagedDirectDomain(_ raw: String) throws -> String {
        let host = try normalizedHost(raw, field: "managed direct domain")
        let allowedSuffixes = [
            "qq.com", "qq.com.cn", "qpic.cn", "qlogo.cn", "gtimg.cn",
            "gtimg.com", "wechat.com", "weixin.com", "weixinbridge.com",
            "wxs.qq.com",
        ]
        guard allowedSuffixes.contains(where: {
            host == $0 || host.hasSuffix(".\($0)")
        }) else {
            throw TonoInjectionError.unsafeNode("managed direct domain")
        }
        return host
    }

    static func validatedWebDirectDomain(_ raw: String) throws -> String {
        let host = try normalizedHost(raw, field: "managed web direct domain")
        let allowedSuffixes = [
            "bilibili.com", "biliapi.net", "bilivideo.com", "hdslb.com",
            "qq.com", "gtimg.cn", "gtimg.com", "iqiyi.com", "qiyi.com",
            "qiyipic.com", "iqiyipic.com", "youku.com", "ykimg.com",
        ]
        let allowedExactHosts = ["ykimg.alicdn.com"]
        guard allowedExactHosts.contains(host) || allowedSuffixes.contains(where: {
            host == $0 || host.hasSuffix(".\($0)")
        }) else {
            throw TonoInjectionError.unsafeNode("managed web direct domain")
        }
        return host
    }

    static func validatedManagedDirectPolicy(
        _ policy: ManagedDirectRuntimePolicy?,
        excluding protectedAddresses: Set<String> = []
    ) throws -> ManagedDirectRuntimePolicy? {
        guard let policy else { return nil }
        let interface = policy.physicalInterface
        guard interface.range(
            of: #"^[a-z][a-z0-9]{0,14}$"#,
            options: .regularExpression
        ) == interface.startIndex..<interface.endIndex,
              interface != "lo0", !interface.hasPrefix("utun") else {
            throw TonoInjectionError.unsafeOverlay
        }
        if policy.isEmpty { return policy }
        let permanentlyProtected = protectedAddresses.union(["1.1.1.1", "8.8.8.8"])
        guard policy.domainPins.count <= 32,
              policy.webDomainPins.count <= 16,
              policy.mediaEndpoints.count <= 128,
              policy.sessionEndpoints.count <= 256,
              policy.directResolverHosts.count <= 48 else {
            throw TonoInjectionError.unsafeOverlay
        }
        // Resolver hosts feed nameserver-policy emission; each must be a
        // cloud-reviewed managed or web direct hostname, unique after
        // normalization.
        let resolverHosts = try policy.directResolverHosts.map { raw -> String in
            if let host = try? validatedManagedDirectDomain(raw) { return host }
            return try validatedWebDirectDomain(raw)
        }
        guard Set(resolverHosts).count == resolverHosts.count else {
            throw TonoInjectionError.unsafeOverlay
        }

        var seenHosts = Set<String>()
        let pins = try policy.domainPins.map { pin in
            let host = try validatedManagedDirectDomain(pin.host)
            guard seenHosts.insert(host).inserted,
                  !pin.addresses.isEmpty, pin.addresses.count <= 8,
                  !pin.ports.isEmpty,
                  Set(pin.ports).count == pin.ports.count,
                  pin.ports.allSatisfy({ $0 == 80 || $0 == 443 }) else {
                throw TonoInjectionError.unsafeNode("managed direct domain")
            }
            let addresses = try pin.addresses.map {
                try validatedPublicIPv4($0, field: "managed direct address")
            }
            guard Set(addresses).count == addresses.count,
                  addresses.allSatisfy({ !permanentlyProtected.contains($0) }) else {
                throw TonoInjectionError.unsafeNode("managed direct address")
            }
            return DirectDomainPin(
                host: host,
                addresses: addresses.sorted(),
                ports: pin.ports.sorted()
            )
        }.sorted { $0.host < $1.host }

        let webPins = try policy.webDomainPins.map { pin in
            let host = try validatedWebDirectDomain(pin.host)
            guard seenHosts.insert(host).inserted,
                  !pin.addresses.isEmpty, pin.addresses.count <= 8,
                  pin.ports == [443] else {
                throw TonoInjectionError.unsafeNode("managed web direct domain")
            }
            let addresses = try pin.addresses.map {
                try validatedPublicIPv4($0, field: "managed web direct address")
            }
            guard Set(addresses).count == addresses.count,
                  addresses.allSatisfy({ !permanentlyProtected.contains($0) }) else {
                throw TonoInjectionError.unsafeNode("managed web direct address")
            }
            return DirectDomainPin(
                host: host,
                addresses: addresses.sorted(),
                ports: [443]
            )
        }.sorted { $0.host < $1.host }

        let media = try policy.mediaEndpoints.map { endpoint in
            let address = try validatedPublicIPv4(
                endpoint.address,
                field: "managed media address"
            )
            guard !permanentlyProtected.contains(address),
                  endpoint.transport == "udp",
                  endpoint.port == 443 || endpoint.port == 8000 else {
                throw TonoInjectionError.unsafeNode("managed media endpoint")
            }
            return DirectEndpoint(
                address: address,
                port: endpoint.port,
                transport: "udp"
            )
        }
        let uniqueMedia = Array(Set(media)).sorted {
            ($0.port, $0.address) < ($1.port, $1.address)
        }
        return ManagedDirectRuntimePolicy(
            physicalInterface: interface,
            domainPins: pins,
            webDomainPins: webPins,
            mediaEndpoints: uniqueMedia,
            directResolverHosts: resolverHosts.sorted()
        )
    }

    private static func isPublicIPv4(_ address: in_addr) -> Bool {
        let bytes = withUnsafeBytes(of: address) { Array($0) }
        guard bytes.count == 4 else { return false }
        return bytes[0] != 0 &&
            bytes[0] != 10 &&
            bytes[0] != 127 &&
            !(bytes[0] == 100 && (64...127).contains(bytes[1])) &&
            !(bytes[0] == 169 && bytes[1] == 254) &&
            !(bytes[0] == 172 && (16...31).contains(bytes[1])) &&
            !(bytes[0] == 192 && bytes[1] == 0 && bytes[2] == 0) &&
            !(bytes[0] == 192 && bytes[1] == 0 && bytes[2] == 2) &&
            !(bytes[0] == 192 && bytes[1] == 168) &&
            !(bytes[0] == 198 && (18...19).contains(bytes[1])) &&
            !(bytes[0] == 198 && bytes[1] == 51 && bytes[2] == 100) &&
            !(bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113) &&
            bytes[0] < 224
    }

    private static func normalizedHost(_ raw: String, field: String) throws -> String {
        let host = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
            .trimmingCharacters(in: CharacterSet(charactersIn: "."))
        guard !host.isEmpty, host.utf8.count <= 253, !host.contains("%"),
              host.unicodeScalars.allSatisfy({ $0.isASCII && $0.value > 0x20 && $0.value < 0x7F }) else {
            throw TonoInjectionError.unsafeNode(field)
        }
        var ipv4 = in_addr()
        var ipv6 = in6_addr()
        if inet_pton(AF_INET, host, &ipv4) == 1 || inet_pton(AF_INET6, host, &ipv6) == 1 {
            return host
        }
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2, labels.allSatisfy({ label in
            guard !label.isEmpty, label.utf8.count <= 63,
                  label.first != "-", label.last != "-" else { return false }
            return label.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }
        }) else {
            throw TonoInjectionError.unsafeNode(field)
        }
        return host
    }

    /// Extract the `proxies:` sequence body only (list items under proxies).
    static func extractProxiesSection(from lines: [String]) -> String {
        guard let start = lines.firstIndex(where: {
            !$0.hasPrefix(" ") && !$0.hasPrefix("\t") &&
            ($0 == "proxies:" || $0.hasPrefix("proxies:"))
        }) else { return "" }
        var end = start + 1
        while end < lines.count {
            let line = lines[end]
            if !line.isEmpty && !line.hasPrefix(" ") && !line.hasPrefix("\t") && !line.hasPrefix("#") {
                break
            }
            end += 1
        }
        return lines[(start + 1)..<end].joined(separator: "\n")
    }

    /// Pure line transformation retained for unit tests of non-Tono inject paths.
    static func injectTono(_ descriptor: TonoTransportDescriptor, into lines: inout [String], tunEnabled: Bool) throws {
        let owned = try buildOwnedTonoRuntime(
            subscriptionYAML: lines.joined(separator: "\n"),
            overlay: OverlayConfig(tunEnabled: tunEnabled, tonoTransport: descriptor),
            transport: descriptor,
            customNodes: []
        )
        lines = owned.components(separatedBy: .newlines)
    }

    private static func yamlScalar(_ value: String) -> String {
        value.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n").replacingOccurrences(of: "\r", with: "\\r")
    }

    private static func secureWrite(_ value: String, to outputPath: URL) throws -> String {
        let data = Data(value.utf8)
        try data.write(to: outputPath, options: .atomic)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: outputPath.path
        )
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
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
        if let sni = node.sni, !sni.isEmpty {
            let key = node.type == .vless ? "servername" : "sni"
            y += "    \(key): \(sni)\n"
        }
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
