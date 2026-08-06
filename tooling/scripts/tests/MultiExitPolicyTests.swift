import Foundation

// ConfigPipeline only needs this value contract; the product definition lives
// in TonoSidecarService.swift.
nonisolated struct TonoTransportDescriptor: Sendable, Equatable {
    let host: String
    let port: UInt16
    let username: String?
    let password: String?
    let udp: Bool

    init(
        host: String = "127.0.0.1",
        port: UInt16,
        username: String? = nil,
        password: String? = nil,
        udp: Bool = true
    ) {
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.udp = udp
    }
}

@main
struct MultiExitPolicyTests {
    static func main() throws {
        guard CommandLine.arguments.count >= 3 else {
            throw TestFailure("expected one or more YAML fixtures and a sanitized runtime path")
        }
        var nodes: [ProxyNode] = []
        for path in CommandLine.arguments.dropFirst().dropLast() {
            let url = URL(fileURLWithPath: path)
            let values = try url.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
            guard values.isRegularFile == true,
                  let size = values.fileSize,
                  size > 0, size <= 1_048_576 else {
                throw TestFailure("fixture must be a bounded regular file")
            }
            let content = try String(contentsOf: url, encoding: .utf8)
            let parsed = ConfigParser.parseSubscription(content)
            guard !parsed.isEmpty else { throw TestFailure("fixture has no supported nodes") }
            nodes.append(contentsOf: parsed)
        }
        let validated = try ConfigPipeline.validatedOwnedNodes(nodes)
        guard validated.count == nodes.count else {
            throw TestFailure("node validation count changed")
        }

        var japanNamed = validated[0]
        japanNamed.id = "jp-default-order-test"
        japanNamed.flag = "🇯🇵"
        japanNamed.name = "JP-VLESS-Reality"
        var usNamed = validated[0]
        usNamed.id = "us-default-order-test"
        usNamed.flag = "🇺🇸"
        usNamed.name = "US-VLESS-Reality"
        let intentionallyJapanFirst = [japanNamed, usNamed]
        guard ConfigPipeline.preferredCloudExit(
            in: intentionallyJapanFirst,
            named: "US Reality"
        )?.id == usNamed.id,
        ConfigPipeline.orderedCloudExits(
            intentionallyJapanFirst,
            preferredName: "US Reality"
        ).first?.id == usNamed.id,
        ConfigPipeline.preferredCloudExit(
            in: intentionallyJapanFirst,
            named: "JP Reality"
        )?.id == japanNamed.id else {
            throw TestFailure("regional Reality exit was not selected deterministically")
        }
        for node in validated {
            guard node.realityPublicKey?.isEmpty == false,
                  node.realityShortId?.isEmpty == false else {
                throw TestFailure("\(node.name) lost its Reality credentials")
            }
            let endpoints = try ConfigPipeline.dialEndpoints(for: node)
            guard endpoints == [
                .init(host: node.server.lowercased(), port: UInt16(node.port), transport: "tcp"),
            ] else {
                throw TestFailure("\(node.name) does not have an exact TCP endpoint contract")
            }
        }
        let inlineReality = """
        proxies:
          - {name: Inline-Reality, type: vless, server: 1.1.1.1, port: 443, uuid: 00000000-0000-4000-8000-000000000099, network: tcp, tls: true, servername: inline.example.com, reality-opts: {public-key: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC, short-id: 0011223344556677}}
        """
        guard let parsedInline = ConfigParser.parseSubscription(inlineReality).first,
              parsedInline.realityPublicKey?.isEmpty == false,
              parsedInline.realityShortId == "0011223344556677" else {
            throw TestFailure("inline Reality options were not preserved")
        }
        let selected = validated[0]
        let sanitizedNodes = validated.enumerated().map { index, original in
            var node = original
            // Mihomo config validation does not dial this address. Use a
            // syntactically public value because protected import deliberately
            // rejects RFC 5737/private ranges.
            node.server = "8.8.4.\(index + 4)"
            node.uuid = "00000000-0000-4000-8000-\(String(format: "%012d", index + 1))"
            node.password = node.password.map { _ in "test-only-password" }
            node.username = node.username.map { _ in "test-only-user" }
            node.realityPublicKey = node.realityPublicKey.map {
                _ in "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            }
            node.realityShortId = node.realityShortId.map { _ in "0123456789abcdef" }
            return node
        }
        let sanitizedNode = sanitizedNodes[0]
        let stableRouteAddresses = Array(Set(sanitizedNodes.map(\.server))).sorted()
        let stableRouteExclusionBlock =
            "\n  route-exclude-address:\n"
            + stableRouteAddresses.map { "    - \"\($0)/32\"\n" }.joined()
            + "\nproxies:"

        let overlay = ConfigPipeline.OverlayConfig(
            mixedPort: 31_234,
            externalController: "127.0.0.1:31235",
            secret: "test-only-controller-secret",
            mode: "global",
            logLevel: "info",
            allowLan: true,
            tunEnabled: true,
            selectedNodeName: sanitizedNode.name,
            tonoTransport: .init(port: 31_236)
        )
        let controllerParts = overlay.externalController.split(
            separator: ":",
            omittingEmptySubsequences: false
        )
        guard overlay.mixedPort > 0, overlay.mixedPort <= 65_535,
              controllerParts.count == 2, controllerParts[0] == "127.0.0.1",
              let controllerPort = Int(controllerParts[1]),
              controllerPort > 0, controllerPort <= 65_535,
              ["debug", "info", "warning", "error", "silent"].contains(overlay.logLevel) else {
            throw TestFailure(
                "test overlay mismatch: mixed=\(overlay.mixedPort), " +
                "controller=\(overlay.externalController), log=\(overlay.logLevel)"
            )
        }
        let runtime = try ConfigPipeline.buildOwnedTonoRuntime(
            // Cloud catalog nodes are supplied through the validated model
            // path; no source document contributes runtime policy.
            subscriptionYAML: "proxies: []\n",
            overlay: overlay,
            transport: overlay.tonoTransport!,
            customNodes: sanitizedNodes
        )
        let required = [
            ("owned-marker", "# Tono owned runtime"),
            ("lan-off", "\nallow-lan: false\n"),
            ("ipv6-off", "\nipv6: false\n"),
            ("rule-mode", "\nmode: rule\n"),
            ("unified-delay", "\nunified-delay: true\n"),
            ("demand-process-lookup", "\nfind-process-mode: strict\n"),
            ("disable-stale-selection-cache", "\n  store-selected: false\n"),
            ("disable-direct-icmp", "\n  disable-icmp-forwarding: true\n"),
            (
                "protected-loopback-dns",
                "\n  listen: \(ProtectedDNSContract.listener)\n"
            ),
            ("gvisor-tun-stack", "\n  stack: gvisor\n"),
            ("owned-tun", "\n  device: utun199\n"),
            (
                "stable-catalog-route-exclusions",
                stableRouteExclusionBlock
            ),
            ("final-route", "\n  - MATCH,Tono-Exit"),
            ("reality", "\n    reality-opts:\n"),
            ("reality-servername", "\n    servername: "),
            ("reality-key", "\n      public-key: "),
            ("reality-short-id", "\n      short-id: "),
        ]
        let missing = required.filter { !runtime.contains($0.1) }.map(\.0)
        guard missing.isEmpty else {
            throw TestFailure("owned runtime omitted: \(missing.joined(separator: ","))")
        }
        guard !runtime.contains("\nmode: global\n"),
              !runtime.contains("skip-cert-verify: true"),
              !runtime.contains("\n    sni:"),
              runtime.contains("\n      - \"\(escaped(selected.name))\"") else {
            throw TestFailure("owned runtime accepted an unsafe source policy")
        }
        for node in sanitizedNodes {
            guard let servername = node.sni,
                  runtime.contains(
                    "\n    servername: \"\(escaped(servername))\"\n"
                  ) else {
                throw TestFailure("\(node.name) lost its Reality servername")
            }
        }

        var cloudOnlyOverlay = overlay
        cloudOnlyOverlay.tonoTransport = nil
        let cloudRuntime = try ConfigPipeline.buildOwnedTonoRuntime(
            subscriptionYAML: "mode: global\nrules:\n  - MATCH,DIRECT\n",
            overlay: cloudOnlyOverlay,
            transport: nil,
            customNodes: sanitizedNodes
        )
        guard cloudRuntime.contains("# Tono owned runtime"),
              cloudRuntime.contains("\n  - MATCH,Tono-Exit"),
              cloudRuntime.contains("\n      - \"\(escaped(selected.name))\""),
              cloudRuntime.contains(stableRouteExclusionBlock),
              !cloudRuntime.contains(ConfigPipeline.homeNodeName),
              !cloudRuntime.contains("PROCESS-NAME,tailscale"),
              !cloudRuntime.contains("PROCESS-NAME,tono-core-helper"),
              !cloudRuntime.contains("\nmode: global\n"),
              !cloudRuntime.contains("MATCH,DIRECT") else {
            throw TestFailure("cloud-only fallback did not preserve the owned fail-closed runtime")
        }

        let managedDirectPolicy = ConfigPipeline.ManagedDirectRuntimePolicy(
            physicalInterface: "en0",
            domainPins: [
                .init(
                    host: "res.wx.qq.com",
                    addresses: ["43.146.27.19"],
                    ports: [80, 443]
                ),
            ],
            webDomainPins: [
                .init(
                    host: "www.bilibili.com",
                    addresses: ["120.92.78.97"],
                    ports: [443]
                ),
            ],
            mediaEndpoints: [
                .init(address: "43.146.27.17", port: 443, transport: "udp"),
                .init(address: "43.146.27.17", port: 8000, transport: "udp"),
            ]
        )
        let validatedDirectPolicy = try ConfigPipeline.validatedManagedDirectPolicy(
            managedDirectPolicy,
            excluding: Set(sanitizedNodes.map(\.server))
        )
        guard validatedDirectPolicy?.sessionEndpoints.count == 5 else {
            throw TestFailure("managed direct policy did not produce exact PF tuples")
        }
        let fallbackTargets = ConfigPipeline.managedDirectFallbackTargets(
            for: validatedDirectPolicy
        )
        guard fallbackTargets.count == 2,
              Set(fallbackTargets.map(\.groupName)).count == 2,
              let fallback80 = fallbackTargets.first(where: { $0.port == 80 }),
              let fallback443 = fallbackTargets.first(where: { $0.port == 443 }),
              fallback80.host == "res.wx.qq.com",
              fallback80.testURL == "http://res.wx.qq.com/",
              fallback443.host == "res.wx.qq.com",
              fallback443.testURL == "https://res.wx.qq.com/",
              fallbackTargets.allSatisfy({
                  $0.groupName.hasPrefix(
                      ConfigPipeline.managedDirectFallbackGroupPrefix
                  )
              }) else {
            throw TestFailure("managed DIRECT fallback targets were not exact")
        }
        let managedDirectRuntime = try ConfigPipeline.buildOwnedTonoRuntime(
            subscriptionYAML: "proxies: []\n",
            overlay: cloudOnlyOverlay,
            transport: nil,
            customNodes: sanitizedNodes,
            directPolicy: managedDirectPolicy
        )
        guard let weChatProcessPathRegex =
                ConfigPipeline.managedDirectProcessPathRegexes.first else {
            throw TestFailure("managed DIRECT omitted the standard WeChat bundle")
        }
        let directRule80 =
            "AND,((NETWORK,TCP),(DST-PORT,80),(DOMAIN,res.wx.qq.com),(PROCESS-PATH-REGEX,\(weChatProcessPathRegex))),\(fallback80.groupName)"
        let directRule443 =
            "AND,((NETWORK,TCP),(DST-PORT,443),(DOMAIN,res.wx.qq.com),(PROCESS-PATH-REGEX,\(weChatProcessPathRegex))),\(fallback443.groupName)"
        let webDirectRule =
            "AND,((NETWORK,TCP),(DST-PORT,443),(DOMAIN,www.bilibili.com)),Tono-China-Web-Direct"
        let mediaRule443 =
            "AND,((NETWORK,UDP),(DST-PORT,443),(IP-CIDR,43.146.27.17/32,no-resolve),(PROCESS-PATH-REGEX,\(weChatProcessPathRegex))),Tono-China-Direct"
        let mediaRule8000 =
            "AND,((NETWORK,UDP),(DST-PORT,8000),(IP-CIDR,43.146.27.17/32,no-resolve),(PROCESS-PATH-REGEX,\(weChatProcessPathRegex))),Tono-China-Direct"
        let directRulePrecedesMatch: Bool
        if let directRuleRange = managedDirectRuntime.range(of: directRule443),
           let matchRuleRange = managedDirectRuntime.range(of: "  - MATCH,Tono-Exit") {
            directRulePrecedesMatch = directRuleRange.lowerBound < matchRuleRange.lowerBound
        } else {
            directRulePrecedesMatch = false
        }
        let claudeRules = [
            "PROCESS-NAME,Claude,Tono-Exit",
            "PROCESS-NAME,claude,Tono-Exit",
            "PROCESS-NAME,claude.exe,Tono-Exit",
        ]
        let claudeRulesPrecedeDirect = claudeRules.allSatisfy { rule in
            guard let claudeRange = managedDirectRuntime.range(of: rule),
                  let directRange = managedDirectRuntime.range(of: directRule443) else {
                return false
            }
            return claudeRange.lowerBound < directRange.lowerBound
        }
        let fallbackGroupCount = managedDirectRuntime
            .components(separatedBy: "\n    type: fallback\n")
            .count - 1
        let fallback443Block = """
          - name: "\(fallback443.groupName)"
            type: fallback
            proxies:
              - REJECT
              - "Tono-China-Direct"
              - "Tono-Exit"
            url: "https://res.wx.qq.com/"
            interval: 60
            timeout: 3500
            lazy: false
            hidden: true
        """
        let managedDirectChecks = [
            ("proxy", managedDirectRuntime.contains("\n  - name: \"Tono-China-Direct\"\n")),
            ("web-proxy", managedDirectRuntime.contains("\n  - name: \"Tono-China-Web-Direct\"\n")),
            ("type", managedDirectRuntime.contains("\n    type: direct\n")),
            ("interface", managedDirectRuntime.contains("\n    interface-name: \"en0\"\n")),
            (
                "host-pin",
                managedDirectRuntime.contains(
                    "\n  \"res.wx.qq.com\":\n    - \"43.146.27.19\"\n"
                )
            ),
            (
                "web-host-pin",
                managedDirectRuntime.contains(
                    "\n  \"www.bilibili.com\":\n    - \"120.92.78.97\"\n"
                )
            ),
            ("tcp-80-fallback-rule", managedDirectRuntime.contains(directRule80)),
            ("tcp-443-fallback-rule", managedDirectRuntime.contains(directRule443)),
            ("web-tcp-rule", managedDirectRuntime.contains(webDirectRule)),
            ("udp-443-rule", managedDirectRuntime.contains(mediaRule443)),
            ("udp-8000-rule", managedDirectRuntime.contains(mediaRule8000)),
            ("rule-order", directRulePrecedesMatch),
            ("claude-process-rules", claudeRulesPrecedeDirect),
            ("one-fallback-per-wechat-port", fallbackGroupCount == fallbackTargets.count),
            ("fail-closed-fallback-order", managedDirectRuntime.contains(fallback443Block)),
            (
                "no-web-fallback-group",
                !fallbackTargets.contains { $0.host == "www.bilibili.com" }
            ),
            (
                "no-unchecked-wechat-direct-tcp",
                !managedDirectRuntime.contains(
                    "DOMAIN,res.wx.qq.com),(PROCESS-PATH-REGEX,\(weChatProcessPathRegex))),Tono-China-Direct"
                )
            ),
            (
                "no-impossible-tcp-domain-cidr-and",
                !managedDirectRuntime.contains(
                    "DOMAIN,res.wx.qq.com),(IP-CIDR,43.146.27.19/32"
                )
            ),
            ("no-name-only-identity", !managedDirectRuntime.contains("PROCESS-NAME,WeChat")),
            ("no-domain-suffix", !managedDirectRuntime.contains("DOMAIN-SUFFIX")),
            ("no-domain-keyword", !managedDirectRuntime.contains("DOMAIN-KEYWORD")),
            ("no-wide-cidr", !managedDirectRuntime.contains("43.146.27.0/24")),
            ("no-direct-fallback", !managedDirectRuntime.contains("MATCH,DIRECT")),
        ]
        let failedManagedDirectChecks = managedDirectChecks
            .filter { !$0.1 }
            .map(\.0)
        guard failedManagedDirectChecks.isEmpty else {
            throw TestFailure(
                "managed DIRECT runtime failed: "
                    + failedManagedDirectChecks.joined(separator: ",")
            )
        }

        do {
            _ = try ConfigPipeline.validatedManagedDirectPolicy(
                .init(
                    physicalInterface: "utun199",
                    domainPins: managedDirectPolicy.domainPins,
                    mediaEndpoints: managedDirectPolicy.mediaEndpoints
                )
            )
            throw TestFailure("managed DIRECT accepted a tunnel interface")
        } catch is ConfigPipeline.TonoInjectionError {
            // Expected.
        }
        do {
            _ = try ConfigPipeline.validatedManagedDirectPolicy(
                .init(
                    physicalInterface: "en0",
                    domainPins: [
                        .init(host: "res.wx.qq.com", addresses: ["1.1.1.1"], ports: [443]),
                    ],
                    mediaEndpoints: []
                )
            )
            throw TestFailure("managed DIRECT accepted a permanently protected address")
        } catch is ConfigPipeline.TonoInjectionError {
            // Expected.
        }
        do {
            _ = try ConfigPipeline.validatedManagedDirectDomain("*.qq.com")
            throw TestFailure("managed DIRECT accepted a wildcard domain")
        } catch is ConfigPipeline.TonoInjectionError {
            // Expected.
        }
        do {
            _ = try ConfigPipeline.validatedWebDirectDomain("api.anthropic.com")
            throw TestFailure("web DIRECT accepted a protected domain")
        } catch is ConfigPipeline.TonoInjectionError {
            // Expected.
        }
        do {
            _ = try ConfigPipeline.validatedManagedDirectPolicy(
                .init(
                    physicalInterface: "en0",
                    domainPins: [
                        .init(host: "v.qq.com", addresses: ["9.9.9.9"], ports: [443]),
                    ],
                    webDomainPins: [
                        .init(host: "v.qq.com", addresses: ["9.9.9.9"], ports: [443]),
                    ],
                    mediaEndpoints: []
                )
            )
            throw TestFailure("web DIRECT accepted a duplicate WeChat domain")
        } catch is ConfigPipeline.TonoInjectionError {
            // Expected.
        }
        do {
            _ = try ConfigPipeline.validatedManagedDirectPolicy(
                .init(
                    physicalInterface: "en0",
                    domainPins: [],
                    mediaEndpoints: [
                        .init(address: "43.146.27.17", port: 443, transport: "tcp"),
                    ]
                )
            )
            throw TestFailure("managed media DIRECT accepted TCP")
        } catch is ConfigPipeline.TonoInjectionError {
            // Expected.
        }
        for builtInName in ["DIRECT", "REJECT"] {
            var reservedBuiltInNode = selected
            reservedBuiltInNode.name = builtInName
            do {
                _ = try ConfigPipeline.validatedOwnedNodes([reservedBuiltInNode])
                throw TestFailure(
                    "Mihomo built-in name \(builtInName) was not reserved"
                )
            } catch is ConfigPipeline.TonoInjectionError {
                // Expected.
            }
        }
        var reservedFallbackNode = selected
        reservedFallbackNode.name =
            ConfigPipeline.managedDirectFallbackGroupPrefix + "0123456789abcdef"
        do {
            _ = try ConfigPipeline.validatedOwnedNodes([reservedFallbackNode])
            throw TestFailure("managed DIRECT fallback group prefix was not reserved")
        } catch is ConfigPipeline.TonoInjectionError {
            // Expected.
        }

        let generatedCloudURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("tono-cloud-only-\(UUID().uuidString).yaml")
        defer { try? FileManager.default.removeItem(at: generatedCloudURL) }
        let generatedCloudDigest = try ConfigPipeline.generateRuntime(
            subscriptionYAML: "mode: global\nrules:\n  - MATCH,DIRECT\n",
            overlay: cloudOnlyOverlay,
            customNodes: sanitizedNodes,
            outputPath: generatedCloudURL
        )
        let generatedCloud = try String(contentsOf: generatedCloudURL, encoding: .utf8)
        guard !generatedCloudDigest.isEmpty,
              generatedCloud == cloudRuntime else {
            throw TestFailure("nil home descriptor fell through to the legacy YAML path")
        }

        guard let runtimeDirectoryPath = CommandLine.arguments.last else {
            throw TestFailure("missing sanitized runtime directory")
        }
        let runtimeDirectory = URL(
            fileURLWithPath: runtimeDirectoryPath,
            isDirectory: true
        )
        let directoryValues = try runtimeDirectory.resourceValues(
            forKeys: [.isDirectoryKey, .isSymbolicLinkKey]
        )
        guard directoryValues.isDirectory == true,
              directoryValues.isSymbolicLink != true else {
            throw TestFailure("sanitized runtime destination must be a directory")
        }
        let managedDirectRuntimeURL = runtimeDirectory
            .appendingPathComponent("managed-direct.yaml", isDirectory: false)
        try Data(managedDirectRuntime.utf8).write(
            to: managedDirectRuntimeURL,
            options: .atomic
        )
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: managedDirectRuntimeURL.path
        )
        for (index, node) in sanitizedNodes.enumerated() {
            var selectedOverlay = cloudOnlyOverlay
            selectedOverlay.selectedNodeName = node.name
            let selectedRuntime = try ConfigPipeline.buildOwnedTonoRuntime(
                subscriptionYAML: "proxies: []\n",
                overlay: selectedOverlay,
                transport: nil,
                customNodes: sanitizedNodes
            )
            let groupMarker = """
            proxy-groups:
              - name: "\(ConfigPipeline.exitGroupName)"
                type: select
                proxies:
                  - "\(escaped(node.name))"
            """
            guard selectedRuntime.contains(groupMarker),
                  selectedRuntime.contains(stableRouteExclusionBlock),
                  !selectedRuntime.contains(ConfigPipeline.homeNodeName) else {
                throw TestFailure(
                    "\(node.name) selection changed the stable TUN route contract"
                )
            }
            let runtimeURL = runtimeDirectory
                .appendingPathComponent("\(index)-selected.yaml", isDirectory: false)
            try Data(selectedRuntime.utf8).write(to: runtimeURL, options: .atomic)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: runtimeURL.path
            )
        }

        var injected = selected
        injected.name = "safe\nrules:\n  - MATCH,DIRECT"
        do {
            _ = try ConfigPipeline.validatedOwnedNode(injected)
            throw TestFailure("newline node-name injection was accepted")
        } catch is ConfigPipeline.TonoInjectionError {
            // Expected.
        }

        var nonVLESS = selected
        nonVLESS.type = .hysteria2
        nonVLESS.password = "test-only-password"
        do {
            _ = try ConfigPipeline.validatedOwnedNode(nonVLESS)
            throw TestFailure("non-VLESS node was accepted")
        } catch is ConfigPipeline.TonoInjectionError {
            // Expected.
        }

        var plaintext = selected
        plaintext.tls = false
        do {
            _ = try ConfigPipeline.validatedOwnedNode(plaintext)
            throw TestFailure("plaintext VLESS node was accepted")
        } catch is ConfigPipeline.TonoInjectionError {
            // Expected.
        }

        var plainTLS = selected
        plainTLS.realityPublicKey = nil
        plainTLS.realityShortId = nil
        do {
            _ = try ConfigPipeline.validatedOwnedNode(plainTLS)
            throw TestFailure("plain VLESS TLS node was accepted as Reality")
        } catch is ConfigPipeline.TonoInjectionError {
            // Expected.
        }

        var invalidRealityKey = selected
        invalidRealityKey.realityPublicKey = "not-a-reality-public-key"
        do {
            _ = try ConfigPipeline.validatedOwnedNode(invalidRealityKey)
            throw TestFailure("invalid Reality public key was accepted")
        } catch is ConfigPipeline.TonoInjectionError {
            // Expected.
        }

        var invalidShortID = selected
        invalidShortID.realityShortId = "not-hex"
        do {
            _ = try ConfigPipeline.validatedOwnedNode(invalidShortID)
            throw TestFailure("invalid Reality short ID was accepted")
        } catch is ConfigPipeline.TonoInjectionError {
            // Expected.
        }

        var unsupportedTransport = selected
        unsupportedTransport.network = "ws"
        do {
            _ = try ConfigPipeline.validatedOwnedNode(unsupportedTransport)
            throw TestFailure("unaudited VLESS transport was accepted")
        } catch is ConfigPipeline.TonoInjectionError {
            // Expected.
        }

        var invalidUUID = selected
        invalidUUID.uuid = "not-a-uuid"
        do {
            _ = try ConfigPipeline.validatedOwnedNode(invalidUUID)
            throw TestFailure("invalid VLESS UUID was accepted")
        } catch is ConfigPipeline.TonoInjectionError {
            // Expected.
        }

        var privateEndpoint = selected
        privateEndpoint.server = "192.168.1.10"
        do {
            _ = try ConfigPipeline.validatedOwnedNode(privateEndpoint)
            throw TestFailure("private proxy endpoint was accepted")
        } catch is ConfigPipeline.TonoInjectionError {
            // Expected.
        }

        print(
            "multi-exit fixture validated and selected individually: " +
            "\(validated.map(\.name).joined(separator: ", "))"
        )
    }

    private static func escaped(_ value: String) -> String {
        value.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
    }
}

private struct TestFailure: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}
