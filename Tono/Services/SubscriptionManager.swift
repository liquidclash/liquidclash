import Foundation

#if TONO_UNSAFE_LEGACY_NETWORKING
#error("Tono product builds must not enable proxy-free legacy subscription networking")
#endif

// MARK: - Subscription Info

nonisolated struct SubscriptionInfo: Codable, Identifiable {
    var id: String = UUID().uuidString
    var url: String
    var name: String
    var lastUpdate: Date?
    var nodeCount: Int = 0
    var isEnabled: Bool = true

    // Traffic info from subscription-userinfo header
    var upload: Int64?
    var download: Int64?
    var total: Int64?
    var expire: TimeInterval?

    var usedBytes: Int64 { (upload ?? 0) + (download ?? 0) }
    var usageRatio: Double {
        guard let t = total, t > 0 else { return 0 }
        return Double(usedBytes) / Double(t)
    }
    var expiryDate: Date? {
        guard let e = expire, e > 0 else { return nil }
        return Date(timeIntervalSince1970: e)
    }

    // Custom decoder to handle missing fields from older JSON
    init(id: String = UUID().uuidString, url: String, name: String, lastUpdate: Date? = nil, nodeCount: Int = 0, isEnabled: Bool = true,
         upload: Int64? = nil, download: Int64? = nil, total: Int64? = nil, expire: TimeInterval? = nil) {
        self.id = id; self.url = url; self.name = name; self.lastUpdate = lastUpdate
        self.nodeCount = nodeCount; self.isEnabled = isEnabled
        self.upload = upload; self.download = download; self.total = total; self.expire = expire
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        url = try c.decode(String.self, forKey: .url)
        name = try c.decode(String.self, forKey: .name)
        lastUpdate = try c.decodeIfPresent(Date.self, forKey: .lastUpdate)
        nodeCount = try c.decodeIfPresent(Int.self, forKey: .nodeCount) ?? 0
        isEnabled = try c.decodeIfPresent(Bool.self, forKey: .isEnabled) ?? true
        upload = try c.decodeIfPresent(Int64.self, forKey: .upload)
        download = try c.decodeIfPresent(Int64.self, forKey: .download)
        total = try c.decodeIfPresent(Int64.self, forKey: .total)
        expire = try c.decodeIfPresent(TimeInterval.self, forKey: .expire)
    }
}

// MARK: - Subscription User Info (from HTTP header)

nonisolated struct SubscriptionUserInfo {
    var upload: Int64 = 0
    var download: Int64 = 0
    var total: Int64 = 0
    var expire: TimeInterval = 0

    /// Parse "upload=xxx; download=xxx; total=xxx; expire=xxx"
    static func parse(_ headerValue: String) -> SubscriptionUserInfo? {
        var info = SubscriptionUserInfo()
        var found = false
        for pair in headerValue.split(separator: ";") {
            let kv = pair.split(separator: "=", maxSplits: 1)
            guard kv.count == 2, let value = Int64(kv[1].trimmingCharacters(in: .whitespaces)) else { continue }
            found = true
            switch kv[0].trimmingCharacters(in: .whitespaces).lowercased() {
            case "upload": info.upload = value
            case "download": info.download = value
            case "total": info.total = value
            case "expire": info.expire = TimeInterval(value)
            default: break
            }
        }
        return found ? info : nil
    }
}

// MARK: - Subscription Manager

actor SubscriptionManager {
    private let storage = ConfigStorage.shared

    /// Subscriptions file path
    private var subscriptionsFilePath: URL {
        storage.appSupportDirectory.appendingPathComponent("subscriptions.json")
    }

    /// Subscription URLs, response previews, and provider tokens are sensitive.
    /// Keep the legacy call sites silent rather than persisting them to /tmp or Console.
    private func log(_ message: String) {
        _ = message
    }

    // MARK: - Fetch & Parse

    /// Download subscription content from URL.
    ///
    /// When `tonoMode` is true (product default once AccountSession is ready):
    /// - HTTPS-only, no private destinations
    /// - ONLY via local Mihomo mixed-port (Home-US path) — never proxy-free
    ///
    /// Non-tono legacy path keeps multi-strategy download for development profiles.
    func downloadContent(url: String, proxyPort: Int? = nil, tonoMode: Bool = true, useSocks5: Bool = false) async throws -> (content: String, userInfo: SubscriptionUserInfo?) {
        switch SubscriptionURLPolicy.validate(url) {
        case .failure:
            throw SubscriptionError.invalidURL
        case .success:
            break
        }

        log("Subscription download started (tonoMode=\(tonoMode), socks5=\(useSocks5))")

        // Product builds have no proxy-free subscription mode. Keep the parameter
        // only for source compatibility with old callers; false is fail-closed.
        guard tonoMode else {
            throw SubscriptionError.downloadFailed
        }
        // Only via local Home-US path (Mihomo mixed-port or Tailscale SOCKS).
        // Never use noproxy / clash-fetcher / direct URLSession.
        do {
            guard let port = proxyPort else {
                throw SubscriptionError.downloadFailed
            }
            let scheme = useSocks5 ? "socks5h" : "http"
            let proxy = "\(scheme)://127.0.0.1:\(port)"
            log("Tono: download via \(proxy) only")
            do {
                let result = try await downloadWithCurlSingleProxy(url: url, proxy: proxy)
                log("Tono download SUCCESS: \(result.content.count) chars")
                return result
            } catch {
                log("Tono download failed")
                throw error
            }
        }

    }

    // MARK: - curl with proxy (single attempt)

    /// The User-Agent that subscription backends recognize as a Clash client.
    /// Must use -A flag in curl (not -H) to properly override default UA.
    private static let clashUA = "clash-verge/v2.4.7"
    private static let maximumDownloadBytes = 5 * 1_024 * 1_024
    private static let maximumHeaderBytes = 128 * 1_024

    private struct DNSAnswer: Decodable {
        let type: Int
        let data: String
    }

    private struct DNSResponse: Decodable {
        let status: Int
        let answers: [DNSAnswer]?
        enum CodingKeys: String, CodingKey {
            case status = "Status"
            case answers = "Answer"
        }
    }

    /// Try downloading via curl through a specific proxy. Fast timeout for probing.
    private func downloadWithCurlSingleProxy(url: String, proxy: String, timeout: Int = 10) async throws -> (content: String, userInfo: SubscriptionUserInfo?) {
        guard case .success(let validatedURL) = SubscriptionURLPolicy.validate(url) else {
            throw SubscriptionError.invalidURL
        }
        let pinning = try await publicAddressPinning(for: validatedURL, proxy: proxy)
        let args = ["-sS", "--compressed", "--max-time", "\(timeout)", "--proxy", proxy,
                    "-A", Self.clashUA] + pinning
        return try await runCurl(args: args, targetURL: validatedURL)
    }

    /// Resolve through a fixed DoH service over the already-pinned Home transport,
    /// reject every non-public answer, then force curl's connection target to one
    /// of those exact addresses while preserving the original TLS SNI/certificate.
    /// This closes private-DNS and DNS-rebinding SSRF through the home exit.
    private func publicAddressPinning(for url: URL, proxy: String) async throws -> [String] {
        guard let host = url.host, !host.isEmpty else { throw SubscriptionError.invalidURL }
        if let literal = SubscriptionURLPolicy.literalIPAddress(host) {
            guard !SubscriptionURLPolicy.isBlockedIP(literal) else { throw SubscriptionError.invalidURL }
            return []
        }

        var addresses: [String] = []
        for recordType in ["A", "AAAA"] {
            var components = URLComponents(string: "https://cloudflare-dns.com/dns-query")!
            components.queryItems = [
                URLQueryItem(name: "name", value: host),
                URLQueryItem(name: "type", value: recordType),
            ]
            guard let queryURL = components.url else { throw SubscriptionError.downloadFailed }
            let result = try await runCurl(args: [
                "-sS", "--compressed", "--max-time", "10",
                "--proxy", proxy,
                "-H", "Accept: application/dns-json",
            ], targetURL: queryURL)
            guard let data = result.content.data(using: .utf8),
                  let response = try? JSONDecoder().decode(DNSResponse.self, from: data),
                  response.status == 0 else {
                throw SubscriptionError.downloadFailed
            }
            for answer in response.answers ?? [] where answer.type == 1 || answer.type == 28 {
                let value = answer.data.trimmingCharacters(in: .whitespacesAndNewlines)
                guard SubscriptionURLPolicy.literalIPAddress(value) != nil,
                      !SubscriptionURLPolicy.isBlockedIP(value) else {
                    throw SubscriptionError.invalidURL
                }
                if !addresses.contains(value) {
                    addresses.append(value)
                }
                guard addresses.count <= 32 else { throw SubscriptionError.invalidURL }
            }
        }
        guard let selected = addresses.first(where: { !$0.contains(":") }) ?? addresses.first else {
            throw SubscriptionError.downloadFailed
        }
        let port = url.port ?? 443
        let resolveAddresses = addresses.map { $0.contains(":") ? "[\($0)]" : $0 }
            .joined(separator: ",")
        let connectAddress = selected.contains(":") ? "[\(selected)]" : selected
        return [
            "--resolve", "\(host):\(port):\(resolveAddresses)",
            "--connect-to", "\(host):\(port):\(connectAddress):\(port)",
        ]
    }

    // MARK: - Shared curl runner

    /// Run curl without exposing the bearer-style subscription URL in argv or the
    /// inherited environment. The URL is supplied through curl's stdin config.
    private func runCurl(args: [String], targetURL: URL) async throws -> (content: String, userInfo: SubscriptionUserInfo?) {
        guard targetURL.scheme?.lowercased() == "https",
              let stdinConfiguration = Self.curlStdinConfiguration(for: targetURL) else {
            throw SubscriptionError.invalidURL
        }
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                let headerFile = URL(fileURLWithPath: NSTemporaryDirectory())
                    .appendingPathComponent(UUID().uuidString + ".headers")
                guard FileManager.default.createFile(
                    atPath: headerFile.path,
                    contents: Data(),
                    attributes: [.posixPermissions: 0o600]
                ) else {
                    continuation.resume(throwing: SubscriptionError.downloadFailed)
                    return
                }
                defer { try? FileManager.default.removeItem(at: headerFile) }

                let process = Process()
                process.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
                process.environment = [
                    "PATH": "/usr/bin:/bin",
                    "LC_ALL": "C",
                ]
                process.arguments = [
                    "--disable",
                    "--proto", "=https",
                    "--proto-redir", "=https",
                    "--max-redirs", "0",
                    "--max-filesize", "\(Self.maximumDownloadBytes)",
                    "-D", headerFile.path,
                ] + args + ["--config", "-"]

                let outputPipe = Pipe()
                let inputPipe = Pipe()
                process.standardOutput = outputPipe
                process.standardError = FileHandle.nullDevice
                process.standardInput = inputPipe

                do { try process.run() } catch {
                    continuation.resume(throwing: SubscriptionError.downloadFailed)
                    return
                }
                // The legacy write(_:) raises an uncatchable ObjC exception if
                // curl exits before reading its stdin config (broken pipe) —
                // an app crash from a subprocess hiccup. The throwing variant
                // fails gracefully; curl then errors out on the empty config.
                do {
                    try inputPipe.fileHandleForWriting.write(
                        contentsOf: stdinConfiguration
                    )
                } catch {
                    if process.isRunning { process.terminate() }
                }
                try? inputPipe.fileHandleForWriting.close()

                var data = Data()
                var outputFailed = false
                do {
                    while let chunk = try outputPipe.fileHandleForReading.read(upToCount: 64 * 1_024),
                          !chunk.isEmpty {
                        guard chunk.count <= Self.maximumDownloadBytes - data.count else {
                            outputFailed = true
                            if process.isRunning { process.terminate() }
                            try? outputPipe.fileHandleForReading.close()
                            break
                        }
                        data.append(chunk)
                    }
                } catch {
                    outputFailed = true
                    if process.isRunning { process.terminate() }
                }
                process.waitUntilExit()

                guard !outputFailed, data.count <= Self.maximumDownloadBytes else {
                    continuation.resume(throwing: SubscriptionError.invalidContent)
                    return
                }
                let content = String(data: data, encoding: .utf8) ?? ""

                let headerAttributes = try? FileManager.default.attributesOfItem(atPath: headerFile.path)
                let headerSize = (headerAttributes?[.size] as? NSNumber)?.intValue ?? 0
                guard headerSize <= Self.maximumHeaderBytes else {
                    continuation.resume(throwing: SubscriptionError.invalidContent)
                    return
                }
                let headers = (try? String(contentsOf: headerFile, encoding: .utf8)) ?? ""
                let statusCodes = headers.components(separatedBy: .newlines).compactMap { line -> Int? in
                    let fields = line.split(whereSeparator: \.isWhitespace)
                    guard fields.count >= 2, fields[0].hasPrefix("HTTP/") else { return nil }
                    return Int(fields[1])
                }
                guard let finalStatus = statusCodes.last else {
                    continuation.resume(throwing: SubscriptionError.downloadFailed)
                    return
                }
                guard (200...299).contains(finalStatus) else {
                    continuation.resume(throwing: SubscriptionError.downloadHTTPError(finalStatus))
                    return
                }

                let lower = content.prefix(500).lowercased()
                if lower.contains("<!doctype") || lower.contains("<html") {
                    continuation.resume(throwing: SubscriptionError.serverReturnedHTML)
                    return
                }

                guard process.terminationStatus == 0 else {
                    continuation.resume(throwing: SubscriptionError.downloadFailed)
                    return
                }

                guard !content.isEmpty else {
                    continuation.resume(throwing: SubscriptionError.invalidContent)
                    return
                }

                // Parse subscription-userinfo from response headers
                var userInfo: SubscriptionUserInfo?
                for line in headers.components(separatedBy: .newlines) {
                    if line.lowercased().hasPrefix("subscription-userinfo:") {
                        let value = String(line.dropFirst("subscription-userinfo:".count))
                            .trimmingCharacters(in: .whitespaces)
                        userInfo = SubscriptionUserInfo.parse(value)
                        break
                    }
                }

                continuation.resume(returning: (content, userInfo))
            }
        }
    }

    private static func curlStdinConfiguration(for url: URL) -> Data? {
        let value = url.absoluteString
        guard !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else {
            return nil
        }
        let escaped = value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        return Data("url = \"\(escaped)\"\n".utf8)
    }

    /// Download and parse subscription from URL
    func fetchSubscription(url: String, proxyPort: Int? = nil, tonoMode: Bool = true, useSocks5: Bool = false) async throws -> (nodes: [ProxyNode], rawContent: String, userInfo: SubscriptionUserInfo?) {
        let (content, userInfo) = try await downloadContent(url: url, proxyPort: proxyPort, tonoMode: tonoMode, useSocks5: useSocks5)

        let resolved = resolveContent(content)

        // If content is not Clash YAML, retry with flag=clash to request YAML format
        if !resolved.contains("proxies:") {
            if let clashURL = Self.appendClashFlag(url) {
                log("Content is not YAML format; retrying with Clash response mode")
                if let (retryContent, retryUserInfo) = try? await downloadContent(url: clashURL, proxyPort: proxyPort, tonoMode: tonoMode, useSocks5: useSocks5) {
                    let retryResolved = resolveContent(retryContent)
                    if retryResolved.contains("proxies:") {
                        log("Retry with flag=clash succeeded, got YAML format")
                        let nodes = ConfigParser.parseSubscription(retryResolved)
                        if !nodes.isEmpty {
                            return (nodes, retryResolved, retryUserInfo ?? userInfo)
                        }
                    }
                }
            }
        }

        let nodes = ConfigParser.parseSubscription(resolved)
        guard !nodes.isEmpty else {
            let trimmedStart = resolved.prefix(500).lowercased()
            if trimmedStart.contains("<!doctype") || trimmedStart.contains("<html") {
                throw SubscriptionError.serverReturnedHTML
            }
            throw SubscriptionError.parseFailed
        }

        // If the original content was URI format (not YAML), generate proper Clash YAML
        // from the parsed nodes. This is needed when the subscription backend uses TLS
        // fingerprinting and only returns YAML for specific TLS libraries (e.g. rustls).
        let rawContent: String
        if resolved.contains("proxies:") {
            rawContent = resolved
        } else {
            log("Content is URI format, generating Clash YAML locally from \(nodes.count) nodes")
            rawContent = ConfigParser.generateClashYAML(from: nodes)
        }

        return (nodes, rawContent, userInfo)
    }

    /// Append flag=clash to URL to request Clash YAML format from subscription backend.
    /// Returns nil if the URL already has a Clash format parameter.
    private static func appendClashFlag(_ urlString: String) -> String? {
        guard var components = URLComponents(string: urlString) else { return nil }
        let existingNames = Set((components.queryItems ?? []).map { $0.name.lowercased() })
        // Don't add if URL already specifies output format
        if existingNames.contains("flag") || existingNames.contains("target") ||
           existingNames.contains("type") || existingNames.contains("client") {
            return nil
        }
        var items = components.queryItems ?? []
        items.append(URLQueryItem(name: "flag", value: "clash"))
        components.queryItems = items
        return components.string
    }

    /// Resolve content that may be base64-encoded
    private func resolveContent(_ content: String) -> String {
        let trimmed = content.trimmingCharacters(in: .whitespacesAndNewlines)

        // If it already looks like YAML, return as-is
        if trimmed.contains("proxies:") {
            return trimmed
        }

        // Try base64 decode
        if let decoded = ConfigParser.decodeBase64(trimmed),
           decoded.contains("proxies:") || decoded.contains("://") {
            return decoded
        }

        return trimmed
    }

    /// Fetch and organize nodes into regions
    func fetchAndOrganize(url: String, proxyPort: Int? = nil, tonoMode: Bool = true, useSocks5: Bool = false) async throws -> ([ProxyRegion], String, SubscriptionUserInfo?) {
        let (nodes, rawContent, headerInfo) = try await fetchSubscription(url: url, proxyPort: proxyPort, tonoMode: tonoMode, useSocks5: useSocks5)
        let (realNodes, nodeInfo) = Self.extractInfoNodes(nodes)
        // Prefer HTTP header info, fallback to node-name-based info
        let userInfo = headerInfo ?? nodeInfo
        return (organizeIntoRegions(realNodes), rawContent, userInfo)
    }

    // MARK: - Info Node Detection

    /// Extract traffic/expiry info from special "info nodes" and filter them out
    static func extractInfoNodes(_ nodes: [ProxyNode]) -> (realNodes: [ProxyNode], info: SubscriptionUserInfo?) {
        var info = SubscriptionUserInfo()
        var foundInfo = false
        var realNodes: [ProxyNode] = []

        let infoPatterns: [(String) -> Bool] = [
            { $0.lowercased().contains("traffic") || $0.contains("流量") },
            { $0.lowercased().contains("expire") || $0.contains("到期") || $0.contains("过期") },
            { $0.contains("套餐") || $0.contains("剩余") || $0.contains("重置") },
            { $0.lowercased().contains("subscription") && !$0.lowercased().contains("subscribe") },
        ]

        for node in nodes {
            let isInfoNode = infoPatterns.contains { $0(node.name) }
            if isInfoNode {
                // Try to parse traffic: "142.3 GB / 600 GB" or "Traffic: 142.3 GB / 600 GB"
                if let (used, total) = parseTrafficFromName(node.name) {
                    info.download = used
                    info.total = total
                    foundInfo = true
                }
                // Try to parse expiry: "2026-07-09" or "Expire: 2026-07-09"
                if let expire = parseExpireFromName(node.name) {
                    info.expire = expire
                    foundInfo = true
                }
            } else {
                realNodes.append(node)
            }
        }

        return (realNodes, foundInfo ? info : nil)
    }

    /// Parse traffic from node name like "Traffic: 142.3 GB / 600 GB"
    private static func parseTrafficFromName(_ name: String) -> (used: Int64, total: Int64)? {
        // Match patterns like "142.3 GB / 600 GB" or "142.3GB/600GB"
        let pattern = #"(\d+(?:\.\d+)?)\s*(GB|MB|TB|KB)\s*/\s*(\d+(?:\.\d+)?)\s*(GB|MB|TB|KB)"#
        guard let regex = try? NSRegularExpression(pattern: pattern, options: .caseInsensitive),
              let match = regex.firstMatch(in: name, range: NSRange(name.startIndex..., in: name)),
              match.numberOfRanges >= 5 else { return nil }

        func extractBytes(_ valueRange: NSRange, _ unitRange: NSRange) -> Int64? {
            guard let vr = Range(valueRange, in: name), let ur = Range(unitRange, in: name),
                  let value = Double(name[vr]) else { return nil }
            let unit = name[ur].uppercased()
            let multiplier: Double = switch unit {
                case "TB": 1_099_511_627_776
                case "GB": 1_073_741_824
                case "MB": 1_048_576
                case "KB": 1024
                default: 1
            }
            return Int64(value * multiplier)
        }

        guard let used = extractBytes(match.range(at: 1), match.range(at: 2)),
              let total = extractBytes(match.range(at: 3), match.range(at: 4)) else { return nil }
        return (used, total)
    }

    /// Parse expiry from node name like "Expire: 2026-07-09"
    private static func parseExpireFromName(_ name: String) -> TimeInterval? {
        let pattern = #"(\d{4}[-/]\d{1,2}[-/]\d{1,2})"#
        guard let regex = try? NSRegularExpression(pattern: pattern),
              let match = regex.firstMatch(in: name, range: NSRange(name.startIndex..., in: name)),
              let range = Range(match.range(at: 1), in: name) else { return nil }

        let dateStr = String(name[range]).replacingOccurrences(of: "/", with: "-")
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        formatter.timeZone = TimeZone(identifier: "UTC")
        guard let date = formatter.date(from: dateStr) else { return nil }
        return date.timeIntervalSince1970
    }

    // MARK: - Organize Nodes

    /// Group nodes by geographic region
    func organizeIntoRegions(_ nodes: [ProxyNode]) -> [ProxyRegion] {
        var regionMap: [String: (name: String, nodes: [ProxyNode])] = [:]

        let regionMapping: [(flags: Set<String>, id: String, name: String)] = [
            (["🇯🇵", "🇸🇬", "🇭🇰", "🇨🇳", "🇰🇷", "🇮🇳", "🇦🇺"], "ap", "ASIA PACIFIC"),
            (["🇺🇸", "🇨🇦", "🇧🇷"], "am", "AMERICAS"),
            (["🇬🇧", "🇩🇪", "🇫🇷", "🇳🇱", "🇷🇺"], "eu", "EUROPE"),
        ]

        for node in nodes {
            var placed = false
            for region in regionMapping {
                if region.flags.contains(node.flag) {
                    var existing = regionMap[region.id] ?? (name: region.name, nodes: [])
                    existing.nodes.append(node)
                    regionMap[region.id] = existing
                    placed = true
                    break
                }
            }
            if !placed {
                var other = regionMap["other"] ?? (name: "OTHER", nodes: [])
                other.nodes.append(node)
                regionMap["other"] = other
            }
        }

        // Build regions in order
        let order = ["ap", "am", "eu", "other"]
        return order.compactMap { id in
            guard let region = regionMap[id], !region.nodes.isEmpty else { return nil }
            return ProxyRegion(id: id, name: region.name, nodes: region.nodes)
        }
    }

    /// Fetch all enabled subscriptions and merge
    func fetchAllAndOrganize(_ subscriptions: [SubscriptionInfo], proxyPort: Int? = nil, tonoMode: Bool = true, useSocks5: Bool = false) async throws -> ([ProxyRegion], [SubscriptionInfo], String) {
        var allNodes: [ProxyNode] = []
        var allRawContents: [String] = []
        var updatedSubs = subscriptions
        var lastError: Error?

        for i in updatedSubs.indices where updatedSubs[i].isEnabled {
            do {
                let (nodes, rawContent, headerInfo) = try await fetchSubscription(url: updatedSubs[i].url, proxyPort: proxyPort, tonoMode: tonoMode, useSocks5: useSocks5)
                let (realNodes, nodeInfo) = Self.extractInfoNodes(nodes)
                allNodes.append(contentsOf: realNodes.map { node in
                    var sourcedNode = node
                    sourcedNode.subscriptionId = updatedSubs[i].id
                    return sourcedNode
                })
                allRawContents.append(rawContent)
                updatedSubs[i].lastUpdate = Date()
                updatedSubs[i].nodeCount = realNodes.count
                // Prefer HTTP header info, fallback to node-name-based info
                let info = headerInfo ?? nodeInfo
                if let info {
                    updatedSubs[i].upload = info.upload
                    updatedSubs[i].download = info.download
                    updatedSubs[i].total = info.total
                    updatedSubs[i].expire = info.expire
                }
            } catch {
                lastError = error
            }
        }

        // If no nodes found, throw the actual error from the last failure
        guard !allNodes.isEmpty else { throw lastError ?? SubscriptionError.noNodesFound }

        // Merge all raw YAML configs: use first as base, inject proxies from others
        let rawYAML = mergeRawYAMLs(allRawContents)

        return (organizeIntoRegions(allNodes), updatedSubs, rawYAML)
    }

    // MARK: - Merge Multiple Raw YAMLs

    /// Merge multiple subscription YAMLs by extracting proxy entries from each
    /// and combining them into the first YAML's proxies section.
    private func mergeRawYAMLs(_ rawContents: [String]) -> String {
        guard let base = rawContents.first, !base.isEmpty else { return "" }
        guard rawContents.count > 1 else { return base }

        // Extract proxy lines from additional subscriptions
        var extraProxyLines: [String] = []
        for content in rawContents.dropFirst() {
            let proxyBlock = extractProxiesBlock(from: content)
            if !proxyBlock.isEmpty {
                extraProxyLines.append(contentsOf: proxyBlock)
            }
        }

        guard !extraProxyLines.isEmpty else { return base }

        // Find the end of the proxies block in the base YAML and inject extra entries
        let lines = base.components(separatedBy: .newlines)
        var result: [String] = []
        var inProxies = false
        var injected = false

        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed == "proxies:" || trimmed == "proxies: " {
                inProxies = true
                result.append(line)
                continue
            }

            if inProxies {
                // Still in proxies block if line is indented or starts with "- "
                let isProxyEntry = line.hasPrefix(" ") || line.hasPrefix("\t") || trimmed.isEmpty
                if !isProxyEntry && !trimmed.isEmpty {
                    // We've left the proxies block — inject extra lines before this line
                    if !injected {
                        result.append(contentsOf: extraProxyLines)
                        injected = true
                    }
                    inProxies = false
                }
            }

            result.append(line)
        }

        // If proxies block extends to end of file
        if inProxies && !injected {
            result.append(contentsOf: extraProxyLines)
        }

        return result.joined(separator: "\n")
    }

    /// Extract the indented proxy entry lines from a YAML string
    private func extractProxiesBlock(from yaml: String) -> [String] {
        let lines = yaml.components(separatedBy: .newlines)
        var inProxies = false
        var proxyLines: [String] = []

        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed == "proxies:" || trimmed == "proxies: " {
                inProxies = true
                continue
            }
            if inProxies {
                let isEntry = line.hasPrefix(" ") || line.hasPrefix("\t") || trimmed.isEmpty
                if isEntry {
                    if !trimmed.isEmpty { proxyLines.append(line) }
                } else {
                    break
                }
            }
        }
        return proxyLines
    }

    // MARK: - Subscription Persistence

    func saveSubscriptions(_ subs: [SubscriptionInfo]) {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = .prettyPrinted
        guard let data = try? encoder.encode(subs) else { return }
        try? storage.writeSensitive(data, to: subscriptionsFilePath)
    }

    func loadSubscriptions() -> [SubscriptionInfo] {
        guard let data = try? Data(contentsOf: subscriptionsFilePath) else { return [] }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        // Try array first, fallback to single
        if let subs = try? decoder.decode([SubscriptionInfo].self, from: data) {
            return subs
        }
        if let single = try? decoder.decode(SubscriptionInfo.self, from: data) {
            return [single]
        }
        // One malformed element must not erase every subscription: the URLs
        // are bearer credentials the user may have nowhere else. Decode
        // per-element, keep what parses, and set the corrupt original aside
        // instead of letting the next save destructively overwrite it.
        if let fragments = try? JSONSerialization.jsonObject(with: data) as? [Any] {
            let salvaged = fragments.compactMap { fragment -> SubscriptionInfo? in
                guard let object = try? JSONSerialization.data(withJSONObject: fragment) else {
                    return nil
                }
                return try? decoder.decode(SubscriptionInfo.self, from: object)
            }
            if !salvaged.isEmpty {
                let backup = subscriptionsFilePath
                    .deletingPathExtension()
                    .appendingPathExtension("corrupt.json")
                try? FileManager.default.removeItem(at: backup)
                try? FileManager.default.copyItem(
                    at: subscriptionsFilePath,
                    to: backup
                )
                return salvaged
            }
        }
        return []
    }

    func saveSubscriptionInfo(_ info: SubscriptionInfo) {
        var subs = loadSubscriptions()
        if let idx = subs.firstIndex(where: { $0.url == info.url }) {
            subs[idx] = info
        } else {
            subs.append(info)
        }
        saveSubscriptions(subs)
    }

    func loadSubscriptionInfo() -> SubscriptionInfo? {
        loadSubscriptions().first
    }
}

// MARK: - Subscription Error

nonisolated enum SubscriptionError: LocalizedError {
    case invalidURL
    case downloadFailed
    case downloadHTTPError(Int)
    case invalidContent
    case noNodesFound
    case serverReturnedHTML
    case parseFailed
    case blockedByServer

    var errorDescription: String? {
        switch self {
        case .invalidURL: "订阅链接无效"
        case .downloadFailed: "下载订阅失败（网络错误）"
        case .downloadHTTPError(let code): "订阅服务器返回 HTTP \(code)"
        case .invalidContent: "订阅内容不是有效文本"
        case .noNodesFound: "订阅中未找到代理节点"
        case .blockedByServer: "订阅源拒绝访问。请先通过「从 Clash Verge 导入」或「文件导入」获取节点，连接代理后再更新订阅。"
        case .serverReturnedHTML: "订阅服务器返回了 HTML 页面而非配置文件，请检查链接"
        case .parseFailed: "无法解析订阅内容，请检查订阅格式"
        }
    }
}
