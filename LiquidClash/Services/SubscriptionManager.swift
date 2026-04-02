import Foundation

// MARK: - Subscription Info

struct SubscriptionInfo: Codable, Identifiable {
    var id: String = UUID().uuidString
    var url: String
    var name: String
    var lastUpdate: Date?
    var nodeCount: Int = 0
    var isEnabled: Bool = true
}

// MARK: - Subscription Manager

actor SubscriptionManager {
    private let storage = ConfigStorage.shared

    /// Subscriptions file path
    private var subscriptionsFilePath: URL {
        storage.appSupportDirectory.appendingPathComponent("subscriptions.json")
    }

    // MARK: - Fetch & Parse

    /// Download subscription content from URL.
    /// Aggressive multi-strategy fallback:
    ///   1. System proxy (HTTP/HTTPS/SOCKS from system settings)
    ///   2. Local mihomo proxy if running
    ///   3. curl with proxy on common local ports (most reliable proxy detection)
    ///   4. Direct URLSession
    ///   5. Direct curl
    ///   6. python3 urllib (different TLS fingerprint)
    func downloadContent(url: String, proxyPort: Int? = nil) async throws -> String {
        guard URL(string: url) != nil else {
            throw SubscriptionError.invalidURL
        }

        // Track the most specific error (don't let generic errors overwrite specific ones)
        var bestError: Error = SubscriptionError.downloadFailed

        func recordError(_ error: Error) {
            if let sub = error as? SubscriptionError {
                switch sub {
                case .serverReturnedHTML, .blockedByServer, .downloadHTTPError:
                    // Always keep server-specific errors — highest priority
                    bestError = error
                case .downloadFailed, .invalidContent:
                    // Only replace if we have nothing better
                    break
                default:
                    if case SubscriptionError.downloadFailed = bestError {
                        bestError = error
                    }
                }
            }
            // Non-SubscriptionError (e.g. URLError) never overwrites SubscriptionError
        }

        // 1. System proxy
        if let systemProxy = Self.getSystemProxy() {
            do {
                return try await downloadWithCurlSingleProxy(
                    url: url, proxy: "http://\(systemProxy.host):\(systemProxy.port)")
            } catch { recordError(error) }
        }

        // 2. Local mihomo proxy
        if let port = proxyPort {
            do {
                return try await downloadWithCurlSingleProxy(
                    url: url, proxy: "http://127.0.0.1:\(port)")
            } catch { recordError(error) }
        }

        // 3. curl through common local proxy ports (parallel)
        let commonPorts = [7897, 7890, 7891, 1080, 10808, 10809]
            .filter { $0 != proxyPort }
        let proxyResult: String? = await withTaskGroup(of: String?.self) { group in
            for port in commonPorts {
                group.addTask { [self] in
                    try? await downloadWithCurlSingleProxy(
                        url: url, proxy: "http://127.0.0.1:\(port)", timeout: 3)
                }
                group.addTask { [self] in
                    try? await downloadWithCurlSingleProxy(
                        url: url, proxy: "socks5://127.0.0.1:\(port)", timeout: 3)
                }
            }
            for await result in group {
                if let content = result {
                    group.cancelAll()
                    return content
                }
            }
            return nil
        }
        if let content = proxyResult { return content }

        // 4. Direct curl (with DoH DNS to bypass pollution)
        do { return try await downloadWithCurl(url: url) }
        catch { recordError(error) }

        // 5. Direct URLSession
        do { return try await downloadWithURLSession(url: url) }
        catch { recordError(error) }

        // If we already know the server blocked us (403/HTML), skip WKWebView and fail fast
        if let sub = bestError as? SubscriptionError {
            switch sub {
            case .serverReturnedHTML, .downloadHTTPError(403):
                throw SubscriptionError.blockedByServer
            default: break
            }
        }

        // 6. WKWebView — last resort for Cloudflare JS challenges
        do { return try await WebViewDownloader.download(url: url) }
        catch { recordError(error) }

        throw bestError
    }

    /// Read macOS system proxy settings (HTTP, HTTPS, and SOCKS)
    private static func getSystemProxy() -> (host: String, port: Int)? {
        guard let settings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] else {
            return nil
        }
        if let enabled = settings["HTTPSEnable"] as? Int, enabled == 1,
           let host = settings["HTTPSProxy"] as? String, !host.isEmpty,
           let port = settings["HTTPSPort"] as? Int, port > 0 {
            return (host, port)
        }
        if let enabled = settings[kCFNetworkProxiesHTTPEnable as String] as? Int, enabled == 1,
           let host = settings[kCFNetworkProxiesHTTPProxy as String] as? String, !host.isEmpty,
           let port = settings[kCFNetworkProxiesHTTPPort as String] as? Int, port > 0 {
            return (host, port)
        }
        if let enabled = settings[kCFNetworkProxiesSOCKSEnable as String] as? Int, enabled == 1,
           let host = settings[kCFNetworkProxiesSOCKSProxy as String] as? String, !host.isEmpty,
           let port = settings[kCFNetworkProxiesSOCKSPort as String] as? Int, port > 0 {
            return (host, port)
        }
        return nil
    }

    // MARK: - curl with proxy (single attempt)

    /// Try downloading via curl through a specific proxy. Fast timeout for probing.
    /// No DoH here — the proxy server handles DNS resolution.
    private func downloadWithCurlSingleProxy(url: String, proxy: String, timeout: Int = 10) async throws -> String {
        let args = ["-sSL", "--compressed", "--max-time", "\(timeout)", "--proxy", proxy,
                    "-H", "User-Agent: clash-verge/v2.4.7",
                    url]
        return try await runCurl(args: args)
    }

    /// Direct curl download. Tries DoH first (bypass DNS pollution),
    /// then plain curl (works under TUN mode where DNS is handled by the tunnel).
    private func downloadWithCurl(url: String) async throws -> String {
        // Try with DoH (bypasses DNS pollution when no proxy/TUN is active)
        do {
            return try await runCurl(args: [
                "-sSL", "--compressed", "--max-time", "10",
                "-H", "User-Agent: clash-verge/v2.4.7",
                "--doh-url", "https://1.1.1.1/dns-query",
                url
            ])
        } catch {}

        // Fallback: plain curl (works under TUN mode where the tunnel handles DNS)
        return try await runCurl(args: [
            "-sSL", "--compressed", "--max-time", "10",
            "-H", "User-Agent: clash-verge/v2.4.7",
            url
        ])
    }

    /// Native URLSession direct download (uses system DNS — may fail with DNS pollution)
    private func downloadWithURLSession(url: String) async throws -> String {
        var request = URLRequest(url: URL(string: url)!)
        request.timeoutInterval = 15
        request.setValue("clash-verge/v2.4.7", forHTTPHeaderField: "User-Agent")

        let (data, response) = try await URLSession.shared.data(for: request)

        if let httpResponse = response as? HTTPURLResponse,
           !(200...299).contains(httpResponse.statusCode) {
            throw SubscriptionError.downloadHTTPError(httpResponse.statusCode)
        }

        guard let content = String(data: data, encoding: .utf8)
                ?? String(data: data, encoding: .isoLatin1) else {
            throw SubscriptionError.invalidContent
        }

        return content
    }

    // MARK: - Shared curl runner

    /// Run curl with given arguments and return output as String.
    /// Validates that the response is not an HTML error page.
    /// Checks output for HTML even on non-zero exit (partial transfer may contain 403 page).
    private func runCurl(args: [String]) async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                let process = Process()
                process.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
                process.arguments = args

                let outputPipe = Pipe()
                process.standardOutput = outputPipe
                process.standardError = Pipe()

                do { try process.run() } catch {
                    continuation.resume(throwing: SubscriptionError.downloadFailed)
                    return
                }

                // Read output BEFORE waitUntilExit to avoid pipe buffer deadlock
                let data = outputPipe.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()

                let content = String(data: data, encoding: .utf8) ?? ""

                // Always check for HTML error pages first, even on non-zero exit
                // (server may send 403 HTML then close connection → curl exits non-zero)
                let lower = content.prefix(500).lowercased()
                if lower.contains("<!doctype") || lower.contains("<html") {
                    continuation.resume(throwing: SubscriptionError.serverReturnedHTML(
                        String(content.prefix(200))
                            .replacingOccurrences(of: "<[^>]+>", with: "", options: .regularExpression)
                            .trimmingCharacters(in: .whitespacesAndNewlines)
                    ))
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

                continuation.resume(returning: content)
            }
        }
    }

    /// Download and parse subscription from URL
    func fetchSubscription(url: String, proxyPort: Int? = nil) async throws -> (nodes: [ProxyNode], rawContent: String) {
        let content = try await downloadContent(url: url, proxyPort: proxyPort)

        // Resolve actual content (may be base64 encoded)
        let resolved = resolveContent(content)

        let nodes = ConfigParser.parseSubscription(resolved)
        guard !nodes.isEmpty else {
            // Show what the server actually returned for diagnosis
            let preview = String(resolved.prefix(200))
                .replacingOccurrences(of: "\n", with: " ")
                .replacingOccurrences(of: "<[^>]+>", with: "", options: .regularExpression) // strip HTML tags
                .trimmingCharacters(in: .whitespaces)
            let trimmedStart = resolved.prefix(500).lowercased()
            if trimmedStart.contains("<!doctype") || trimmedStart.contains("<html") {
                throw SubscriptionError.serverReturnedHTML(preview)
            }
            throw SubscriptionError.parseFailedWithPreview(preview)
        }

        return (nodes, resolved)
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
    func fetchAndOrganize(url: String, proxyPort: Int? = nil) async throws -> ([ProxyRegion], String) {
        let (nodes, rawContent) = try await fetchSubscription(url: url, proxyPort: proxyPort)
        return (organizeIntoRegions(nodes), rawContent)
    }

    // MARK: - Organize Nodes

    /// Group nodes by geographic region
    func organizeIntoRegions(_ nodes: [ProxyNode]) -> [ProxyRegion] {
        var regionMap: [String: (name: String, nodes: [ProxyNode])] = [:]

        let regionMapping: [(flags: Set<String>, id: String, name: String)] = [
            (["🇯🇵", "🇸🇬", "🇭🇰", "🇹🇼", "🇰🇷", "🇮🇳", "🇦🇺"], "ap", "ASIA PACIFIC"),
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
    func fetchAllAndOrganize(_ subscriptions: [SubscriptionInfo], proxyPort: Int? = nil) async throws -> ([ProxyRegion], [SubscriptionInfo], String) {
        var allNodes: [ProxyNode] = []
        var allRawContents: [String] = []
        var updatedSubs = subscriptions
        var lastError: Error?

        for i in updatedSubs.indices where updatedSubs[i].isEnabled {
            do {
                let (nodes, rawContent) = try await fetchSubscription(url: updatedSubs[i].url, proxyPort: proxyPort)
                allNodes.append(contentsOf: nodes)
                allRawContents.append(rawContent)
                updatedSubs[i].lastUpdate = Date()
                updatedSubs[i].nodeCount = nodes.count
            } catch {
                lastError = error
                // Continue trying other subscriptions
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
        try? data.write(to: subscriptionsFilePath, options: .atomic)
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

enum SubscriptionError: LocalizedError {
    case invalidURL
    case downloadFailed
    case downloadHTTPError(Int)
    case invalidContent
    case noNodesFound
    case serverReturnedHTML(String)
    case parseFailedWithPreview(String)
    case blockedByServer

    var errorDescription: String? {
        switch self {
        case .invalidURL: "订阅链接无效"
        case .downloadFailed: "下载订阅失败（网络错误）"
        case .downloadHTTPError(let code): "订阅服务器返回 HTTP \(code)"
        case .invalidContent: "订阅内容不是有效文本"
        case .noNodesFound: "订阅中未找到代理节点"
        case .blockedByServer: "订阅源拒绝访问。请先通过「从 Clash Verge 导入」或「文件导入」获取节点，连接代理后再更新订阅。"
        case .serverReturnedHTML(let preview):
            if preview.contains("403") || preview.contains("访问受限") || preview.contains("denied") {
                "订阅源拒绝访问。请先通过「从 Clash Verge 导入」或「文件导入」获取节点，连接代理后再更新订阅。"
            } else if preview.isEmpty {
                "订阅服务器返回了 HTML 页面而非配置文件，请检查链接"
            } else {
                "订阅服务器返回：\(preview)"
            }
        case .parseFailedWithPreview(let preview): "无法解析订阅内容，服务器返回：\(preview)"
        }
    }
}
