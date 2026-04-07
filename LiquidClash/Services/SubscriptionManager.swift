import Foundation

// MARK: - Subscription Info

struct SubscriptionInfo: Codable, Identifiable {
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

struct SubscriptionUserInfo {
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

    /// Log file for download debugging — use /tmp for guaranteed accessibility
    private var downloadLogPath: URL {
        URL(fileURLWithPath: "/tmp/liquidclash_download.log")
    }

    /// Write a line to the download log file (and also print to console)
    private func log(_ message: String) {
        let line = "[\(ISO8601DateFormatter().string(from: Date()))] \(message)\n"
        print("[LiquidClash] \(message)")
        if let data = line.data(using: .utf8) {
            if FileManager.default.fileExists(atPath: downloadLogPath.path) {
                if let handle = try? FileHandle(forWritingTo: downloadLogPath) {
                    handle.seekToEndOfFile()
                    handle.write(data)
                    handle.closeFile()
                }
            } else {
                try? data.write(to: downloadLogPath)
            }
        }
    }

    // MARK: - Fetch & Parse

    /// Download subscription content from URL.
    /// Strategy: direct first (bypasses system proxy to avoid Cloudflare), then proxy fallbacks.
    ///   1. Direct curl (--noproxy, bypasses system proxy — like Verge's first attempt)
    ///   2. Direct URLSession (proxy-free session)
    ///   3. Local mihomo proxy if running
    ///   4. System proxy
    ///   5. curl through common local proxy ports
    ///   6. WKWebView with hybrid UA (browser + clash)
    ///   7. WKWebView with browser UA (last resort)
    func downloadContent(url: String, proxyPort: Int? = nil) async throws -> (content: String, userInfo: SubscriptionUserInfo?) {
        guard URL(string: url) != nil else {
            throw SubscriptionError.invalidURL
        }

        var bestError: Error = SubscriptionError.downloadFailed

        func recordError(_ error: Error) {
            if let sub = error as? SubscriptionError {
                switch sub {
                case .serverReturnedHTML, .blockedByServer, .downloadHTTPError:
                    bestError = error
                case .downloadFailed, .invalidContent:
                    break
                default:
                    if case SubscriptionError.downloadFailed = bestError {
                        bestError = error
                    }
                }
            }
        }

        log("\n=== Download started for: \(url) ===")

        // 0. clash-fetcher (reqwest+rustls — same TLS fingerprint as Clash Verge)
        // Bypasses Cloudflare TLS fingerprint detection and system proxy
        log("Step 0: clash-fetcher (rustls TLS, Verge-compatible)...")
        do {
            let result = try await downloadWithClashFetcher(url: url)
            log("Step 0 SUCCESS: \(result.content.count) chars, has proxies: \(result.content.contains("proxies:")), has rules: \(result.content.contains("rules:")), userInfo: \(result.userInfo != nil ? "yes" : "no")")
            return result
        } catch {
            log("Step 0 failed: \(error)")
            recordError(error)
        }

        // 1. Direct curl — truly direct with --noproxy '*', bypasses system proxy
        log("Step 1: Direct curl (bypassing system proxy)...")
        do {
            let result = try await downloadWithCurl(url: url)
            log("Step 1 SUCCESS: \(result.content.count) chars, has proxies: \(result.content.contains("proxies:")), has rules: \(result.content.contains("rules:")), preview: \(String(result.content.prefix(100)))")
            return result
        } catch {
            log("Step 1 failed: \(error)")
            recordError(error)
        }

        // 2. Direct URLSession (proxy-free)
        log("Step 2: Direct URLSession (proxy-free)...")
        do {
            let result = try await downloadWithURLSession(url: url)
            log("Step 2 SUCCESS: \(result.content.count) chars, has proxies: \(result.content.contains("proxies:")), has rules: \(result.content.contains("rules:")), preview: \(String(result.content.prefix(100)))")
            return result
        } catch {
            log("Step 2 failed: \(error)")
            recordError(error)
        }

        // 3. Local mihomo proxy (if our own mihomo is running)
        if let port = proxyPort {
            log("Step 3: Trying local mihomo on port \(port)")
            do {
                let result = try await downloadWithCurlSingleProxy(
                    url: url, proxy: "http://127.0.0.1:\(port)")
                log("Step 3 SUCCESS: \(result.content.count) chars, preview: \(String(result.content.prefix(100)))")
                return result
            } catch {
                log("Step 3 failed: \(error)")
                recordError(error)
            }
        }

        // 4. System proxy
        if let systemProxy = Self.getSystemProxy() {
            log("Step 4: Trying system proxy \(systemProxy.host):\(systemProxy.port)")
            do {
                let result = try await downloadWithCurlSingleProxy(
                    url: url, proxy: "http://\(systemProxy.host):\(systemProxy.port)")
                log("Step 4 SUCCESS: \(result.content.count) chars, preview: \(String(result.content.prefix(100)))")
                return result
            } catch {
                log("Step 4 failed: \(error)")
                recordError(error)
            }
        }

        // 5. curl through common local proxy ports (parallel)
        log("Step 5: Scanning common proxy ports...")
        typealias CurlResult = (content: String, userInfo: SubscriptionUserInfo?)?
        let commonPorts = [7897, 7890, 7891, 1080, 10808, 10809]
            .filter { $0 != proxyPort }
        let proxyResult: CurlResult = await withTaskGroup(of: CurlResult.self) { group in
            for port in commonPorts {
                group.addTask { [self] in
                    try? await downloadWithCurlSingleProxy(
                        url: url, proxy: "http://127.0.0.1:\(port)", timeout: 15)
                }
                group.addTask { [self] in
                    try? await downloadWithCurlSingleProxy(
                        url: url, proxy: "socks5://127.0.0.1:\(port)", timeout: 15)
                }
            }
            for await result in group {
                if let r = result {
                    group.cancelAll()
                    return r
                }
            }
            return nil
        }
        if let result = proxyResult {
            log("Step 5 SUCCESS: \(result.content.count) chars, has proxies: \(result.content.contains("proxies:")), has rules: \(result.content.contains("rules:")), preview: \(String(result.content.prefix(100)))")
            return result
        }
        log("Step 5 failed: no proxy port responded")

        // 6. WKWebView with hybrid UA — browser-like (passes Cloudflare) + contains "clash" (backend returns YAML)
        let hybridUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) clash-verge/v2.4.7 Safari/605.1.15"
        log("Step 6: WKWebView with hybrid UA (browser + clash)...")
        do {
            let webResult = try await WebViewDownloader.download(url: url, timeout: 30, userAgent: hybridUA)
            if !webResult.content.isEmpty {
                log("Step 6 got content: \(webResult.content.count) chars, has proxies: \(webResult.content.contains("proxies:")), has rules: \(webResult.content.contains("rules:")), preview: \(String(webResult.content.prefix(200)))")
                return (webResult.content, nil)
            }
        } catch {
            log("Step 6 failed: \(error)")
            recordError(error)
        }

        // 7. WKWebView with pure browser UA — last resort
        log("Step 7: WKWebView with browser UA (fallback)...")
        do {
            let webResult = try await WebViewDownloader.download(url: url, timeout: 30)
            if !webResult.content.isEmpty {
                log("Step 7 got content: \(webResult.content.count) chars, preview: \(String(webResult.content.prefix(200)))")
                return (webResult.content, nil)
            }
        } catch {
            log("Step 7 failed: \(error)")
            recordError(error)
        }

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

    /// The User-Agent that subscription backends recognize as a Clash client.
    /// Must use -A flag in curl (not -H) to properly override default UA.
    private static let clashUA = "clash-verge/v2.4.7"

    /// Try downloading via curl through a specific proxy. Fast timeout for probing.
    private func downloadWithCurlSingleProxy(url: String, proxy: String, timeout: Int = 10) async throws -> (content: String, userInfo: SubscriptionUserInfo?) {
        let args = ["-sSL", "--compressed", "--max-time", "\(timeout)", "--proxy", proxy,
                    "-A", Self.clashUA,
                    url]
        return try await runCurl(args: args)
    }

    /// curl with extracted Cloudflare cookies + clash UA to get YAML format
    private func downloadWithCurlAndCookies(url: String, cookies: String) async throws -> (content: String, userInfo: SubscriptionUserInfo?) {
        return try await runCurl(args: [
            "-sSL", "--compressed", "--max-time", "15",
            "-A", Self.clashUA,
            "-b", cookies,
            url
        ])
    }

    /// Direct curl download — truly direct, bypasses system proxy with --noproxy '*'
    /// Download using clash-fetcher binary (reqwest+rustls, same TLS fingerprint as Clash Verge)
    /// Bypasses Cloudflare TLS-based blocking. Outputs body to stdout, headers to stderr.
    private func downloadWithClashFetcher(url: String) async throws -> (content: String, userInfo: SubscriptionUserInfo?) {
        // Find clash-fetcher binary: bundled in app > app support > /usr/local/bin
        let binaryPath: String? = {
            if let bundled = Bundle.main.url(forResource: "clash-fetcher", withExtension: nil) {
                return bundled.path
            }
            let appSupport = ConfigStorage.shared.appSupportDirectory
                .appendingPathComponent("bin/clash-fetcher")
            if FileManager.default.fileExists(atPath: appSupport.path) {
                return appSupport.path
            }
            return nil
        }()

        guard let binary = binaryPath else {
            throw SubscriptionError.downloadFailed
        }

        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                let proc = Process()
                proc.executableURL = URL(fileURLWithPath: binary)
                proc.arguments = [url]

                let outPipe = Pipe()
                let errPipe = Pipe()
                proc.standardOutput = outPipe
                proc.standardError = errPipe

                do {
                    try proc.run()
                } catch {
                    continuation.resume(throwing: SubscriptionError.downloadFailed)
                    return
                }

                // Timeout: kill process after 30 seconds
                let timer = DispatchSource.makeTimerSource(queue: .global())
                timer.schedule(deadline: .now() + 30)
                timer.setEventHandler { if proc.isRunning { proc.terminate() } }
                timer.resume()
                proc.waitUntilExit()
                timer.cancel()

                guard proc.terminationStatus == 0 else {
                    continuation.resume(throwing: SubscriptionError.downloadFailed)
                    return
                }

                let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
                let errData = errPipe.fileHandleForReading.readDataToEndOfFile()

                guard let content = String(data: outData, encoding: .utf8),
                      !content.isEmpty else {
                    continuation.resume(throwing: SubscriptionError.invalidContent)
                    return
                }

                // Check for HTML error pages
                if content.contains("<!doctype html>") || content.contains("<html") {
                    if content.contains("403") || content.contains("访问受限") {
                        continuation.resume(throwing: SubscriptionError.blockedByServer)
                    } else {
                        continuation.resume(throwing: SubscriptionError.serverReturnedHTML(String(content.prefix(200))))
                    }
                    return
                }

                // Parse subscription-userinfo from stderr
                var userInfo: SubscriptionUserInfo?
                if let errStr = String(data: errData, encoding: .utf8) {
                    for line in errStr.split(separator: "\n") {
                        if line.lowercased().hasPrefix("subscription-userinfo:") {
                            let value = String(line.dropFirst("subscription-userinfo:".count)).trimmingCharacters(in: .whitespaces)
                            userInfo = SubscriptionUserInfo.parse(value)
                        }
                    }
                }

                continuation.resume(returning: (content, userInfo))
            }
        }
    }

    private func downloadWithCurl(url: String) async throws -> (content: String, userInfo: SubscriptionUserInfo?) {
        do {
            return try await runCurl(args: [
                "-sSL", "--compressed", "--max-time", "10",
                "--noproxy", "*",
                "-A", Self.clashUA,
                "--doh-url", "https://1.1.1.1/dns-query",
                url
            ])
        } catch {}

        return try await runCurl(args: [
            "-sSL", "--compressed", "--max-time", "10",
            "--noproxy", "*",
            "-A", Self.clashUA,
            url
        ])
    }

    /// Native URLSession direct download — uses proxy-free configuration to bypass system proxy
    private func downloadWithURLSession(url: String) async throws -> (content: String, userInfo: SubscriptionUserInfo?) {
        var request = URLRequest(url: URL(string: url)!)
        request.timeoutInterval = 15
        request.setValue("clash-verge/v2.4.7", forHTTPHeaderField: "User-Agent")

        // Create a proxy-free session — URLSession.shared honors system proxy settings,
        // which would route traffic through Verge's proxy and trigger Cloudflare
        let config = URLSessionConfiguration.ephemeral
        config.connectionProxyDictionary = [:]
        let session = URLSession(configuration: config)
        let (data, response) = try await session.data(for: request)

        if let httpResponse = response as? HTTPURLResponse,
           !(200...299).contains(httpResponse.statusCode) {
            throw SubscriptionError.downloadHTTPError(httpResponse.statusCode)
        }

        guard let content = String(data: data, encoding: .utf8)
                ?? String(data: data, encoding: .isoLatin1) else {
            throw SubscriptionError.invalidContent
        }

        // Parse subscription-userinfo from response headers
        var userInfo: SubscriptionUserInfo?
        if let httpResponse = response as? HTTPURLResponse,
           let headerValue = httpResponse.value(forHTTPHeaderField: "subscription-userinfo") {
            userInfo = SubscriptionUserInfo.parse(headerValue)
        }

        return (content, userInfo)
    }

    // MARK: - Shared curl runner

    /// Run curl with given arguments and return output as String + optional subscription user info.
    /// Validates that the response is not an HTML error page.
    private func runCurl(args: [String]) async throws -> (content: String, userInfo: SubscriptionUserInfo?) {
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                let headerFile = URL(fileURLWithPath: NSTemporaryDirectory())
                    .appendingPathComponent(UUID().uuidString + ".headers")
                defer { try? FileManager.default.removeItem(at: headerFile) }

                let process = Process()
                process.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
                process.arguments = ["-D", headerFile.path] + args

                let outputPipe = Pipe()
                process.standardOutput = outputPipe
                process.standardError = Pipe()

                do { try process.run() } catch {
                    continuation.resume(throwing: SubscriptionError.downloadFailed)
                    return
                }

                let data = outputPipe.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()

                let content = String(data: data, encoding: .utf8) ?? ""

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

                // Parse subscription-userinfo from response headers
                var userInfo: SubscriptionUserInfo?
                if let headers = try? String(contentsOf: headerFile, encoding: .utf8) {
                    for line in headers.components(separatedBy: .newlines) {
                        if line.lowercased().hasPrefix("subscription-userinfo:") {
                            let value = String(line.dropFirst("subscription-userinfo:".count))
                                .trimmingCharacters(in: .whitespaces)
                            userInfo = SubscriptionUserInfo.parse(value)
                            break
                        }
                    }
                }

                continuation.resume(returning: (content, userInfo))
            }
        }
    }

    /// Download and parse subscription from URL
    func fetchSubscription(url: String, proxyPort: Int? = nil) async throws -> (nodes: [ProxyNode], rawContent: String, userInfo: SubscriptionUserInfo?) {
        let (content, userInfo) = try await downloadContent(url: url, proxyPort: proxyPort)

        let resolved = resolveContent(content)

        // If content is not Clash YAML, retry with flag=clash to request YAML format
        if !resolved.contains("proxies:") {
            if let clashURL = Self.appendClashFlag(url) {
                log("Content is not YAML format, retrying with flag=clash: \(clashURL)")
                if let (retryContent, retryUserInfo) = try? await downloadContent(url: clashURL, proxyPort: proxyPort) {
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
            let preview = String(resolved.prefix(200))
                .replacingOccurrences(of: "\n", with: " ")
                .replacingOccurrences(of: "<[^>]+>", with: "", options: .regularExpression)
                .trimmingCharacters(in: .whitespaces)
            let trimmedStart = resolved.prefix(500).lowercased()
            if trimmedStart.contains("<!doctype") || trimmedStart.contains("<html") {
                throw SubscriptionError.serverReturnedHTML(preview)
            }
            throw SubscriptionError.parseFailedWithPreview(preview)
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
    func fetchAndOrganize(url: String, proxyPort: Int? = nil) async throws -> ([ProxyRegion], String, SubscriptionUserInfo?) {
        let (nodes, rawContent, headerInfo) = try await fetchSubscription(url: url, proxyPort: proxyPort)
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
    func fetchAllAndOrganize(_ subscriptions: [SubscriptionInfo], proxyPort: Int? = nil) async throws -> ([ProxyRegion], [SubscriptionInfo], String) {
        var allNodes: [ProxyNode] = []
        var allRawContents: [String] = []
        var updatedSubs = subscriptions
        var lastError: Error?

        for i in updatedSubs.indices where updatedSubs[i].isEnabled {
            do {
                let (nodes, rawContent, headerInfo) = try await fetchSubscription(url: updatedSubs[i].url, proxyPort: proxyPort)
                let (realNodes, nodeInfo) = Self.extractInfoNodes(nodes)
                allNodes.append(contentsOf: realNodes)
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
