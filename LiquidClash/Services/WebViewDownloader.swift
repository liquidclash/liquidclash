import Foundation
import WebKit

/// Result from WKWebView download, includes cookies for subsequent requests
struct WebViewDownloadResult {
    let content: String
    let cookies: [HTTPCookie]
}

/// Downloads URL content using a hidden WKWebView.
/// WKWebView's JS engine can solve Cloudflare challenges regardless of User-Agent.
/// After the challenge is solved, the page reloads and returns content matching the UA.
@MainActor
final class WebViewDownloader: NSObject, WKNavigationDelegate {
    private var webView: WKWebView?
    private var continuation: CheckedContinuation<WebViewDownloadResult, Error>?
    private var completed = false
    private var loadCount = 0
    private var timeoutTask: Task<Void, Never>?
    private var targetURL: URL?
    private var lastBodyHash: Int = 0
    private var sameContentCount = 0

    /// Download content from a URL using a hidden WKWebView.
    /// - Parameters:
    ///   - url: The URL to download
    ///   - timeout: Maximum time to wait
    ///   - userAgent: Custom UA (e.g. "clash-verge/v2.4.7" for YAML format). Defaults to Safari UA.
    static func download(url: String, timeout: TimeInterval = 30, userAgent: String? = nil) async throws -> WebViewDownloadResult {
        guard let parsedURL = URL(string: url) else {
            throw SubscriptionError.invalidURL
        }

        let downloader = WebViewDownloader()
        return try await downloader.performDownload(url: parsedURL, timeout: timeout, userAgent: userAgent)
    }

    private func performDownload(url: URL, timeout: TimeInterval, userAgent: String?) async throws -> WebViewDownloadResult {
        try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            self.completed = false
            self.loadCount = 0
            self.targetURL = url
            self.lastBodyHash = 0
            self.sameContentCount = 0

            let config = WKWebViewConfiguration()
            config.websiteDataStore = .nonPersistent()
            let webView = WKWebView(frame: CGRect(x: 0, y: 0, width: 1, height: 1), configuration: config)
            webView.navigationDelegate = self
            webView.customUserAgent = userAgent ?? "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"
            self.webView = webView

            print("[LiquidClash] WKWebView loading with UA: \(webView.customUserAgent ?? "nil")")
            webView.load(URLRequest(url: url))

            self.timeoutTask = Task { @MainActor [weak self] in
                try? await Task.sleep(for: .seconds(timeout))
                self?.finish(with: .failure(SubscriptionError.downloadFailed))
            }
        }
    }

    // MARK: - WKNavigationDelegate

    nonisolated func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        Task { @MainActor in
            self.loadCount += 1
            print("[LiquidClash] WKWebView didFinish #\(self.loadCount), URL: \(webView.url?.absoluteString ?? "nil")")

            // Wait briefly for potential Cloudflare redirect
            try? await Task.sleep(for: .milliseconds(loadCount == 1 ? 2000 : 500))

            guard !self.completed else { return }

            // Check page content
            let checkJS = """
            (function() {
                var title = document.title || '';
                var body = (document.body.textContent || '').substring(0, 1000);
                var fullLen = (document.body.textContent || '').length;
                return JSON.stringify({title: title, body: body, fullLen: fullLen});
            })()
            """
            webView.evaluateJavaScript(checkJS) { [weak self] result, error in
                guard let self, !self.completed else { return }

                Task { @MainActor in
                    guard let jsonStr = result as? String,
                          let data = jsonStr.data(using: .utf8),
                          let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                        // Can't parse — probably still loading
                        if self.loadCount >= 6 {
                            self.finish(with: .failure(SubscriptionError.downloadFailed))
                        }
                        return
                    }

                    let title = json["title"] as? String ?? ""
                    let body = json["body"] as? String ?? ""
                    let fullLen = json["fullLen"] as? Int ?? 0

                    print("[LiquidClash] Page title: \(title.prefix(50)), body length: \(fullLen), preview: \(body.prefix(80))")

                    // Check if content looks like subscription data (YAML or URI list)
                    let trimmedBody = body.trimmingCharacters(in: .whitespacesAndNewlines)
                    if fullLen > 100 && self.looksLikeSubscriptionContent(trimmedBody) {
                        print("[LiquidClash] Content looks like subscription data, extracting...")
                        await self.extractCookiesAndContent()
                        return
                    }

                    // Detect if page is stuck (same content after multiple loads = hard block, not solvable challenge)
                    let bodyHash = body.hashValue
                    if bodyHash == self.lastBodyHash {
                        self.sameContentCount += 1
                        if self.sameContentCount >= 2 {
                            print("[LiquidClash] Page stuck on same content after \(self.loadCount) loads, giving up")
                            // Still return what we have (content + cookies)
                            await self.extractCookiesAndContent()
                            return
                        }
                    } else {
                        self.sameContentCount = 0
                        self.lastBodyHash = bodyHash
                    }

                    // Check for challenge/block pages
                    let isChallenge = self.detectChallengePage(title: title, body: body)
                    if isChallenge {
                        print("[LiquidClash] Challenge/block page detected, waiting... (load #\(self.loadCount))")
                        if self.loadCount >= 6 {
                            // Return whatever we have as a last resort
                            await self.extractCookiesAndContent()
                        }
                        return
                    }

                    // Content is not subscription data but also not a challenge — extract anyway
                    print("[LiquidClash] Unknown content type, extracting as-is")
                    await self.extractCookiesAndContent()
                }
            }
        }
    }

    /// Check if content looks like subscription data
    private func looksLikeSubscriptionContent(_ body: String) -> Bool {
        // Clash YAML
        if body.contains("proxies:") || body.contains("proxy-groups:") || body.contains("mixed-port:") {
            return true
        }
        // URI format (trojan://, ss://, vmess://, vless://, etc.)
        if body.hasPrefix("trojan://") || body.hasPrefix("ss://") ||
           body.hasPrefix("vmess://") || body.hasPrefix("vless://") {
            return true
        }
        // Base64 content (long string without spaces/newlines)
        let firstLine = body.prefix(200)
        if firstLine.count > 100 && !firstLine.contains(" ") && !firstLine.contains("\n") {
            return true
        }
        return false
    }

    /// Detect if the current page is a Cloudflare challenge or block page
    private func detectChallengePage(title: String, body: String) -> Bool {
        let combined = title + " " + body

        // Cloudflare challenge indicators
        if combined.contains("Just a moment") || combined.contains("Checking your browser") ||
           combined.contains("Attention Required") || combined.contains("challenge-platform") {
            return true
        }

        // Chinese challenge page indicators
        if combined.contains("访问受限") || combined.contains("无法访问") ||
           combined.contains("正在验证") || combined.contains("请稍候") {
            return true
        }

        // Very short content = likely still loading
        if body.trimmingCharacters(in: .whitespacesAndNewlines).count < 20 {
            return true
        }

        return false
    }

    /// Extract cookies from WKWebView's cookie store and page content
    private func extractCookiesAndContent() async {
        guard let webView else {
            finish(with: .failure(SubscriptionError.downloadFailed))
            return
        }

        // Extract all cookies from the WKWebView's data store
        let cookies = await webView.configuration.websiteDataStore.httpCookieStore.allCookies()
        print("[LiquidClash] Extracted \(cookies.count) cookies: \(cookies.map { $0.name }.joined(separator: ", "))")

        // Get full page content
        let js = "document.body.textContent || document.body.innerText || ''"
        webView.evaluateJavaScript(js) { [weak self] result, error in
            guard let self, !self.completed else { return }

            Task { @MainActor in
                let content: String
                if let text = result as? String {
                    content = text.trimmingCharacters(in: .whitespacesAndNewlines)
                } else {
                    content = ""
                }
                print("[LiquidClash] Final content length: \(content.count), has proxies: \(content.contains("proxies:")), has rules: \(content.contains("rules:"))")
                self.finish(with: .success(WebViewDownloadResult(content: content, cookies: cookies)))
            }
        }
    }

    nonisolated func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        Task { @MainActor in
            print("[LiquidClash] WKWebView didFail: \(error.localizedDescription)")
            self.finish(with: .failure(SubscriptionError.downloadFailed))
        }
    }

    nonisolated func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        Task { @MainActor in
            print("[LiquidClash] WKWebView didFailProvisional: \(error.localizedDescription)")
            self.finish(with: .failure(SubscriptionError.downloadFailed))
        }
    }

    // MARK: - Completion

    private func finish(with result: Result<WebViewDownloadResult, Error>) {
        guard !completed else { return }
        completed = true
        timeoutTask?.cancel()
        timeoutTask = nil
        webView?.stopLoading()
        webView?.navigationDelegate = nil
        webView = nil

        switch result {
        case .success(let downloadResult):
            continuation?.resume(returning: downloadResult)
        case .failure(let error):
            continuation?.resume(throwing: error)
        }
        continuation = nil
    }
}
