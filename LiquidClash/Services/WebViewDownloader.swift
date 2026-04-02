import Foundation
import WebKit

/// Downloads URL content using a hidden WKWebView.
/// This bypasses Cloudflare JS challenges because WKWebView has a full
/// JavaScript engine that can solve the challenge automatically.
@MainActor
final class WebViewDownloader: NSObject, WKNavigationDelegate {
    private var webView: WKWebView?
    private var continuation: CheckedContinuation<String, Error>?
    private var completed = false
    private var loadCount = 0
    private var timeoutTask: Task<Void, Never>?

    /// Download content from a URL using a hidden WKWebView.
    /// The WebView solves Cloudflare JS challenges automatically.
    static func download(url: String, timeout: TimeInterval = 20) async throws -> String {
        guard let parsedURL = URL(string: url) else {
            throw SubscriptionError.invalidURL
        }

        let downloader = WebViewDownloader()
        return try await downloader.performDownload(url: parsedURL, timeout: timeout)
    }

    private func performDownload(url: URL, timeout: TimeInterval) async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            self.completed = false
            self.loadCount = 0

            let config = WKWebViewConfiguration()
            config.websiteDataStore = .nonPersistent()
            let webView = WKWebView(frame: CGRect(x: 0, y: 0, width: 1, height: 1), configuration: config)
            webView.navigationDelegate = self
            webView.customUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"
            self.webView = webView

            webView.load(URLRequest(url: url))

            // Timeout
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

            // Cloudflare typically does: challenge page → JS solve → redirect → real content
            // Wait a moment for potential redirect after challenge
            try? await Task.sleep(for: .milliseconds(loadCount == 1 ? 1500 : 500))

            guard !self.completed else { return }

            // Extract the page text content
            webView.evaluateJavaScript("document.body.innerText || document.documentElement.textContent || ''") { [weak self] result, error in
                guard let self, !self.completed else { return }

                Task { @MainActor in
                    if let text = result as? String, !text.isEmpty {
                        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)

                        // Check if it's still a Cloudflare challenge page
                        if trimmed.contains("访问受限") || trimmed.contains("challenge") ||
                           trimmed.contains("Checking your browser") {
                            // Still on challenge page, wait for next navigation
                            if self.loadCount < 5 { return }
                            // Too many attempts, give up
                            self.finish(with: .failure(SubscriptionError.serverReturnedHTML(
                                String(trimmed.prefix(200))
                            )))
                        } else if trimmed.contains("proxies:") || trimmed.contains("proxy-groups:") ||
                                  trimmed.contains("port:") || trimmed.contains("mixed-port:") {
                            // Looks like valid Clash config!
                            self.finish(with: .success(trimmed))
                        } else if self.loadCount >= 3 {
                            // After multiple loads, return whatever we have
                            self.finish(with: .success(trimmed))
                        }
                        // Otherwise wait for more navigations
                    } else if self.loadCount >= 3 {
                        self.finish(with: .failure(SubscriptionError.invalidContent))
                    }
                }
            }
        }
    }

    nonisolated func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        Task { @MainActor in
            self.finish(with: .failure(SubscriptionError.downloadFailed))
        }
    }

    nonisolated func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        Task { @MainActor in
            self.finish(with: .failure(SubscriptionError.downloadFailed))
        }
    }

    // MARK: - Completion

    private func finish(with result: Result<String, Error>) {
        guard !completed else { return }
        completed = true
        timeoutTask?.cancel()
        timeoutTask = nil
        webView?.stopLoading()
        webView?.navigationDelegate = nil
        webView = nil

        switch result {
        case .success(let content):
            continuation?.resume(returning: content)
        case .failure(let error):
            continuation?.resume(throwing: error)
        }
        continuation = nil
    }
}
