import Foundation

// MARK: - Clash RESTful API Client

actor ClashAPI {
    let baseURL: URL
    let secret: String
    private let session: URLSession

    init(host: String = "127.0.0.1", port: Int = 9090, secret: String = "") {
        self.baseURL = URL(string: "http://\(host):\(port)")!
        self.secret = secret
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 5
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.urlCache = nil
        config.waitsForConnectivity = false
        self.session = URLSession(configuration: config)
    }

    // MARK: - Generic Request

    private func makeURL(_ path: String) -> URL {
        URL(string: baseURL.absoluteString + path)!
    }

    private func request<T: Decodable>(_ path: String, method: String = "GET", body: Data? = nil) async throws -> T {
        var urlRequest = URLRequest(url: makeURL(path))
        urlRequest.httpMethod = method
        urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if !secret.isEmpty {
            urlRequest.setValue("Bearer \(secret)", forHTTPHeaderField: "Authorization")
        }
        urlRequest.httpBody = body

        let (data, response) = try await session.data(for: urlRequest)
        guard let httpResponse = response as? HTTPURLResponse,
              (200...299).contains(httpResponse.statusCode) else {
            throw ClashAPIError.requestFailed(path)
        }
        return try JSONDecoder().decode(T.self, from: data)
    }

    private func requestVoid(_ path: String, method: String, body: Data? = nil) async throws {
        var urlRequest = URLRequest(url: makeURL(path))
        urlRequest.httpMethod = method
        urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if !secret.isEmpty {
            urlRequest.setValue("Bearer \(secret)", forHTTPHeaderField: "Authorization")
        }
        urlRequest.httpBody = body

        let (_, response) = try await session.data(for: urlRequest)
        guard let httpResponse = response as? HTTPURLResponse,
              (200...299).contains(httpResponse.statusCode) else {
            throw ClashAPIError.requestFailed(path)
        }
    }

    /// Raw data request for manual JSON parsing
    func requestRawData(_ path: String) async throws -> Data {
        var urlRequest = URLRequest(url: makeURL(path))
        urlRequest.httpMethod = "GET"
        if !secret.isEmpty {
            urlRequest.setValue("Bearer \(secret)", forHTTPHeaderField: "Authorization")
        }
        let (data, response) = try await session.data(for: urlRequest)
        guard let httpResponse = response as? HTTPURLResponse,
              (200...299).contains(httpResponse.statusCode) else {
            throw ClashAPIError.requestFailed(path)
        }
        return data
    }

    /// Query Mihomo's raw upstream resolver. Unlike the protected fake-IP DNS
    /// listener, this controller endpoint returns real records while its DoH
    /// transport still follows Tono-Exit.
    func resolveIPv4(_ host: String) async throws -> [String] {
        var components = URLComponents(
            url: makeURL("/dns/query"),
            resolvingAgainstBaseURL: false
        )
        components?.queryItems = [
            URLQueryItem(name: "name", value: host),
            URLQueryItem(name: "type", value: "A"),
        ]
        guard let url = components?.url else {
            throw ClashAPIError.requestFailed("/dns/query")
        }
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = "GET"
        urlRequest.timeoutInterval = 2
        if !secret.isEmpty {
            urlRequest.setValue("Bearer \(secret)", forHTTPHeaderField: "Authorization")
        }
        let (data, response) = try await session.data(for: urlRequest)
        guard let httpResponse = response as? HTTPURLResponse,
              (200...299).contains(httpResponse.statusCode),
              let answer = try? JSONDecoder().decode(
                APIDNSQueryResponse.self,
                from: data
              ),
              answer.status == 0 else {
            throw ClashAPIError.requestFailed("/dns/query")
        }
        return answer.answers
            .filter { $0.type == 1 }
            .map(\.data)
    }

    // MARK: - Version

    func getVersion() async throws -> APIVersion {
        try await request("/version")
    }

    // MARK: - Config

    func getConfig() async throws -> APIConfig {
        try await request("/configs")
    }

    func patchConfig(_ patch: [String: Any]) async throws {
        let body = try JSONSerialization.data(withJSONObject: patch)
        try await requestVoid("/configs", method: "PATCH", body: body)
    }

    func updateMode(_ mode: String) async throws {
        try await patchConfig(["mode": mode])
    }

    // MARK: - Proxies

    func getProxies() async throws -> APIProxiesResponse {
        try await request("/proxies")
    }

    /// Characters safe for a single URL path segment (no `/`, `?`, `#`, etc.)
    private static let pathSegmentAllowed: CharacterSet = {
        var cs = CharacterSet.urlPathAllowed
        cs.remove("/")
        return cs
    }()

    func selectProxy(group: String, proxy: String) async throws {
        let body = try JSONEncoder().encode(["name": proxy])
        let encodedGroup = group.addingPercentEncoding(withAllowedCharacters: Self.pathSegmentAllowed) ?? group
        try await requestVoid("/proxies/\(encodedGroup)", method: "PUT", body: body)
    }

    /// Test proxy delay. Like Verge: non-2xx → delay=0 (timeout), never throws for test failures.
    func testProxyDelay(name: String, url: String = "http://www.gstatic.com/generate_204", timeout: Int = 5000) async -> APIDelayResponse {
        let encodedName = name.addingPercentEncoding(withAllowedCharacters: Self.pathSegmentAllowed) ?? name
        let encodedURL = url.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? url
        let path = "/proxies/\(encodedName)/delay?url=\(encodedURL)&timeout=\(timeout)"

        var urlRequest = URLRequest(url: makeURL(path))
        urlRequest.httpMethod = "GET"
        // Mihomo owns the probe deadline. Keep only a one-second local grace
        // period instead of making every failed selection appear frozen for
        // an additional three seconds.
        urlRequest.timeoutInterval = max(1, TimeInterval(timeout) / 1_000 + 1)
        if !secret.isEmpty {
            urlRequest.setValue("Bearer \(secret)", forHTTPHeaderField: "Authorization")
        }

        do {
            let (data, response) = try await session.data(for: urlRequest)
            guard let httpResponse = response as? HTTPURLResponse else {
                return APIDelayResponse(delay: 0, message: "No response")
            }
            if httpResponse.statusCode >= 200 && httpResponse.statusCode < 300 {
                return (try? JSONDecoder().decode(APIDelayResponse.self, from: data))
                    ?? APIDelayResponse(delay: 0, message: nil)
            }
            // Non-2xx: mark as timeout (like Verge)
            return APIDelayResponse(delay: 0, message: "timeout")
        } catch {
            return APIDelayResponse(delay: 0, message: error.localizedDescription)
        }
    }

    /// Reality handshakes can be briefly cold immediately after the protected
    /// TUN and PF rules come up. Transactional operations (initial connect,
    /// node switch, and config replacement) should not tear down an otherwise
    /// healthy tunnel because of one transient probe failure.
    func testProxyDelayWithRetry(
        name: String,
        url: String = "http://www.gstatic.com/generate_204",
        timeout: Int = 5000,
        attempts: Int = 3,
        retryIntervalMs: UInt64 = 500
    ) async -> APIDelayResponse {
        let attemptCount = max(1, attempts)
        var latest = APIDelayResponse(delay: 0, message: nil)

        for attempt in 0..<attemptCount {
            if Task.isCancelled {
                return latest
            }

            latest = await testProxyDelay(name: name, url: url, timeout: timeout)
            if let delay = latest.delay, delay > 0 {
                return latest
            }

            guard attempt + 1 < attemptCount else { break }
            do {
                try await Task.sleep(for: .milliseconds(retryIntervalMs))
            } catch {
                return latest
            }
        }

        return latest
    }

    // MARK: - Health Check

    /// Poll the loopback controller until it responds. A normal restart answers
    /// immediately, but the first root-owned launch after a helper replacement
    /// can spend several seconds initializing gVisor/TUN before binding the
    /// controller. Keep each request short while allowing that bounded first-run
    /// grace period; Build 17's three-second refusal window produced a false
    /// startup failure even though the same core connected on the next click.
    func waitUntilReady(maxAttempts: Int = 40, intervalMs: UInt64 = 250) async throws {
        let attemptCount = max(1, maxAttempts)
        for attempt in 0..<attemptCount {
            try Task.checkCancellation()
            do {
                var urlRequest = URLRequest(url: makeURL("/version"))
                urlRequest.httpMethod = "GET"
                urlRequest.timeoutInterval = 0.75
                if !secret.isEmpty {
                    urlRequest.setValue("Bearer \(secret)", forHTTPHeaderField: "Authorization")
                }
                let (data, response) = try await session.data(for: urlRequest)
                guard let httpResponse = response as? HTTPURLResponse,
                      (200...299).contains(httpResponse.statusCode) else {
                    throw ClashAPIError.requestFailed("/version")
                }
                _ = try JSONDecoder().decode(APIVersion.self, from: data)
                return // Core is ready
            } catch {
                try Task.checkCancellation()
                guard attempt + 1 < attemptCount else { break }
                try await Task.sleep(for: .milliseconds(intervalMs))
            }
        }
        throw ClashAPIError.requestFailed("核心未能在规定时间内就绪")
    }

    // MARK: - Reload Config

    /// Tell mihomo to reload config from disk (PUT /configs?force=true)
    func reloadConfig(path: String) async throws {
        let body = try JSONEncoder().encode(["path": path])
        let maximumAttempts = 2
        for attempt in 1...maximumAttempts {
            try Task.checkCancellation()
            var urlRequest = URLRequest(
                url: URL(
                    string: baseURL.absoluteString + "/configs?force=true"
                )!
            )
            urlRequest.httpMethod = "PUT"
            // Mihomo applies a full catalog/policy config synchronously and may
            // recreate TUN when its route fingerprint changes. The session-wide
            // five-second timeout can therefore report failure while that apply
            // is still completing. A repeated PUT of the same root-owned config
            // is idempotent; require a definite 2xx before proceeding.
            urlRequest.timeoutInterval = 30
            urlRequest.setValue(
                "application/json",
                forHTTPHeaderField: "Content-Type"
            )
            if !secret.isEmpty {
                urlRequest.setValue(
                    "Bearer \(secret)",
                    forHTTPHeaderField: "Authorization"
                )
            }
            urlRequest.httpBody = body

            do {
                let (_, response) = try await session.data(for: urlRequest)
                guard let httpResponse = response as? HTTPURLResponse,
                      (200...299).contains(httpResponse.statusCode) else {
                    throw ClashAPIError.requestFailed(
                        "PUT /configs?force=true"
                    )
                }
                return
            } catch let error as URLError
                where error.code == .timedOut
                    || error.code == .networkConnectionLost
                    || error.code == .cannotConnectToHost
            {
                guard attempt < maximumAttempts else { throw error }
                // The first apply may still own Mihomo's config mutex. Wait
                // until the local controller is responsive, then reissue the
                // same config and accept only its explicit success response.
                try await waitUntilReady(
                    maxAttempts: 20,
                    intervalMs: 500
                )
            }
        }
    }

    // MARK: - Rules

    func getRules() async throws -> APIRulesResponse {
        try await request("/rules")
    }

    func getRuleProviders() async throws -> APIRuleProvidersResponse {
        try await request("/providers/rules")
    }

    /// Fetch rules for a specific provider. Returns (type, payload) tuples.
    /// Mihomo returns rules as either [String] or [{type, payload}] depending on version.
    func getProviderRules(name: String) async throws -> [(type: String?, payload: String)] {
        let encoded = name.addingPercentEncoding(withAllowedCharacters: Self.pathSegmentAllowed) ?? name
        let data = try await requestRawData("/providers/rules/\(encoded)")

        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let rules = json["rules"] else {
            return []
        }

        // rules can be [String] or [[String: Any]]
        if let stringRules = rules as? [String] {
            return stringRules.map { (type: nil, payload: $0) }
        } else if let objectRules = rules as? [[String: Any]] {
            return objectRules.compactMap { obj in
                guard let payload = obj["payload"] as? String else { return nil }
                return (type: obj["type"] as? String, payload: payload)
            }
        }
        return []
    }

    // MARK: - Connections

    func getConnections() async throws -> APIConnectionsResponse {
        try await request("/connections")
    }

    func closeAllConnections() async throws {
        try await requestVoid("/connections", method: "DELETE")
    }

    func closeConnection(id: String) async throws {
        try await requestVoid("/connections/\(id)", method: "DELETE")
    }
}

// MARK: - API Response Models

nonisolated struct APIVersion: Codable, Sendable {
    let version: String
    let meta: Bool?
}

nonisolated struct APIConfig: Codable, Sendable {
    let port: Int?
    let socksPort: Int?
    let mixedPort: Int?
    let allowLan: Bool?
    let mode: String?
    let logLevel: String?

    enum CodingKeys: String, CodingKey {
        case port
        case socksPort = "socks-port"
        case mixedPort = "mixed-port"
        case allowLan = "allow-lan"
        case mode
        case logLevel = "log-level"
    }
}

nonisolated struct APIProxiesResponse: Codable, Sendable {
    let proxies: [String: APIProxy]
}

nonisolated struct APIProxy: Codable, Sendable {
    let type: String
    let now: String?
    let all: [String]?
    let history: [APIProxyHistory]?
}

nonisolated struct APIProxyHistory: Codable, Sendable {
    let time: String?
    let delay: Int
}

nonisolated struct APIDelayResponse: Codable, Sendable {
    let delay: Int?
    let message: String?
}

nonisolated struct APIRulesResponse: Codable, Sendable {
    let rules: [APIRule]
}

nonisolated struct APIRule: Codable, Identifiable, Sendable {
    let type: String
    let payload: String
    let proxy: String

    var id: String { "\(type)|\(payload)|\(proxy)" }
}

nonisolated struct APIRuleProvidersResponse: Codable, Sendable {
    let providers: [String: APIRuleProvider]
}

nonisolated struct APIRuleProvider: Codable, Sendable {
    let name: String
    let type: String
    let behavior: String
    let ruleCount: Int
    let updatedAt: String?
    let vehicleType: String?
}


nonisolated struct APIConnectionsResponse: Codable, Sendable {
    let downloadTotal: Int64
    let uploadTotal: Int64
    let connections: [APIConnection]?
}

nonisolated struct APIConnection: Codable, Sendable {
    let id: String
    let metadata: APIConnectionMetadata
    let upload: Int64
    let download: Int64
    let start: String
    let chains: [String]
    let rule: String
    let rulePayload: String?
}

nonisolated struct APIConnectionMetadata: Codable, Sendable {
    let network: String
    let type: String
    let process: String?
    let processPath: String?
    let sourceIP: String?
    let destinationIP: String?
    let sourcePort: String?
    let destinationPort: String?
    let host: String
}

nonisolated private struct APIDNSQueryResponse: Decodable, Sendable {
    let status: Int
    let answers: [APIDNSRecord]

    private enum CodingKeys: String, CodingKey {
        case status = "Status"
        case answers = "Answer"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        status = try container.decode(Int.self, forKey: .status)
        answers = try container.decodeIfPresent(
            [APIDNSRecord].self,
            forKey: .answers
        ) ?? []
    }
}

nonisolated private struct APIDNSRecord: Decodable, Sendable {
    let type: Int
    let data: String
}

// MARK: - API Error

nonisolated enum ClashAPIError: LocalizedError {
    case requestFailed(String)
    case decodingFailed

    var errorDescription: String? {
        switch self {
        case .requestFailed(let path): "API request failed: \(path)"
        case .decodingFailed: "Failed to decode API response"
        }
    }
}
