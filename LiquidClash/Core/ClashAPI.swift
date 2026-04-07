import Foundation

// MARK: - Clash RESTful API Client

actor ClashAPI {
    let baseURL: URL
    let secret: String
    private let session: URLSession

    init(host: String = "127.0.0.1", port: Int = 9090, secret: String = "") {
        self.baseURL = URL(string: "http://\(host):\(port)")!
        self.secret = secret
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 5
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

    func testProxyDelay(name: String, url: String = "http://www.gstatic.com/generate_204", timeout: Int = 5000) async throws -> APIDelayResponse {
        let encodedName = name.addingPercentEncoding(withAllowedCharacters: Self.pathSegmentAllowed) ?? name
        let encodedURL = url.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? url
        let data = try await requestRawData("/proxies/\(encodedName)/delay?url=\(encodedURL)&timeout=\(timeout)")
        return try JSONDecoder().decode(APIDelayResponse.self, from: data)
    }

    // MARK: - Health Check

    /// Poll the core until it responds to /version, or give up after maxAttempts.
    func waitUntilReady(maxAttempts: Int = 30, intervalMs: UInt64 = 500) async throws {
        for _ in 0..<maxAttempts {
            do {
                let _: APIVersion = try await request("/version")
                return // Core is ready
            } catch {
                try await Task.sleep(nanoseconds: intervalMs * 1_000_000)
            }
        }
        throw ClashAPIError.requestFailed("核心未能在规定时间内就绪")
    }

    // MARK: - Reload Config

    /// Tell mihomo to reload config from disk (PUT /configs?force=true)
    func reloadConfig(path: String) async throws {
        let body = try JSONEncoder().encode(["path": path])
        var urlRequest = URLRequest(url: URL(string: baseURL.absoluteString + "/configs?force=true")!)
        urlRequest.httpMethod = "PUT"
        urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if !secret.isEmpty {
            urlRequest.setValue("Bearer \(secret)", forHTTPHeaderField: "Authorization")
        }
        urlRequest.httpBody = body

        let (_, response) = try await session.data(for: urlRequest)
        guard let httpResponse = response as? HTTPURLResponse,
              (200...299).contains(httpResponse.statusCode) else {
            throw ClashAPIError.requestFailed("PUT /configs?force=true")
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

struct APIVersion: Codable {
    let version: String
    let meta: Bool?
}

struct APIConfig: Codable {
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

struct APIProxiesResponse: Codable {
    let proxies: [String: APIProxy]
}

struct APIProxy: Codable {
    let type: String
    let now: String?
    let all: [String]?
    let history: [APIProxyHistory]?
}

struct APIProxyHistory: Codable {
    let time: String?
    let delay: Int
}

struct APIDelayResponse: Codable {
    let delay: Int?
    let message: String?
}

struct APIRulesResponse: Codable {
    let rules: [APIRule]
}

struct APIRule: Codable, Identifiable {
    let type: String
    let payload: String
    let proxy: String

    var id: String { "\(type)|\(payload)|\(proxy)" }
}

struct APIRuleProvidersResponse: Codable {
    let providers: [String: APIRuleProvider]
}

struct APIRuleProvider: Codable {
    let name: String
    let type: String
    let behavior: String
    let ruleCount: Int
    let updatedAt: String?
    let vehicleType: String?
}


struct APIConnectionsResponse: Codable {
    let downloadTotal: Int64
    let uploadTotal: Int64
    let connections: [APIConnection]?
}

struct APIConnection: Codable {
    let id: String
    let metadata: APIConnectionMetadata
    let upload: Int64
    let download: Int64
    let start: String
    let chains: [String]
    let rule: String
    let rulePayload: String?
}

struct APIConnectionMetadata: Codable {
    let network: String
    let type: String
    let sourceIP: String?
    let destinationIP: String?
    let sourcePort: String?
    let destinationPort: String?
    let host: String
}

// MARK: - API Error

enum ClashAPIError: LocalizedError {
    case requestFailed(String)
    case decodingFailed

    var errorDescription: String? {
        switch self {
        case .requestFailed(let path): "API request failed: \(path)"
        case .decodingFailed: "Failed to decode API response"
        }
    }
}
