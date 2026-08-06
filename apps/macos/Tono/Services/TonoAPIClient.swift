import Foundation

nonisolated private final class TonoNoRedirectDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        // Control-plane endpoints are a fixed origin. Following redirects risks
        // changing the authority of requests carrying access or refresh tokens.
        completionHandler(nil)
    }
}

actor TonoAPIClient {
    enum APIError: LocalizedError, Equatable {
        case invalidConfiguration, transport(String), unauthorized, forbidden, notFound
        case deviceLimit, server(status: Int, message: String), invalidResponse
        var errorDescription: String? {
            switch self {
            case .invalidConfiguration: "Tono service is not configured."
            case .transport: "Could not reach Tono. Check your connection and try again."
            case .unauthorized: "Your session has expired. Please sign in again."
            case .forbidden: "This account does not have permission for that action."
            case .notFound: "The requested item no longer exists."
            case .deviceLimit: "This Tono account has reached its device allowance. Revoke another device first."
            case let .server(_, message): message
            case .invalidResponse: "Tono returned an invalid response."
            }
        }
    }

    private struct APIErrorBody: Decodable { let message: String?; let code: String? }
    private struct ErrorEnvelope: Decodable { let error: APIErrorBody }
    private let baseURL: URL
    private let session: URLSession
    private let keychain: KeychainStore
    private var accessToken: String?
    private var refreshTask: Task<String, Error>?
    /// A rotated refresh token whose keychain write failed. The server has
    /// already invalidated the previous token, so this value must stay usable
    /// in-memory (and be re-persisted at the next opportunity) or the user is
    /// irreversibly logged out by a transient keychain error.
    private var unpersistedRefreshToken: String?

    init(baseURL: URL = TonoAPIClient.configuredBaseURL(), keychain: KeychainStore = KeychainStore(), session: URLSession? = nil) {
        self.baseURL = baseURL
        self.keychain = keychain
        if let session { self.session = session } else {
            let configuration = URLSessionConfiguration.ephemeral
            // Mainland cross-border paths can take several seconds to recover
            // DNS, TLS, or connectivity. Keep the wait bounded, but do not
            // turn a short network transition into an immediate login error.
            configuration.timeoutIntervalForRequest = 30
            configuration.timeoutIntervalForResource = 45
            configuration.waitsForConnectivity = true
            configuration.httpCookieStorage = nil
            configuration.httpShouldSetCookies = false
            self.session = URLSession(
                configuration: configuration,
                delegate: TonoNoRedirectDelegate(),
                delegateQueue: nil
            )
        }
    }

    nonisolated static func configuredBaseURL(bundle: Bundle = .main, environment: [String: String] = ProcessInfo.processInfo.environment) -> URL {
        #if DEBUG
        if let override = environment["TONO_API_BASE_URL"], let url = URL(string: override) { return url }
        #endif
        if let value = bundle.object(forInfoDictionaryKey: "TonoAPIBaseURL") as? String, let url = URL(string: value) { return url }
        return URL(string: "https://api.tono.invalid")!
    }

    func authMethods() async throws -> TonoAuthMethodsResponse {
        try await publicGet("auth/methods")
    }
    func startEmailSignIn(_ body: TonoEmailStartRequest) async throws -> TonoEmailChallengeResponse {
        try await publicRequest("auth/email/start", body: body)
    }
    func verifyEmailSignIn(_ body: TonoEmailVerifyRequest) async throws -> TonoAuthResponse {
        try await publicAuthRequest("auth/email/verify", body: body)
    }
    func oidcChallenge(_ body: TonoOIDCChallengeRequest) async throws -> TonoOIDCChallengeResponse {
        try await publicRequest("auth/oidc/challenge", body: body)
    }
    func verifyOIDC(_ body: TonoOIDCVerifyRequest) async throws -> TonoAuthResponse {
        try await publicAuthRequest("auth/oidc/verify", body: body)
    }
    func me() async throws -> TonoMeResponse { try await authorizedRequest("me", method: "GET") }
    func devices() async throws -> TonoDevicesResponse { try await authorizedRequest("devices", method: "GET") }
    func exitCatalog() async throws -> TonoExitCatalogResponse {
        try await authorizedRequest("exit-catalog", method: "GET")
    }
    func trafficPolicy() async throws -> TonoTrafficPolicyResponse {
        try await authorizedRequest("traffic-policy", method: "GET")
    }
    func deviceActions() async throws -> TonoDeviceActionsResponse {
        try await authorizedRequest("device-actions", method: "GET")
    }
    func submitDeviceActionResult(id: String, result: TonoDeviceActionResult) async throws {
        let validID = try validatedDeviceID(id)
        let _: TonoDeviceActionResultResponse = try await authorizedRequest(
            "device-actions/\(validID)/result", method: "POST", body: result
        )
    }
    func revokeDevice(_ id: String) async throws { try await authorizedVoid("devices/\(try validatedDeviceID(id))", method: "DELETE") }
    func enrollment(deviceId: String, installationId: String) async throws -> TonoEnrollmentResponse {
        try await authorizedRequest("devices/\(try validatedDeviceID(deviceId))/enrollment", method: "POST", body: TonoEnrollmentRequest(installationId: installationId))
    }
    func confirm(deviceId: String, identity: TonoNodeIdentity) async throws -> TonoConfirmResponse {
        try await authorizedRequest(
            "devices/\(try validatedDeviceID(deviceId))/confirm",
            method: "POST",
            body: TonoConfirmRequest(
                stableNodeId: identity.stableNodeId,
                nodeId: identity.nodeId,
                publicKey: identity.publicKey,
                tailscaleIPs: identity.tailscaleIPs
            )
        )
    }

    func adopt(_ auth: TonoAuthResponse) throws {
        accessToken = auth.accessToken
        if let refresh = auth.refreshToken { try keychain.set(refresh, for: .refreshToken) }
    }

    func logout() async {
        // Revoke server-side whenever a refresh token exists, even without a
        // live access token — deleting only the local copy leaves a valid
        // credential orphaned server-side. The body is re-encoded per attempt:
        // a 401-triggered refresh rotates the token, and revoking the
        // pre-rotation value would orphan the freshly rotated one instead.
        if currentRefreshToken() != nil {
            do {
                let token: String
                if let accessToken {
                    token = accessToken
                } else {
                    token = try await refreshAccessToken()
                }
                do {
                    try await sendLogout(bearer: token)
                } catch APIError.unauthorized {
                    accessToken = nil
                    let renewed = try await refreshAccessToken()
                    try await sendLogout(bearer: renewed)
                }
            } catch {
                // Refresh or revoke failed: the token is already dead
                // server-side or the network is gone. Local deletion is all
                // that remains either way.
            }
        }
        accessToken = nil
        unpersistedRefreshToken = nil
        try? keychain.remove(.refreshToken)
    }

    private func sendLogout(bearer: String) async throws {
        let body = try TonoCoding.encoder().encode(
            TonoLogoutRequest(refreshToken: currentRefreshToken())
        )
        _ = try await sendData(
            "auth/logout", method: "POST", body: body, bearer: bearer
        )
    }

    /// The freshest usable refresh token: a rotated-but-unpersisted value
    /// always wins over the keychain copy it failed to replace.
    private func currentRefreshToken() -> String? {
        unpersistedRefreshToken ?? (try? keychain.string(for: .refreshToken))
    }

    private func refreshAccessToken() async throws -> String {
        if let refreshTask { return try await refreshTask.value }
        let task = Task<String, Error> {
            if let pending = unpersistedRefreshToken,
               (try? keychain.set(pending, for: .refreshToken)) != nil {
                unpersistedRefreshToken = nil
            }
            guard let refresh = currentRefreshToken() else { throw APIError.unauthorized }
            let response: TonoTokenResponse = try await publicRequest("auth/refresh", body: TonoRefreshRequest(refreshToken: refresh))
            accessToken = response.accessToken
            do {
                try keychain.set(response.refreshToken, for: .refreshToken)
                unpersistedRefreshToken = nil
            } catch {
                // The server has already rotated; dropping the new token here
                // would be an irreversible logout. Keep it usable in-memory
                // and retry persistence on the next refresh.
                unpersistedRefreshToken = response.refreshToken
            }
            return response.accessToken
        }
        refreshTask = task
        defer { refreshTask = nil }
        return try await task.value
    }

    private func publicRequest<Response: Decodable, Body: Encodable>(_ path: String, body: Body) async throws -> Response {
        try await send(path, method: "POST", body: TonoCoding.encoder().encode(body), bearer: nil)
    }
    private func publicGet<Response: Decodable>(_ path: String) async throws -> Response {
        try await send(path, method: "GET", body: nil, bearer: nil)
    }
    private func publicAuthRequest<Body: Encodable>(_ path: String, body: Body) async throws -> TonoAuthResponse {
        let envelope: TonoAuthEnvelope = try await publicRequest(path, body: body)
        return envelope.auth
    }
    private func authorizedRequest<Response: Decodable>(_ path: String, method: String) async throws -> Response {
        try await authorizedRequest(path, method: method, bodyData: nil)
    }
    private func authorizedRequest<Response: Decodable, Body: Encodable>(_ path: String, method: String, body: Body) async throws -> Response {
        try await authorizedRequest(path, method: method, bodyData: TonoCoding.encoder().encode(body))
    }
    private func authorizedRequest<Response: Decodable>(_ path: String, method: String, bodyData: Data?) async throws -> Response {
        let token: String
        if let accessToken { token = accessToken } else { token = try await refreshAccessToken() }
        do { return try await send(path, method: method, body: bodyData, bearer: token) }
        catch APIError.unauthorized {
            accessToken = nil
            let renewed = try await refreshAccessToken()
            return try await send(path, method: method, body: bodyData, bearer: renewed)
        }
    }
    private func authorizedVoid(_ path: String, method: String) async throws {
        let token: String
        if let accessToken { token = accessToken } else { token = try await refreshAccessToken() }
        do { _ = try await sendData(path, method: method, body: nil, bearer: token) }
        catch APIError.unauthorized {
            accessToken = nil
            let renewed = try await refreshAccessToken()
            _ = try await sendData(path, method: method, body: nil, bearer: renewed)
        }
    }
    private func authorizedVoid<Body: Encodable>(_ path: String, method: String, body: Body) async throws {
        let token: String
        if let accessToken { token = accessToken } else { token = try await refreshAccessToken() }
        let bodyData = try TonoCoding.encoder().encode(body)
        do { _ = try await sendData(path, method: method, body: bodyData, bearer: token) }
        catch APIError.unauthorized {
            accessToken = nil
            let renewed = try await refreshAccessToken()
            _ = try await sendData(path, method: method, body: bodyData, bearer: renewed)
        }
    }

    private func send<Response: Decodable>(_ path: String, method: String, body: Data?, bearer: String?) async throws -> Response {
        let data = try await sendData(path, method: method, body: body, bearer: bearer)
        do { return try TonoCoding.decoder().decode(Response.self, from: data.isEmpty ? Data("{}".utf8) : data) }
        catch { throw APIError.invalidResponse }
    }
    private func sendData(_ path: String, method: String, body: Data?, bearer: String?) async throws -> Data {
        let validOrigin: Bool
        #if DEBUG
        validOrigin = {
            guard let components = URLComponents(url: baseURL, resolvingAgainstBaseURL: false),
                  let scheme = components.scheme?.lowercased(),
                  let host = components.host?.lowercased() else { return false }
            return (scheme == "https" && (components.port == nil || components.port == 443)) ||
                (scheme == "http" && ["localhost", "127.0.0.1", "::1"].contains(host))
        }()
        #else
        validOrigin = {
            guard let components = URLComponents(url: baseURL, resolvingAgainstBaseURL: false),
                  components.scheme?.lowercased() == "https" else { return false }
            return components.port == nil || components.port == 443
        }()
        #endif
        guard let components = URLComponents(url: baseURL, resolvingAgainstBaseURL: false),
              components.host?.isEmpty == false,
              components.user == nil,
              components.password == nil,
              components.query == nil,
              components.fragment == nil,
              components.path.isEmpty || components.path == "/",
              validOrigin
        else { throw APIError.invalidConfiguration }
        let requestStartedAt = Date()
        let auditDetails = [
            "method": method,
            "endpoint": path,
            "host": baseURL.host ?? "invalid",
        ]
        LocalTrafficAudit.shared.recordEvent(
            "control_plane_request_started",
            details: auditDetails
        )
        var request = URLRequest(url: baseURL.appending(path: "api/v1/\(path)")); request.httpMethod = method; request.httpBody = body
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if body != nil { request.setValue("application/json", forHTTPHeaderField: "Content-Type") }
        if let bearer { request.setValue("Bearer \(bearer)", forHTTPHeaderField: "Authorization") }
        let maximumAttempts = 2
        for attempt in 1...maximumAttempts {
            let bytes: URLSession.AsyncBytes
            let response: URLResponse
            do {
                (bytes, response) = try await session.bytes(for: request)
            } catch {
                try await handleTransportFailure(
                    error,
                    method: method,
                    attempt: attempt,
                    maximumAttempts: maximumAttempts,
                    requestStartedAt: requestStartedAt,
                    auditDetails: auditDetails
                )
                continue
            }
            guard let http = response as? HTTPURLResponse else {
                throw APIError.invalidResponse
            }
            let maximumResponseBytes = 2 * 1024 * 1024
            if let declared = http.value(forHTTPHeaderField: "Content-Length").flatMap(Int.init),
               declared < 0 || declared > maximumResponseBytes {
                throw APIError.invalidResponse
            }
            var data = Data()
            data.reserveCapacity(
                min(
                    http.value(forHTTPHeaderField: "Content-Length").flatMap(Int.init) ?? 0,
                    maximumResponseBytes
                )
            )
            do {
                for try await byte in bytes {
                    guard data.count < maximumResponseBytes else {
                        throw APIError.invalidResponse
                    }
                    data.append(byte)
                }
            } catch let apiError as APIError {
                throw apiError
            } catch {
                try await handleTransportFailure(
                    error,
                    method: method,
                    attempt: attempt,
                    maximumAttempts: maximumAttempts,
                    requestStartedAt: requestStartedAt,
                    auditDetails: auditDetails,
                    httpStatus: http.statusCode
                )
                continue
            }
            guard (200..<300).contains(http.statusCode) else {
                LocalTrafficAudit.shared.recordEvent(
                    "control_plane_http_failed",
                    details: auditDetails.merging([
                        "duration_ms": Self.durationMilliseconds(since: requestStartedAt),
                        "http_status": String(http.statusCode),
                    ]) { _, new in new }
                )
                let envelope = try? TonoCoding.decoder().decode(ErrorEnvelope.self, from: data)
                if http.statusCode == 401 { throw APIError.unauthorized }; if http.statusCode == 403 { throw APIError.forbidden }
                if http.statusCode == 404 { throw APIError.notFound }
                if http.statusCode == 409 && envelope?.error.code == "DEVICE_LIMIT" { throw APIError.deviceLimit }
                throw APIError.server(status: http.statusCode, message: envelope?.error.message ?? "Tono request failed (\(http.statusCode)).")
            }
            LocalTrafficAudit.shared.recordEvent(
                "control_plane_request_succeeded",
                details: auditDetails.merging([
                    "attempt": String(attempt),
                    "duration_ms": Self.durationMilliseconds(since: requestStartedAt),
                    "http_status": String(http.statusCode),
                ]) { _, new in new }
            )
            return data
        }
        throw APIError.transport("Retry attempts exhausted.")
    }

    private func handleTransportFailure(
        _ error: Error,
        method: String,
        attempt: Int,
        maximumAttempts: Int,
        requestStartedAt: Date,
        auditDetails: [String: String],
        httpStatus: Int? = nil
    ) async throws {
        if Self.isCancellation(error) {
            throw CancellationError()
        }
        let networkError = error as NSError
        let willRetry = Self.shouldRetry(
            method: method,
            error: networkError,
            responseReceived: httpStatus != nil,
            attempt: attempt,
            maximumAttempts: maximumAttempts
        )
        var failureDetails = auditDetails.merging([
            "attempt": String(attempt),
            "duration_ms": Self.durationMilliseconds(since: requestStartedAt),
            "error_domain": networkError.domain,
            "error_code": String(networkError.code),
            "will_retry": String(willRetry),
        ]) { _, new in new }
        if let httpStatus {
            failureDetails["http_status"] = String(httpStatus)
        }
        LocalTrafficAudit.shared.recordEvent(
            "control_plane_transport_failed",
            details: failureDetails
        )
        guard willRetry else {
            throw APIError.transport(error.localizedDescription)
        }
        try await Task.sleep(for: .seconds(1))
    }

    nonisolated private static func shouldRetry(
        method: String,
        error: NSError,
        responseReceived: Bool,
        attempt: Int,
        maximumAttempts: Int
    ) -> Bool {
        guard attempt < maximumAttempts else { return false }
        // Reads are safe to replay after any transport failure. Mutating
        // requests are retried only when URLSession says no server connection
        // was established; retrying a timed-out POST could duplicate a code or
        // consume/rotate an authentication credential twice.
        if method == "GET" { return true }
        guard !responseReceived else { return false }
        guard error.domain == NSURLErrorDomain else { return false }
        return [
            NSURLErrorCannotFindHost,
            NSURLErrorCannotConnectToHost,
            NSURLErrorDNSLookupFailed,
            NSURLErrorNotConnectedToInternet,
        ].contains(error.code)
    }

    nonisolated private static func durationMilliseconds(since startedAt: Date) -> String {
        String(Int(Date().timeIntervalSince(startedAt) * 1_000))
    }

    nonisolated private static func isCancellation(_ error: Error) -> Bool {
        if error is CancellationError { return true }
        let value = error as NSError
        return value.domain == NSURLErrorDomain
            && value.code == NSURLErrorCancelled
    }

    private func validatedDeviceID(_ value: String) throws -> String {
        guard UUID(uuidString: value) != nil else { throw APIError.invalidResponse }
        return value
    }
}
