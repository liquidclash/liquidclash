#if DEBUG
import AppKit
import AuthenticationServices
import CryptoKit
import Foundation
import Network
import Security

enum TonoIdentityProviderError: LocalizedError {
    case alreadyRunning
    case cancelled
    case invalidCallback
    case invalidCredential
    case browserUnavailable
    case listenerFailed
    case timedOut
    case tokenExchangeFailed

    var errorDescription: String? {
        switch self {
        case .alreadyRunning: "A sign-in request is already in progress."
        case .cancelled: "Sign-in was cancelled."
        case .invalidCallback: "The identity provider returned an invalid callback."
        case .invalidCredential: "The identity provider returned an invalid credential."
        case .browserUnavailable: "Tono could not open your browser for sign-in."
        case .listenerFailed: "Tono could not create the local sign-in callback."
        case .timedOut: "Sign-in timed out. Please try again."
        case .tokenExchangeFailed: "Google could not complete sign-in."
        }
    }
}

nonisolated private enum TonoOAuthRandom {
    static func token(bytes: Int) throws -> String {
        var data = Data(count: bytes)
        let status = data.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, bytes, buffer.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw TonoIdentityProviderError.invalidCredential
        }
        return data.base64EncodedString()
            .replacingOccurrences(of: "=", with: "")
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
    }

    static func sha256Base64URL(_ value: String) -> String {
        Data(SHA256.hash(data: Data(value.utf8))).base64EncodedString()
            .replacingOccurrences(of: "=", with: "")
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
    }
}

@MainActor
final class AppleSignInCoordinator: NSObject,
    ASAuthorizationControllerDelegate,
    ASAuthorizationControllerPresentationContextProviding
{
    private var continuation: CheckedContinuation<String, Swift.Error>?
    private var expectedState: String?
    private var controller: ASAuthorizationController?
    private lazy var fallbackWindow = NSWindow()

    func identityToken(nonce: String) async throws -> String {
        guard continuation == nil else { throw TonoIdentityProviderError.alreadyRunning }
        let state = try TonoOAuthRandom.token(bytes: 24)
        let request = ASAuthorizationAppleIDProvider().createRequest()
        request.requestedScopes = [.email]
        // AuthenticationServices returns this value in the signed ID token.
        request.nonce = nonce
        request.state = state
        expectedState = state

        let controller = ASAuthorizationController(authorizationRequests: [request])
        controller.delegate = self
        controller.presentationContextProvider = self
        self.controller = controller
        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
            controller.performRequests()
        }
    }

    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        NSApp.keyWindow ?? NSApp.windows.first ?? fallbackWindow
    }

    func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithAuthorization authorization: ASAuthorization
    ) {
        guard let credential = authorization.credential as? ASAuthorizationAppleIDCredential,
              credential.state == expectedState,
              let data = credential.identityToken,
              data.count <= 16_384,
              let token = String(data: data, encoding: .utf8),
              token.count >= 100
        else {
            finish(.failure(TonoIdentityProviderError.invalidCredential))
            return
        }
        finish(.success(token))
    }

    func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithError error: Swift.Error
    ) {
        if (error as? ASAuthorizationError)?.code == .canceled {
            finish(.failure(TonoIdentityProviderError.cancelled))
        } else {
            finish(.failure(TonoIdentityProviderError.invalidCredential))
        }
    }

    private func finish(_ result: Result<String, Swift.Error>) {
        let continuation = continuation
        self.continuation = nil
        expectedState = nil
        controller = nil
        continuation?.resume(with: result)
    }
}

nonisolated private final class GoogleLoopbackReceiver: @unchecked Sendable {
    private let expectedState: String
    private let listener: NWListener
    private let queue = DispatchQueue(label: "com.raydocs.tono.google-oauth-loopback")
    private let lock = NSLock()
    private var readyContinuation: CheckedContinuation<URL, Swift.Error>?
    private var readyResult: Result<URL, Swift.Error>?
    private var callbackContinuation: CheckedContinuation<URL, Swift.Error>?
    private var callbackResult: Result<URL, Swift.Error>?

    init(expectedState: String) throws {
        self.expectedState = expectedState
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: parameters)
    }

    func start() async throws -> URL {
        listener.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                guard let port = listener.port,
                      let url = URL(string: "http://127.0.0.1:\(port.rawValue)/oauth2callback")
                else {
                    completeReady(.failure(TonoIdentityProviderError.listenerFailed))
                    return
                }
                completeReady(.success(url))
            case .failed:
                completeReady(.failure(TonoIdentityProviderError.listenerFailed))
                completeCallback(.failure(TonoIdentityProviderError.listenerFailed))
            case .cancelled:
                completeReady(.failure(CancellationError()))
                completeCallback(.failure(CancellationError()))
            default:
                break
            }
        }
        listener.newConnectionHandler = { [weak self] connection in
            self?.accept(connection)
        }
        listener.start(queue: queue)
        return try await withCheckedThrowingContinuation { continuation in
            lock.lock()
            if let result = readyResult {
                lock.unlock()
                continuation.resume(with: result)
            } else {
                readyContinuation = continuation
                lock.unlock()
            }
        }
    }

    func waitForCallback() async throws -> URL {
        try await withCheckedThrowingContinuation { continuation in
            lock.lock()
            if let result = callbackResult {
                lock.unlock()
                continuation.resume(with: result)
            } else {
                callbackContinuation = continuation
                lock.unlock()
            }
        }
    }

    func cancel() {
        listener.cancel()
        completeReady(.failure(CancellationError()))
        completeCallback(.failure(CancellationError()))
    }

    private func completeReady(_ result: Result<URL, Swift.Error>) {
        lock.lock()
        guard readyResult == nil else { lock.unlock(); return }
        readyResult = result
        let continuation = readyContinuation
        readyContinuation = nil
        lock.unlock()
        continuation?.resume(with: result)
    }

    private func completeCallback(_ result: Result<URL, Swift.Error>) {
        lock.lock()
        guard callbackResult == nil else { lock.unlock(); return }
        callbackResult = result
        let continuation = callbackContinuation
        callbackContinuation = nil
        lock.unlock()
        continuation?.resume(with: result)
    }

    private func accept(_ connection: NWConnection) {
        connection.start(queue: queue)
        receive(connection, accumulated: Data())
    }

    private func receive(_ connection: NWConnection, accumulated: Data) {
        guard accumulated.count < 8_192 else {
            respond(connection, status: "413 Payload Too Large", success: false)
            return
        }
        connection.receive(
            minimumIncompleteLength: 1,
            maximumLength: 8_192 - accumulated.count
        ) { [weak self] data, _, complete, error in
            guard let self else { connection.cancel(); return }
            var request = accumulated
            if let data { request.append(data) }
            if request.range(of: Data("\r\n\r\n".utf8)) != nil {
                handle(request, connection: connection)
            } else if complete || error != nil {
                respond(connection, status: "400 Bad Request", success: false)
            } else {
                receive(connection, accumulated: request)
            }
        }
    }

    private func handle(_ request: Data, connection: NWConnection) {
        guard request.count <= 8_192,
              let text = String(data: request, encoding: .utf8),
              let firstLine = text.components(separatedBy: "\r\n").first
        else {
            respond(connection, status: "400 Bad Request", success: false)
            return
        }
        let components = firstLine.split(separator: " ", omittingEmptySubsequences: true)
        guard components.count == 3,
              components[0] == "GET",
              components[2] == "HTTP/1.1",
              components[1].count <= 4_096,
              let callback = URL(string: "http://127.0.0.1\(components[1])"),
              let parsed = URLComponents(url: callback, resolvingAgainstBaseURL: false),
              parsed.path == "/oauth2callback",
              let stateItems = parsed.queryItems?.filter({ $0.name == "state" }),
              stateItems.count == 1,
              stateItems[0].value == expectedState
        else {
            respond(connection, status: "404 Not Found", success: false)
            return
        }
        respond(connection, status: "200 OK", success: true)
        completeCallback(.success(callback))
        listener.cancel()
    }

    private func respond(_ connection: NWConnection, status: String, success: Bool) {
        let message = success
            ? "Tono sign-in is complete. You can close this window."
            : "This is not a valid Tono sign-in callback."
        let body = """
        <!doctype html><meta charset="utf-8"><title>Tono sign-in</title>
        <p>\(message)</p>
        """
        let response = """
        HTTP/1.1 \(status)\r
        Content-Type: text/html; charset=utf-8\r
        Content-Security-Policy: default-src 'none'; frame-ancestors 'none'\r
        Referrer-Policy: no-referrer\r
        X-Content-Type-Options: nosniff\r
        Content-Length: \(body.utf8.count)\r
        Connection: close\r
        \r
        \(body)
        """
        connection.send(content: Data(response.utf8), completion: .contentProcessed { _ in
            connection.cancel()
        })
    }
}

nonisolated private final class TonoOAuthNoRedirectDelegate: NSObject, URLSessionTaskDelegate,
    @unchecked Sendable
{
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

@MainActor
enum GoogleSignInCoordinator {
    private nonisolated struct TokenResponse: Decodable, Sendable {
        let idToken: String
        private enum CodingKeys: String, CodingKey { case idToken = "id_token" }
    }

    static func identityToken(clientID: String, nonce: String) async throws -> String {
        guard clientID.count >= 3, clientID.count <= 512, nonce.count >= 8, nonce.count <= 512
        else { throw TonoIdentityProviderError.invalidCredential }

        let state = try TonoOAuthRandom.token(bytes: 24)
        let verifier = try TonoOAuthRandom.token(bytes: 64)
        let receiver = try GoogleLoopbackReceiver(expectedState: state)
        let redirectURI = try await receiver.start()
        defer { receiver.cancel() }

        var authorization = URLComponents(string: "https://accounts.google.com/o/oauth2/v2/auth")!
        authorization.queryItems = [
            URLQueryItem(name: "client_id", value: clientID),
            URLQueryItem(name: "redirect_uri", value: redirectURI.absoluteString),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "scope", value: "openid email profile"),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "nonce", value: nonce),
            URLQueryItem(name: "code_challenge", value: TonoOAuthRandom.sha256Base64URL(verifier)),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
            URLQueryItem(name: "prompt", value: "select_account"),
        ]
        guard let authorizationURL = authorization.url,
              NSWorkspace.shared.open(authorizationURL)
        else { throw TonoIdentityProviderError.browserUnavailable }

        let callback = try await withTaskCancellationHandler {
            try await withThrowingTaskGroup(of: URL.self) { group in
                group.addTask { try await receiver.waitForCallback() }
                group.addTask {
                    try await Task.sleep(for: .seconds(300))
                    receiver.cancel()
                    throw TonoIdentityProviderError.timedOut
                }
                guard let first = try await group.next() else {
                    throw TonoIdentityProviderError.invalidCallback
                }
                group.cancelAll()
                return first
            }
        } onCancel: {
            receiver.cancel()
        }
        guard let callbackComponents = URLComponents(
            url: callback,
            resolvingAgainstBaseURL: false
        ) else { throw TonoIdentityProviderError.invalidCallback }
        let queryItems = callbackComponents.queryItems ?? []
        func singleValue(_ name: String) throws -> String? {
            let matches = queryItems.filter { $0.name == name }
            guard matches.count <= 1 else {
                throw TonoIdentityProviderError.invalidCallback
            }
            return matches.first?.value
        }
        guard try singleValue("state") == state else {
            throw TonoIdentityProviderError.invalidCallback
        }
        let providerError = try singleValue("error")
        let code = try singleValue("code")
        guard providerError == nil || code == nil else {
            throw TonoIdentityProviderError.invalidCallback
        }
        if providerError == "access_denied" { throw TonoIdentityProviderError.cancelled }
        guard providerError == nil, let code, !code.isEmpty, code.count <= 4_096 else {
            throw TonoIdentityProviderError.invalidCallback
        }
        return try await exchange(
            code: code,
            verifier: verifier,
            clientID: clientID,
            redirectURI: redirectURI
        )
    }

    private static func exchange(
        code: String,
        verifier: String,
        clientID: String,
        redirectURI: URL
    ) async throws -> String {
        var request = URLRequest(url: URL(string: "https://oauth2.googleapis.com/token")!)
        request.httpMethod = "POST"
        request.setValue(
            "application/x-www-form-urlencoded",
            forHTTPHeaderField: "Content-Type"
        )
        var form = URLComponents()
        form.queryItems = [
            URLQueryItem(name: "client_id", value: clientID),
            URLQueryItem(name: "code", value: code),
            URLQueryItem(name: "code_verifier", value: verifier),
            URLQueryItem(name: "grant_type", value: "authorization_code"),
            URLQueryItem(name: "redirect_uri", value: redirectURI.absoluteString),
        ]
        request.httpBody = Data((form.percentEncodedQuery ?? "").utf8)

        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 20
        configuration.timeoutIntervalForResource = 30
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        let session = URLSession(
            configuration: configuration,
            delegate: TonoOAuthNoRedirectDelegate(),
            delegateQueue: nil
        )
        defer { session.finishTasksAndInvalidate() }
        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw TonoIdentityProviderError.tokenExchangeFailed
        }
        guard data.count <= 64 * 1_024,
              let http = response as? HTTPURLResponse,
              http.statusCode == 200,
              let token = try? JSONDecoder().decode(TokenResponse.self, from: data).idToken,
              token.count >= 100,
              token.count <= 16_384
        else { throw TonoIdentityProviderError.tokenExchangeFailed }
        return token
    }
}
#endif
