import Foundation

// MARK: - Traffic Data

struct TrafficData: Sendable {
    let up: Int64
    let down: Int64
}

// MARK: - Clash WebSocket Manager

final class ClashWebSocket: @unchecked Sendable {
    private let baseURL: URL
    private let secret: String
    private var trafficTask: URLSessionWebSocketTask?
    private var connectionsTask: URLSessionWebSocketTask?
    private var logsTask: URLSessionWebSocketTask?
    private let session: URLSession
    private var isStopped = false
    private var logLevel: String = "info"

    var onTraffic: (@Sendable (TrafficData) -> Void)?
    var onConnections: (@Sendable (APIConnectionsResponse) -> Void)?
    var onLog: (@Sendable (String, String) -> Void)? // (level, message)

    init(host: String = "127.0.0.1", port: Int = 9090, secret: String = "") {
        self.baseURL = URL(string: "ws://\(host):\(port)")!
        self.secret = secret
        self.session = URLSession(configuration: .default)
    }

    // MARK: - Traffic Stream

    func startTrafficStream() {
        let url = baseURL.appendingPathComponent("traffic")
        trafficTask = createTask(url: url)
        trafficTask?.resume()
        receiveTraffic()
    }

    private func receiveTraffic() {
        trafficTask?.receive { [weak self] result in
            switch result {
            case .success(let message):
                if case .string(let text) = message,
                   let data = text.data(using: .utf8),
                   let json = try? JSONDecoder().decode(TrafficJSON.self, from: data) {
                    self?.onTraffic?(TrafficData(up: json.up, down: json.down))
                }
                self?.receiveTraffic()
            case .failure:
                self?.reconnectTraffic()
            }
        }
    }

    private func reconnectTraffic() {
        guard !isStopped else { return }
        DispatchQueue.global().asyncAfter(deadline: .now() + 2) { [weak self] in
            guard let self, !self.isStopped else { return }
            self.startTrafficStream()
        }
    }

    // MARK: - Connections Stream

    func startConnectionsStream() {
        let url = baseURL.appendingPathComponent("connections")
        connectionsTask = createTask(url: url)
        connectionsTask?.resume()
        receiveConnections()
    }

    private func receiveConnections() {
        connectionsTask?.receive { [weak self] result in
            switch result {
            case .success(let message):
                if case .string(let text) = message,
                   let data = text.data(using: .utf8),
                   let response = try? JSONDecoder().decode(APIConnectionsResponse.self, from: data) {
                    self?.onConnections?(response)
                }
                self?.receiveConnections()
            case .failure:
                self?.reconnectConnections()
            }
        }
    }

    private func reconnectConnections() {
        guard !isStopped else { return }
        DispatchQueue.global().asyncAfter(deadline: .now() + 2) { [weak self] in
            guard let self, !self.isStopped else { return }
            self.startConnectionsStream()
        }
    }

    // MARK: - Logs Stream

    func startLogsStream(level: String = "info") {
        self.logLevel = level
        var components = URLComponents(url: baseURL.appendingPathComponent("logs"), resolvingAgainstBaseURL: false)!
        components.queryItems = [URLQueryItem(name: "level", value: level)]
        logsTask = createTask(url: components.url!)
        logsTask?.resume()
        receiveLogs()
    }

    private func receiveLogs() {
        logsTask?.receive { [weak self] result in
            switch result {
            case .success(let message):
                if case .string(let text) = message,
                   let data = text.data(using: .utf8),
                   let json = try? JSONDecoder().decode(LogJSON.self, from: data) {
                    self?.onLog?(json.type, json.payload)
                }
                self?.receiveLogs()
            case .failure:
                self?.reconnectLogs()
            }
        }
    }

    private func reconnectLogs() {
        guard !isStopped else { return }
        DispatchQueue.global().asyncAfter(deadline: .now() + 2) { [weak self] in
            guard let self, !self.isStopped else { return }
            self.startLogsStream(level: self.logLevel)
        }
    }

    // MARK: - Stop All

    func stopAll() {
        isStopped = true
        trafficTask?.cancel(with: .goingAway, reason: nil)
        connectionsTask?.cancel(with: .goingAway, reason: nil)
        logsTask?.cancel(with: .goingAway, reason: nil)
        trafficTask = nil
        connectionsTask = nil
        logsTask = nil
        onTraffic = nil
        onConnections = nil
        onLog = nil
        session.invalidateAndCancel()
    }

    // MARK: - Helper

    private func createTask(url: URL) -> URLSessionWebSocketTask {
        var request = URLRequest(url: url)
        if !secret.isEmpty {
            request.setValue("Bearer \(secret)", forHTTPHeaderField: "Authorization")
        }
        return session.webSocketTask(with: request)
    }
}

// MARK: - JSON Models

private struct TrafficJSON: Codable {
    let up: Int64
    let down: Int64
}

private struct LogJSON: Codable {
    let type: String
    let payload: String
}
