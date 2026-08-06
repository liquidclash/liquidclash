import Foundation

// MARK: - Traffic Data

nonisolated struct TrafficData: Sendable {
    let up: Int64
    let down: Int64
}

// MARK: - Clash WebSocket Manager

@MainActor
final class ClashWebSocket {
    private let baseURL: URL
    private let secret: String
    private var trafficTask: URLSessionWebSocketTask?
    private var connectionsTask: URLSessionWebSocketTask?
    private var logsTask: URLSessionWebSocketTask?
    private var trafficReconnectTask: Task<Void, Never>?
    private var connectionsReconnectTask: Task<Void, Never>?
    private var logsReconnectTask: Task<Void, Never>?
    private let session: URLSession
    private var isStopped = false
    private var trafficEnabled = false
    private var connectionsEnabled = false
    private var connectionsIntervalMilliseconds = 2_500
    private var logsEnabled = false
    private var logLevel: String = "info"
    private var pendingLogs: [(level: String, message: String)] = []
    private var logFlushTask: Task<Void, Never>?
    private var watchdogTask: Task<Void, Never>?
    private var lastTrafficMessageAt: Date?
    private var lastConnectionsMessageAt: Date?
    private var logsPingStartedAt: Date?
    private var lastLogsPingAt: Date?
    private var stalledStreams = Set<String>()

    var onTraffic: ((TrafficData) -> Void)?
    var onConnections: ((APIConnectionsResponse) -> Void)?
    var onLogs: (([(level: String, message: String)]) -> Void)?
    var onStreamStalled: ((String) -> Void)?
    var onStreamRecovered: ((String) -> Void)?

    init(host: String = "127.0.0.1", port: Int = 9090, secret: String = "") {
        self.baseURL = URL(string: "ws://\(host):\(port)")!
        self.secret = secret
        let configuration = URLSessionConfiguration.ephemeral
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.urlCache = nil
        configuration.waitsForConnectivity = false
        self.session = URLSession(configuration: configuration)
    }

    // MARK: - Traffic Stream

    func startTrafficStream() {
        guard !isStopped else { return }
        trafficEnabled = true
        guard trafficTask == nil else { return }
        trafficReconnectTask?.cancel()
        trafficReconnectTask = nil
        let url = baseURL.appendingPathComponent("traffic")
        let task = createTask(url: url)
        trafficTask = task
        lastTrafficMessageAt = Date()
        task.resume()
        receiveTraffic(from: task)
        ensureWatchdog()
    }

    func stopTrafficStream() {
        trafficEnabled = false
        trafficReconnectTask?.cancel()
        trafficReconnectTask = nil
        trafficTask?.cancel(with: .goingAway, reason: nil)
        trafficTask = nil
        lastTrafficMessageAt = nil
        stalledStreams.remove("traffic")
        stopWatchdogIfIdle()
    }

    private func receiveTraffic(from task: URLSessionWebSocketTask) {
        task.receive { [weak self] result in
            let traffic: TrafficData? = if case .success(.string(let text)) = result,
                                           let data = text.data(using: .utf8),
                                           let json = try? JSONDecoder().decode(TrafficJSON.self, from: data) {
                TrafficData(up: json.up, down: json.down)
            } else {
                nil
            }
            Task { @MainActor [weak self] in
                guard let self, !self.isStopped, self.trafficTask === task else { return }
                switch result {
                case .success:
                    self.lastTrafficMessageAt = Date()
                    self.markStreamRecovered("traffic")
                    if let traffic { self.onTraffic?(traffic) }
                    self.receiveTraffic(from: task)
                case .failure:
                    self.trafficTask = nil
                    self.reconnectTraffic()
                }
            }
        }
    }

    private func reconnectTraffic() {
        guard !isStopped, trafficEnabled else { return }
        trafficReconnectTask?.cancel()
        trafficReconnectTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(2))
            guard let self, !Task.isCancelled, !self.isStopped,
                  self.trafficEnabled else { return }
            self.trafficReconnectTask = nil
            self.startTrafficStream()
        }
    }

    // MARK: - Connections Stream

    func startConnectionsStream(intervalMilliseconds: Int = 2_500) {
        guard !isStopped else { return }
        connectionsEnabled = true
        connectionsIntervalMilliseconds = min(max(intervalMilliseconds, 1_000), 10_000)
        guard connectionsTask == nil else { return }
        connectionsReconnectTask?.cancel()
        connectionsReconnectTask = nil
        var components = URLComponents(
            url: baseURL.appendingPathComponent("connections"),
            resolvingAgainstBaseURL: false
        )!
        components.queryItems = [
            URLQueryItem(
                name: "interval",
                value: String(connectionsIntervalMilliseconds)
            ),
        ]
        let task = createTask(url: components.url!)
        connectionsTask = task
        lastConnectionsMessageAt = Date()
        task.resume()
        receiveConnections(from: task)
        ensureWatchdog()
    }

    func stopConnectionsStream() {
        connectionsEnabled = false
        connectionsReconnectTask?.cancel()
        connectionsReconnectTask = nil
        connectionsTask?.cancel(with: .goingAway, reason: nil)
        connectionsTask = nil
        lastConnectionsMessageAt = nil
        stalledStreams.remove("connections")
        stopWatchdogIfIdle()
    }

    private func receiveConnections(from task: URLSessionWebSocketTask) {
        task.receive { [weak self] result in
            let response: APIConnectionsResponse? = if case .success(.string(let text)) = result,
                                                       let data = text.data(using: .utf8) {
                try? JSONDecoder().decode(APIConnectionsResponse.self, from: data)
            } else {
                nil
            }
            Task { @MainActor [weak self] in
                guard let self, !self.isStopped, self.connectionsTask === task else { return }
                switch result {
                case .success:
                    self.lastConnectionsMessageAt = Date()
                    self.markStreamRecovered("connections")
                    if let response { self.onConnections?(response) }
                    self.receiveConnections(from: task)
                case .failure:
                    self.connectionsTask = nil
                    self.reconnectConnections()
                }
            }
        }
    }

    private func reconnectConnections() {
        guard !isStopped, connectionsEnabled else { return }
        connectionsReconnectTask?.cancel()
        connectionsReconnectTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(2))
            guard let self, !Task.isCancelled, !self.isStopped,
                  self.connectionsEnabled else { return }
            self.connectionsReconnectTask = nil
            self.startConnectionsStream(
                intervalMilliseconds: self.connectionsIntervalMilliseconds
            )
        }
    }

    // MARK: - Logs Stream

    func startLogsStream(level: String = "info") {
        guard !isStopped else { return }
        logsEnabled = true
        if logsTask != nil, logLevel == level { return }
        stopLogsTask(keepEnabled: true)
        self.logLevel = level
        var components = URLComponents(url: baseURL.appendingPathComponent("logs"), resolvingAgainstBaseURL: false)!
        components.queryItems = [URLQueryItem(name: "level", value: level)]
        let task = createTask(url: components.url!)
        logsTask = task
        logsPingStartedAt = nil
        lastLogsPingAt = nil
        task.resume()
        receiveLogs(from: task)
        ensureWatchdog()
    }

    func stopLogsStream() {
        stopLogsTask(keepEnabled: false)
    }

    private func stopLogsTask(keepEnabled: Bool) {
        logsEnabled = keepEnabled
        logFlushTask?.cancel()
        logFlushTask = nil
        pendingLogs.removeAll(keepingCapacity: true)
        logsReconnectTask?.cancel()
        logsReconnectTask = nil
        logsTask?.cancel(with: .goingAway, reason: nil)
        logsTask = nil
        logsPingStartedAt = nil
        lastLogsPingAt = nil
        if !keepEnabled { stalledStreams.remove("logs") }
        stopWatchdogIfIdle()
    }

    private func receiveLogs(from task: URLSessionWebSocketTask) {
        task.receive { [weak self] result in
            let entry: (String, String)? = if case .success(.string(let text)) = result,
                                              let data = text.data(using: .utf8),
                                              let json = try? JSONDecoder().decode(LogJSON.self, from: data) {
                (json.type, json.payload)
            } else {
                nil
            }
            Task { @MainActor [weak self] in
                guard let self, !self.isStopped, self.logsTask === task else { return }
                switch result {
                case .success:
                    // Any inbound frame proves the observation path is alive.
                    // Foundation can delay sendPing's completion while Mihomo
                    // continues delivering logs; leaving that ping marked as
                    // outstanding made the watchdog cancel a healthy socket
                    // every ~10 seconds. Clearing the marker also invalidates
                    // the late callback through the identity check below.
                    self.logsPingStartedAt = nil
                    self.markStreamRecovered("logs")
                    if let entry {
                        self.enqueueLog(level: entry.0, message: entry.1)
                    }
                    self.receiveLogs(from: task)
                case .failure:
                    self.logsTask = nil
                    self.reconnectLogs()
                }
            }
        }
    }

    /// Mihomo can emit dozens of messages in one UI frame. Coalesce them into
    /// one observation mutation so the Logs page lays out at most four times per
    /// second instead of once per line.
    private func enqueueLog(level: String, message: String) {
        pendingLogs.append((level, message))
        if pendingLogs.count > 500 {
            pendingLogs.removeFirst(pendingLogs.count - 500)
        }
        guard logFlushTask == nil else { return }
        logFlushTask = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(250))
            guard let self, !Task.isCancelled, !self.isStopped,
                  self.logsEnabled else { return }
            let batch = self.pendingLogs
            self.pendingLogs.removeAll(keepingCapacity: true)
            self.logFlushTask = nil
            if !batch.isEmpty {
                self.onLogs?(batch)
            }
        }
    }

    private func reconnectLogs() {
        guard !isStopped, logsEnabled else { return }
        logsReconnectTask?.cancel()
        logsReconnectTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(2))
            guard let self, !Task.isCancelled, !self.isStopped,
                  self.logsEnabled else { return }
            self.logsReconnectTask = nil
            self.startLogsStream(level: self.logLevel)
        }
    }

    // MARK: - Half-open stream watchdog

    private func ensureWatchdog() {
        guard watchdogTask == nil else { return }
        watchdogTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(5))
                guard let self, !Task.isCancelled, !self.isStopped else { return }
                self.checkStreamLiveness()
            }
        }
    }

    private func stopWatchdogIfIdle() {
        guard trafficTask == nil, connectionsTask == nil, logsTask == nil,
              trafficReconnectTask == nil, connectionsReconnectTask == nil,
              logsReconnectTask == nil else { return }
        watchdogTask?.cancel()
        watchdogTask = nil
    }

    private func checkStreamLiveness(now: Date = Date()) {
        if let task = trafficTask,
           let lastTrafficMessageAt,
           now.timeIntervalSince(lastTrafficMessageAt) > 15 {
            markStreamStalled("traffic")
            task.cancel(with: .goingAway, reason: nil)
            trafficTask = nil
            self.lastTrafficMessageAt = nil
            reconnectTraffic()
        }

        let connectionsDeadline = max(
            15,
            Double(connectionsIntervalMilliseconds) / 1_000 * 4
        )
        if let task = connectionsTask,
           let lastConnectionsMessageAt,
           now.timeIntervalSince(lastConnectionsMessageAt) > connectionsDeadline {
            markStreamStalled("connections")
            task.cancel(with: .goingAway, reason: nil)
            connectionsTask = nil
            self.lastConnectionsMessageAt = nil
            reconnectConnections()
        }

        guard let task = logsTask else {
            logsPingStartedAt = nil
            lastLogsPingAt = nil
            return
        }
        if let logsPingStartedAt {
            guard now.timeIntervalSince(logsPingStartedAt) > 5 else { return }
            markStreamStalled("logs")
            task.cancel(with: .goingAway, reason: nil)
            logsTask = nil
            self.logsPingStartedAt = nil
            reconnectLogs()
            return
        }

        if let lastLogsPingAt,
           now.timeIntervalSince(lastLogsPingAt) < 15 {
            return
        }
        let pingStartedAt = now
        logsPingStartedAt = pingStartedAt
        lastLogsPingAt = now
        task.sendPing { [weak self, weak task] error in
            Task { @MainActor [weak self, weak task] in
                guard let self, let task,
                      !self.isStopped, self.logsTask === task,
                      self.logsPingStartedAt == pingStartedAt else { return }
                self.logsPingStartedAt = nil
                guard error != nil else {
                    self.markStreamRecovered("logs")
                    return
                }
                self.markStreamStalled("logs")
                task.cancel(with: .goingAway, reason: nil)
                self.logsTask = nil
                self.reconnectLogs()
            }
        }
    }

    private func markStreamStalled(_ stream: String) {
        guard stalledStreams.insert(stream).inserted else { return }
        onStreamStalled?(stream)
    }

    private func markStreamRecovered(_ stream: String) {
        guard stalledStreams.remove(stream) != nil else { return }
        onStreamRecovered?(stream)
    }

    // MARK: - Stop All

    func stopAll() {
        isStopped = true
        trafficEnabled = false
        connectionsEnabled = false
        logsEnabled = false
        trafficReconnectTask?.cancel()
        connectionsReconnectTask?.cancel()
        logsReconnectTask?.cancel()
        logFlushTask?.cancel()
        watchdogTask?.cancel()
        trafficReconnectTask = nil
        connectionsReconnectTask = nil
        logsReconnectTask = nil
        logFlushTask = nil
        watchdogTask = nil
        lastTrafficMessageAt = nil
        lastConnectionsMessageAt = nil
        logsPingStartedAt = nil
        lastLogsPingAt = nil
        stalledStreams.removeAll(keepingCapacity: false)
        pendingLogs.removeAll(keepingCapacity: false)
        trafficTask?.cancel(with: .goingAway, reason: nil)
        connectionsTask?.cancel(with: .goingAway, reason: nil)
        logsTask?.cancel(with: .goingAway, reason: nil)
        trafficTask = nil
        connectionsTask = nil
        logsTask = nil
        onTraffic = nil
        onConnections = nil
        onLogs = nil
        onStreamStalled = nil
        onStreamRecovered = nil
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

nonisolated private struct TrafficJSON: Codable {
    let up: Int64
    let down: Int64
}

nonisolated private struct LogJSON: Codable {
    let type: String
    let payload: String
}
