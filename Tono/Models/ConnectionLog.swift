import Foundation

// MARK: - Connection Type

nonisolated enum ConnectionType: String, Codable {
    case proxied  = "Proxied"
    case direct   = "Direct"
    case rejected = "Rejected"
}

// MARK: - Connection Entry

nonisolated struct ConnectionEntry: Identifiable, Codable {
    var id: String = UUID().uuidString
    var domain: String
    var protocolName: String
    var rule: String
    var nodeFlag: String
    var nodeName: String
    var latency: Int?
    var dataSize: String
    var dataLabel: String
    var timestamp: String
    var type: ConnectionType
    var network: String = ""
    var destination: String = ""
    var processName: String? = nil
    var route: String = ""
}
