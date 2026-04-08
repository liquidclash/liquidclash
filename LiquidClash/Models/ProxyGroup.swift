import Foundation

// MARK: - Group Type (Clash native)

enum GroupType: String, Codable, CaseIterable {
    case select
    case urlTest = "url-test"
    case fallback
    case loadBalance = "load-balance"

    var displayName: String {
        switch self {
        case .select: "Select"
        case .urlTest: "URL Test"
        case .fallback: "Fallback"
        case .loadBalance: "Load Balance"
        }
    }
}

// MARK: - Proxy Group (Clash config concept)

struct ProxyGroup: Identifiable, Codable {
    var id: String = UUID().uuidString
    var name: String
    var type: GroupType = .select
    var proxies: [String] = []
    var selectedProxy: String?
    var url: String?
    var interval: Int?
}

// MARK: - Proxy Region (UI display grouping)

struct ProxyRegion: Identifiable {
    var id: String = UUID().uuidString
    var name: String
    var nodes: [ProxyNode]
    var isExpanded: Bool = true
}
