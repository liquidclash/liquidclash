import Foundation

// MARK: - Rule Policy

enum RulePolicy: String, Codable {
    case proxy  = "Proxy"
    case direct = "Direct"
    case reject = "Reject"

    var dotColor: String {
        switch self {
        case .proxy:  "4B6EFF"
        case .direct: "30D158"
        case .reject: "FF6E52"
        }
    }
}

// MARK: - Rule Item

struct RuleItem: Identifiable, Codable {
    var id: String = UUID().uuidString
    var type: String
    var value: String
    var policy: RulePolicy
    /// Original policy/group name from subscription (e.g. "YouTube", "Netflix", "Final").
    /// nil means it's a standard policy (Proxy/DIRECT/REJECT).
    var policyName: String?
    /// Whether this rule has the no-resolve flag
    var noResolve: Bool = false

    /// Display name shown in UI — preserves original group names
    var displayPolicy: String { policyName ?? policy.rawValue }

    /// Clash config format: "TYPE,VALUE,POLICY[,no-resolve]"
    var clashString: String {
        let target = policyName ?? clashPolicyValue
        var str: String
        if type == "MATCH" {
            str = "MATCH,\(target)"
        } else {
            str = "\(type),\(value),\(target)"
        }
        if noResolve { str += ",no-resolve" }
        return str
    }

    /// Standard policy value for Clash config (when no custom group name)
    private var clashPolicyValue: String {
        switch policy {
        case .proxy:  "Proxy"
        case .direct: "DIRECT"
        case .reject: "REJECT"
        }
    }

    init(id: String = UUID().uuidString, type: String, value: String, policy: RulePolicy, policyName: String? = nil, noResolve: Bool = false) {
        self.id = id
        self.type = type
        self.value = value
        self.policy = policy
        self.policyName = policyName
        self.noResolve = noResolve
    }

    // Custom decoder to handle missing noResolve/policyName from older JSON
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        type = try container.decode(String.self, forKey: .type)
        value = try container.decode(String.self, forKey: .value)
        policy = try container.decode(RulePolicy.self, forKey: .policy)
        policyName = try container.decodeIfPresent(String.self, forKey: .policyName)
        noResolve = try container.decodeIfPresent(Bool.self, forKey: .noResolve) ?? false
    }

    /// Parse from Clash config line (e.g. "DOMAIN-SUFFIX,google.com,YouTube" or "GEOIP,CN,DIRECT,no-resolve")
    static func from(clashString: String) -> RuleItem? {
        var parts = clashString.split(separator: ",").map(String.init)
        guard parts.count >= 2 else { return nil }

        // Handle no-resolve suffix
        let noResolve = parts.last == "no-resolve"
        if noResolve { parts.removeLast() }

        let type = parts[0]
        if type == "MATCH" {
            let (policy, name) = parsePolicyWithName(parts[1])
            return RuleItem(type: type, value: "", policy: policy, policyName: name, noResolve: noResolve)
        }

        guard parts.count >= 3 else { return nil }
        let (policy, name) = parsePolicyWithName(parts[2])
        return RuleItem(type: type, value: parts[1], policy: policy, policyName: name, noResolve: noResolve)
    }

    /// Parse policy string, preserving custom group names
    private static func parsePolicyWithName(_ value: String) -> (RulePolicy, String?) {
        switch value.uppercased() {
        case "DIRECT": return (.direct, nil)
        case "REJECT": return (.reject, nil)
        case "PROXY":  return (.proxy, nil)
        default:       return (.proxy, value)  // Custom group name (YouTube, Netflix, etc.)
        }
    }
}
