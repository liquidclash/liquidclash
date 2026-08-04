import Foundation

// Wire models for the Tono v1 account API. Optional response fields deliberately
// tolerate additive server changes and partially populated suspended accounts.
nonisolated struct TonoUser: Codable, Identifiable, Sendable, Equatable {
    let id: String
    let email: String
    let name: String?
    let plan: String?
    let deviceLimit: Int?
    let quotaBytes: Int64?
    let usageBytes: Int64?
    let expiresAt: Date?
    let suspended: Bool?
}

nonisolated struct TonoDevice: Codable, Identifiable, Sendable, Equatable {
    let id: String
    let name: String
    let installationId: String?
    let createdAt: Date?
    let lastSeenAt: Date?
    let confirmedAt: Date?
    let current: Bool?
    let status: String?
    /// Tailscale Device API management id used for tag/delete (not status Self.ID).
    let tailscaleNodeId: String?
    /// Wire field is `stableNodeId` (status Self.ID), not the management id.
    let tailscaleStableId: String?
    let tailscaleApiNodeId: String?
    let tailscaleIPs: [String]?

    enum CodingKeys: String, CodingKey {
        case id, name, installationId, createdAt, lastSeenAt, confirmedAt, current, status
        case tailscaleNodeId
        case tailscaleStableId = "stableNodeId"
        case tailscaleApiNodeId, tailscaleIPs
    }
}

/// Local Tailscale identity collected from `tailscale status --json` for confirm.
nonisolated struct TonoNodeIdentity: Sendable, Equatable {
    /// status Self.ID — StableNodeID
    let stableNodeId: String
    /// Optional Device API nodeId if known (usually resolved server-side)
    let nodeId: String?
    /// status Self.PublicKey. Required because StableNodeID is a client-reported
    /// audit value; the Worker must bind confirm to a server-observed identity.
    let publicKey: String
    let tailscaleIPs: [String]
}

nonisolated struct TonoEnrollment: Codable, Sendable, Equatable {
    let id: String?
    let authKey: String?
    /// Server-issued unguessable label passed to `tailscale up --hostname`.
    /// The Worker requires the same label in inventory during confirm.
    let hostname: String?
    let expiresAt: Date?
    let state: String?
}

nonisolated struct TonoTokenResponse: Codable, Sendable {
    let accessToken: String
    let refreshToken: String
}

nonisolated struct TonoAuthResponse: Codable, Sendable {
    let accessToken: String
    let refreshToken: String?
    let user: TonoUser
    let device: TonoDevice?
    let enrollment: TonoEnrollment?
}

/// The worker may wrap authentication payloads as `{ auth: ... }`; accept both
/// that final envelope and the legacy unwrapped development response.
nonisolated struct TonoAuthEnvelope: Decodable, Sendable {
    let auth: TonoAuthResponse
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        auth = try container.decodeIfPresent(TonoAuthResponse.self, forKey: .auth)
            ?? TonoAuthResponse(from: decoder)
    }
    private enum CodingKeys: String, CodingKey { case auth }
}

nonisolated struct TonoMeResponse: Codable, Sendable { let user: TonoUser }
nonisolated struct TonoDevicesResponse: Codable, Sendable { let devices: [TonoDevice] }
nonisolated struct TonoEnrollmentResponse: Codable, Sendable { let enrollment: TonoEnrollment }
nonisolated struct TonoConfirmResponse: Codable, Sendable { let device: TonoDevice }
nonisolated struct TonoExitCatalogResponse: Codable, Sendable, Equatable {
    let revision: Int
    let yaml: String
    let sha256: String
    let updatedAt: Int?
}
nonisolated struct TonoTrafficPolicyResponse: Codable, Sendable, Equatable {
    let revision: Int
    let json: String
    let sha256: String
    let updatedAt: Int?
}
nonisolated struct TonoTrafficPolicy: Codable, Sendable, Equatable {
    let version: Int
    let domains: [TonoTrafficPolicyDomain]
    let mediaEndpoints: [TonoTrafficPolicyMediaEndpoint]
    let webDomains: [TonoTrafficPolicyDomain]

    init(
        version: Int,
        domains: [TonoTrafficPolicyDomain],
        mediaEndpoints: [TonoTrafficPolicyMediaEndpoint],
        webDomains: [TonoTrafficPolicyDomain] = []
    ) {
        self.version = version
        self.domains = domains
        self.mediaEndpoints = mediaEndpoints
        self.webDomains = webDomains
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decode(Int.self, forKey: .version)
        domains = try container.decode(
            [TonoTrafficPolicyDomain].self,
            forKey: .domains
        )
        mediaEndpoints = try container.decode(
            [TonoTrafficPolicyMediaEndpoint].self,
            forKey: .mediaEndpoints
        )
        webDomains = try container.decodeIfPresent(
            [TonoTrafficPolicyDomain].self,
            forKey: .webDomains
        ) ?? []
    }
}
nonisolated struct TonoTrafficPolicyDomain: Codable, Sendable, Equatable {
    let host: String
    let ports: [Int]
}
nonisolated struct TonoTrafficPolicyMediaEndpoint: Codable, Sendable, Equatable {
    let address: String
    let ports: [Int]
}
nonisolated struct TonoEmptyResponse: Codable, Sendable {}

nonisolated enum TonoDeviceActionName: String, Codable, Sendable {
    case diagnosticSnapshot = "diagnostic_snapshot"
    case claudeTrafficSnapshot = "claude_traffic_snapshot"
    case refreshCatalog = "refresh_catalog"
    case retryProtection = "retry_protection"
}
nonisolated struct TonoDeviceAction: Codable, Identifiable, Sendable {
    let id: String
    let action: TonoDeviceActionName
    let expiresAt: Int
}
nonisolated struct TonoDeviceActionsResponse: Codable, Sendable { let actions: [TonoDeviceAction] }
nonisolated struct TonoDiagnosticSnapshot: Codable, Sendable {
    let appVersion: String
    let build: String
    let connected: Bool
    let connecting: Bool
    let disconnecting: Bool
    let protectionBlocked: Bool
    let killSwitchArmed: Bool
    let utunPresent: Bool
    let protectedDNSConfigured: Bool
    let selectedExit: String
    let connectionStage: String
    let reconnectAttempt: Int
    let lastErrorCategory: String?
}
nonisolated struct TonoClaudeTrafficResearchEntry: Codable, Sendable {
    let service: String
    let client: String
    let host: String
    let network: String
    let port: Int
    let route: String
    let connections: Int
    let upBytes: Int64
    let downBytes: Int64
}
nonisolated struct TonoClaudeTrafficResearchSnapshot: Codable, Sendable {
    let observedSince: Int
    let droppedEndpointCount: Int
    let observedConnectionCount: Int
    let identifiedProcessConnectionCount: Int
    let proxiedConnectionCount: Int
    let directConnectionCount: Int
    let blockedConnectionCount: Int
    let directRouteAttemptCount: Int
    let managedDirectRouteCount: Int
    let unclassifiedRouteCount: Int
    let unsafeProtectionObservationCount: Int
    let webManagedDirectConnectionCount: Int
    let weChatConnectionCount: Int
    let weChatManagedDirectConnectionCount: Int
    let weChatProxiedConnectionCount: Int
    let weChatBlockedConnectionCount: Int
    let weChatEndpointUnknownProcessConnectionCount: Int
    let unknownManagedDirectConnectionCount: Int
    let otherManagedDirectConnectionCount: Int
    let protectedDirectConnectionCount: Int
    let connectionLimitReached: Bool
    let connected: Bool
    let killSwitchArmed: Bool
    let tunPresent: Bool
    let protectedDNSConfigured: Bool
    let exitIdentityConsistency: String
    let physicalBypassProbe: String
    let entries: [TonoClaudeTrafficResearchEntry]
}
nonisolated struct TonoDeviceActionResult: Codable, Sendable {
    let outcome: String
    let message: String?
    let snapshot: TonoDiagnosticSnapshot?
    let trafficResearch: TonoClaudeTrafficResearchSnapshot?
}
nonisolated struct TonoDeviceActionResultResponse: Codable, Sendable { let action: TonoDeviceAction }

nonisolated struct TonoAuthMethod: Codable, Sendable, Equatable {
    let enabled: Bool
    let clientId: String?
}

nonisolated struct TonoAuthMethodsResponse: Codable, Sendable, Equatable {
    let email: TonoAuthMethod
    let apple: TonoAuthMethod
    let google: TonoAuthMethod
}

nonisolated struct TonoEmailStartRequest: Codable, Sendable {
    let email: String
    let deviceName: String
    let installationId: String
}

nonisolated struct TonoEmailChallengeResponse: Codable, Sendable, Equatable {
    let challengeId: String
    let expiresIn: Int
    let message: String
}

nonisolated struct TonoEmailVerifyRequest: Codable, Sendable {
    let challengeId: String
    let code: String
}

nonisolated struct TonoOIDCChallengeRequest: Codable, Sendable {
    let provider: String
    let deviceName: String
    let installationId: String
}

nonisolated struct TonoOIDCChallengeResponse: Codable, Sendable, Equatable {
    let challengeId: String
    let nonce: String
    let expiresIn: Int
    let audience: String
}

nonisolated struct TonoOIDCVerifyRequest: Codable, Sendable {
    let provider: String
    let challengeId: String
    let idToken: String
}

nonisolated struct TonoRefreshRequest: Codable, Sendable { let refreshToken: String }
nonisolated struct TonoLogoutRequest: Codable, Sendable { let refreshToken: String? }
nonisolated struct TonoEnrollmentRequest: Codable, Sendable { let installationId: String }
/// Confirm body uses the three distinct Tailscale identities:
/// - stableNodeId: status Self.ID (stable)
/// - nodeId: Device API nodeId when known (optional on client)
/// - publicKey: status Self.PublicKey for inventory disambiguation
/// Worker resolves the management device id from the tailnet inventory.
nonisolated struct TonoConfirmRequest: Codable, Sendable {
    let stableNodeId: String
    let nodeId: String?
    let publicKey: String
    let tailscaleIPs: [String]
}

nonisolated enum TonoCoding {
    nonisolated static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            if let seconds = try? container.decode(Double.self) {
                return Date(timeIntervalSince1970: seconds)
            }
            let value = try container.decode(String.self)
            let fractional = ISO8601DateFormatter()
            fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            if let date = fractional.date(from: value) ?? ISO8601DateFormatter().date(from: value) {
                return date
            }
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid Tono date")
        }
        return decoder
    }

    nonisolated static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }
}
