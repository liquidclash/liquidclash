import Foundation
import Darwin

nonisolated struct TrafficAuditProtectionSnapshot: Sendable {
    let connected: Bool
    let connecting: Bool
    let protectionBlocked: Bool
    let killSwitchArmed: Bool
    let tunPresent: Bool
    let protectedDNSConfigured: Bool
    let selectedExit: String
}

nonisolated private struct CoreAuditEntry: Sendable {
    let level: String
    let message: String
}

nonisolated private struct ClaudeTrafficResearchKey: Hashable, Sendable {
    let service: String
    let client: String
    let host: String
    let network: String
    let port: Int
    let route: String
}

nonisolated private struct ClaudeTrafficResearchTotal: Sendable {
    var connections: Int
    var upBytes: Int64
    var downBytes: Int64
}

nonisolated private struct ClaudeTrafficResearchConnection: Sendable {
    let key: ClaudeTrafficResearchKey
    var upBytes: Int64
    var downBytes: Int64
}

nonisolated private struct AuditRedaction: @unchecked Sendable {
    let expression: NSRegularExpression
    let replacement: String
}

/// A local-only, bounded JSONL audit trail for diagnosing routing and DNS
/// failures. It records connection metadata and Mihomo routing messages, but it
/// never observes TLS bodies, prompts, Authorization headers, cookies, or
/// account tokens. Files are mode 0600 and rotate before reaching 10 MiB.
nonisolated final class LocalTrafficAudit: @unchecked Sendable {
    static let shared = LocalTrafficAudit()
    static let maximumFileBytes = 10 * 1_024 * 1_024
    static let maximumBackups = 2

    static var isEnabled: Bool {
        AppProfile.defaults.object(
            forKey: SettingsKey.localTrafficAuditEnabled
        ) as? Bool ?? true
    }

    static var isClaudeTrafficResearchEnabled: Bool {
        AppProfile.defaults.bool(
            forKey: SettingsKey.claudeTrafficResearchEnabled
        )
    }

    let logFileURL: URL

    private let fileManager = FileManager.default
    private let queue = DispatchQueue(
        label: "com.raydocs.tono.local-traffic-audit",
        qos: .utility
    )
    private let sessionID = UUID().uuidString
    private let timestampFormatter: ISO8601DateFormatter
    private var pending: [Data] = []
    private var pendingBytes = 0
    private var flushWorkItem: DispatchWorkItem?
    private var seenConnectionIDs = Set<String>()
    private var seenConnectionOrder: [String] = []
    private var researchObservedSince = Int(Date().timeIntervalSince1970)
    private var researchTotals: [
        ClaudeTrafficResearchKey: ClaudeTrafficResearchTotal
    ] = [:]
    private var researchConnections: [
        String: ClaudeTrafficResearchConnection
    ] = [:]
    private var researchSeenConnectionIDs = Set<String>()
    private var researchSeenConnectionOrder: [String] = []
    private var researchDroppedKeys = Set<ClaudeTrafficResearchKey>()
    private var researchObservedConnectionCount = 0
    private var researchIdentifiedProcessConnectionCount = 0
    private var researchProxiedConnectionCount = 0
    private var researchDirectConnectionCount = 0
    private var researchBlockedConnectionCount = 0
    private var researchDirectRouteAttemptCount = 0
    private var researchManagedDirectRouteCount = 0
    private var researchUnclassifiedRouteCount = 0
    private var researchUnsafeProtectionObservationCount = 0
    private var researchWebManagedDirectConnectionCount = 0
    private var researchWeChatConnectionCount = 0
    private var researchWeChatManagedDirectConnectionCount = 0
    private var researchWeChatProxiedConnectionCount = 0
    private var researchWeChatBlockedConnectionCount = 0
    private var researchWeChatEndpointUnknownProcessConnectionCount = 0
    private var researchUnknownManagedDirectConnectionCount = 0
    private var researchOtherManagedDirectConnectionCount = 0
    private var researchProtectedDirectConnectionCount = 0
    private var researchConnectionLimitReached = false
    private var researchProtection = TrafficAuditProtectionSnapshot(
        connected: false,
        connecting: false,
        protectionBlocked: false,
        killSwitchArmed: false,
        tunPresent: false,
        protectedDNSConfigured: false,
        selectedExit: "unknown"
    )
    private static let maximumResearchEndpointKeys = 64
    private static let maximumResearchConnections = 20_000
    private static let maximumResearchCount = 1_000_000
    private static let maximumResearchBytes: Int64 = 1_000_000_000_000_000
    private static let redactions: [AuditRedaction] = [
        (
            #"(?i)(authorization|proxy-authorization|cookie|set-cookie)\s*[:=].*$"#,
            "$1=<redacted>"
        ),
        (#"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+"#, "$1 <redacted>"),
        (
            #"(?i)(access[_-]?token|refresh[_-]?token|password|secret|api[_-]?key|auth[_-]?key)=([^&\s]+)"#,
            "$1=<redacted>"
        ),
        (#"(?i)\b(sk-ant-[A-Za-z0-9_-]+|sk-[A-Za-z0-9_-]{16,})\b"#, "<redacted>"),
        (#"(?i)(https?://)[^/@\s]+@"#, "$1<redacted>@"),
        (#"(https?://[^\s?#]+)\?[^\s]+"#, "$1?<redacted>"),
    ].compactMap { pattern, replacement in
        guard let expression = try? NSRegularExpression(pattern: pattern) else {
            return nil
        }
        return AuditRedaction(
            expression: expression,
            replacement: replacement
        )
    }

    private init() {
        let directory = ConfigStorage.shared.appSupportDirectory
            .appendingPathComponent("Logs", isDirectory: true)
        try? fileManager.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try? fileManager.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: directory.path
        )
        logFileURL = directory.appendingPathComponent("traffic-audit.jsonl")
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        timestampFormatter = formatter
    }

    func setEnabled(_ enabled: Bool) {
        AppProfile.defaults.set(
            enabled,
            forKey: SettingsKey.localTrafficAuditEnabled
        )
        queue.async { [self] in
            enqueue(
                kind: enabled ? "audit_enabled" : "audit_disabled",
                fields: [:],
                force: true
            )
            if !enabled {
                flushPending()
            }
        }
    }

    func setClaudeTrafficResearchEnabled(_ enabled: Bool) {
        AppProfile.defaults.set(
            enabled,
            forKey: SettingsKey.claudeTrafficResearchEnabled
        )
        queue.async { [self] in
            researchObservedSince = Int(Date().timeIntervalSince1970)
            researchTotals.removeAll(keepingCapacity: true)
            researchConnections.removeAll(keepingCapacity: true)
            researchSeenConnectionIDs.removeAll(keepingCapacity: true)
            researchSeenConnectionOrder.removeAll(keepingCapacity: true)
            researchDroppedKeys.removeAll(keepingCapacity: true)
            researchObservedConnectionCount = 0
            researchIdentifiedProcessConnectionCount = 0
            researchProxiedConnectionCount = 0
            researchDirectConnectionCount = 0
            researchBlockedConnectionCount = 0
            researchDirectRouteAttemptCount = 0
            researchManagedDirectRouteCount = 0
            researchUnclassifiedRouteCount = 0
            researchUnsafeProtectionObservationCount = 0
            researchWebManagedDirectConnectionCount = 0
            researchWeChatConnectionCount = 0
            researchWeChatManagedDirectConnectionCount = 0
            researchWeChatProxiedConnectionCount = 0
            researchWeChatBlockedConnectionCount = 0
            researchWeChatEndpointUnknownProcessConnectionCount = 0
            researchUnknownManagedDirectConnectionCount = 0
            researchOtherManagedDirectConnectionCount = 0
            researchProtectedDirectConnectionCount = 0
            researchConnectionLimitReached = false
            researchProtection = TrafficAuditProtectionSnapshot(
                connected: false,
                connecting: false,
                protectionBlocked: false,
                killSwitchArmed: false,
                tunPresent: false,
                protectedDNSConfigured: false,
                selectedExit: "unknown"
            )
        }
    }

    func claudeTrafficResearchSnapshot(
        exitIdentityConsistency: String = "INCONCLUSIVE",
        physicalBypassProbe: String = "INCONCLUSIVE"
    )
        -> TonoClaudeTrafficResearchSnapshot {
        queue.sync { [self] in
            let entries = researchTotals.map { key, total in
                TonoClaudeTrafficResearchEntry(
                    service: key.service,
                    client: key.client,
                    host: key.host,
                    network: key.network,
                    port: key.port,
                    route: key.route,
                    connections: total.connections,
                    upBytes: total.upBytes,
                    downBytes: total.downBytes
                )
            }.sorted {
                let leftBytes = $0.upBytes + $0.downBytes
                let rightBytes = $1.upBytes + $1.downBytes
                if leftBytes != rightBytes { return leftBytes > rightBytes }
                if $0.connections != $1.connections {
                    return $0.connections > $1.connections
                }
                if $0.host != $1.host { return $0.host < $1.host }
                if $0.client != $1.client { return $0.client < $1.client }
                if $0.network != $1.network { return $0.network < $1.network }
                return $0.port < $1.port
            }
            // Two worst-case 100-byte hosts plus the WeChat trial aggregates
            // remain below the Worker's strict 2 KiB result limit.
            let visibleEntries = Array(entries.prefix(2))
            let omittedEntries = max(0, entries.count - visibleEntries.count)
            return TonoClaudeTrafficResearchSnapshot(
                observedSince: researchObservedSince,
                droppedEndpointCount: min(
                    researchDroppedKeys.count + omittedEntries,
                    Self.maximumResearchEndpointKeys
                ),
                observedConnectionCount: researchObservedConnectionCount,
                identifiedProcessConnectionCount:
                    researchIdentifiedProcessConnectionCount,
                proxiedConnectionCount: researchProxiedConnectionCount,
                directConnectionCount: researchDirectConnectionCount,
                blockedConnectionCount: researchBlockedConnectionCount,
                directRouteAttemptCount: researchDirectRouteAttemptCount,
                managedDirectRouteCount: researchManagedDirectRouteCount,
                unclassifiedRouteCount: researchUnclassifiedRouteCount,
                unsafeProtectionObservationCount:
                    researchUnsafeProtectionObservationCount,
                webManagedDirectConnectionCount:
                    researchWebManagedDirectConnectionCount,
                weChatConnectionCount: researchWeChatConnectionCount,
                weChatManagedDirectConnectionCount:
                    researchWeChatManagedDirectConnectionCount,
                weChatProxiedConnectionCount:
                    researchWeChatProxiedConnectionCount,
                weChatBlockedConnectionCount:
                    researchWeChatBlockedConnectionCount,
                weChatEndpointUnknownProcessConnectionCount:
                    researchWeChatEndpointUnknownProcessConnectionCount,
                unknownManagedDirectConnectionCount:
                    researchUnknownManagedDirectConnectionCount,
                otherManagedDirectConnectionCount:
                    researchOtherManagedDirectConnectionCount,
                protectedDirectConnectionCount:
                    researchProtectedDirectConnectionCount,
                connectionLimitReached: researchConnectionLimitReached,
                connected: researchProtection.connected,
                killSwitchArmed: researchProtection.killSwitchArmed,
                tunPresent: researchProtection.tunPresent,
                protectedDNSConfigured:
                    researchProtection.protectedDNSConfigured,
                exitIdentityConsistency: exitIdentityConsistency,
                physicalBypassProbe: physicalBypassProbe,
                entries: visibleEntries
            )
        }
    }

    func recordEvent(_ event: String, details: [String: String] = [:]) {
        guard Self.isEnabled else { return }
        queue.async { [self] in
            var fields = details
            fields["event"] = event
            enqueue(kind: "protection_event", fields: fields)
        }
    }

    func recordCoreLogs(_ entries: [(level: String, message: String)]) {
        let localAuditEnabled = Self.isEnabled
        let researchEnabled = Self.isClaudeTrafficResearchEnabled
        guard (localAuditEnabled || researchEnabled), !entries.isEmpty else {
            return
        }
        let values = entries.map {
            CoreAuditEntry(level: $0.level, message: $0.message)
        }
        queue.async { [self] in
            for entry in values {
                let routeClassification: String
                if entry.message.contains(
                    " using \(ConfigPipeline.directProxyName)"
                ) || entry.message.contains(
                    " using \(ConfigPipeline.webDirectProxyName)"
                ) {
                    routeClassification = "MANAGED_DIRECT"
                } else if entry.message.contains(" using DIRECT") {
                    // A Mihomo route decision is not proof that PF put the
                    // packet on the wire, but it must remain conspicuous in an
                    // exported audit instead of being hidden from connection
                    // snapshots that do not include ICMP.
                    routeClassification = "DIRECT_ATTEMPT"
                } else if entry.message.contains(" using Tono-Exit[") {
                    routeClassification = "PROXIED"
                } else {
                    routeClassification = "UNCLASSIFIED"
                }
                if researchEnabled && Self.isClaudeTrafficResearchEnabled {
                    switch routeClassification {
                    case "DIRECT_ATTEMPT":
                        researchDirectRouteAttemptCount = min(
                            researchDirectRouteAttemptCount + 1,
                            Self.maximumResearchCount
                        )
                    case "MANAGED_DIRECT":
                        researchManagedDirectRouteCount = min(
                            researchManagedDirectRouteCount + 1,
                            Self.maximumResearchCount
                        )
                    case "UNCLASSIFIED":
                        researchUnclassifiedRouteCount = min(
                            researchUnclassifiedRouteCount + 1,
                            Self.maximumResearchCount
                        )
                    default:
                        break
                    }
                }
                guard localAuditEnabled, Self.isEnabled else { continue }
                let network = entry.message.first == "["
                    ? entry.message.dropFirst().prefix { $0 != "]" }.uppercased()
                    : "UNKNOWN"
                enqueue(
                    kind: "mihomo_route",
                    fields: [
                        "level": entry.level,
                        "message": entry.message,
                        "network": network,
                        "route_classification": routeClassification,
                    ]
                )
            }
        }
    }

    func recordConnections(
        _ connections: [APIConnection],
        protection: TrafficAuditProtectionSnapshot
    ) {
        let localAuditEnabled = Self.isEnabled
        let researchEnabled = Self.isClaudeTrafficResearchEnabled
        guard localAuditEnabled || researchEnabled else { return }
        queue.async { [self] in
            if researchEnabled && Self.isClaudeTrafficResearchEnabled {
                recordResearchProtection(protection)
            }
            for connection in connections {
                if researchEnabled && Self.isClaudeTrafficResearchEnabled {
                    recordResearchConnectionObservation(connection)
                    recordClaudeTrafficResearch(connection)
                }
                guard localAuditEnabled, Self.isEnabled else { continue }
                guard seenConnectionIDs.insert(connection.id).inserted else {
                    continue
                }
                seenConnectionOrder.append(connection.id)
                if seenConnectionOrder.count > 20_000 {
                    let expired = Array(seenConnectionOrder.prefix(2_000))
                    seenConnectionOrder.removeFirst(expired.count)
                    seenConnectionIDs.subtract(expired)
                }

                let metadata = connection.metadata
                let host = metadata.host.isEmpty
                    ? metadata.destinationIP ?? "unknown"
                    : metadata.host
                let process = metadata.process?.isEmpty == false
                    ? metadata.process ?? "unknown"
                    : "unknown"
                let processPath = metadata.processPath?.isEmpty == false
                    ? metadata.processPath ?? "unknown"
                    : "unknown"
                let chain = connection.chains.isEmpty
                    ? "Direct"
                    : connection.chains.joined(separator: " -> ")
                let lowerHost = host.lowercased().trimmingCharacters(
                    in: CharacterSet(charactersIn: ".")
                )
                let lowerProcessIdentity = "\(process) \(processPath)".lowercased()
                let isClaudeHost = lowerHost == "claude.ai"
                    || lowerHost.hasSuffix(".claude.ai")
                let isAnthropicHost = lowerHost == "anthropic.com"
                    || lowerHost.hasSuffix(".anthropic.com")
                let client: String
                if isClaudeHost || lowerProcessIdentity.contains("claude") {
                    client = "claude-related"
                } else if isAnthropicHost
                    || lowerProcessIdentity.contains("anthropic") {
                    client = "anthropic-related"
                } else if lowerHost.contains("claude")
                    || lowerHost.contains("anthropic") {
                    // Preserve discovery of third-party lookalike domains
                    // without claiming they are official Claude traffic.
                    client = "name-match-only"
                } else {
                    client = "other"
                }
                let routeClassification = Self.routeClassification(connection)

                enqueue(
                    kind: "connection_opened",
                    fields: [
                        "connection_id": connection.id,
                        "client": client,
                        "process": process,
                        "process_path": processPath,
                        "network": metadata.network.uppercased(),
                        "socket_type": metadata.type,
                        "source_ip": metadata.sourceIP ?? "unknown",
                        "source_port": metadata.sourcePort ?? "unknown",
                        "host": host,
                        "destination_ip": metadata.destinationIP ?? "unknown",
                        "destination_port": metadata.destinationPort ?? "unknown",
                        "route": chain,
                        "route_classification": routeClassification,
                        "rule": connection.rule,
                        "rule_payload": connection.rulePayload ?? "",
                        "started_at": connection.start,
                        "selected_exit": protection.selectedExit,
                        "connected": String(protection.connected),
                        "connecting": String(protection.connecting),
                        "protection_blocked": String(protection.protectionBlocked),
                        "kill_switch_armed": String(protection.killSwitchArmed),
                        "tun_present": String(protection.tunPresent),
                        "protected_dns_configured": String(
                            protection.protectedDNSConfigured
                        ),
                    ]
                )
            }
        }
    }

    private func recordResearchProtection(
        _ protection: TrafficAuditProtectionSnapshot
    ) {
        researchProtection = protection
        if protection.connected
            && (!protection.killSwitchArmed
                || !protection.tunPresent
                || !protection.protectedDNSConfigured) {
            researchUnsafeProtectionObservationCount = min(
                researchUnsafeProtectionObservationCount + 1,
                Self.maximumResearchCount
            )
        }
    }

    private func recordResearchConnectionObservation(
        _ connection: APIConnection
    ) {
        guard !researchSeenConnectionIDs.contains(connection.id) else { return }
        researchSeenConnectionIDs.insert(connection.id)
        researchSeenConnectionOrder.append(connection.id)
        // Prune dedup memory instead of freezing every counter forever once
        // 20k unique connections have been seen. Dropping the oldest IDs can
        // at worst double-count a connection that outlives 18k successors,
        // which is far better than a silently dead metric.
        if researchSeenConnectionOrder.count > Self.maximumResearchConnections {
            researchConnectionLimitReached = true
            let expired = researchSeenConnectionOrder.prefix(2_000)
            researchSeenConnectionIDs.subtract(expired)
            researchSeenConnectionOrder.removeFirst(expired.count)
        }
        researchObservedConnectionCount = min(
            researchObservedConnectionCount + 1,
            Self.maximumResearchCount
        )
        let process = (connection.metadata.process ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let processPath = (connection.metadata.processPath ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let processIdentified = Self.processIsIdentified(
            process: process,
            processPath: processPath
        )
        if processIdentified {
            researchIdentifiedProcessConnectionCount = min(
                researchIdentifiedProcessConnectionCount + 1,
                Self.maximumResearchCount
            )
        }
        let route = Self.routeClassification(connection)
        let isWeChat = Self.isNativeWeChatProcess(processPath)
        let isManagedDirect = Self.isManagedDirectConnection(connection)
        let isWebManagedDirect = Self.isWebManagedDirectConnection(connection)
        if isWebManagedDirect {
            researchWebManagedDirectConnectionCount = min(
                researchWebManagedDirectConnectionCount + 1,
                Self.maximumResearchCount
            )
        }
        if isWeChat {
            researchWeChatConnectionCount = min(
                researchWeChatConnectionCount + 1,
                Self.maximumResearchCount
            )
            switch route {
            case "DIRECT" where isManagedDirect || isWebManagedDirect:
                researchWeChatManagedDirectConnectionCount = min(
                    researchWeChatManagedDirectConnectionCount + 1,
                    Self.maximumResearchCount
                )
            case "DIRECT":
                // Unmanaged direct is neither a managed-direct success nor a
                // proxy verdict. It stays visible through the global direct
                // counter instead of skewing the WeChat proxied count.
                break
            case "BLOCKED":
                researchWeChatBlockedConnectionCount = min(
                    researchWeChatBlockedConnectionCount + 1,
                    Self.maximumResearchCount
                )
            default:
                researchWeChatProxiedConnectionCount = min(
                    researchWeChatProxiedConnectionCount + 1,
                    Self.maximumResearchCount
                )
            }
        } else if isManagedDirect {
            if processIdentified {
                researchOtherManagedDirectConnectionCount = min(
                    researchOtherManagedDirectConnectionCount + 1,
                    Self.maximumResearchCount
                )
            } else {
                researchUnknownManagedDirectConnectionCount = min(
                    researchUnknownManagedDirectConnectionCount + 1,
                    Self.maximumResearchCount
                )
            }
        }
        // Endpoint-based safety net for WeChat attribution gaps: count every
        // WeChat-destined flow that the bundle-path predicate above did NOT
        // claim, whether the process was identified (a helper outside the
        // reviewed bundle, a relocated install) or unknown. Gating this on
        // unidentified processes hid exactly the dominant gap.
        if !isWeChat,
           Self.isWeChatEndpoint(connection.metadata.host) {
            researchWeChatEndpointUnknownProcessConnectionCount = min(
                researchWeChatEndpointUnknownProcessConnectionCount + 1,
                Self.maximumResearchCount
            )
        }
        if route == "DIRECT", Self.isProtectedClaudeConnection(connection) {
            researchProtectedDirectConnectionCount = min(
                researchProtectedDirectConnectionCount + 1,
                Self.maximumResearchCount
            )
        }
        switch route {
        case "DIRECT":
            researchDirectConnectionCount = min(
                researchDirectConnectionCount + 1,
                Self.maximumResearchCount
            )
        case "BLOCKED":
            researchBlockedConnectionCount = min(
                researchBlockedConnectionCount + 1,
                Self.maximumResearchCount
            )
        default:
            researchProxiedConnectionCount = min(
                researchProxiedConnectionCount + 1,
                Self.maximumResearchCount
            )
        }
    }

    private static func processIsIdentified(
        process: String,
        processPath: String
    ) -> Bool {
        (!process.isEmpty && process.lowercased() != "unknown")
            || (!processPath.isEmpty && processPath.lowercased() != "unknown")
    }

    private static func isNativeWeChatProcess(_ processPath: String) -> Bool {
        // Match the whole reviewed bundle, mirroring the routing rules: image
        // and media traffic comes from helper executables inside the bundle,
        // not the main binary.
        let path = processPath.lowercased()
        return ConfigPipeline.managedDirectProcessBundlePaths.contains {
            path.hasPrefix($0.lowercased())
        }
    }

    private static func isManagedDirectConnection(_ connection: APIConnection) -> Bool {
        connection.chains.contains {
            $0.caseInsensitiveCompare(ConfigPipeline.directProxyName) == .orderedSame
        }
    }

    private static func isWebManagedDirectConnection(
        _ connection: APIConnection
    ) -> Bool {
        connection.chains.contains {
            $0.caseInsensitiveCompare(
                ConfigPipeline.webDirectProxyName
            ) == .orderedSame
        }
    }

    private static func isWeChatEndpoint(_ rawHost: String) -> Bool {
        let host = rawHost.lowercased().trimmingCharacters(
            in: CharacterSet(charactersIn: ".")
        )
        // WeChat-specific subtrees only. Bare "qq.com" matched every Tencent
        // property (QQ Music, mail, game CDNs) and drowned the counter this
        // suffix list feeds in non-WeChat traffic.
        let suffixes = [
            "weixin.qq.com", "wx.qq.com", "wxs.qq.com", "tc.qq.com",
            "qpic.cn", "qlogo.cn", "gtimg.cn",
            "gtimg.com", "wechat.com", "weixin.com", "weixinbridge.com",
            "wechatos.net",
        ]
        return suffixes.contains { host == $0 || host.hasSuffix(".\($0)") }
    }

    private static func isProtectedClaudeConnection(
        _ connection: APIConnection
    ) -> Bool {
        let host = connection.metadata.host.lowercased().trimmingCharacters(
            in: CharacterSet(charactersIn: ".")
        )
        if host == "claude.ai" || host.hasSuffix(".claude.ai")
            || host == "anthropic.com" || host.hasSuffix(".anthropic.com") {
            return true
        }
        let process = (connection.metadata.process ?? "").lowercased()
        let processPath = (connection.metadata.processPath ?? "").lowercased()
        return Self.isClaudeCodeProcess(process: process, processPath: processPath)
            || processPath.contains("/claude.app/")
    }

    private func recordClaudeTrafficResearch(_ connection: APIConnection) {
        guard let key = Self.claudeTrafficResearchKey(connection) else { return }
        let upBytes = min(
            max(connection.upload, 0),
            Self.maximumResearchBytes
        )
        let downBytes = min(
            max(connection.download, 0),
            Self.maximumResearchBytes
        )

        if var previous = researchConnections[connection.id] {
            guard previous.key == key,
                  var total = researchTotals[key] else { return }
            total.upBytes = min(
                total.upBytes + max(0, upBytes - previous.upBytes),
                Self.maximumResearchBytes
            )
            total.downBytes = min(
                total.downBytes + max(0, downBytes - previous.downBytes),
                Self.maximumResearchBytes
            )
            previous.upBytes = max(previous.upBytes, upBytes)
            previous.downBytes = max(previous.downBytes, downBytes)
            researchConnections[connection.id] = previous
            researchTotals[key] = total
            return
        }

        guard researchTotals[key] != nil
                || researchTotals.count < Self.maximumResearchEndpointKeys else {
            if researchDroppedKeys.count < Self.maximumResearchEndpointKeys {
                researchDroppedKeys.insert(key)
            }
            return
        }
        guard researchConnections.count < Self.maximumResearchConnections else {
            researchConnectionLimitReached = true
            return
        }
        var total = researchTotals[key] ?? ClaudeTrafficResearchTotal(
            connections: 0,
            upBytes: 0,
            downBytes: 0
        )
        total.connections = min(total.connections + 1, 1_000_000)
        total.upBytes = min(
            total.upBytes + upBytes,
            Self.maximumResearchBytes
        )
        total.downBytes = min(
            total.downBytes + downBytes,
            Self.maximumResearchBytes
        )
        researchTotals[key] = total
        researchConnections[connection.id] = ClaudeTrafficResearchConnection(
            key: key,
            upBytes: upBytes,
            downBytes: downBytes
        )
    }

    private static func claudeTrafficResearchKey(
        _ connection: APIConnection
    ) -> ClaudeTrafficResearchKey? {
        let host = connection.metadata.host.lowercased()
            .trimmingCharacters(in: CharacterSet(charactersIn: "."))
        guard isResearchHostname(host) else { return nil }
        let network = connection.metadata.network.uppercased()
        guard network == "TCP" || network == "UDP",
              let port = Int(connection.metadata.destinationPort ?? ""),
              (1...65_535).contains(port) else { return nil }

        let process = (connection.metadata.process ?? "").lowercased()
        let processPath = (connection.metadata.processPath ?? "").lowercased()
        let client: String
        if processPath.contains("/claude.app/") {
            client = "app"
        } else if isClaudeCodeProcess(process: process, processPath: processPath) {
            client = "code"
        } else if [
            "safari", "google chrome", "chromium", "arc", "firefox",
            "brave browser", "microsoft edge",
        ].contains(where: {
            process == $0 || processPath.contains("/\($0).app/")
        }) {
            client = "web"
        } else {
            client = "unknown"
        }

        let service: String
        if host == "claude.ai" || host.hasSuffix(".claude.ai") {
            service = "claude"
        } else if host == "anthropic.com"
                    || host.hasSuffix(".anthropic.com") {
            service = "anthropic"
        } else if client == "app" || client == "code" {
            // Only a positively attributed Claude process may contribute a
            // non-official destination. Browser processes are intentionally
            // excluded because Mihomo cannot identify which browser tab made
            // a request, and child tools remain explicitly reported as an
            // attribution-coverage limitation rather than guessed.
            service = "other"
        } else {
            return nil
        }

        // The research consent promises aggregates and verdicts, not browsing
        // destinations. Official Claude/Anthropic hostnames are the research
        // subject and may be transmitted; every other destination is folded
        // into a single "other" bucket so no third-party hostname leaves the
        // device.
        let reportedHost = (service == "claude" || service == "anthropic")
            ? host
            : "other"
        return ClaudeTrafficResearchKey(
            service: service,
            client: client,
            host: reportedHost,
            network: network,
            port: port,
            route: routeClassification(connection)
        )
    }

    private static func isClaudeCodeProcess(
        process: String,
        processPath: String
    ) -> Bool {
        process == "claude" || process == "claude.exe"
            || processPath.hasSuffix("/claude")
            || processPath.hasSuffix("/claude.exe")
    }

    private static func isResearchHostname(_ host: String) -> Bool {
        guard !host.isEmpty, host.utf8.count <= 100,
              host.unicodeScalars.allSatisfy({ $0.isASCII }),
              !host.contains("..") else { return false }
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2,
              labels.allSatisfy({ label in
                  guard !label.isEmpty, label.utf8.count <= 63,
                        label.first != "-", label.last != "-" else {
                      return false
                  }
                  return label.allSatisfy {
                      $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-")
                  }
              }),
              let topLevel = labels.last,
              topLevel.count >= 2,
              topLevel.allSatisfy({ $0.isASCII && $0.isLetter }) else {
            return false
        }
        return !["local", "internal", "localhost", "home", "lan"].contains(
            String(topLevel)
        )
    }

    private static func routeClassification(
        _ connection: APIConnection
    ) -> String {
        let upperRouteValues = connection.chains.map { $0.uppercased() }
        let upperRule = connection.rule.uppercased()
        if upperRule.hasPrefix("REJECT")
            || upperRouteValues.contains(where: { $0.hasPrefix("REJECT") }) {
            return "BLOCKED"
        }
        if upperRouteValues.contains("DIRECT")
            || upperRouteValues.contains(ConfigPipeline.directProxyName.uppercased())
            || upperRouteValues.contains(
                ConfigPipeline.webDirectProxyName.uppercased()
            )
            || upperRule == "DIRECT" {
            return "DIRECT"
        }
        return "PROXIED"
    }

    /// Flush queued entries before revealing the file in Finder.
    func prepareForReveal() -> URL {
        queue.sync { [self] in
            flushPending()
            _ = ensureLogFile()
        }
        return logFileURL
    }

    private func enqueue(
        kind: String,
        fields: [String: String],
        force: Bool = false
    ) {
        guard force || Self.isEnabled else { return }
        var object: [String: Any] = [
            "schema": 1,
            "timestamp": timestampFormatter.string(from: Date()),
            "session_id": sessionID,
            "kind": kind,
        ]
        for (key, value) in fields {
            object[key] = Self.sanitize(value)
        }
        guard var data = try? JSONSerialization.data(
            withJSONObject: object,
            options: [.sortedKeys]
        ) else { return }
        data.append(0x0A)
        pending.append(data)
        pendingBytes += data.count

        if pending.count >= 64 || pendingBytes >= 64 * 1_024 {
            flushPending()
            return
        }
        guard flushWorkItem == nil else { return }
        let work = DispatchWorkItem { [weak self] in
            self?.flushPending()
        }
        flushWorkItem = work
        queue.asyncAfter(deadline: .now() + 1, execute: work)
    }

    private func flushPending() {
        flushWorkItem?.cancel()
        flushWorkItem = nil
        guard !pending.isEmpty else { return }
        let output = pending.reduce(into: Data()) { $0.append($1) }
        pending.removeAll(keepingCapacity: true)
        pendingBytes = 0
        guard rotateIfNeeded(adding: output.count), ensureLogFile(),
              let handle = try? FileHandle(forWritingTo: logFileURL) else {
            return
        }
        defer { try? handle.close() }
        do {
            try handle.seekToEnd()
            try handle.write(contentsOf: output)
        } catch {
            return
        }
    }

    private func rotateIfNeeded(adding bytes: Int) -> Bool {
        let currentSize = (
            try? fileManager.attributesOfItem(atPath: logFileURL.path)[.size]
                as? NSNumber
        )??.intValue ?? 0
        guard currentSize + bytes > Self.maximumFileBytes else { return true }

        for index in stride(
            from: Self.maximumBackups,
            through: 2,
            by: -1
        ) {
            let destination = backupURL(index)
            let source = backupURL(index - 1)
            if fileManager.fileExists(atPath: destination.path) {
                try? fileManager.removeItem(at: destination)
            }
            if fileManager.fileExists(atPath: source.path) {
                try? fileManager.moveItem(at: source, to: destination)
            }
        }
        let firstBackup = backupURL(1)
        if fileManager.fileExists(atPath: firstBackup.path) {
            do {
                try fileManager.removeItem(at: firstBackup)
            } catch {
                return false
            }
        }
        guard fileManager.fileExists(atPath: logFileURL.path) else {
            return true
        }
        do {
            try fileManager.moveItem(at: logFileURL, to: firstBackup)
            return true
        } catch {
            return false
        }
    }

    private func backupURL(_ index: Int) -> URL {
        logFileURL.deletingLastPathComponent()
            .appendingPathComponent("traffic-audit.jsonl.\(index)")
    }

    private func ensureLogFile() -> Bool {
        if fileManager.fileExists(atPath: logFileURL.path) {
            guard let values = try? logFileURL.resourceValues(forKeys: [
                .isRegularFileKey,
                .isSymbolicLinkKey,
            ]),
                  values.isRegularFile == true,
                  values.isSymbolicLink != true,
                  let attributes = try? fileManager.attributesOfItem(
                    atPath: logFileURL.path
                  ),
                  (attributes[.ownerAccountID] as? NSNumber)?.uint32Value
                    == getuid(),
                  let permissions = (attributes[.posixPermissions] as? NSNumber)?
                    .uint16Value,
                  permissions & 0o077 == 0 else {
                return false
            }
            return true
        }
        return fileManager.createFile(
            atPath: logFileURL.path,
            contents: nil,
            attributes: [.posixPermissions: 0o600]
        )
    }

    private static func sanitize(_ raw: String) -> String {
        var value = raw.replacingOccurrences(of: "\r", with: " ")
            .replacingOccurrences(of: "\n", with: " ")
        for redaction in redactions {
            value = redaction.expression.stringByReplacingMatches(
                in: value,
                range: NSRange(value.startIndex..., in: value),
                withTemplate: redaction.replacement
            )
        }
        return String(value.prefix(4_096))
    }
}
