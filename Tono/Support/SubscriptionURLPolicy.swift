import Foundation
import Darwin

/// Restricts subscription import/refresh destinations so Tono never dials
/// private networks, loopback, or non-HTTPS origins outside the home transport.
nonisolated enum SubscriptionURLPolicy {
    enum Rejection: LocalizedError, Equatable {
        case invalidURL
        case schemeNotHTTPS
        case missingHost
        case credentialsNotAllowed
        case blockedPort(Int)
        case blockedHost(String)
        case blockedAddress(String)

        var errorDescription: String? {
            switch self {
            case .invalidURL: return "Subscription URL is invalid."
            case .schemeNotHTTPS: return "Subscription URLs must use HTTPS."
            case .missingHost: return "Subscription URL is missing a host."
            case .credentialsNotAllowed: return "Subscription URLs cannot contain embedded credentials."
            case .blockedPort(let port): return "Subscription HTTPS port is not allowed: \(port)"
            case .blockedHost(let h): return "Subscription host is not allowed: \(h)"
            case .blockedAddress(let a): return "Subscription target address is not allowed: \(a)"
            }
        }
    }

    /// Validates a candidate subscription URL string before any network I/O.
    static func validate(_ raw: String) -> Result<URL, Rejection> {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard var components = URLComponents(string: trimmed),
              let scheme = components.scheme?.lowercased(),
              let parsedURL = components.url else {
            return .failure(.invalidURL)
        }
        guard scheme == "https" else { return .failure(.schemeNotHTTPS) }
        guard components.user == nil, components.password == nil else {
            return .failure(.credentialsNotAllowed)
        }
        if let port = components.port, port != 443 { return .failure(.blockedPort(port)) }
        // URL.host preserves an ASCII/punycode DNS name and removes IPv6
        // brackets. URLComponents.host decodes IDNs and includes brackets on
        // some Foundation versions, so it is unsuitable for this classifier.
        guard let rawHost = parsedURL.host, !rawHost.isEmpty else { return .failure(.missingHost) }
        let host = rawHost.lowercased()
            .trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
            .trimmingCharacters(in: CharacterSet(charactersIn: "."))
        guard !host.isEmpty else { return .failure(.missingHost) }
        if isBlockedHost(host) { return .failure(.blockedHost(host)) }
        if let ip = hostAsIP(host), isBlockedIP(ip) { return .failure(.blockedAddress(host)) }
        if hostAsIP(host) == nil {
            let labels = host.split(separator: ".", omittingEmptySubsequences: false)
            let valid = labels.count >= 2 && labels.allSatisfy { label in
                guard !label.isEmpty, label.count <= 63,
                      let first = label.first, let last = label.last,
                      first.isASCII, last.isASCII, first.isLetter || first.isNumber,
                      last.isLetter || last.isNumber else { return false }
                return label.allSatisfy { character in
                    character.isASCII && (character.isLetter || character.isNumber || character == "-")
                }
            }
            if !valid { return .failure(.blockedHost(host)) }
        }
        components.scheme = "https"
        // Rebuild DNS hosts to remove case and a trailing dot. Keep the original
        // URLComponents representation for IPv6 literals so brackets survive.
        if hostAsIP(host) == nil {
            components.host = host
        }
        guard let normalized = components.url else { return .failure(.invalidURL) }
        return .success(normalized)
    }

    static func isBlockedHost(_ host: String) -> Bool {
        let h = host.lowercased()
            .trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
            .trimmingCharacters(in: CharacterSet(charactersIn: "."))
        if h == "localhost" || h.hasSuffix(".localhost") ||
            h.hasSuffix(".local") || h.hasSuffix(".internal") ||
            h.hasSuffix(".lan") || h.hasSuffix(".home.arpa") {
            return true
        }
        if h == "0.0.0.0" || h == "::" || h == "::1" { return true }
        return false
    }

    static func literalIPAddress(_ host: String) -> String? {
        hostAsIP(host)
    }

    /// IPv4/IPv6 literal classification for private, link-local, loopback, CGNAT.
    static func isBlockedIP(_ ip: String) -> Bool {
        let address = ip.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        var ipv4 = in_addr()
        if inet_pton(AF_INET, address, &ipv4) == 1 {
            return isBlockedIPv4(UInt32(bigEndian: ipv4.s_addr))
        }
        var ipv6 = in6_addr()
        guard inet_pton(AF_INET6, address, &ipv6) == 1 else { return true }
        let bytes = withUnsafeBytes(of: &ipv6) { Array($0) }
        guard bytes.count == 16 else { return true }
        if bytes.allSatisfy({ $0 == 0 }) { return true } // unspecified
        if bytes.dropLast().allSatisfy({ $0 == 0 }) && bytes[15] == 1 { return true } // loopback
        if bytes.prefix(10).allSatisfy({ $0 == 0 }), bytes[10] == 0xff, bytes[11] == 0xff {
            let mapped = (UInt32(bytes[12]) << 24) | (UInt32(bytes[13]) << 16) |
                (UInt32(bytes[14]) << 8) | UInt32(bytes[15])
            return isBlockedIPv4(mapped)
        }
        if bytes[0] & 0xfe == 0xfc { return true } // ULA fc00::/7
        if bytes[0] == 0xfe, bytes[1] & 0xc0 == 0x80 { return true } // link-local fe80::/10
        if bytes[0] == 0xff { return true } // multicast
        if bytes[0] == 0x20, bytes[1] == 0x01, bytes[2] <= 0x01 {
            return true // IETF special-purpose 2001:0000::/23
        }
        if bytes[0] == 0x20, bytes[1] == 0x01, bytes[2] == 0x0d, bytes[3] == 0xb8 {
            return true // documentation 2001:db8::/32
        }
        if bytes[0] == 0x20, bytes[1] == 0x02 {
            return true // deprecated 6to4 may encode a non-public IPv4 target
        }
        if bytes[0] == 0x3f, bytes[1] & 0xf0 == 0xf0 {
            return true // documentation 3fff::/20
        }
        // Accept only global-unicast 2000::/3 literals. DNS answers are checked
        // again immediately before curl is pinned to one public address.
        return bytes[0] & 0xe0 != 0x20
    }

    private static func isBlockedIPv4(_ value: UInt32) -> Bool {
        let a = UInt8((value >> 24) & 0xff)
        let b = UInt8((value >> 16) & 0xff)
        let c = UInt8((value >> 8) & 0xff)
        if a == 10 { return true }
        if a == 127 { return true }
        if a == 0 { return true }
        if a == 169 && b == 254 { return true }
        if a == 172 && (16...31).contains(b) { return true }
        if a == 192 && b == 168 { return true }
        if a == 100 && (64...127).contains(b) { return true } // CGNAT / Tailscale CGN range caution
        if a == 192 && b == 0 && c == 0 { return true }
        if a == 192 && b == 0 && c == 2 { return true }
        if a == 192 && b == 88 && c == 99 { return true }
        if a == 198 && (b == 18 || b == 19) { return true }
        if a == 198 && b == 51 && c == 100 { return true }
        if a == 203 && b == 0 && c == 113 { return true }
        if a >= 224 { return true } // multicast/reserved
        return false
    }

    private static func hostAsIP(_ host: String) -> String? {
        let h = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        var sin = sockaddr_in()
        if inet_pton(AF_INET, h, &sin.sin_addr) == 1 { return h }
        var sin6 = sockaddr_in6()
        if inet_pton(AF_INET6, h, &sin6.sin6_addr) == 1 { return h }
        return nil
    }
}
