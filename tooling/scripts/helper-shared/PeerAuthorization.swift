import Foundation
import Darwin
import Security

enum PeerAuthorizationError: Error {
    case requirement
}

/// Authenticates the process at the other end of a connected Unix-domain
/// socket. UID checks alone are not an application identity boundary: every
/// process owned by the interactive user shares that UID. LOCAL_PEERTOKEN is
/// supplied by the kernel and binds the Security.framework dynamic-code lookup
/// to the exact process incarnation (including the audit-token pid version).
struct TonoPeerAuthorizer {
    static let clientRequirementText =
        #"anchor apple generic and identifier "com.raydocs.tono" and certificate leaf[subject.OU] = "YY57758GS7""#

    private let allowedUID: uid_t
    private let requirement: SecRequirement

    init(allowedUID: uid_t) throws {
        self.allowedUID = allowedUID
        var created: SecRequirement?
        guard SecRequirementCreateWithString(
            Self.clientRequirementText as CFString,
            SecCSFlags(rawValue: 0),
            &created
        ) == errSecSuccess, let created else {
            throw PeerAuthorizationError.requirement
        }
        requirement = created
    }

    func accepts(socket fd: Int32) -> Bool {
        var peerUID: uid_t = 0
        var peerGID: gid_t = 0
        var token = audit_token_t()
        var length = socklen_t(MemoryLayout<audit_token_t>.size)
        guard getpeereid(fd, &peerUID, &peerGID) == 0,
              peerUID == allowedUID,
              withUnsafeMutablePointer(to: &token, {
            getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, $0, &length)
        }) == 0, length == MemoryLayout<audit_token_t>.size else {
            return false
        }

        let tokenData = withUnsafeBytes(of: &token) { Data($0) }
        let attributes = [kSecGuestAttributeAudit: tokenData] as CFDictionary
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(
            nil,
            attributes,
            SecCSFlags(rawValue: 0),
            &code
        ) == errSecSuccess, let code else {
            return false
        }
        return SecCodeCheckValidity(
            code,
            SecCSFlags(rawValue: 0),
            requirement
        ) == errSecSuccess
    }
}
