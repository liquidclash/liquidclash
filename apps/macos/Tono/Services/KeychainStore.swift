import Foundation
import Security

nonisolated struct KeychainStore: Sendable {
    enum Key: String, Sendable { case refreshToken, installationId, tailscaleStateKey }
    enum Error: Swift.Error { case unexpectedStatus(OSStatus), invalidData }

    private let service: String
    init(service: String = Bundle.main.bundleIdentifier.map { "\($0).tono" } ?? "app.tono.account") { self.service = service }

    func data(for key: Key) throws -> Data? {
        var query = base(key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw Error.unexpectedStatus(status) }
        guard let data = item as? Data else { throw Error.invalidData }
        return data
    }

    func set(_ data: Data, for key: Key) throws {
        let query = base(key)
        let update = [kSecValueData as String: data]
        let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            var add = query; add[kSecValueData as String] = data
            let addStatus = SecItemAdd(add as CFDictionary, nil)
            guard addStatus == errSecSuccess else { throw Error.unexpectedStatus(addStatus) }
        } else if status != errSecSuccess { throw Error.unexpectedStatus(status) }
    }

    func string(for key: Key) throws -> String? {
        guard let data = try data(for: key) else { return nil }
        guard let value = String(data: data, encoding: .utf8) else { throw Error.invalidData }
        return value
    }
    func set(_ value: String, for key: Key) throws { try set(Data(value.utf8), for: key) }
    func remove(_ key: Key) throws {
        let status = SecItemDelete(base(key) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw Error.unexpectedStatus(status) }
    }
    func installationId() throws -> String {
        if let existing = try string(for: .installationId) { return existing }
        let value = UUID().uuidString.lowercased(); try set(value, for: .installationId); return value
    }

    private func base(_ key: Key) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
         kSecAttrAccount as String: key.rawValue, kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
    }
}
