import Foundation

enum TonoAccountRules {
    static let maximumDevices = 2

    static func normalizedEmail(_ value: String) -> String {
        value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    static func validEmail(_ value: String) -> Bool {
        let parts = normalizedEmail(value).split(separator: "@", omittingEmptySubsequences: false)
        return parts.count == 2 && parts[0].isEmpty == false && parts[1].contains(".")
    }

    static func normalizedDeviceName(_ value: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return String((trimmed.isEmpty ? "Mac" : trimmed).prefix(80))
    }

    static func quotaText(used: Int, limit: Int) -> String { "\(used) / \(limit) devices" }
    static func expiryText(_ date: Date?, locale: Locale = .current) -> String {
        guard let date else { return "No expiration" }
        return date.formatted(.dateTime.year().month().day().locale(locale))
    }
}
