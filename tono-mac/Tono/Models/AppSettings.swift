import Foundation

// MARK: - App Settings Keys

enum SettingsKey {
    static let launchAtStartup = "launchAtStartup"
    static let interfaceLanguage = "interfaceLanguage"
    static let subscriptionURL = "subscriptionURL"
    static let mixedPort = "mixedPort"
    static let tunMode = "tunMode"
    static let allowLAN = "allowLAN"
    static let themeMode = "themeMode"
    static let glassTransparency = "glassTransparency"
    static let liquidAnimation = "liquidAnimation"
    static let checkForUpdates = "checkForUpdates"
    static let logsEnabled = "logsEnabled"
    static let remoteDiagnosticsEnabled = "remoteDiagnosticsEnabled"
    nonisolated static let claudeTrafficResearchEnabled =
        "claudeTrafficResearchEnabled"
    nonisolated static let localTrafficAuditEnabled =
        "localTrafficAuditEnabled"
    static let hasCompletedOnboarding = "hasCompletedOnboarding"
    static let selectedProxyTargetName = "selectedProxyTargetName"
    static let cloudExitDefaultPolicyVersion = "cloudExitDefaultPolicyVersion"
    static let windowGeometryPolicyVersion = "windowGeometryPolicyVersion"
    static let didStartCore = "didStartCore"
    static let lastTunEnabled = "lastTunEnabled"
}
