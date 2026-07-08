import Foundation

enum AppProfile {
    static let devArgument = "--liquidclash-dev"
    static let devEnvironmentKey = "LIQUIDCLASH_PROFILE"

    static var isDev: Bool {
        ProcessInfo.processInfo.arguments.contains(devArgument)
            || ProcessInfo.processInfo.environment[devEnvironmentKey] == "dev"
    }

    static var displayName: String {
        isDev ? "LiquidClash Dev" : "LiquidClash"
    }

    static var appSupportDirectoryName: String {
        isDev ? "LiquidClash-Dev" : "LiquidClash"
    }

    static let defaults: UserDefaults = {
        guard isDev,
              let defaults = UserDefaults(suiteName: "liquidclash.LiquidClash.dev") else {
            return .standard
        }
        return defaults
    }()
}
