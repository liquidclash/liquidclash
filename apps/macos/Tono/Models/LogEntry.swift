import Foundation

struct LogEntry: Identifiable {
    private static let timestampFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "HH:mm:ss.SSS"
        return formatter
    }()

    let id = UUID()
    let level: String
    let message: String
    let timestamp: Date

    var levelColor: String {
        switch level.lowercased() {
        case "error": "FF453A"
        case "warning": "F59E0B"
        case "info": "4B6EFF"
        case "debug": "A2A3C4"
        default: "8E8EA0"
        }
    }

    var formattedTime: String {
        Self.timestampFormatter.string(from: timestamp)
    }
}
