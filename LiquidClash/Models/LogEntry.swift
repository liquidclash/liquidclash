import Foundation

struct LogEntry: Identifiable {
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
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss.SSS"
        return formatter.string(from: timestamp)
    }
}
