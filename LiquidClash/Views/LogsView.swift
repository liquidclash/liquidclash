import SwiftUI
import UniformTypeIdentifiers

struct LogsView: View {
    @Environment(AppState.self) private var appState
    @Environment(\.colorScheme) private var colorScheme
    @State private var searchText: String = ""

    private var filteredLogs: [LogEntry] {
        appState.logEntries.filter { entry in
            searchText.isEmpty || entry.message.localizedCaseInsensitiveContains(searchText)
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            headerRow
                .padding(.bottom, 16)

            // Log container
            VStack(spacing: 0) {
                // Table header
                HStack(spacing: 0) {
                    Text("TIME")
                        .frame(width: 100, alignment: .leading)
                    Text("LEVEL")
                        .frame(width: 80, alignment: .leading)
                    Text("MESSAGE")
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(.secondary)
                .tracking(0.5)
                .padding(.horizontal, 20)
                .padding(.vertical, 12)
                .background(.white.opacity(colorScheme == .dark ? 0.06 : 0.15))

                Divider().opacity(0.3)

                // Log entries
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(spacing: 0) {
                            ForEach(filteredLogs) { entry in
                                logRow(entry)
                                    .id(entry.id)
                            }
                        }
                        .padding(.vertical, 4)
                    }
                    .scrollIndicators(.hidden)
                    .onChange(of: appState.logEntries.count) {
                        if let last = filteredLogs.last {
                            withAnimation(.easeOut(duration: 0.15)) {
                                proxy.scrollTo(last.id, anchor: .bottom)
                            }
                        }
                    }
                }

                // Empty state
                if filteredLogs.isEmpty {
                    VStack(spacing: 8) {
                        Image(systemName: "doc.text.magnifyingglass")
                            .font(.system(size: 32))
                            .foregroundStyle(.secondary)
                        Text(LocalizedStringKey(appState.isConnected ? "No logs matching filter" : "Connect to see logs"))
                            .font(.system(size: 13))
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
            .background(.white.opacity(colorScheme == .dark ? 0.08 : 0.4), in: RoundedRectangle(cornerRadius: 20))
            .overlay(
                RoundedRectangle(cornerRadius: 20)
                    .strokeBorder(.white.opacity(colorScheme == .dark ? 0.12 : 0.7), lineWidth: 0.5)
            )
        }
        .padding(.horizontal, 32)
        .padding(.vertical, 16)
        .padding(.bottom, 16)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    // MARK: - Header

    private var headerRow: some View {
        HStack(alignment: .center) {
            HStack(spacing: 10) {
                Text("Logs")
                    .font(.system(size: 24, weight: .semibold))
                    .foregroundStyle(.primary)

                Text("\(appState.logEntries.count) entries")
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 4)
                    .background(.white.opacity(colorScheme == .dark ? 0.08 : 0.4), in: Capsule())
            }

            Spacer()

            HStack(spacing: 10) {
                // Search
                HStack(spacing: 6) {
                    Image(systemName: "magnifyingglass")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                    TextField("Filter logs...", text: $searchText)
                        .textFieldStyle(.plain)
                        .font(.system(size: 12))
                        .frame(width: 160)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .background(.white.opacity(colorScheme == .dark ? 0.08 : 0.4), in: Capsule())
                .overlay(Capsule().strokeBorder(.white.opacity(colorScheme == .dark ? 0.12 : 0.5), lineWidth: 0.5))

                // Export logs
                Button {
                    exportLogs()
                } label: {
                    HStack(spacing: 4) {
                        Image(systemName: "square.and.arrow.down")
                            .font(.system(size: 11))
                        Text("Export")
                            .font(.system(size: 12, weight: .medium))
                    }
                    .foregroundStyle(Color(hex: "4B6EFF"))
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(.white.opacity(colorScheme == .dark ? 0.08 : 0.4), in: Capsule())
                    .overlay(Capsule().strokeBorder(.white.opacity(colorScheme == .dark ? 0.12 : 0.5), lineWidth: 0.5))
                }
                .buttonStyle(.plain)
                .fixedSize()

                // Clear
                Button {
                    appState.clearLogs()
                } label: {
                    HStack(spacing: 4) {
                        Image(systemName: "trash")
                            .font(.system(size: 11))
                        Text("Clear")
                            .font(.system(size: 12, weight: .medium))
                    }
                    .foregroundStyle(Color(hex: "FF6E52"))
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(.white.opacity(colorScheme == .dark ? 0.08 : 0.4), in: Capsule())
                    .overlay(Capsule().strokeBorder(Color(hex: "FF6E52").opacity(0.3), lineWidth: 0.5))
                }
                .buttonStyle(.plain)
                .fixedSize()
            }
        }
    }

    // MARK: - Log Row

    private func logRow(_ entry: LogEntry) -> some View {
        HStack(spacing: 0) {
            Text(entry.formattedTime)
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(.secondary)
                .frame(width: 100, alignment: .leading)

            Text(entry.level.uppercased())
                .font(.system(size: 10, weight: .semibold, design: .monospaced))
                .foregroundStyle(Color(hex: entry.levelColor))
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(Color(hex: entry.levelColor).opacity(0.1), in: RoundedRectangle(cornerRadius: 4))
                .frame(width: 80, alignment: .leading)

            Text(entry.message)
                .font(.system(size: 12, design: .monospaced))
                .foregroundStyle(.primary)
                .lineLimit(2)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 6)
    }

    // MARK: - Export

    private func exportLogs() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.plainText]
        panel.nameFieldStringValue = "clash-logs.txt"

        guard panel.runModal() == .OK, let url = panel.url else { return }

        let content = appState.logEntries.map { entry in
            "[\(entry.formattedTime)] [\(entry.level.uppercased())] \(entry.message)"
        }.joined(separator: "\n")

        try? content.write(to: url, atomically: true, encoding: .utf8)
    }
}

#Preview {
    ZStack {
        MeshGradientBackground()
        LogsView()
    }
    .frame(width: 900, height: 600)
    .environment({
        let state = AppState()
        state.logEntries = [
            LogEntry(level: "info", message: "Start initial compatible provider Auto", timestamp: Date()),
            LogEntry(level: "info", message: "Proxy [Tokyo-01] connected", timestamp: Date()),
            LogEntry(level: "warning", message: "DNS lookup timeout for example.com", timestamp: Date()),
            LogEntry(level: "error", message: "Failed to connect to 10.0.0.1:443", timestamp: Date()),
            LogEntry(level: "debug", message: "TCP connection established to 192.168.1.1:8080", timestamp: Date()),
        ]
        return state
    }())
}
