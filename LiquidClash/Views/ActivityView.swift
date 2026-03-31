import SwiftUI

struct ActivityView: View {
    @State private var connections: [ConnectionEntry] = mockConnections
    @State private var selectedFilter: String = "All"

    private let filters = ["All", "Proxied", "Direct", "Rejected"]

    private var filteredConnections: [ConnectionEntry] {
        if selectedFilter == "All" { return connections }
        return connections.filter { $0.type.rawValue == selectedFilter }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            headerRow
                .padding(.bottom, 24)

            // Timeline logs
            ScrollView {
                ZStack(alignment: .leading) {
                    // Timeline line
                    timelineLine

                    // Log entries
                    VStack(spacing: 14) {
                        ForEach(filteredConnections) { entry in
                            LogEntryRow(entry: entry)
                        }
                    }
                    .padding(.leading, 32)
                }
            }
            .scrollIndicators(.hidden)
        }
        .padding(.horizontal, 32)
        .padding(.vertical, 16)
        .padding(.bottom, 16)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    // MARK: - Timeline Line

    private var timelineLine: some View {
        LinearGradient(
            colors: [Color(hex: "4B6EFF"), Color(hex: "A2A3C4").opacity(0.3)],
            startPoint: .top,
            endPoint: .bottom
        )
        .frame(width: 2)
        .padding(.leading, 10)
        .frame(maxHeight: .infinity, alignment: .top)
    }

    // MARK: - Header

    private var headerRow: some View {
        HStack(alignment: .center) {
            Text("Connections")
                .font(.system(size: 24, weight: .semibold))
                .foregroundStyle(Color(hex: "383A76"))

            Spacer()

            HStack(spacing: 14) {
                // Filter pills
                HStack(spacing: 6) {
                    ForEach(filters, id: \.self) { filter in
                        Button {
                            withAnimation(.easeInOut(duration: 0.2)) {
                                selectedFilter = filter
                            }
                        } label: {
                            Text(filter)
                                .font(.system(size: 12, weight: .medium))
                                .foregroundStyle(selectedFilter == filter ? .white : Color(hex: "7A7B9F"))
                                .padding(.horizontal, 14)
                                .padding(.vertical, 6)
                                .background(
                                    selectedFilter == filter
                                        ? Color(hex: "4B6EFF")
                                        : .white.opacity(0.4),
                                    in: Capsule()
                                )
                                .overlay(
                                    Capsule().strokeBorder(
                                        selectedFilter == filter ? .clear : .white.opacity(0.7),
                                        lineWidth: 0.5
                                    )
                                )
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
        }
    }
}

// MARK: - Log Entry Row

private struct LogEntryRow: View {
    let entry: ConnectionEntry
    @State private var isHovered = false

    private var dotColor: Color {
        switch entry.type {
        case .proxied:  return Color(hex: "4B6EFF")
        case .direct:   return Color(hex: "FF6E52")
        case .rejected: return Color(hex: "333333")
        }
    }

    private var latencyStyle: (fg: String, bg: String) {
        guard let ms = entry.latency else { return ("A2A3C4", "000000") }
        if ms <= 80 { return ("10B981", "10B981") }
        if ms <= 200 { return ("F59E0B", "F59E0B") }
        return ("EF4444", "EF4444")
    }

    var body: some View {
        HStack(spacing: 0) {
            // Timeline dot
            Circle()
                .fill(.white)
                .frame(width: 10, height: 10)
                .overlay(Circle().strokeBorder(dotColor, lineWidth: 2))
                .shadow(color: dotColor.opacity(0.4), radius: 4)
                .offset(x: -26)

            // Card content
            HStack(spacing: 16) {
                // Domain info
                VStack(alignment: .leading, spacing: 3) {
                    Text(entry.domain)
                        .font(.system(size: 13, weight: .semibold, design: .monospaced))
                        .foregroundStyle(Color(hex: "383A76"))
                        .lineLimit(1)

                    Text("\(entry.protocolName) • rule: \(entry.rule)")
                        .font(.system(size: 10, weight: .medium))
                        .foregroundStyle(Color(hex: "A2A3C4"))
                        .textCase(.uppercase)
                }
                .frame(maxWidth: .infinity, alignment: .leading)

                // Node
                HStack(spacing: 6) {
                    Text(entry.nodeFlag)
                        .font(.system(size: 14))
                    Text(entry.nodeName)
                        .font(.system(size: 13, weight: .medium))
                        .foregroundStyle(
                            entry.type == .rejected
                                ? Color(hex: "A2A3C4")
                                : Color(hex: "7A7B9F")
                        )
                        .lineLimit(1)
                }
                .frame(width: 160, alignment: .leading)

                // Latency
                if let ms = entry.latency {
                    Text("\(ms)ms")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(Color(hex: latencyStyle.fg))
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(Color(hex: latencyStyle.bg).opacity(0.1), in: RoundedRectangle(cornerRadius: 6))
                        .frame(width: 80)
                } else {
                    Text("- -")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(Color(hex: "A2A3C4"))
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(.black.opacity(0.04), in: RoundedRectangle(cornerRadius: 6))
                        .frame(width: 80)
                }

                // Stats
                VStack(alignment: .trailing, spacing: 2) {
                    Text(entry.dataSize)
                        .font(.system(size: 13, weight: .medium))
                        .foregroundStyle(Color(hex: "383A76"))
                    Text(entry.dataLabel)
                        .font(.system(size: 10))
                        .foregroundStyle(Color(hex: "A2A3C4"))
                }
                .frame(width: 80, alignment: .trailing)
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 14)
        }
        .background(
            isHovered ? .white.opacity(0.9) : .white.opacity(0.4),
            in: RoundedRectangle(cornerRadius: 18)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 18)
                .strokeBorder(.white.opacity(0.7), lineWidth: 1)
        )
        .contentShape(Rectangle())
        .onHover { hovering in
            withAnimation(.easeInOut(duration: 0.15)) {
                isHovered = hovering
            }
        }
    }
}

#Preview {
    ZStack {
        MeshGradientBackground()
        ActivityView()
    }
    .frame(width: 900, height: 600)
}
