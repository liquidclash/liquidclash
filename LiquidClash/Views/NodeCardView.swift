import SwiftUI

struct NodeCardView: View {
    @Environment(\.colorScheme) private var colorScheme
    let node: ProxyNode
    let isSelected: Bool
    let onTap: () -> Void

    var body: some View {
        Button(action: onTap) {
            HStack(spacing: 12) {
                // Flag circle
                Text(node.flag)
                    .font(.system(size: 15))
                    .frame(width: 32, height: 32)
                    .background(.white.opacity(colorScheme == .dark ? 0.06 : 0.3), in: Circle())

                // Node info
                VStack(alignment: .leading, spacing: 2) {
                    Text(node.name)
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(.primary)
                        .lineLimit(1)

                    Text("\(node.protocolType) \u{2022} \(node.relay)")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }

                Spacer(minLength: 0)

                // Latency badge
                Text(node.latency > 0 ? "\(node.latency)ms" : "—")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(node.latency > 0 ? Color(hex: node.latencyColor.color) : .secondary)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(
                        (node.latency > 0 ? Color(hex: node.latencyColor.bgColor).opacity(0.12) : Color.secondary.opacity(0.08)),
                        in: RoundedRectangle(cornerRadius: 6)
                    )
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .background(.white.opacity(isSelected ? 0.75 : 0.4), in: RoundedRectangle(cornerRadius: 14))
        .overlay(
            RoundedRectangle(cornerRadius: 14)
                .strokeBorder(
                    isSelected ? Color(hex: "4B6EFF").opacity(0.5) : .white.opacity(colorScheme == .dark ? 0.12 : 0.7),
                    lineWidth: 1
                )
        )
        .shadow(
            color: isSelected ? Color(hex: "4B6EFF").opacity(0.08) : .clear,
            radius: 12, y: 4
        )
    }
}

#Preview {
    ZStack {
        MeshGradientBackground()
        VStack(spacing: 12) {
            NodeCardView(
                node: mockProxyRegions[0].nodes[0],
                isSelected: true,
                onTap: {}
            )
            NodeCardView(
                node: mockProxyRegions[0].nodes[1],
                isSelected: false,
                onTap: {}
            )
        }
        .padding(40)
    }
    .frame(width: 400, height: 300)
}
