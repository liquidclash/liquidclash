import SwiftUI

struct RegionGroupView: View {
    let region: ProxyRegion
    let selectedNodeId: String?
    let onToggleExpand: () -> Void
    let onSelectNode: (ProxyNode) -> Void

    private let columns = [
        GridItem(.flexible(), spacing: 12),
        GridItem(.flexible(), spacing: 12),
    ]

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            // Region header — large hit area
            HStack(spacing: 8) {
                Image(systemName: "chevron.right")
                    .font(.system(size: 10, weight: .bold))
                    .foregroundStyle(.secondary)
                    .rotationEffect(.degrees(region.isExpanded ? 90 : 0))

                Text(region.name)
                    .font(.system(size: 11, weight: .semibold))
                    .kerning(1.0)
                    .foregroundStyle(.secondary)

                Text("\(region.nodes.count)")
                    .font(.system(size: 10))
                    .foregroundStyle(.tertiary)

                Spacer()
            }
            .padding(.vertical, 6)
            .contentShape(Rectangle())
            .onTapGesture(perform: onToggleExpand)

            // Node cards grid
            if region.isExpanded {
                LazyVGrid(columns: columns, spacing: 12) {
                    ForEach(region.nodes) { node in
                        NodeCardView(
                            node: node,
                            isSelected: node.id == selectedNodeId,
                            onTap: { onSelectNode(node) }
                        )
                    }
                }
                .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
    }
}

#Preview {
    ZStack {
        MeshGradientBackground()
        RegionGroupView(
            region: mockProxyRegions[0],
            selectedNodeId: "ap1",
            onToggleExpand: {},
            onSelectNode: { _ in }
        )
        .padding(32)
    }
    .frame(width: 700, height: 300)
}
