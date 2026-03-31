import SwiftUI

struct ProxiesView: View {
    @State private var regions: [ProxyRegion] = mockProxyRegions
    @State private var selectedNodeId: String? = "ap1"
    @State private var showingAddNode = false
    private var totalNodes: Int {
        regions.flatMap(\.nodes).count
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            headerRow
                .padding(.bottom, 24)

            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    ForEach(regions) { region in
                        RegionGroupView(
                            region: region,
                            selectedNodeId: selectedNodeId,
                            onToggleExpand: {
                                withAnimation(.easeInOut(duration: 0.25)) {
                                    toggleRegion(region.id)
                                }
                            },
                            onSelectNode: { node in
                                withAnimation(.easeInOut(duration: 0.2)) {
                                    selectedNodeId = node.id
                                }
                            }
                        )
                    }
                }
            }
            .scrollIndicators(.hidden)
        }
        .padding(.horizontal, 32)
        .padding(.vertical, 16)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .overlay {
            if showingAddNode {
                AddNodeSheet(isPresented: $showingAddNode)
                    .transition(.opacity)
            }
        }
    }

    // MARK: - Header

    private var headerRow: some View {
        HStack(alignment: .center) {
            // Title + count
            HStack(spacing: 10) {
                Text("Proxies")
                    .font(.system(size: 24, weight: .semibold))
                    .foregroundStyle(Color(hex: "383A76"))

                Text("\(totalNodes) Available")
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(Color(hex: "8E8EA0"))
                    .padding(.horizontal, 10)
                    .padding(.vertical, 4)
                    .background(
                        .white.opacity(0.4),
                        in: Capsule()
                    )
            }

            Spacer()

            // Add Node + Test All
            HStack(spacing: 10) {
                Button {
                    withAnimation(.easeOut(duration: 0.25)) {
                        showingAddNode = true
                    }
                } label: {
                    HStack(spacing: 5) {
                        Image(systemName: "plus")
                            .font(.system(size: 11, weight: .bold))
                        Text("Add Node")
                            .font(.system(size: 12, weight: .semibold))
                    }
                    .foregroundStyle(.white)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 8)
                    .background(
                        LinearGradient(
                            colors: [Color(hex: "FF6E52"), Color(hex: "C34AC2")],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        ),
                        in: Capsule()
                    )
                }
                .buttonStyle(.plain)
                .fixedSize()
                .shadow(color: Color(hex: "FF6E52").opacity(0.25), radius: 8, y: 3)

                Button {
                    // TODO: Test all latency
                } label: {
                    HStack(spacing: 5) {
                        Image(systemName: "bolt.fill")
                            .font(.system(size: 11))
                        Text("Test All")
                            .font(.system(size: 12, weight: .semibold))
                    }
                    .foregroundStyle(Color(hex: "4B6EFF"))
                    .padding(.horizontal, 16)
                    .padding(.vertical, 8)
                }
                .buttonStyle(.plain)
                .fixedSize()
                .glassEffect(
                    .regular.tint(.white.opacity(0.08)),
                    in: Capsule()
                )
            }
        }
    }

    // MARK: - Actions

    private func toggleRegion(_ id: String) {
        if let idx = regions.firstIndex(where: { $0.id == id }) {
            regions[idx].isExpanded.toggle()
        }
    }
}

#Preview {
    ZStack {
        MeshGradientBackground()
        ProxiesView()
    }
    .frame(width: 700, height: 600)
}
