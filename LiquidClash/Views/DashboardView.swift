import SwiftUI

struct DashboardView: View {
    @State private var selectedMode: ProxyMode = .rule
    @State private var isConnected: Bool
    @Namespace private var dashboardNS

    init(initialConnected: Bool = false) {
        _isConnected = State(initialValue: initialConnected)
    }

    var body: some View {
        GlassEffectContainer(spacing: 24) {
            VStack(spacing: 0) {
                // Top: ModeSelector
                ModeSelector(selectedMode: $selectedMode)
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding(.top, 2)

                // Center: ConnectPill + ActiveNodeCard
                Spacer()

                VStack(spacing: 24) {
                    ConnectPill(isConnected: $isConnected)
                        .glassEffectID("pill", in: dashboardNS)

                    if isConnected {
                        ActiveNodeCard(node: mockActiveNode)
                            .glassEffectID("card", in: dashboardNS)
                            .glassEffectTransition(.materialize)
                            .transition(.opacity)
                    }
                }

                Spacer()

                // Bottom: Network info glass capsule
                networkInfoRow
                    .padding(.bottom, 4)
            }
            .padding(.horizontal, 32)
            .padding(.vertical, 12)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .contentShape(Rectangle())
        .animation(.spring(duration: 0.5, bounce: 0.15), value: isConnected)
        .animation(.spring(duration: 0.35, bounce: 0.12), value: selectedMode)
    }

    // MARK: - Network Info Row

    private var networkInfoRow: some View {
        HStack(spacing: 16) {
            infoItem(icon: "globe", value: isConnected ? "103.152.220.42" : "--")
            infoItem(icon: "antenna.radiowaves.left.and.right", value: isConnected ? "BGP / Residential" : "--")
            infoItem(icon: "mappin", value: isConnected ? "Tokyo, JP" : "--")
        }
        .font(.system(size: 11, weight: .medium))
        .foregroundStyle(.secondary.opacity(0.8))
        .padding(.horizontal, 20)
        .padding(.vertical, 8)
        .glassEffect(
            .regular.tint(.white.opacity(0.02)),
            in: Capsule()
        )
    }

    private func infoItem(icon: String, value: String) -> some View {
        HStack(spacing: 4) {
            Image(systemName: icon)
                .font(.system(size: 9, weight: .medium))
                .foregroundStyle(.tertiary)
            Text(value)
        }
    }
}

// MARK: - Previews

#Preview("Disconnected") {
    ZStack {
        MeshGradientBackground()
        DashboardView()
    }
    .frame(width: 680, height: 600)
}

#Preview("Connected") {
    ZStack {
        MeshGradientBackground()
        DashboardView(initialConnected: true)
    }
    .frame(width: 680, height: 600)
}
