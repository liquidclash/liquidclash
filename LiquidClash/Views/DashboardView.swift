import SwiftUI

struct DashboardView: View {
    @Environment(AppState.self) private var appState
    @Namespace private var dashboardNS

    var body: some View {
        @Bindable var appState = appState

        GlassEffectContainer(spacing: 24) {
            VStack(spacing: 0) {
                // Top: ModeSelector
                ModeSelector(selectedMode: Binding(
                    get: { appState.proxyMode },
                    set: { appState.setProxyMode($0) }
                ))
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding(.top, 2)

                // Center: ConnectPill + ActiveNodeCard
                Spacer()

                VStack(spacing: 24) {
                    ConnectPill(isConnected: Binding(
                        get: { appState.isConnected },
                        set: { newValue in
                            if newValue { appState.connect() } else { appState.disconnect() }
                        }
                    ), isConnecting: appState.isConnecting)
                        .glassEffectID("pill", in: dashboardNS)

                    if appState.isConnected, let node = appState.activeNode {
                        ActiveNodeCard(node: node, onSwitch: {
                            appState.selectedPage = .proxies
                        })
                            .glassEffectID("card", in: dashboardNS)
                            .glassEffectTransition(.materialize)
                            .transition(.opacity)
                    }

                    // Error message
                    if let error = appState.errorMessage {
                        Text(error)
                            .font(.system(size: 12))
                            .foregroundStyle(.red)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal, 24)
                    }
                }

                Spacer()
            }
            .padding(.horizontal, 32)
            .padding(.vertical, 12)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .contentShape(Rectangle())
        .animation(.spring(duration: 0.5, bounce: 0.15), value: appState.isConnected)
        .animation(.spring(duration: 0.35, bounce: 0.12), value: appState.proxyMode)
        .onChange(of: appState.isConnected) { _, connected in
            if !connected {
                appState.networkInfo = NetworkInfo()
            }
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
    .environment(AppState())
}

#Preview("Connected") {
    ZStack {
        MeshGradientBackground()
        DashboardView()
    }
    .frame(width: 680, height: 600)
    .environment({
        let state = AppState()
        state.isConnected = true
        state.activeNode = mockProxyRegions.first?.nodes.first
        state.networkInfo = NetworkInfo(ip: "103.152.220.42", networkType: "BGP / Residential", location: "Tokyo, JP")
        return state
    }())
}
