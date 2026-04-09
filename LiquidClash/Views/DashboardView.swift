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

                    if appState.isConnected, let nodeName = appState.proxyService.activeNodeName {
                        let nodeLatency = appState.proxyService.nodes.first(where: { $0.name == nodeName })?.latency ?? 0
                        ActiveNodeCard(nodeName: nodeName, groupName: appState.proxyService.activeGroupName, latency: nodeLatency, onSwitch: {
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

                // Network info bar (when connected)
                if appState.isConnected {
                    networkInfoBar
                }
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


    // MARK: - Network Info Bar

    private var networkInfoBar: some View {
        HStack(spacing: 24) {
            infoItem(label: "IP", value: appState.networkInfo.ip)
            infoItem(label: "ASN Type", value: appState.networkInfo.asType)
            infoItem(label: "City", value: appState.networkInfo.city)

            Spacer()

            // Traffic stats
            HStack(spacing: 16) {
                HStack(spacing: 4) {
                    Image(systemName: "arrow.up")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundStyle(.secondary)
                    Text(formatSpeed(appState.trafficStats.uploadSpeed))
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
                HStack(spacing: 4) {
                    Image(systemName: "arrow.down")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundStyle(.secondary)
                    Text(formatSpeed(appState.trafficStats.downloadSpeed))
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
            }
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 10)
        .background(.white.opacity(0.08), in: RoundedRectangle(cornerRadius: 12))
        .padding(.horizontal, 12)
        .padding(.bottom, 8)
    }

    private func infoItem(label: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.system(size: 9, weight: .semibold))
                .foregroundStyle(.tertiary)
                .textCase(.uppercase)
            Text(value)
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
    }

    private func formatSpeed(_ bytesPerSec: Int64) -> String {
        let kb = Double(bytesPerSec) / 1024
        if kb < 1024 { return String(format: "%.1f KB/s", kb) }
        let mb = kb / 1024
        return String(format: "%.1f MB/s", mb)
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
        state.networkInfo = NetworkInfo(ip: "192.0.2.1", asType: "ISP", city: "Tokyo, JP")
        return state
    }())
}
