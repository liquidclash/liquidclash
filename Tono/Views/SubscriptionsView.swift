import SwiftUI

struct SubscriptionsView: View {
    @Environment(AppState.self) private var appState
    @Environment(AccountSession.self) private var accountSession
    @State private var refreshing = false
    @State private var refreshResult: String?
    @State private var refreshSucceeded: Bool?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Cloud Servers")
                        .font(.system(size: 24, weight: .semibold))
                    Text("Cloud exits are managed by Tono and synchronized automatically.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button {
                    refreshing = true
                    Task {
                        let succeeded =
                            await accountSession.refreshManagedCatalog()
                        refreshing = false
                        refreshSucceeded = succeeded
                        refreshResult = succeeded
                            ? String(localized: "Cloud servers are up to date.")
                            : accountSession.catalogFailureMessage
                                ?? String(localized: "Cloud server refresh failed.")
                    }
                } label: {
                    Label(refreshing ? "Refreshing…" : "Refresh Now", systemImage: "arrow.clockwise")
                }
                .disabled(refreshing || accountSession.state != .ready)
            }

            VStack(alignment: .leading, spacing: 12) {
                Label("Default: \(AppProfile.defaultCloudExitName)", systemImage: "cloud.fill")
                    .font(.headline)
                Divider()
                HStack {
                    Label(
                        "\(appState.managedCatalogNodeCount) cloud server\(appState.managedCatalogNodeCount == 1 ? "" : "s")",
                        systemImage: "cloud.fill"
                    )
                    Spacer()
                    if let version = appState.managedCatalogVersion {
                        Text("Catalog v\(version)")
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.secondary)
                    } else {
                        Text("Waiting for first verified sync")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                Text("Tono checks for changes every 5 minutes. Invalid or unavailable updates never replace the last verified local copy.")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                if let refreshResult {
                    Label(
                        refreshResult,
                        systemImage: refreshSucceeded == true
                            ? "checkmark.circle.fill"
                            : "exclamationmark.triangle.fill"
                    )
                    .font(.caption)
                    .foregroundStyle(
                        refreshSucceeded == true
                            ? Color.green
                            : Color.orange
                    )
                }
            }
            .padding(18)
            .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 16))

            Spacer(minLength: 0)
        }
        .padding(.horizontal, 32)
        .padding(.vertical, 16)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

#Preview {
    ZStack {
        MeshGradientBackground()
        SubscriptionsView()
    }
    .frame(width: 760, height: 560)
    .environment({
        let state = AppState()
        state.loadMockData()
        return state
    }())
    .environment(AccountSession(
        sidecar: TonoSidecarService(),
        descriptorConsumer: { _ in }
    ))
}
