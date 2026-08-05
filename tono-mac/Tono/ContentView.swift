import SwiftUI

struct ContentView: View {
    @Environment(AppState.self) private var appState
    @State private var columnVisibility: NavigationSplitViewVisibility = .doubleColumn

    var body: some View {
        @Bindable var appState = appState

        ZStack {
            MeshGradientBackground()

            NavigationSplitView(columnVisibility: $columnVisibility) {
                SidebarView(selectedPage: $appState.selectedPage)
                    .navigationSplitViewColumnWidth(200)
            } detail: {
                ZStack(alignment: .topTrailing) {
                    Group {
                        switch appState.selectedPage {
                        case .dashboard:
                            DashboardView()
                        case .subscriptions:
                            SubscriptionsView()
                        case .proxies:
                            ProxiesView()
                        case .rules:
                            RulesView()
                        case .activity:
                            ActivityView()
                        case .logs:
                            LogsView()
                        case .settings:
                            SettingsView()
                        }
                    }

                    if let error = appState.errorMessage {
                        ErrorBanner(message: error) {
                            appState.errorMessage = nil
                        }
                        .padding(16)
                        .transition(.move(edge: .top).combined(with: .opacity))
                    }
                }
                .frame(minWidth: 660, minHeight: 540)
                .animation(
                    .easeOut(duration: 0.18),
                    value: appState.errorMessage != nil
                )
            }
            .navigationSplitViewStyle(.balanced)
            .onChange(of: columnVisibility) {
                columnVisibility = .doubleColumn
            }
        }
    }
}

private struct ErrorBanner: View {
    let message: String
    let dismiss: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
                .padding(.top, 1)

            Text(message)
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(.primary)
                .fixedSize(horizontal: false, vertical: true)

            Button(action: dismiss) {
                Image(systemName: "xmark")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(.secondary)
                    .frame(width: 22, height: 22)
                    .contentShape(Circle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Dismiss")
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 11)
        .frame(maxWidth: 480, alignment: .leading)
        .glassEffect(
            .regular.tint(.orange.opacity(0.08)),
            in: RoundedRectangle(cornerRadius: 14)
        )
        .shadow(color: .black.opacity(0.12), radius: 16, y: 7)
    }
}

#Preview {
    ContentView()
        .environment(AppState())
}
