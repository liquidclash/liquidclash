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
                Group {
                    switch appState.selectedPage {
                    case .dashboard:
                        DashboardView()
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
                .frame(minWidth: 660, minHeight: 540)
            }
            .navigationSplitViewStyle(.balanced)
            .onChange(of: columnVisibility) {
                columnVisibility = .doubleColumn
            }
        }
    }
}

#Preview {
    ContentView()
        .environment(AppState())
}
