import SwiftUI

struct ContentView: View {
    @State private var selectedPage: AppPage = .dashboard
    @State private var columnVisibility: NavigationSplitViewVisibility = .doubleColumn

    var body: some View {
        ZStack {
            MeshGradientBackground()

            NavigationSplitView(columnVisibility: $columnVisibility) {
                SidebarView(selectedPage: $selectedPage)
                    .toolbar(removing: .sidebarToggle)
                    .toolbar {
                        ToolbarItem(placement: .automatic) {
                            Color.clear.frame(width: 0, height: 0)
                        }
                    }
            } detail: {
                switch selectedPage {
                case .dashboard:
                    DashboardView()
                case .proxies:
                    ProxiesView()
                case .rules:
                    RulesView()
                case .activity:
                    ActivityView()
                case .settings:
                    SettingsView()
                }
            }
            .navigationSplitViewStyle(.balanced)
            .onChange(of: columnVisibility) {
                columnVisibility = .doubleColumn
            }
        }
        .background(.windowBackground)
    }
}

#Preview {
    ContentView()
        .frame(width: 900, height: 600)
}
