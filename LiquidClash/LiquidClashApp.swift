import SwiftUI

@main
struct LiquidClashApp: App {
    @AppStorage("hasCompletedOnboarding") private var hasCompletedOnboarding = false

    var body: some Scene {
        WindowGroup {
            if hasCompletedOnboarding {
                ContentView()
                    .frame(minWidth: 960, minHeight: 580)
            } else {
                WelcomeView {
                    withAnimation(.easeInOut(duration: 0.3)) {
                        hasCompletedOnboarding = true
                    }
                }
                .frame(minWidth: 700, minHeight: 550)
            }
        }
        .defaultSize(width: hasCompletedOnboarding ? 1050 : 700, height: hasCompletedOnboarding ? 680 : 550)
        .windowResizability(.contentSize)
        .windowStyle(.hiddenTitleBar)
    }
}
