import SwiftUI
import ServiceManagement
import AppKit

// MARK: - App Delegate for Window Configuration

class AppDelegate: NSObject, NSApplicationDelegate {
    /// Reference to app state for cleanup on termination
    var appState: AppState?

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Fallback: force-resize window if SwiftUI still created it too small
        enforceDefaultWindowSize()

        // Clean up stale system proxy from previous crash/force-quit
        SystemProxy.cleanupIfStale()

        // Handle SIGTERM (kill command) - clean up proxy before exit
        signal(SIGTERM) { _ in
            if SystemProxy.didSetProxy {
                try? SystemProxy.disable()
            }
            exit(0)
        }
    }

    private func enforceDefaultWindowSize() {
        let defaultSize = NSSize(width: 920, height: 600)
        let minSize = NSSize(width: 860, height: 540)

        for delay in [0.1, 0.5] {
            DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
                guard let window = NSApp.windows.first(where: {
                    $0.isVisible && !($0 is NSPanel)
                }) else { return }

                window.minSize = minSize
                window.contentMinSize = minSize

                if window.frame.width < minSize.width || window.frame.height < minSize.height {
                    let screen = window.screen ?? NSScreen.main
                    let visibleFrame = screen?.visibleFrame ?? NSRect(x: 0, y: 0, width: 1440, height: 900)
                    let origin = NSPoint(
                        x: visibleFrame.midX - defaultSize.width / 2,
                        y: visibleFrame.midY - defaultSize.height / 2
                    )
                    window.setFrame(NSRect(origin: origin, size: defaultSize), display: true, animate: false)
                }
            }
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        appState?.disconnect()
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        appState?.disconnect()
        return .terminateNow
    }
}

// MARK: - Window Configurator (NSWindow-level safety net)

struct WindowConfigurator: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        DispatchQueue.main.async { [weak view] in
            guard let view, let window = view.window else { return }
            window.minSize = NSSize(width: 860, height: 540)
            window.contentMinSize = NSSize(width: 860, height: 540)
            window.isOpaque = false
            window.backgroundColor = .clear
        }
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {}
}

@main
struct LiquidClashApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @AppStorage(SettingsKey.hasCompletedOnboarding) private var hasCompletedOnboarding = false
    @AppStorage(SettingsKey.themeMode) private var themeMode = "Adaptive"
    @AppStorage(SettingsKey.interfaceLanguage) private var interfaceLanguage = "English"
    @State private var appState = AppState()
    @State private var pendingSubscriptionURL: String?
    @State private var showImportAlert = false

    init() {
        // CRITICAL: Purge saved window frames BEFORE SwiftUI's scene management
        // reads them. SwiftUI reads NSWindow Frame / NSSplitView Subview Frames
        // during scene initialization (before applicationDidFinishLaunching),
        // so we must clear them here in init() to prevent stale sizes.
        let defaults = UserDefaults.standard
        for key in defaults.dictionaryRepresentation().keys
            where key.hasPrefix("NSWindow Frame ") || key.hasPrefix("NSSplitView Subview Frames ")
        {
            defaults.removeObject(forKey: key)
        }
        defaults.synchronize()
    }

    private var preferredScheme: ColorScheme? {
        switch themeMode {
        case "Light": return .light
        case "Dark": return .dark
        default: return nil
        }
    }

    private var appLocale: Locale {
        switch interfaceLanguage {
        case "简体中文": return Locale(identifier: "zh-Hans")
        case "日本語": return Locale(identifier: "ja")
        default: return Locale(identifier: "en")
        }
    }

    var body: some Scene {
        WindowGroup(id: "main") {
            ZStack {
                // Size anchor: forces the ZStack to report 860×540 minimum
                // and 920×600 ideal to SwiftUI's window-sizing engine.
                // Without this, NavigationSplitView reports ~200px minimum
                // which causes the window to open at sidebar-only width.
                Color.clear
                    .frame(minWidth: 860, idealWidth: 920,
                           minHeight: 540, idealHeight: 600)

                if hasCompletedOnboarding {
                    ContentView()
                        .environment(appState)
                } else {
                    WelcomeView {
                        withAnimation(.easeInOut(duration: 0.3)) {
                            hasCompletedOnboarding = true
                        }
                        appState.loadInitialData()
                    }
                }
            }
            .background(WindowConfigurator())
            .task {
                appDelegate.appState = appState
                if hasCompletedOnboarding {
                    appState.loadInitialData()
                }
            }
            .preferredColorScheme(preferredScheme)
            .environment(\.locale, appLocale)
            .onOpenURL { url in
                handleIncomingURL(url)
            }
            .alert("Import Subscription", isPresented: $showImportAlert) {
                Button("Import") {
                    if let subURL = pendingSubscriptionURL {
                        appState.addSubscription(url: subURL, name: "")
                        Task { try? await appState.updateAllSubscriptions() }
                    }
                    pendingSubscriptionURL = nil
                }
                Button("Cancel", role: .cancel) {
                    pendingSubscriptionURL = nil
                }
            } message: {
                Text("Add subscription from URL?\n\(pendingSubscriptionURL ?? "")")
            }
        }
        .defaultSize(width: 920, height: 600)
        .windowResizability(.contentMinSize)
        .restorationBehavior(.disabled)
        .windowStyle(.hiddenTitleBar)

        // Menu Bar Extra
        MenuBarExtra {
            MenuBarView()
                .environment(appState)
                .preferredColorScheme(preferredScheme)
                .environment(\.locale, appLocale)
        } label: {
            Image("MenuBarIcon")
                .resizable()
                .aspectRatio(contentMode: .fit)
        }
        .menuBarExtraStyle(.window)
    }

    /// Handle clash:// or liquidclash:// URLs
    /// Format: clash://install-config?url=<encoded_url>
    private func handleIncomingURL(_ url: URL) {
        guard let scheme = url.scheme?.lowercased(),
              (scheme == "clash" || scheme == "liquidclash") else { return }

        guard url.host == "install-config" else { return }

        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let subURL = components.queryItems?.first(where: { $0.name == "url" })?.value,
              !subURL.isEmpty else { return }

        // Show confirmation alert
        pendingSubscriptionURL = subURL
        showImportAlert = true

        // Bring app to front
        NSApp.activate(ignoringOtherApps: true)
    }
}
