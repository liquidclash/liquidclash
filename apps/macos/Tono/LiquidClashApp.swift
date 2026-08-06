import SwiftUI
import ServiceManagement
import AppKit
import Combine
import Sparkle
import SystemConfiguration

/// Owns Sparkle's single long-lived updater. Release builds start it only from
/// /Applications, so a read-only DMG launch cannot perform network or update
/// work before the existing installation guard terminates the app.
@MainActor
final class AppUpdater: ObservableObject {
    @Published private(set) var canCheckForUpdates = false
    private let updaterController: SPUStandardUpdaterController?

    init(enabled: Bool) {
        guard enabled else {
            updaterController = nil
            return
        }

        let controller = SPUStandardUpdaterController(
            startingUpdater: true,
            updaterDelegate: nil,
            userDriverDelegate: nil
        )
        updaterController = controller
        controller.updater.publisher(for: \.canCheckForUpdates)
            .assign(to: &$canCheckForUpdates)
    }

    func checkForUpdates() {
        updaterController?.updater.checkForUpdates()
    }
}

private struct CheckForUpdatesView: View {
    @ObservedObject var updater: AppUpdater

    var body: some View {
        Button("Check for Updates") {
            updater.checkForUpdates()
        }
        .disabled(!updater.canCheckForUpdates)
    }
}

/// Watches committed default-route and resolver changes without spawning
/// `route`/`networksetup` on a timer. The callback is observation only: PF is
/// already the synchronous fail-closed boundary for every transition.
nonisolated private final class SystemNetworkChangeMonitor: @unchecked Sendable {
    private let callback: @MainActor @Sendable () -> Void
    private let queue = DispatchQueue(label: "com.raydocs.tono.network-events")
    private var store: SCDynamicStore?

    init(callback: @escaping @MainActor @Sendable () -> Void) {
        self.callback = callback
    }

    func start() {
        guard store == nil else { return }
        var context = SCDynamicStoreContext(
            version: 0,
            info: Unmanaged.passUnretained(self).toOpaque(),
            retain: nil,
            release: nil,
            copyDescription: nil
        )
        let storeCallback: SCDynamicStoreCallBack = { _, _, info in
            guard let info else { return }
            let monitor = Unmanaged<SystemNetworkChangeMonitor>
                .fromOpaque(info)
                .takeUnretainedValue()
            Task { @MainActor in monitor.callback() }
        }
        guard let dynamicStore = SCDynamicStoreCreate(
            nil,
            "com.raydocs.tono.network-events" as CFString,
            storeCallback,
            &context
        ) else { return }
        let keys = [
            SCDynamicStoreKeyCreateNetworkGlobalEntity(
                nil,
                kSCDynamicStoreDomainState,
                kSCEntNetIPv4
            ) as String,
            SCDynamicStoreKeyCreateNetworkGlobalEntity(
                nil,
                kSCDynamicStoreDomainState,
                kSCEntNetIPv6
            ) as String,
            SCDynamicStoreKeyCreateNetworkGlobalEntity(
                nil,
                kSCDynamicStoreDomainState,
                kSCEntNetDNS
            ) as String,
        ]
        guard SCDynamicStoreSetNotificationKeys(
            dynamicStore,
            keys as CFArray,
            nil
        ) else { return }
        store = dynamicStore
        SCDynamicStoreSetDispatchQueue(dynamicStore, queue)
    }

    func stop() {
        guard let store else { return }
        SCDynamicStoreSetDispatchQueue(store, nil)
        self.store = nil
    }

    deinit {
        stop()
    }
}

// MARK: - Runtime Cleanup

enum RuntimeCleanup {
    static func markCoreStarted(tunEnabled: Bool) {
        AppProfile.defaults.set(true, forKey: SettingsKey.didStartCore)
        AppProfile.defaults.set(tunEnabled, forKey: SettingsKey.lastTunEnabled)
    }

    static func clearCoreStarted() {
        AppProfile.defaults.removeObject(forKey: SettingsKey.didStartCore)
        AppProfile.defaults.removeObject(forKey: SettingsKey.lastTunEnabled)
    }

    /// Recover a previous process's network mutations transactionally before
    /// account restoration performs any request. If protection had been active,
    /// PF stays armed with only Tono's bounded control-plane recovery exception
    /// until a verified session reconnects or the user explicitly disarms it.
    static func cleanupStaleRuntime() async throws -> Bool {
        await PrivilegedRuntimeCoordinator.shared.cleanupStaleSystemProxy()
        // A daemon that refuses this app's identity fails every status, arm,
        // stop, and DNS call below with Forbidden, and no retry of this launch
        // sequence can change that outcome — the host would stay fail-closed
        // behind an unexplained startup error. The authenticated reinstall is
        // the one path that does not depend on the rejecting socket, so run it
        // first, before any step below trusts a helper answer.
        if await PrivilegedRuntimeCoordinator.shared.daemonRejectsClient() {
            do {
                try await PrivilegedRuntimeCoordinator.shared.prepareHelper()
            } catch {
                throw ClashError.startFailed(
                    "The installed network helper no longer accepts this copy "
                    + "of Tono. Click Retry and approve the administrator "
                    + "prompt to repair it, or run the documented sudo "
                    + "emergency-disarm command and reopen Tono. "
                    + error.localizedDescription
                )
            }
        }
        let localProtectionIntent = KillSwitchService.isArmed
        let helperProtectionObservation =
            await PrivilegedRuntimeCoordinator.shared.refreshKillSwitchStatus()
        let shouldResumeProtection: Bool
        switch helperProtectionObservation {
        case .confirmed(let requiresProtectionRecovery):
            // An authenticated helper status is authoritative. In particular,
            // root emergency recovery clears helper-owned PF state but cannot
            // update this user's defaults; do not let that stale local bit
            // immediately re-arm the machine on reopen.
            KillSwitchService.isArmed = requiresProtectionRecovery
            shouldResumeProtection = requiresProtectionRecovery
        case .unavailable, .rejected:
            // Timeout, malformed status, and 403 are never evidence that PF is
            // open. Preserve the last local fail-closed intent.
            shouldResumeProtection = localProtectionIntent
        }

        if shouldResumeProtection {
            // Remove stale TUN/proxy exceptions and retain the persisted exact
            // control-plane HTTPS addresses before stopping the old core. A
            // failed reassert leaves the previous PF block live, so cleanup can
            // still continue without ever opening unrestricted egress.
            try? await PrivilegedRuntimeCoordinator.shared
                .reassertKillSwitchIfNeeded()
        }

        let didStartCore = AppProfile.defaults.bool(forKey: SettingsKey.didStartCore)
        let coreStatus = await PrivilegedRuntimeCoordinator.shared.coreStatus()
        if didStartCore || coreStatus.running {
            do {
                try await PrivilegedRuntimeCoordinator.shared.stopCore()
            } catch {
                let status = await PrivilegedRuntimeCoordinator.shared.coreStatus()
                guard !status.running else {
                    throw ClashError.startFailed(
                        "A previous protected core could not be stopped safely."
                    )
                }
            }
            clearCoreStarted()
        }

        // Restore DNS while PF remains armed. A fresh installation or a legacy
        // helper has no DNS endpoint and therefore nothing to recover.
        let protectedDNS =
            await PrivilegedRuntimeCoordinator.shared.protectedDNSStatus()
        if protectedDNS.snapshotPresent {
            _ = try await PrivilegedRuntimeCoordinator.shared
                .restoreProtectedDNSIfConfigured()
        } else if !protectedDNS.available,
                  didStartCore || shouldResumeProtection {
            // An armed host whose helper cannot report DNS state (a legacy
            // daemon without the DNS contract, or one that stopped answering)
            // is unrecoverable over IPC, and retrying this launch sequence
            // could never end differently. Upgrade through the authenticated
            // install path once before declaring the launch failed.
            var repaired = false
            do {
                try await PrivilegedRuntimeCoordinator.shared.prepareHelper()
                let recheck = await PrivilegedRuntimeCoordinator.shared
                    .protectedDNSStatus()
                if recheck.snapshotPresent {
                    _ = try await PrivilegedRuntimeCoordinator.shared
                        .restoreProtectedDNSIfConfigured()
                    repaired = true
                } else {
                    repaired = recheck.available
                }
            } catch {
                // Losing the real cause here (most often a cancelled
                // administrator prompt) would present the unrelated DNS
                // message below and leave the user guessing.
                throw ClashError.startFailed(
                    "The network helper needs repair before its protected "
                    + "DNS state can be inspected. Click Retry and approve "
                    + "the administrator prompt, or run the documented sudo "
                    + "emergency-disarm command and reopen Tono. "
                    + error.localizedDescription
                )
            }
            if !repaired {
                throw ClashError.startFailed(
                    "A previous protected DNS state could not be inspected "
                    + "safely. Click Retry and approve the administrator "
                    + "prompt to repair the network helper, or run the "
                    + "documented sudo emergency-disarm command and reopen "
                    + "Tono."
                )
            }
        }
        return shouldResumeProtection
    }
}

// MARK: - App Delegate for Window Configuration

@MainActor
class AppDelegate: NSObject, NSApplicationDelegate {
    /// Reference to app state for cleanup on termination
    var appState: AppState?
    var accountSession: AccountSession?
    private var runtimeStopped = false
    private var signalTerminationStarted = false
    private var terminationCleanupStarted = false
    private var terminationCompletionSent = false
    private var terminationCleanupTask: Task<Void, Never>?
    private var terminationDeadlineTask: Task<Void, Never>?
    private var terminationSignalSource: DispatchSourceSignal?
    private var networkChangeMonitor: SystemNetworkChangeMonitor?

    static var canStartRuntimeFromCurrentLocation: Bool {
#if DEBUG
        true
#else
        Bundle.main.bundleURL
            .resolvingSymlinksInPath()
            .standardizedFileURL
            .deletingLastPathComponent()
            == URL(fileURLWithPath: "/Applications", isDirectory: true)
                .standardizedFileURL
#endif
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        guard Self.canStartRuntimeFromCurrentLocation else {
            runtimeStopped = true
            NSApp.activate(ignoringOtherApps: true)

            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = String(localized: "Install Tono in Applications")
            alert.informativeText = String(localized: "To work reliably, Tono must run from the Applications folder. Quit Tono, drag it onto Applications in the installer window, then open the installed copy.")
            alert.addButton(withTitle: String(localized: "Open Applications"))
            alert.addButton(withTitle: String(localized: "Quit"))
            if alert.runModal() == .alertFirstButtonReturn {
                NSWorkspace.shared.open(
                    URL(fileURLWithPath: "/Applications", isDirectory: true)
                )
            }
            NSApp.terminate(nil)
            return
        }

        if !AppProfile.isDev {
            // Register URL schemes with Launch Services (ensures clash:// works immediately)
            let appURL = Bundle.main.bundleURL
            if !appURL.path.isEmpty {
                DispatchQueue.global(qos: .utility).async {
                    LSRegisterURL(appURL as CFURL, true)
                }
            }

            // Register for URL open events (works even when no window is open)
            NSAppleEventManager.shared().setEventHandler(
                self,
                andSelector: #selector(handleGetURLEvent(_:replyEvent:)),
                forEventClass: AEEventClass(kInternetEventClass),
                andEventID: AEEventID(kAEGetURL)
            )
        }

        // Fallback: force-resize window if SwiftUI still created it too small
        enforceDefaultWindowSize()

        // Convert SIGTERM into the normal AppKit termination flow. Raw signal handlers
        // cannot safely call Foundation/AppKit or await sidecar cleanup.
        signal(SIGTERM, SIG_IGN)
        let source = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        source.setEventHandler { [weak self] in
            Task { @MainActor [weak self] in
                await self?.terminateAfterSignal()
            }
        }
        source.resume()
        terminationSignalSource = source

        let workspaceNotifications = NSWorkspace.shared.notificationCenter
        workspaceNotifications.addObserver(
            self,
            selector: #selector(systemWillSleep(_:)),
            name: NSWorkspace.willSleepNotification,
            object: nil
        )
        workspaceNotifications.addObserver(
            self,
            selector: #selector(systemDidWake(_:)),
            name: NSWorkspace.didWakeNotification,
            object: nil
        )
        let monitor = SystemNetworkChangeMonitor { [weak self] in
            self?.appState?.handleSystemNetworkChange()
        }
        networkChangeMonitor = monitor
        monitor.start()
    }

    func applicationDidBecomeActive(_ notification: Notification) {
        _ = notification
        // A user may have run the documented root recovery while Tono was in
        // the background. Reconcile only an authenticated, confirmed unarmed
        // helper state; this callback never raises an administrator prompt.
        appState?.reconcileExternalProtectionState()
    }

    @objc private func systemWillSleep(_ notification: Notification) {
        _ = notification
        appState?.prepareForSystemSleep()
        accountSession?.prepareForSystemSleep()
    }

    @objc private func systemDidWake(_ notification: Notification) {
        _ = notification
        appState?.resumeAfterSystemWake()
        accountSession?.resumeAfterSystemWake()
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

    @objc func handleGetURLEvent(_ event: NSAppleEventDescriptor, replyEvent: NSAppleEventDescriptor) {
        let urlString = event.paramDescriptor(forKeyword: AEKeyword(keyDirectObject))?.stringValue ?? "nil"
        writeDebug("handleGetURLEvent: received, appState=\(appState != nil)")

        guard !AppProfile.isDev else {
            writeDebug("handleGetURLEvent: ignored in dev profile")
            return
        }

        guard let url = URL(string: urlString),
              let scheme = url.scheme?.lowercased(),
              scheme == "tono" else {
            writeDebug("handleGetURLEvent: scheme mismatch")
            return
        }

        writeDebug("handleGetURLEvent: host=\(url.host ?? "nil")")
        guard url.host == "install-config" else {
            writeDebug("handleGetURLEvent: parse failed")
            return
        }

        // Server credentials are delivered only by the authenticated managed
        // catalog. Never retain or fetch a credential-bearing third-party URL.
        appState?.errorMessage = Self.managedCatalogImportMessage
        writeDebug("handleGetURLEvent: legacy subscription import rejected")
        NSApp.activate(ignoringOtherApps: true)
    }

    static let managedCatalogImportMessage =
        "External subscription links are disabled. Servers are synchronized from the authenticated Tono cloud catalog."

    private func writeDebug(_ msg: String) {
        // Subscription URLs commonly contain bearer tokens. Never persist URL-event
        // diagnostics to a fixed /tmp file or Console.
        _ = msg
    }

    func applicationWillTerminate(_ notification: Notification) {
        networkChangeMonitor?.stop()
        networkChangeMonitor = nil
        NSWorkspace.shared.notificationCenter.removeObserver(self)
        guard !runtimeStopped else { return }
        // AppKit reached termination without completing the ordered async
        // cleanup. Stop local runtime work, but never open PF when DNS/core
        // restoration could not be proven before process exit.
        appState?.disconnect(releaseKillSwitch: false)
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard !runtimeStopped else { return .terminateNow }
        beginTerminationCleanup {
            sender.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }

    /// A main-queue dispatch source must not synchronously enter AppKit's
    /// `terminateLater` loop: the cleanup Task would be queued behind the
    /// dispatch callback that is waiting for its reply. Complete cleanup first,
    /// then terminate through the already-stopped fast path.
    private func terminateAfterSignal() async {
        guard !signalTerminationStarted else { return }
        signalTerminationStarted = true
        beginTerminationCleanup {
            NSApp.terminate(nil)
        }
    }

    /// AppKit can otherwise wait indefinitely when a helper IPC or sidecar
    /// teardown is stuck. The deadline never performs an emergency disarm: a
    /// timed-out cleanup deliberately leaves the helper's PF policy fail-closed.
    private func beginTerminationCleanup(completion: @escaping @MainActor () -> Void) {
        guard !terminationCleanupStarted else { return }
        terminationCleanupStarted = true

        terminationCleanupTask = Task { @MainActor [weak self] in
            guard let self else { return }
            await self.finishTerminationCleanup()
            guard !Task.isCancelled else { return }
            self.completeTermination(completion)
        }
        terminationDeadlineTask = Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(3))
            guard let self, !Task.isCancelled else { return }
            self.terminationCleanupTask?.cancel()
            self.completeTermination(completion)
        }
    }

    private func completeTermination(_ completion: @escaping @MainActor () -> Void) {
        guard !terminationCompletionSent else { return }
        terminationCompletionSent = true
        terminationDeadlineTask?.cancel()
        terminationDeadlineTask = nil
        runtimeStopped = true
        completion()
    }

    private func finishTerminationCleanup() async {
        // First stop transports while retaining PF. Noncritical persistence is
        // also completed before the final release transaction, so a timeout in
        // either phase cannot leave an unknown network path open.
        if let accountSession {
            await accountSession.stopRuntime(releaseKillSwitch: false)
        } else {
            appState?.disconnect(releaseKillSwitch: false)
        }
        guard !Task.isCancelled else { return }
        await appState?.finishPendingDisconnect()
        guard !Task.isCancelled else { return }
        await appState?.finishPendingPersistence()
        guard !Task.isCancelled else { return }

        // Release only as the last ordered operation. AppState restores DNS,
        // confirms the core has stopped, and only then disarms PF.
        if let appState {
            await appState.disconnectAndWait(releaseKillSwitch: true)
        } else {
            // Launch-time termination can occur before AppState is attached.
            do {
                _ = try await PrivilegedRuntimeCoordinator.shared
                    .restoreProtectedDNSIfConfigured()
                try await PrivilegedRuntimeCoordinator.shared.disarmKillSwitch()
            } catch {
                // Never open PF when DNS recovery could not be proven.
            }
        }
    }
}

// MARK: - Window Configurator (NSWindow-level safety net)

struct WindowConfigurator: NSViewRepresentable {
    let onVisibilityChange: @MainActor @Sendable (Bool) -> Void

    @MainActor
    final class Coordinator: NSObject {
        let onVisibilityChange: @MainActor @Sendable (Bool) -> Void
        weak var window: NSWindow?

        init(onVisibilityChange: @escaping @MainActor @Sendable (Bool) -> Void) {
            self.onVisibilityChange = onVisibilityChange
        }

        func attach(to window: NSWindow) {
            guard self.window !== window else {
                reportVisibility()
                return
            }
            NotificationCenter.default.removeObserver(self)
            self.window = window
            for name in [
                NSWindow.didChangeOcclusionStateNotification,
                NSWindow.didMiniaturizeNotification,
                NSWindow.didDeminiaturizeNotification,
                NSWindow.willCloseNotification,
            ] {
                NotificationCenter.default.addObserver(
                    self,
                    selector: #selector(windowVisibilityChanged(_:)),
                    name: name,
                    object: window
                )
            }
            reportVisibility()
        }

        @objc private func windowVisibilityChanged(_ notification: Notification) {
            if notification.name == NSWindow.willCloseNotification {
                onVisibilityChange(false)
            } else {
                reportVisibility()
            }
        }

        private func reportVisibility() {
            guard let window else {
                onVisibilityChange(false)
                return
            }
            onVisibilityChange(
                window.isVisible
                    && !window.isMiniaturized
                    && window.occlusionState.contains(.visible)
            )
        }

        deinit {
            NotificationCenter.default.removeObserver(self)
        }
    }

    func makeCoordinator() -> Coordinator {
        Coordinator { visible in
            onVisibilityChange(visible)
        }
    }

    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        DispatchQueue.main.async { [weak view] in
            guard let view, let window = view.window else { return }
            window.minSize = NSSize(width: 860, height: 540)
            window.contentMinSize = NSSize(width: 860, height: 540)
            window.isOpaque = false
            window.backgroundColor = .clear
            context.coordinator.attach(to: window)
        }
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        if let window = nsView.window {
            context.coordinator.attach(to: window)
        }
    }

    static func dismantleNSView(_ nsView: NSView, coordinator: Coordinator) {
        _ = nsView
        coordinator.onVisibilityChange(false)
        NotificationCenter.default.removeObserver(coordinator)
    }
}

@main
struct LiquidClashApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @AppStorage(SettingsKey.themeMode, store: AppProfile.defaults) private var themeMode = "Adaptive"
    @AppStorage(SettingsKey.interfaceLanguage, store: AppProfile.defaults) private var interfaceLanguage = "Auto"
    @StateObject private var updater: AppUpdater
    @State private var appState: AppState
    @State private var sidecar: TonoSidecarService
    @State private var accountSession: AccountSession

    init() {
        let appState = AppState()
        let sidecar = TonoSidecarService()
#if DEBUG
        let updaterEnabled = false
#else
        let updaterEnabled = AppDelegate.canStartRuntimeFromCurrentLocation
#endif
        _updater = StateObject(
            wrappedValue: AppUpdater(enabled: updaterEnabled)
        )
        _appState = State(initialValue: appState)
        _sidecar = State(initialValue: sidecar)
        _accountSession = State(initialValue: AccountSession(
            sidecar: sidecar,
            descriptorConsumer: { descriptor in
                await appState.acceptTonoTransport(descriptor)
                if descriptor == nil {
                    // acceptTonoTransport already stopped Mihomo while retaining PF.
                } else {
                    // The authenticated managed catalog was pulled before this
                    // descriptor was exposed; acceptTonoTransport auto-starts TUN.
                }
            },
            catalogConsumer: { catalog in
                try await appState.acceptManagedExitCatalog(catalog)
            },
            trafficPolicyConsumer: { policy in
                try await appState.acceptManagedTrafficPolicy(policy)
            },
            cloudFallbackPreferred: {
                appState.prefersManagedCloudExit
            },
            cloudFallbackConsumer: { resumeProtection in
                try appState.acceptCloudOnlyTransport(
                    resumeProtection: resumeProtection
                )
            },
            killSwitchDisarmConsumer: {
                await appState.disconnectAndWait(releaseKillSwitch: true)
            },
            diagnosticSnapshotConsumer: { appState.compactRemoteDiagnosticSnapshot() },
            claudeTrafficResearchConsumer: {
                await appState.claudeTrafficResearchSnapshot()
            },
            protectionBlockedConsumer: { appState.isProtectionBlocked },
            protectedRetryConsumer: { appState.retryProtectedConnectionNow() }
        ))
        // CRITICAL: Purge saved window frames BEFORE SwiftUI's scene management
        // reads them. SwiftUI reads NSWindow Frame / NSSplitView Subview Frames
        // during scene initialization (before applicationDidFinishLaunching),
        // so we must clear them here in init() to prevent stale sizes.
        let defaults = AppProfile.defaults
        if defaults.integer(forKey: SettingsKey.windowGeometryPolicyVersion) < 1 {
            for key in defaults.dictionaryRepresentation().keys
                where key.hasPrefix("NSWindow Frame ")
                    || key.hasPrefix("NSSplitView Subview Frames ")
            {
                defaults.removeObject(forKey: key)
            }
            defaults.set(1, forKey: SettingsKey.windowGeometryPolicyVersion)
        }
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
        case "English": return Locale(identifier: "en")
        default: return Locale.current  // "Auto" — follow system
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

                AccountGateView(session: accountSession) {
                    ContentView()
                        .environment(appState)
                        .environment(accountSession)
                        .environmentObject(updater)
                }
            }
            .background(WindowConfigurator { visible in
                appState.setMainWindowVisible(visible)
            })
            .defaultAppStorage(AppProfile.defaults)
            .task {
                guard AppDelegate.canStartRuntimeFromCurrentLocation else {
                    return
                }
                appDelegate.appState = appState
                appDelegate.accountSession = accountSession
                // Disk only — network remains gated on account + transport ready.
                await appState.loadInitialData()
                // Load the verified local catalog before account restoration so
                // the cloud-only session can become usable from cache without
                // waiting for a second control-plane round trip.
                if accountSession.state == .restoring {
                    await accountSession.restore()
                }
            }
            .preferredColorScheme(preferredScheme)
            .environment(\.locale, appLocale)
            .onOpenURL { url in
                handleIncomingURL(url)
            }
        }
        .defaultSize(width: 920, height: 600)
        .windowResizability(.contentMinSize)
        .restorationBehavior(.disabled)
        .windowStyle(.hiddenTitleBar)
        .commands {
            CommandGroup(after: .appInfo) {
                CheckForUpdatesView(updater: updater)
            }
        }

        // Menu Bar Extra
        MenuBarExtra {
            MenuBarView()
                .environment(appState)
                .environment(accountSession)
                .environmentObject(updater)
                .defaultAppStorage(AppProfile.defaults)
                .preferredColorScheme(preferredScheme)
                .environment(\.locale, appLocale)
        } label: {
            // Status items must be template images so AppKit can tint them
            // for light/dark menu bars and the open-highlight state. The old
            // asset was an opaque white tile with "original" rendering intent
            // — washed out on light bars, never inverting when open. An SF
            // Symbol is inherently a template and adapts automatically.
            Image(systemName: "shield.lefthalf.filled")
        }
        .menuBarExtraStyle(.window)
    }

    /// Legacy install links are deliberately rejected: cloud catalog state is
    /// the only production source for credential-bearing server definitions.
    private func handleIncomingURL(_ url: URL) {
        guard !AppProfile.isDev else { return }
        guard let scheme = url.scheme?.lowercased(),
              scheme == "tono" else { return }

        guard url.host == "install-config" else { return }
        appState.errorMessage = AppDelegate.managedCatalogImportMessage
        NSApp.activate(ignoringOtherApps: true)
    }
}
