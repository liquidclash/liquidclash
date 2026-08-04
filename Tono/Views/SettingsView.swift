import SwiftUI
import ServiceManagement
import AppKit

struct SettingsView: View {
    @Environment(AppState.self) private var appState
    @Environment(AccountSession.self) private var accountSession
    @EnvironmentObject private var updater: AppUpdater
    @Environment(\.colorScheme) private var colorScheme

    // General
    @State private var launchAtStartup =
        SMAppService.mainApp.status == .enabled
    @State private var isUpdatingLaunchAtStartup = false
    @State private var launchAtStartupMessage: String?
    @AppStorage(SettingsKey.interfaceLanguage) private var selectedLanguage = "Auto"
    @AppStorage(SettingsKey.logsEnabled) private var logsEnabled = true
    @AppStorage(SettingsKey.localTrafficAuditEnabled)
    private var localTrafficAuditEnabled = true
    @AppStorage(SettingsKey.remoteDiagnosticsEnabled)
    private var remoteDiagnosticsEnabled = false
    @AppStorage(SettingsKey.claudeTrafficResearchEnabled)
    private var claudeTrafficResearchEnabled = false

    // Proxy Engine. The field edits a local draft; only validated values are
    // committed to storage, so a half-typed "78" abandoned via focus loss can
    // never become the persisted (and thus effective) port.
    @AppStorage(SettingsKey.mixedPort) private var mixedPort = "7890"
    @State private var mixedPortDraft = ""
    @AppStorage(SettingsKey.tunMode) private var tunMode = false
    @AppStorage(SettingsKey.allowLAN) private var allowLAN = false
    // Appearance
    @AppStorage(SettingsKey.themeMode) private var themeMode = "Adaptive"
    @AppStorage(SettingsKey.glassTransparency) private var glassTransparency: Double = 50
    @State private var glassTransparencyDraft: Double = 50

    private let languages = ["Auto", "English", "简体中文"]
    private let themes = ["Light", "Dark", "Adaptive"]

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Title
            Text("Settings")
                .font(.system(size: 24, weight: .semibold))
                .foregroundStyle(.primary)
                .padding(.bottom, 24)

            // 2×2 Grid
            ScrollView {
                AccountSettingsCard(session: accountSession)
                    .padding(.bottom, 24)
                Grid(horizontalSpacing: 24, verticalSpacing: 24) {
                    GridRow {
                        generalCard
                        proxyEngineCard
                    }
                    GridRow {
                        appearanceCard
                        aboutCard
                    }
                }
            }
            .scrollIndicators(.hidden)
        }
        .padding(.horizontal, 32)
        .padding(.vertical, 16)
        .padding(.bottom, 16)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    // MARK: - General Card

    private var generalCard: some View {
        SettingsCard(icon: "gearshape", title: "General") {
            SettingToggleRow(
                label: "Launch at Startup",
                subtitle: "Start app when system boots",
                isOn: Binding(
                    get: { launchAtStartup },
                    set: setLaunchAtStartup
                )
            )
            .disabled(isUpdatingLaunchAtStartup)

            if let launchAtStartupMessage {
                Text(launchAtStartupMessage)
                    .font(.system(size: 10))
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }

            settingDivider

            SettingRow(label: "Interface Language", subtitle: "System-wide display language") {
                settingsPicker(selection: $selectedLanguage, options: languages)
                    .onChange(of: selectedLanguage) { _, language in
                        // .environment(\.locale) only re-localizes SwiftUI
                        // LocalizedStringKey text; eager String(localized:)
                        // sites resolve against AppleLanguages at call time.
                        // Persist the choice so the whole app is consistent
                        // from the next launch.
                        let identifiers: [String: [String]] = [
                            "English": ["en"],
                            "简体中文": ["zh-Hans"],
                        ]
                        if let value = identifiers[language] {
                            UserDefaults.standard.set(value, forKey: "AppleLanguages")
                        } else {
                            UserDefaults.standard.removeObject(forKey: "AppleLanguages")
                        }
                    }
            }

            settingDivider

            SettingToggleRow(
                label: "Enable Logs",
                subtitle: "Show the Logs page and stream logs while it is open",
                isOn: $logsEnabled
            )

            settingDivider

            SettingToggleRow(
                label: "Local Traffic Audit",
                subtitle: "Save local domains, destination IPs, processes and proxy routes",
                isOn: $localTrafficAuditEnabled
            )
            .onChange(of: localTrafficAuditEnabled) { _, enabled in
                appState.setLocalTrafficAuditEnabled(enabled)
            }

            settingDivider

            SettingToggleRow(
                label: "Remote Diagnostics & Safe Actions",
                subtitle: "Opt in to compact protection state and four fixed actions only. Sends no traffic data unless Claude Traffic Research is enabled separately.",
                isOn: $remoteDiagnosticsEnabled
            )
            .onChange(of: remoteDiagnosticsEnabled) { _, enabled in
                accountSession.remoteDiagnosticsSettingChanged()
                // The research toggle states "Requires Remote Diagnostics";
                // an orphaned child setting kept local streaming alive while
                // uploads were silently inert — confusing in both directions.
                if !enabled, claudeTrafficResearchEnabled {
                    claudeTrafficResearchEnabled = false
                    appState.setClaudeTrafficResearchEnabled(false)
                }
            }

            settingDivider

            SettingToggleRow(
                label: "Claude & WeChat Traffic Research",
                subtitle: "Requires Remote Diagnostics. Shares aggregate Claude protection and native WeChat trial route counts, including rejected or unknown app attribution, plus fixed exit and bypass verdicts. Official claude.ai/anthropic.com hostnames, ports and byte totals may be included; every other destination is aggregated into an \"other\" bucket carrying only route class, port and byte totals — never the hostname. Raw IPs, process names, paths, content and raw logs stay local.",
                isOn: $claudeTrafficResearchEnabled
            )
            .onChange(of: claudeTrafficResearchEnabled) { _, enabled in
                appState.setClaudeTrafficResearchEnabled(enabled)
            }
            .disabled(!remoteDiagnosticsEnabled)

            SettingRow(
                label: "Audit Log",
                subtitle: "Local only · 10 MB × 3 · credentials and URL queries redacted"
            ) {
                Button("Show in Finder") {
                    let url = LocalTrafficAudit.shared.prepareForReveal()
                    NSWorkspace.shared.activateFileViewerSelecting([url])
                }
                .buttonStyle(.plain)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(.tint)
            }
        }
    }

    // MARK: - Proxy Engine Card

    private var proxyEngineCard: some View {
        SettingsCard(icon: "bolt", title: "Proxy Engine") {
            SettingRow(label: "Mixed Port", subtitle: "HTTP/SOCKS listener port") {
                TextField("", text: $mixedPortDraft)
                    .textFieldStyle(.plain)
                    .font(.system(size: 13, weight: .semibold, design: .monospaced))
                    .foregroundStyle(.primary)
                    .multilineTextAlignment(.center)
                    .frame(width: 72)
                    .padding(.vertical, 6)
                    .padding(.horizontal, 12)
                    .background(.white.opacity(colorScheme == .dark ? 0.08 : 0.4), in: RoundedRectangle(cornerRadius: 8))
                    .overlay(
                        RoundedRectangle(cornerRadius: 8)
                            .strokeBorder(.white.opacity(colorScheme == .dark ? 0.08 : 0.4), lineWidth: 0.5)
                    )
                    .onAppear { mixedPortDraft = mixedPort }
                    .onSubmit {
                        if let port = Int(mixedPortDraft), (1024...65535).contains(port) {
                            mixedPort = String(port)
                            mixedPortDraft = String(port)
                            appState.applySettingChange(key: "mixed-port", value: port)
                        } else {
                            // Invalid input never reaches storage; snap the
                            // draft back to the committed value.
                            mixedPortDraft = mixedPort
                        }
                    }
            }

            settingDivider

            SettingToggleRow(
                label: "TUN Mode",
                subtitle: "Required by Tono to prevent application bypass",
                isOn: $tunMode
            )
            .disabled(true)
            .onAppear { tunMode = true }

            settingDivider

            SettingToggleRow(
                label: "Allow LAN",
                subtitle: "Disabled for protected Reality routing",
                isOn: $allowLAN
            )
            .disabled(true)
            .onAppear { allowLAN = false }

        }
    }

    // MARK: - Appearance Card

    private var appearanceCard: some View {
        SettingsCard(icon: "paintpalette", title: "Appearance") {
            SettingRow(label: "Theme Mode", subtitle: "Light, Dark or Liquid adaptive") {
                settingsPicker(selection: $themeMode, options: themes)
            }

            settingDivider

            SettingRow(label: "Glass Transparency", subtitle: "Adjust backdrop visibility") {
                HStack(spacing: 8) {
                    Slider(
                        value: $glassTransparencyDraft,
                        in: 0...100,
                        onEditingChanged: { editing in
                            if !editing {
                                glassTransparency = glassTransparencyDraft
                            }
                        }
                    )
                        .tint(.accentColor)
                        .frame(maxWidth: 140)
                    Text("\(Int(glassTransparencyDraft.rounded()))%")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .frame(width: 34, alignment: .trailing)
                }
                .onAppear {
                    glassTransparencyDraft = glassTransparency
                }
                .onChange(of: glassTransparency) { _, value in
                    glassTransparencyDraft = value
                }
            }

        }
    }

    // MARK: - About Card

    private var aboutCard: some View {
        VStack(spacing: 10) {
            // App icon + info
            HStack(spacing: 12) {
                Image(nsImage: NSApp.applicationIconImage)
                    .resizable()
                    .aspectRatio(contentMode: .fit)
                    .frame(width: 48, height: 48)

                VStack(alignment: .leading, spacing: 2) {
                    Text("Tono")
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundStyle(.primary)
                    Text("Version \(Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.0.1") (\(Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "0"))")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            settingDivider

            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Automatic App Updates")
                        .font(.system(size: 13, weight: .medium))
                        .foregroundStyle(.primary)
                    Text("Checks every 6 hours and installs only after approval")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Check for Updates") {
                    updater.checkForUpdates()
                }
                .buttonStyle(.plain)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(.tint)
                .disabled(!updater.canCheckForUpdates)
            }

            settingDivider

            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Protected cloud connection")
                        .font(.system(size: 13, weight: .medium))
                        .foregroundStyle(.primary)
                    Text("Authenticated VLESS Reality routing with a fail-closed Kill Switch")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Image(systemName: "lock.shield")
                    .foregroundStyle(.secondary)
            }

            Spacer()
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(
            LinearGradient(
                colors: [
                    Color(hex: "4B6EFF").opacity(0.1),
                    Color(hex: "FF6E52").opacity(0.1)
                ],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            ),
            in: RoundedRectangle(cornerRadius: 24)
        )
        .background(.white.opacity(colorScheme == .dark ? 0.08 : 0.4), in: RoundedRectangle(cornerRadius: 24))
        .overlay(
            RoundedRectangle(cornerRadius: 24)
                .strokeBorder(.white.opacity(colorScheme == .dark ? 0.12 : 0.7), lineWidth: 1)
        )
    }

    // MARK: - Helpers

    private func setLaunchAtStartup(_ enabled: Bool) {
        guard !isUpdatingLaunchAtStartup else { return }
        isUpdatingLaunchAtStartup = true
        launchAtStartupMessage = nil

        Task {
            defer { isUpdatingLaunchAtStartup = false }
            do {
                if enabled {
                    if SMAppService.mainApp.status != .enabled {
                        try SMAppService.mainApp.register()
                    }
                } else if SMAppService.mainApp.status == .enabled
                            || SMAppService.mainApp.status == .requiresApproval {
                    try await SMAppService.mainApp.unregister()
                }

                let status = SMAppService.mainApp.status
                launchAtStartup = status == .enabled
                AppProfile.defaults.set(
                    launchAtStartup,
                    forKey: SettingsKey.launchAtStartup
                )
                if status == .requiresApproval {
                    launchAtStartupMessage =
                        "Allow Tono in System Settings › General › Login Items."
                }
            } catch {
                launchAtStartup =
                    SMAppService.mainApp.status == .enabled
                launchAtStartupMessage =
                    "Could not update Login Items: \(error.localizedDescription)"
            }
        }
    }

    private var settingDivider: some View {
        Divider()
            .opacity(0.3)
            .padding(.vertical, 2)
    }

    private func settingsPicker(selection: Binding<String>, options: [String]) -> some View {
        Menu {
            ForEach(options, id: \.self) { option in
                Button {
                    selection.wrappedValue = option
                } label: {
                    if selection.wrappedValue == option {
                        Label(option, systemImage: "checkmark")
                    } else {
                        Text(option)
                    }
                }
            }
        } label: {
            HStack(spacing: 8) {
                Text(LocalizedStringKey(selection.wrappedValue))
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(.primary)
                Image(systemName: "chevron.down")
                    .font(.system(size: 9, weight: .semibold))
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 6)
            .background(.white.opacity(colorScheme == .dark ? 0.08 : 0.4), in: Capsule())
            .overlay(Capsule().strokeBorder(.white.opacity(colorScheme == .dark ? 0.08 : 0.4), lineWidth: 0.5))
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
    }

}

// MARK: - Settings Card Container

private struct SettingsCard<Content: View>: View {
    @Environment(\.colorScheme) private var colorScheme
    let icon: String
    let title: String
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            // Card header
            HStack(spacing: 12) {
                Image(systemName: icon)
                    .font(.system(size: 14))
                    .foregroundStyle(.primary)
                    .frame(width: 36, height: 36)
                    .background(.white.opacity(colorScheme == .dark ? 0.1 : 0.5), in: RoundedRectangle(cornerRadius: 10))

                Text(LocalizedStringKey(title))
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(.primary)
            }
            .padding(.bottom, 4)

            content
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(.white.opacity(colorScheme == .dark ? 0.08 : 0.4), in: RoundedRectangle(cornerRadius: 24))
        .overlay(
            RoundedRectangle(cornerRadius: 24)
                .strokeBorder(.white.opacity(colorScheme == .dark ? 0.12 : 0.7), lineWidth: 1)
        )
    }
}

// MARK: - Setting Row

private struct SettingRow<Trailing: View>: View {
    let label: String
    let subtitle: String
    @ViewBuilder let trailing: Trailing

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(LocalizedStringKey(label))
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(.primary)
                Text(LocalizedStringKey(subtitle))
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            trailing
        }
        .padding(.vertical, 4)
    }
}

// MARK: - Setting Toggle Row

private struct SettingToggleRow: View {
    let label: String
    let subtitle: String
    @Binding var isOn: Bool

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(LocalizedStringKey(label))
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(.primary)
                Text(LocalizedStringKey(subtitle))
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Toggle("", isOn: $isOn)
                .toggleStyle(.switch)
                .tint(.accentColor)
                .labelsHidden()
        }
        .padding(.vertical, 4)
    }
}

// MARK: - Preview

#Preview {
    ZStack {
        MeshGradientBackground()
        SettingsView()
    }
    .frame(width: 800, height: 600)
    .environment(AppState())
    .environmentObject(AppUpdater(enabled: false))
}
