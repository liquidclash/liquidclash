import SwiftUI

struct SettingsView: View {
    @Environment(AppState.self) private var appState
    @Environment(\.colorScheme) private var colorScheme

    // General
    @AppStorage(SettingsKey.launchAtStartup) private var launchAtStartup = true
    @AppStorage(SettingsKey.interfaceLanguage) private var selectedLanguage = "Auto"
    @AppStorage(SettingsKey.logsEnabled) private var logsEnabled = true

    // Proxy Engine
    @AppStorage(SettingsKey.mixedPort) private var mixedPort = "7890"
    @AppStorage(SettingsKey.tunMode) private var tunMode = false
    @AppStorage(SettingsKey.allowLAN) private var allowLAN = false
    // Appearance
    @AppStorage(SettingsKey.themeMode) private var themeMode = "Adaptive"
    @AppStorage(SettingsKey.glassTransparency) private var glassTransparency: Double = 50

    // About
    @AppStorage(SettingsKey.checkForUpdates) private var checkForUpdates = true



    private let languages = ["Auto", "English", "简体中文", "日本語"]
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
                isOn: $launchAtStartup
            )

            settingDivider

            SettingRow(label: "Interface Language", subtitle: "System-wide display language") {
                settingsPicker(selection: $selectedLanguage, options: languages)
            }

            settingDivider

            SettingToggleRow(
                label: "Enable Logs",
                subtitle: "Show Logs page and record logs",
                isOn: $logsEnabled
            )
        }
    }

    // MARK: - Proxy Engine Card

    private var proxyEngineCard: some View {
        SettingsCard(icon: "bolt", title: "Proxy Engine") {
            SettingRow(label: "Mixed Port", subtitle: "HTTP/SOCKS listener port") {
                TextField("", text: $mixedPort)
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
                    .onSubmit {
                        if let port = Int(mixedPort), (1024...65535).contains(port) {
                            appState.applySettingChange(key: "mixed-port", value: port)
                        } else {
                            mixedPort = "7890" // Reset to default on invalid input
                        }
                    }
            }

            settingDivider

            SettingToggleRow(
                label: "TUN Mode",
                subtitle: "Virtual network adapter for system-wide proxy",
                isOn: $tunMode
            )
            .onChange(of: tunMode) { _, newValue in
                if !newValue { allowLAN = false }
                if appState.isConnected {
                    appState.errorMessage = newValue
                        ? String(localized: "TUN mode will take effect after reconnecting.")
                        : String(localized: "TUN mode disabled. Reconnect to apply.")
                }
            }

            settingDivider

            SettingToggleRow(
                label: "Allow LAN",
                subtitle: "Let LAN devices connect through your proxy",
                isOn: $allowLAN
            )
            .disabled(!tunMode)
            .opacity(tunMode ? 1.0 : 0.4)
            .onChange(of: allowLAN) { _, newValue in
                appState.applySettingChange(key: "allow-lan", value: newValue)
            }

        }
    }

    // MARK: - Appearance Card

    private var appearanceCard: some View {
        SettingsCard(icon: "paintpalette", title: "Appearance") {
            SettingRow(label: "Theme Mode", subtitle: "Light, Dark or Liquid adaptive") {
                settingsPicker(selection: $themeMode, options: themes)
            }

            settingDivider

            SettingRow(label: "Glass Transparency", subtitle: "Adjust backdrop blur intensity") {
                HStack(spacing: 8) {
                    Slider(value: $glassTransparency, in: 0...100)
                        .tint(.accentColor)
                        .frame(maxWidth: 140)
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
                    Text("LiquidClash Desktop")
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundStyle(.primary)
                    Text("Version 2.4.0 (Stable)")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            settingDivider

            // Check for Updates row
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Check for Updates")
                        .font(.system(size: 13, weight: .medium))
                        .foregroundStyle(.primary)
                    Text("Auto update core binaries")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Toggle("", isOn: $checkForUpdates)
                    .toggleStyle(.switch)
                    .tint(.accentColor)
                    .labelsHidden()
            }

            Spacer()

            // Links
            HStack(spacing: 10) {
                linkButton(label: "Github", url: "https://github.com/liquidclash/liquidclash")
                linkButton(label: "Website", url: "https://liquidclash.github.io/liquidclash_web/web.html")
            }
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
        }
        .buttonStyle(.plain)
    }

    private func linkButton(label: String, url: String) -> some View {
        Button {
            if let url = URL(string: url) {
                NSWorkspace.shared.open(url)
            }
        } label: {
            Text(LocalizedStringKey(label))
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(.primary)
                .padding(.horizontal, 14)
                .padding(.vertical, 5)
                .background(.white.opacity(colorScheme == .dark ? 0.06 : 0.25), in: Capsule())
                .overlay(Capsule().strokeBorder(.white.opacity(colorScheme == .dark ? 0.06 : 0.3), lineWidth: 0.5))
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
}
