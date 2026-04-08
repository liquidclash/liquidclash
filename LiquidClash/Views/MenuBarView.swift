import SwiftUI

// MARK: - Menu Bar Extra View

struct MenuBarView: View {
    @Environment(AppState.self) private var appState

    var body: some View {
        VStack(spacing: 0) {
            // MARK: Header - System Proxy + Toggle
            HStack {
                VStack(alignment: .leading, spacing: 1) {
                    Text("System Proxy")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundStyle(.primary)

                    HStack(spacing: 5) {
                        Circle()
                            .fill(appState.isConnected ? Color(hex: "32D74B") : Color(hex: "A2A3C4"))
                            .frame(width: 5, height: 5)
                            .shadow(color: appState.isConnected ? Color(hex: "32D74B").opacity(0.6) : .clear, radius: 3)
                        Text(LocalizedStringKey(appState.isConnected ? "Active" : "Inactive"))
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                    }
                }
                Spacer()
                Toggle("", isOn: Binding(
                    get: { appState.isConnected },
                    set: { newValue in
                        if newValue {
                            appState.connect()
                        } else {
                            appState.disconnect()
                        }
                    }
                ))
                .toggleStyle(.switch)
                .labelsHidden()
                .controlSize(.mini)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)

            menuDivider

            // MARK: Proxy Mode Segmented Control
            HStack(spacing: 0) {
                ForEach(ProxyMode.allCases, id: \.self) { mode in
                    Button {
                        withAnimation(.easeInOut(duration: 0.2)) {
                            appState.setProxyMode(mode)
                        }
                    } label: {
                        Text(LocalizedStringKey(mode.rawValue))
                            .font(.system(size: 11, weight: .semibold))
                            .foregroundStyle(appState.proxyMode == mode ? .white : .secondary)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 6)
                            .background(
                                appState.proxyMode == mode
                                    ? Capsule().fill(Color.accentColor)
                                        .shadow(color: .black.opacity(0.12), radius: 3, y: 1)
                                    : nil
                            )
                            .contentShape(Capsule())
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(3)
            .background(Color.primary.opacity(0.06), in: Capsule())
            .padding(.horizontal, 16)
            .padding(.vertical, 10)

            // MARK: Node Selector
            NodeSelectorMenu(appState: appState)
                .padding(.horizontal, 16)
                .padding(.bottom, 10)

            menuDivider

            // MARK: TUN Mode Toggle
            HStack {
                Text("TUN Mode")
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(.primary)
                Spacer()
                Toggle("", isOn: Binding(
                    get: { UserDefaults.standard.bool(forKey: SettingsKey.tunMode) },
                    set: { newValue in
                        UserDefaults.standard.set(newValue, forKey: SettingsKey.tunMode)
                        if appState.isConnected {
                            appState.errorMessage = newValue
                                ? String(localized: "TUN mode will take effect after reconnecting.")
                                : String(localized: "TUN mode disabled. Reconnect to apply.")
                        }
                    }
                ))
                .toggleStyle(.switch)
                .labelsHidden()
                .controlSize(.mini)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 8)

            menuDivider

            // MARK: Public IP Info
            HStack {
                Text("Public IP")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                Spacer()
                Text(appState.isConnected ? appState.networkInfo.ip : "--")
                    .font(.system(size: 11, weight: .medium, design: .monospaced))
                    .foregroundStyle(.primary)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 8)

            // MARK: Footer Buttons
            HStack(spacing: 8) {
                Button {
                    NSApp.activate(ignoringOtherApps: true)
                    for window in NSApp.windows {
                        if window.identifier?.rawValue != "menu-bar" && window.canBecomeMain {
                            window.makeKeyAndOrderFront(nil)
                            break
                        }
                    }
                } label: {
                    HStack(spacing: 4) {
                        Image(systemName: "house")
                            .font(.system(size: 10))
                        Text("Dashboard")
                            .font(.system(size: 12, weight: .semibold))
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                    .background(Color.primary.opacity(0.06), in: Capsule())
                    .foregroundStyle(.primary)
                    .contentShape(Capsule())
                }
                .buttonStyle(.plain)

                Button {
                    NSApp.terminate(nil)
                } label: {
                    HStack(spacing: 4) {
                        Image(systemName: "rectangle.portrait.and.arrow.right")
                            .font(.system(size: 10))
                        Text("Quit")
                            .font(.system(size: 12, weight: .semibold))
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                    .background(Color.primary.opacity(0.06), in: Capsule())
                    .foregroundStyle(.primary)
                    .contentShape(Capsule())
                }
                .buttonStyle(.plain)
            }
            .padding(.horizontal, 16)
            .padding(.top, 8)
            .padding(.bottom, 12)
        }
        .frame(width: 280)
        .fixedSize()
    }

    // MARK: - Subviews

    private var menuDivider: some View {
        Rectangle()
            .fill(Color.primary.opacity(0.06))
            .frame(height: 0.5)
            .padding(.horizontal, 16)
    }
}

// MARK: - Node Selector Menu

private struct NodeSelectorMenu: View {
    var appState: AppState
    @State private var selected: String = ""

    private let regionNames: Set<String> = ["HK","JP","SG","TW","US","UK","KR","DE","FR","CA","AU","IN","RU","BR","NL","Auto Select","PROXY","Proxies","Fallback","GLOBAL","Final","default"]

    var body: some View {
        Picker("", selection: $selected) {
            Text(String(localized: "No Node Selected")).tag("")

            if appState.isConnected && !appState.proxyService.nodes.isEmpty {
                Section("Nodes") {
                    ForEach(appState.proxyService.nodes) { node in
                        let delay = node.latency > 0 ? "\(node.latency)ms" : "-ms"
                        Text("\(node.flag) \(ConfigParser.extractFlag(from: node.name).cleanName)   | \(delay)")
                            .tag(node.name)
                    }
                }

                Section("Services") {
                    ForEach(appState.proxyService.groups.filter { !regionNames.contains($0.name) }) { group in
                        let delay = group.latency > 0 ? "\(group.latency)ms" : "-ms"
                        Text("\(group.name)   | \(delay)")
                            .tag(group.name)
                    }
                }

                Section("Regions") {
                    ForEach(appState.proxyService.groups.filter { regionNames.contains($0.name) && $0.name != "GLOBAL" }) { group in
                        let delay = group.latency > 0 ? "\(group.latency)ms" : "-ms"
                        Text("\(group.name)   | \(delay)")
                            .tag(group.name)
                    }
                }
            } else {
                ForEach(appState.proxyRegions.flatMap(\.nodes)) { node in
                    Text("\(node.flag) \(node.name)")
                        .tag(node.name)
                }
            }
        }
        .pickerStyle(.menu)
        .labelsHidden()
        .buttonStyle(.borderless)
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .frame(maxWidth: .infinity, minHeight: 42)
        .background(Color.primary.opacity(0.05))
        .clipShape(RoundedRectangle(cornerRadius: 14))
        .overlay(
            RoundedRectangle(cornerRadius: 14)
                .stroke(Color.primary.opacity(0.06), lineWidth: 0.5)
        )
        .onAppear {
            selected = appState.proxyService.activeNodeName ?? ""
        }
        .onChange(of: appState.proxyService.activeNodeName) { _, newValue in
            selected = newValue ?? ""
        }
        .onChange(of: selected) { _, newValue in
            guard !newValue.isEmpty else { return }
            appState.selectNode(newValue)
        }
    }
}
