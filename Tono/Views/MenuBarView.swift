import SwiftUI

// MARK: - Menu Bar Extra View

struct MenuBarView: View {
    @Environment(AppState.self) private var appState
    @Environment(AccountSession.self) private var accountSession
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(spacing: 0) {
            // MARK: Header - Protected route + Toggle
            HStack {
                VStack(alignment: .leading, spacing: 1) {
                    Text("Tono Protection")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundStyle(.primary)

                    HStack(spacing: 5) {
                        Circle()
                            .fill(
                                appState.isProtectionBlocked
                                    ? Color(hex: "FF9F0A")
                                    : appState.isProxyDegraded
                                        ? Color(hex: "FFD60A")
                                        : appState.isConnected
                                            ? Color(hex: "32D74B")
                                            : Color(hex: "A2A3C4")
                            )
                            .frame(width: 5, height: 5)
                            .shadow(color: appState.isConnected ? Color(hex: "32D74B").opacity(0.6) : .clear, radius: 3)
                        Text(LocalizedStringKey(
                            appState.isDisconnecting ? "Disconnecting…"
                                : appState.isConnecting ? appState.connectionStage.rawValue
                                : appState.isProtectedReconnectScheduled
                                    ? "Waiting to retry…"
                                : appState.protectedReconnectPausedForUserAction
                                    ? "Protected Offline · retries paused"
                                : appState.isProtectionBlocked ? "Protected Offline"
                                : appState.isProxyDegraded ? "Degraded"
                                : appState.isConnected ? "Active"
                                : "Inactive"
                        ))
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                    }
                }
                Spacer()
                Toggle("", isOn: Binding(
                    get: { appState.isConnected },
                    set: { newValue in
                        Task { @MainActor in
                            if appState.isProtectionBlocked {
                                // In Protected Offline the switch appears off;
                                // turning it on must retry the protected path,
                                // never restore the machine's direct route.
                                if newValue {
                                    appState.retryProtectedConnectionNow()
                                }
                            } else if newValue {
                                appState.connect()
                            } else {
                                // Intentional user disconnect: restore host internet.
                                appState.disconnect(releaseKillSwitch: true)
                            }
                        }
                    }
                ))
                .toggleStyle(.switch)
                .labelsHidden()
                .controlSize(.mini)
                .disabled(
                    accountSession.state != .ready
                        || !appState.isTonoReady
                        || appState.isConnecting
                        || appState.isDisconnecting
                )
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)

            // Escape hatch parity with the dashboard pill: in Protected
            // Offline (or fail-closed with the session not ready) the on/off
            // switch above deliberately cannot restore internet, so labeled
            // explicit actions must exist here — previously the menu bar
            // offered no way out of a fail-closed host at all.
            if appState.isProtectionBlocked
                || (KillSwitchService.isArmed && accountSession.state != .ready) {
                menuDivider
                VStack(spacing: 6) {
                    if appState.isProtectionBlocked, accountSession.state == .ready {
                        Button {
                            appState.retryProtectedConnectionNow()
                        } label: {
                            Label("Retry protected connection", systemImage: "arrow.clockwise")
                                .font(.system(size: 12, weight: .medium))
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                    }
                    Button {
                        Task { @MainActor in
                            if accountSession.state == .ready {
                                appState.disconnect(releaseKillSwitch: true)
                            } else {
                                await accountSession.restoreDirectInternet()
                            }
                        }
                    } label: {
                        Label("Restore internet (turn off protection)", systemImage: "wifi")
                            .font(.system(size: 12, weight: .medium))
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 8)
            }

            menuDivider

            Label {
                VStack(alignment: .leading, spacing: 1) {
                    Text("Protected Reality route")
                        .font(.system(size: 11, weight: .semibold))
                    Text("Rule routing · TUN · Kill Switch")
                        .font(.system(size: 10))
                        .foregroundStyle(.secondary)
                }
            } icon: {
                Image(systemName: "lock.shield.fill")
                    .foregroundStyle(Color(hex: "4B6EFF"))
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 16)
            .padding(.vertical, 10)

            // MARK: Node Selector
            NodeSelectorMenu(appState: appState)
                .padding(.horizontal, 16)
                .padding(.bottom, 10)

            menuDivider

            // MARK: TUN Mode
            HStack {
                Text("TUN Mode")
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(.primary)
                Spacer()
                Toggle("", isOn: .constant(true))
                .toggleStyle(.switch)
                .labelsHidden()
                .controlSize(.mini)
                .disabled(true)
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

            // MARK: Protected DNS
            HStack {
                Text("DNS")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                Spacer()
                HStack(spacing: 4) {
                    Image(systemName: appState.isConnected ? "lock.fill" : "lock.open")
                        .font(.system(size: 8, weight: .semibold))
                        .foregroundStyle(
                            appState.isConnected
                                ? Color(hex: "32D74B")
                                : .secondary
                        )
                    Text(
                        appState.isConnected
                            ? "\(ProtectedDNSContract.server) · Protected"
                            : "--"
                    )
                        .font(.system(size: 11, weight: .medium, design: .monospaced))
                        .foregroundStyle(.primary)
                }
                .help(
                    "System DNS: \(ProtectedDNSContract.server) · "
                        + "Upstream: 1.1.1.1 / 8.8.8.8 DoH via the protected exit"
                )
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 8)

            // MARK: Footer Buttons
            HStack(spacing: 8) {
                Button {
                    // Try to find and restore existing main window
                    var found = false
                    for window in NSApp.windows where window.title == "Tono" || window.identifier?.rawValue.contains("main") == true {
                        window.deminiaturize(nil)
                        window.makeKeyAndOrderFront(nil)
                        found = true
                        break
                    }
                    if !found {
                        openWindow(id: "main")
                    }
                    NSApp.activate(ignoringOtherApps: true)
                } label: {
                    HStack(spacing: 4) {
                        Image(systemName: "house")
                            .font(.system(size: 10))
                        Text(LocalizedStringKey("Dashboard"))
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

    private var selectedName: String {
        appState.activeNode?.name ?? appState.proxyService.activeNodeName ?? ""
    }

    private var displayLabel: String {
        if appState.switchingNodeId != nil {
            return String(localized: "Switching server…")
        }
        let name = selectedName
        guard !name.isEmpty else { return String(localized: "No Server Selected") }
        let (flag, clean) = ConfigParser.extractFlag(from: name)
        return "\(flag) \(ProxyNode.displayName(for: clean))"
    }

    var body: some View {
        Menu {
            let nodes = appState.proxyRegions
                .filter { $0.id != "custom" }
                .flatMap(\.nodes)
            if nodes.isEmpty {
                Text("No cloud servers available")
            } else {
                Section("Cloud Servers") {
                    ForEach(nodes) { node in
                        let runtimeNode = appState.proxyService.nodes.first {
                            $0.name == node.name
                                || ConfigParser.extractFlag(from: $0.name).cleanName
                                    == ConfigParser.extractFlag(from: node.name).cleanName
                        }
                        let delay = runtimeNode.map { $0.latency > 0 ? "\($0.latency)ms" : "—" } ?? "—"
                        let label = "\(node.flag) \(node.displayName)   · \(delay)"
                        Button {
                            appState.selectNode(node.name)
                        } label: {
                            if selectedName == node.name
                                || ConfigParser.extractFlag(from: selectedName).cleanName
                                    == ConfigParser.extractFlag(from: node.name).cleanName {
                                Label(label, systemImage: "checkmark")
                            } else {
                                Text(label)
                            }
                        }
                        .disabled(appState.switchingNodeId != nil)
                    }
                }
                if AppProfile.isDev, !appState.customNodes.isEmpty {
                    Section("Custom") {
                        ForEach(appState.customNodes) { node in
                            Button {
                                appState.selectNode(node.name)
                            } label: {
                                if selectedName == node.name {
                                    Label("\(node.flag) \(node.name)", systemImage: "checkmark")
                                } else {
                                    Text("\(node.flag) \(node.name)")
                                }
                            }
                        }
                    }
                }
            }
        } label: {
            HStack {
                Text(displayLabel)
                    .font(.system(size: 13))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                Spacer()
            }
        }
        .disabled(appState.isConnecting || appState.isDisconnecting)
        .menuStyle(.borderlessButton)
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .frame(maxWidth: .infinity, minHeight: 42)
        .background(Color.primary.opacity(0.05))
        .clipShape(RoundedRectangle(cornerRadius: 14))
        .overlay(
            RoundedRectangle(cornerRadius: 14)
                .stroke(Color.primary.opacity(0.06), lineWidth: 0.5)
        )
    }
}
