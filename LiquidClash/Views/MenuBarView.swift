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
            Button {
                NSApp.activate(ignoringOtherApps: true)
                if let window = NSApp.windows.first(where: { $0.identifier?.rawValue != "menu-bar" }) {
                    window.makeKeyAndOrderFront(nil)
                }
            } label: {
                HStack(spacing: 8) {
                    ZStack {
                        Circle()
                            .fill(Color.primary.opacity(0.08))
                            .frame(width: 22, height: 22)
                        Image(systemName: "shield.checkered")
                            .font(.system(size: 10))
                            .foregroundStyle(.primary)
                    }
                    Text(appState.activeNode.map { $0.name } ?? String(localized: "No Node Selected"))
                        .font(.system(size: 12, weight: .medium))
                        .foregroundStyle(.primary)
                        .lineLimit(1)
                    Spacer()
                    Image(systemName: "chevron.down")
                        .font(.system(size: 9, weight: .medium))
                        .foregroundStyle(.tertiary)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(Color.primary.opacity(0.05), in: RoundedRectangle(cornerRadius: 14))
                .overlay(
                    RoundedRectangle(cornerRadius: 14)
                        .stroke(Color.primary.opacity(0.03), lineWidth: 0.5)
                )
            }
            .buttonStyle(.plain)
            .padding(.horizontal, 16)
            .padding(.bottom, 10)

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
