import SwiftUI

struct AccountSettingsCard: View {
    @Bindable var session: AccountSession

    var body: some View {
        GroupBox("Tono Account") {
            VStack(alignment: .leading, spacing: 12) {
                if let user = session.user {
                    LabeledContent("User", value: user.name ?? user.email)
                    if user.name != nil { LabeledContent("Email", value: user.email) }
                    LabeledContent("Plan", value: user.plan ?? "Tono")
                    LabeledContent("Devices", value: TonoAccountRules.quotaText(used: session.devices.count, limit: session.deviceLimit))
                    LabeledContent("Expires", value: TonoAccountRules.expiryText(user.expiresAt))
                    if let quota = user.quotaBytes, let usage = user.usageBytes {
                        LabeledContent("Usage", value: "\(ByteCountFormatter.string(fromByteCount: usage, countStyle: .file)) / \(ByteCountFormatter.string(fromByteCount: quota, countStyle: .file))")
                    }
                }
                Divider()
                ForEach(session.devices) { device in
                    HStack {
                        Image(systemName: "desktopcomputer")
                        VStack(alignment: .leading) {
                            Text(device.name)
                            if let seen = device.lastSeenAt { Text("Last seen \(seen.formatted(.relative(presentation: .named)))").font(.caption).foregroundStyle(.secondary) }
                        }
                        Spacer()
                        if device.id == session.device?.id || device.current == true { Text("This Mac").foregroundStyle(.secondary) }
                        else { Button("Revoke", role: .destructive) { Task { await session.revoke(device) } } }
                    }
                }
                if session.isAtDeviceLimit {
                    Label("\(session.deviceLimit)-device limit reached", systemImage: "info.circle")
                        .foregroundStyle(.orange)
                }
                Divider()
                Button("Sign Out", role: .destructive) { Task { await session.logout() } }
            }.padding(8)
        }
    }
}

struct AccountSettingsView: View {
    @Bindable var session: AccountSession
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Tono").font(.title2.bold())
            AccountSettingsCard(session: session)
            HStack { Spacer(); Button("Sign Out", role: .destructive) { Task { await session.logout() } } }
        }
        .padding()
        .task { try? await session.reloadDevices() }
    }
}
