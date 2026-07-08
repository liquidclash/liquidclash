import SwiftUI
import UniformTypeIdentifiers

struct SubscriptionSourcesPanel: View {
    @Environment(AppState.self) private var appState
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.locale) private var locale

    @State private var isUpdatingSubscription = false
    @State private var subscriptionStatus: String?
    @State private var showingFilePicker = false
    @State private var showingEditor = false
    @State private var editingSubscription: SubscriptionInfo?
    @State private var draftSubscriptionName = ""
    @State private var draftSubscriptionURL = ""
    @State private var draftSubscriptionEnabled = true

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            pageHeader

            VStack(alignment: .leading, spacing: 16) {
                sourceHeader
                subscriptionsGrid

                if let status = subscriptionStatus {
                    Text(status)
                        .font(.system(size: 11))
                        .foregroundStyle(status.contains("✓") ? Color(hex: "30D158") : .red)
                }
            }
            .padding(16)
            .background(.white.opacity(colorScheme == .dark ? 0.08 : 0.4), in: RoundedRectangle(cornerRadius: 16))
            .overlay(
                RoundedRectangle(cornerRadius: 16)
                    .strokeBorder(.white.opacity(colorScheme == .dark ? 0.12 : 0.7), lineWidth: 0.5)
            )
        }
        .fileImporter(
            isPresented: $showingFilePicker,
            allowedContentTypes: [.yaml, .init(filenameExtension: "yml")!, .plainText],
            allowsMultipleSelection: false
        ) { result in
            if case .success(let urls) = result, let fileURL = urls.first {
                importFromFile(fileURL)
            }
        }
        .sheet(isPresented: $showingEditor) {
            SubscriptionEditorSheet(
                isEditing: editingSubscription != nil,
                name: $draftSubscriptionName,
                url: $draftSubscriptionURL,
                isEnabled: $draftSubscriptionEnabled,
                onCancel: { showingEditor = false },
                onSave: saveSubscriptionDraft
            )
        }
    }

    private var pageHeader: some View {
        HStack(alignment: .center) {
            Text("Subscriptions")
                .font(.system(size: 24, weight: .semibold))
                .foregroundStyle(.primary)

            Spacer()

            HStack(spacing: 10) {
                addSubscriptionButton

                importFileButton

                if Self.clashVergeProfilesExist {
                    clashVergeButton
                }
            }
        }
    }

    private var sourceHeader: some View {
        HStack(alignment: .center, spacing: 12) {
            Image(systemName: "link.circle.fill")
                .font(.system(size: 18, weight: .semibold))
                .foregroundStyle(Color(hex: "4B6EFF"))
                .frame(width: 24)

            VStack(alignment: .leading, spacing: 2) {
                Text("Subscription Sources")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(.primary)
                Text(sourceSummary)
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            }

            Spacer()
        }
    }

    private var sourceSummary: String {
        let subscriptionCount = appState.subscriptions.count
        let nodeCount = appState.subscriptions.reduce(0) { $0 + $1.nodeCount }
        let activeCount = appState.subscriptions.filter(\.isEnabled).count
        guard subscriptionCount > 0 else { return String(localized: "No subscription added") }
        return String(
            format: String(localized: "%lld subscriptions · %lld active · %lld nodes"),
            Int64(subscriptionCount),
            Int64(activeCount),
            Int64(nodeCount)
        )
    }

    @ViewBuilder
    private var subscriptionsGrid: some View {
        if appState.subscriptions.isEmpty {
            emptyState
        } else {
            let columns = [
                GridItem(.adaptive(minimum: 240, maximum: 320), spacing: 12, alignment: .top)
            ]

            LazyVGrid(columns: columns, alignment: .leading, spacing: 12) {
                ForEach(appState.subscriptions) { subscription in
                    subscriptionCard(subscription)
                }
            }
        }
    }

    private var emptyState: some View {
        VStack(spacing: 8) {
            Image(systemName: "link.circle.fill")
                .font(.system(size: 24, weight: .semibold))
                .foregroundStyle(Color(hex: "4B6EFF"))
            Text("No subscription added")
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(.primary)
        }
        .frame(maxWidth: .infinity, minHeight: 180)
        .background(.white.opacity(colorScheme == .dark ? 0.05 : 0.24), in: RoundedRectangle(cornerRadius: 12))
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .strokeBorder(.white.opacity(colorScheme == .dark ? 0.12 : 0.45), lineWidth: 0.5)
        )
    }

    private func subscriptionCard(_ subscription: SubscriptionInfo) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: subscription.isEnabled ? "checkmark.circle.fill" : "circle")
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(subscription.isEnabled ? Color(hex: "30D158") : .secondary)
                    .frame(width: 20)

                VStack(alignment: .leading, spacing: 3) {
                    Text(subscription.name)
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(.primary)
                        .lineLimit(1)

                    Text(LocalizedStringKey(subscription.isEnabled ? "Active" : "Inactive"))
                        .font(.system(size: 10, weight: .medium))
                        .foregroundStyle(subscription.isEnabled ? Color(hex: "30D158") : .secondary)
                }

                Spacer(minLength: 0)

                Toggle("", isOn: Binding(
                    get: { subscription.isEnabled },
                    set: { setSubscription(subscription, enabled: $0) }
                ))
                .labelsHidden()
                .toggleStyle(.switch)
                .disabled(isUpdatingSubscription)
            }

            Text(subscription.url)
                .font(.system(size: 10, design: .monospaced))
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled)

            VStack(alignment: .leading, spacing: 6) {
                Text(subscriptionMeta(subscription))
                    .font(.system(size: 10))
                    .foregroundStyle(.secondary)

                if let traffic = trafficSummary(subscription) {
                    Text(traffic)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }

                if let total = subscription.total, total > 0 {
                    subscriptionUsageBar(subscription, total: total)
                }
            }

            Spacer(minLength: 0)

            HStack(spacing: 8) {
                Button {
                    updateSubscription(subscription)
                } label: {
                    Image(systemName: "arrow.clockwise")
                        .font(.system(size: 11, weight: .medium))
                        .frame(width: 28, height: 28)
                        .contentShape(Circle())
                }
                .buttonStyle(.plain)
                .help(Text("Update subscription"))
                .disabled(isUpdatingSubscription)

                Button {
                    openEditSubscriptionSheet(subscription)
                } label: {
                    Image(systemName: "pencil")
                        .font(.system(size: 11, weight: .medium))
                        .frame(width: 28, height: 28)
                        .contentShape(Circle())
                }
                .buttonStyle(.plain)
                .help(Text("Edit subscription"))
                .disabled(isUpdatingSubscription)

                Spacer(minLength: 0)

                Button(role: .destructive) {
                    appState.removeSubscription(subscription.id)
                    showTemporaryStatus(String(localized: "✓ Subscription saved"))
                } label: {
                    Image(systemName: "trash")
                        .font(.system(size: 11))
                        .frame(width: 28, height: 28)
                        .contentShape(Circle())
                }
                .buttonStyle(.plain)
                .help(Text("Remove subscription"))
                .disabled(isUpdatingSubscription)
            }
            .foregroundStyle(.secondary)
        }
        .padding(14)
        .frame(maxWidth: .infinity, minHeight: 168, alignment: .topLeading)
        .background(.white.opacity(subscription.isEnabled ? (colorScheme == .dark ? 0.1 : 0.42) : (colorScheme == .dark ? 0.05 : 0.26)), in: RoundedRectangle(cornerRadius: 12))
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .strokeBorder(
                    subscription.isEnabled
                        ? Color(hex: "4B6EFF").opacity(0.6)
                        : .white.opacity(colorScheme == .dark ? 0.12 : 0.45),
                    lineWidth: subscription.isEnabled ? 1 : 0.5
                )
        )
    }

    private var importFileButton: some View {
        Button {
            showingFilePicker = true
        } label: {
            HStack(spacing: 5) {
                Image(systemName: "doc.badge.plus")
                    .font(.system(size: 11, weight: .medium))
                Text("Import File")
                    .font(.system(size: 11, weight: .medium))
            }
            .foregroundStyle(.primary)
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .glassEffect(.regular.tint(.white.opacity(0.06)), in: Capsule())
        .disabled(isUpdatingSubscription)
    }

    private var addSubscriptionButton: some View {
        GradientAddButton("Add Subscription") {
            openAddSubscriptionSheet()
        }
    }

    private var clashVergeButton: some View {
        Button {
            importFromClashVerge()
        } label: {
            HStack(spacing: 5) {
                Image(systemName: "arrow.down.circle")
                    .font(.system(size: 11))
                Text("Clash Verge")
                    .font(.system(size: 11, weight: .medium))
            }
            .foregroundStyle(.primary)
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .glassEffect(.regular.tint(.white.opacity(0.06)), in: Capsule())
        .disabled(isUpdatingSubscription)
    }

    // MARK: - Subscription Actions

    private func openAddSubscriptionSheet() {
        editingSubscription = nil
        draftSubscriptionName = ""
        draftSubscriptionURL = ""
        draftSubscriptionEnabled = true
        showingEditor = true
    }

    private func openEditSubscriptionSheet(_ subscription: SubscriptionInfo) {
        editingSubscription = subscription
        draftSubscriptionName = subscription.name
        draftSubscriptionURL = subscription.url
        draftSubscriptionEnabled = subscription.isEnabled
        showingEditor = true
    }

    private func saveSubscriptionDraft() {
        let trimmedURL = draftSubscriptionURL.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedName = draftSubscriptionName.trimmingCharacters(in: .whitespacesAndNewlines)

        guard Self.isValidSubscriptionURL(trimmedURL) else {
            showTemporaryStatus(String(localized: "Subscription URL is invalid"))
            return
        }
        guard !appState.subscriptions.contains(where: { $0.id != editingSubscription?.id && $0.url == trimmedURL }) else {
            showTemporaryStatus(String(localized: "Subscription already exists"))
            return
        }

        if let editingSubscription {
            appState.updateSubscriptionDetails(editingSubscription.id, name: trimmedName, url: trimmedURL)
            appState.setSubscriptionEnabled(editingSubscription.id, enabled: draftSubscriptionEnabled)
            showingEditor = false
            showTemporaryStatus(String(localized: "✓ Subscription saved"))
        } else {
            appState.addSubscription(url: trimmedURL, name: trimmedName, isEnabled: draftSubscriptionEnabled)
            showingEditor = false
            showTemporaryStatus(String(localized: "✓ Subscription saved"))
        }
    }

    private func setSubscription(_ subscription: SubscriptionInfo, enabled: Bool) {
        if enabled {
            updateSubscriptionByActivating(subscription.id, successMessage: nil)
        } else {
            appState.deactivateSubscription(subscription.id)
            showTemporaryStatus(String(localized: "✓ Subscription saved"))
        }
    }

    private func updateSubscription(_ subscription: SubscriptionInfo) {
        if subscription.isEnabled {
            updateEnabledSubscriptions(successMessage: nil)
        } else {
            updateSubscriptionByActivating(subscription.id, successMessage: nil)
        }
    }

    private func updateSubscriptionByActivating(_ id: String, successMessage: String?) {
        isUpdatingSubscription = true
        subscriptionStatus = nil

        Task {
            do {
                try await appState.activateSubscription(id)
                await MainActor.run {
                    isUpdatingSubscription = false
                    showTemporaryStatus(successMessage ?? updateSuccessMessage())
                }
            } catch {
                await MainActor.run {
                    isUpdatingSubscription = false
                    showTemporaryStatus(error.localizedDescription)
                }
            }
        }
    }

    private func updateEnabledSubscriptions(successMessage: String?) {
        isUpdatingSubscription = true
        subscriptionStatus = nil

        Task {
            do {
                try await appState.updateAllSubscriptions()
                await MainActor.run {
                    isUpdatingSubscription = false
                    showTemporaryStatus(successMessage ?? updateSuccessMessage())
                }
            } catch {
                await MainActor.run {
                    isUpdatingSubscription = false
                    showTemporaryStatus(error.localizedDescription)
                }
            }
        }
    }

    private func updateSuccessMessage() -> String {
        let rulesCount = appState.rules.count
        if rulesCount > 0 {
            return String(localized: "✓ \(appState.totalNodes) nodes, \(rulesCount) rules")
        }
        return String(localized: "✓ \(appState.totalNodes) nodes")
    }

    private func importFromFile(_ fileURL: URL) {
        isUpdatingSubscription = true
        subscriptionStatus = nil

        Task {
            do {
                _ = fileURL.startAccessingSecurityScopedResource()
                defer { fileURL.stopAccessingSecurityScopedResource() }

                let content = try String(contentsOf: fileURL, encoding: .utf8)
                let nodes = ConfigParser.parseSubscription(content)
                guard !nodes.isEmpty else {
                    throw SubscriptionError.noNodesFound
                }

                let manager = SubscriptionManager()
                let regions = await manager.organizeIntoRegions(nodes)

                let parsedRules = content.contains("rules:") ? ConfigParser.parseClashYAMLRules(content, source: .subscription) : []

                await MainActor.run {
                    let previousSelection = appState.proxyService.activeNodeName ?? appState.activeNode?.name ?? appState.selectedNodeId
                    let customRegions = appState.proxyRegions.filter { $0.id == "custom" }
                    appState.proxyRegions = regions + customRegions
                    appState.restoreProxySelection(preferredTarget: previousSelection, persistFallback: true)
                    if !parsedRules.isEmpty {
                        let userRules = appState.rules.filter { $0.source == .user }
                        appState.rules = userRules + parsedRules
                    }
                    appState.saveState()
                    ConfigStorage.shared.saveProxyRegions(appState.proxyRegions)
                    ConfigStorage.shared.saveRawSubscriptionYAML(content)
                    isUpdatingSubscription = false
                    showTemporaryStatus(String(localized: "✓ Imported \(nodes.count) nodes"))
                }
            } catch {
                await MainActor.run {
                    isUpdatingSubscription = false
                    showTemporaryStatus(error.localizedDescription)
                }
            }
        }
    }

    private func importFromClashVerge() {
        isUpdatingSubscription = true
        subscriptionStatus = nil

        Task {
            do {
                guard let content = Self.readClashVergeProfile() else {
                    throw SubscriptionError.noNodesFound
                }

                let nodes = ConfigParser.parseSubscription(content)
                guard !nodes.isEmpty else {
                    throw SubscriptionError.noNodesFound
                }

                let manager = SubscriptionManager()
                let regions = await manager.organizeIntoRegions(nodes)

                let parsedRules = content.contains("rules:") ? ConfigParser.parseClashYAMLRules(content, source: .subscription) : []

                await MainActor.run {
                    let previousSelection = appState.proxyService.activeNodeName ?? appState.activeNode?.name ?? appState.selectedNodeId
                    let customRegions = appState.proxyRegions.filter { $0.id == "custom" }
                    appState.proxyRegions = regions + customRegions
                    appState.restoreProxySelection(preferredTarget: previousSelection, persistFallback: true)
                    if !parsedRules.isEmpty {
                        let userRules = appState.rules.filter { $0.source == .user }
                        appState.rules = userRules + parsedRules
                    }
                    appState.saveState()
                    ConfigStorage.shared.saveProxyRegions(appState.proxyRegions)
                    ConfigStorage.shared.saveRawSubscriptionYAML(content)
                    isUpdatingSubscription = false
                    showTemporaryStatus(String(localized: "✓ Imported \(nodes.count) nodes from Clash Verge"))
                }
            } catch {
                await MainActor.run {
                    isUpdatingSubscription = false
                    showTemporaryStatus(error.localizedDescription)
                }
            }
        }
    }

    // MARK: - Clash Verge Profile Detection

    private static var clashVergeProfileDir: URL? {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let candidates = [
            "io.github.clash-verge-rev.clash-verge-rev",
            "clash-verge",
            "io.github.clashverge.rev",
        ]
        for name in candidates {
            let dir = appSupport.appendingPathComponent(name).appendingPathComponent("profiles")
            if FileManager.default.fileExists(atPath: dir.path) {
                return dir
            }
        }
        return nil
    }

    private static var clashVergeProfilesExist: Bool {
        clashVergeProfileDir != nil
    }

    private static func readClashVergeProfile() -> String? {
        guard let dir = clashVergeProfileDir else { return nil }
        guard let files = try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: [.contentModificationDateKey]) else { return nil }

        let yamlFiles = files.filter { $0.pathExtension == "yaml" || $0.pathExtension == "yml" }
        let sorted = yamlFiles.sorted { a, b in
            let aDate = (try? a.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
            let bDate = (try? b.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
            return aDate > bDate
        }

        for file in sorted {
            if let content = try? String(contentsOf: file, encoding: .utf8),
               content.contains("proxies:") {
                return content
            }
        }
        return nil
    }

    private func subscriptionMeta(_ subscription: SubscriptionInfo) -> String {
        if let lastUpdate = subscription.lastUpdate {
            return String(
                format: String(localized: "%lld nodes · updated %@"),
                Int64(subscription.nodeCount),
                relativeDateString(for: lastUpdate)
            )
        }
        return String(format: String(localized: "%lld nodes · not updated"), Int64(subscription.nodeCount))
    }

    private func trafficSummary(_ subscription: SubscriptionInfo) -> String? {
        guard let total = subscription.total, total > 0 else { return nil }
        let used = Self.formatBytes(subscription.usedBytes)
        let totalText = Self.formatBytes(total)
        if let expiry = subscription.expiryDate {
            return String(
                format: String(localized: "%@ / %@ · expires %@"),
                used,
                totalText,
                shortDateString(for: expiry)
            )
        }
        return String(format: String(localized: "%@ / %@"), used, totalText)
    }

    private func subscriptionUsageBar(_ subscription: SubscriptionInfo, total: Int64) -> some View {
        GeometryReader { geo in
            ZStack(alignment: .leading) {
                Capsule()
                    .fill(Color.primary.opacity(0.08))
                Capsule()
                    .fill(subscription.usageRatio > 0.9 ? Color(hex: "FF3B30") :
                          subscription.usageRatio > 0.7 ? Color(hex: "FF9F0A") :
                          Color(hex: "4B6EFF"))
                    .frame(width: geo.size.width * min(subscription.usageRatio, 1.0))
            }
        }
        .frame(height: 4)
        .accessibilityLabel(
            String(
                format: String(localized: "%@ of %@ used"),
                Self.formatBytes(subscription.usedBytes),
                Self.formatBytes(total)
            )
        )
    }

    private func relativeDateString(for date: Date) -> String {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .short
        formatter.locale = locale
        return formatter.localizedString(for: date, relativeTo: Date())
    }

    private func shortDateString(for date: Date) -> String {
        date.formatted(.dateTime.year().month().day().locale(locale))
    }

    private static func isValidSubscriptionURL(_ value: String) -> Bool {
        guard let url = URL(string: value),
              let scheme = url.scheme?.lowercased(),
              ["http", "https"].contains(scheme),
              url.host != nil else {
            return false
        }
        return true
    }

    private static func formatBytes(_ bytes: Int64) -> String {
        let gb = Double(bytes) / 1_073_741_824
        if gb >= 1 { return String(format: "%.1f GB", gb) }
        let mb = Double(bytes) / 1_048_576
        if mb >= 1 { return String(format: "%.0f MB", mb) }
        return String(format: "%.0f KB", Double(bytes) / 1024)
    }

    private func showTemporaryStatus(_ message: String) {
        withAnimation { subscriptionStatus = message }
        Task {
            try? await Task.sleep(for: .seconds(3))
            await MainActor.run { withAnimation { subscriptionStatus = nil } }
        }
    }
}

private struct SubscriptionEditorSheet: View {
    let isEditing: Bool
    @Binding var name: String
    @Binding var url: String
    @Binding var isEnabled: Bool
    let onCancel: () -> Void
    let onSave: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 4) {
                Text(LocalizedStringKey(isEditing ? "Edit Subscription" : "Add Subscription"))
                    .font(.system(size: 18, weight: .semibold))
            }

            VStack(alignment: .leading, spacing: 10) {
                field("Name (optional)", text: $name, monospaced: false)
                field("Subscription URL", text: $url, monospaced: true)

                Toggle(isOn: $isEnabled) {
                    Text("Enable this subscription")
                        .font(.system(size: 12, weight: .medium))
                }
                .toggleStyle(.switch)
            }

            HStack(spacing: 10) {
                Spacer()

                Button {
                    onCancel()
                } label: {
                    Text("Cancel")
                        .font(.system(size: 12, weight: .semibold))
                        .padding(.horizontal, 14)
                        .padding(.vertical, 8)
                        .contentShape(Capsule())
                }
                .keyboardShortcut(.cancelAction)
                .buttonStyle(.plain)
                .glassEffect(.regular.tint(.white.opacity(0.14)), in: Capsule())

                Button {
                    onSave()
                } label: {
                    Text(LocalizedStringKey(isEditing ? "Save" : "Add"))
                        .font(.system(size: 12, weight: .semibold))
                        .frame(width: 80)
                        .padding(.vertical, 8)
                        .contentShape(Capsule())
                }
                .keyboardShortcut(.defaultAction)
                .disabled(url.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                .buttonStyle(.plain)
                .foregroundStyle(.white)
                .glassEffect(
                    .regular.tint(url.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? .gray.opacity(0.2) : .blue.opacity(0.65)),
                    in: Capsule()
                )
            }
        }
        .padding(22)
        .frame(width: 440)
    }

    private func field(_ title: LocalizedStringKey, text: Binding<String>, monospaced: Bool) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(.secondary)

            TextField(title, text: text)
                .textFieldStyle(.plain)
                .font(monospaced ? .system(size: 12, design: .monospaced) : .system(size: 12))
                .padding(10)
                .background(Color.primary.opacity(0.06), in: RoundedRectangle(cornerRadius: 8))
        }
    }
}

#Preview {
    ZStack {
        MeshGradientBackground()
        SubscriptionSourcesPanel()
            .padding(32)
    }
    .frame(width: 760, height: 460)
    .environment({
        let state = AppState()
        state.loadMockData()
        state.subscriptions = [
            SubscriptionInfo(
                url: "https://example.com/subscription",
                name: "Example Provider",
                lastUpdate: Date(),
                nodeCount: 24,
                upload: 2_000_000_000,
                download: 7_000_000_000,
                total: 100_000_000_000,
                expire: Date().addingTimeInterval(86400 * 30).timeIntervalSince1970
            ),
            SubscriptionInfo(
                url: "https://backup.example.com/sub",
                name: "Backup Provider",
                nodeCount: 12,
                isEnabled: false
            )
        ]
        return state
    }())
}
