import SwiftUI
import UniformTypeIdentifiers

struct ProxiesView: View {
    @Environment(AppState.self) private var appState
    @Environment(\.colorScheme) private var colorScheme
    @State private var showingAddNode = false
    @State private var isTesting = false

    // Subscription management
    @AppStorage(SettingsKey.subscriptionURL) private var subscriptionURL = ""
    @State private var isUpdatingSubscription = false
    @State private var subscriptionStatus: String?
    @State private var showSubscriptionBar = false
    @State private var showingFilePicker = false
    @State private var editingSubscriptionId: String?
    @State private var editingSubscriptionName = ""
    @State private var toastMessage: String?
    @State private var showAddInput = false
    @State private var showConfigEditor = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            headerRow
                .padding(.bottom, showSubscriptionBar ? 16 : 24)

            // Collapsible subscription panel
            if showSubscriptionBar {
                subscriptionPanel
                    .padding(.bottom, 16)
                    .transition(.opacity.combined(with: .move(edge: .top)))
            }

            // Toast hint (e.g. "需要先连接才能测速")
            if let toast = toastMessage {
                Text(toast)
                    .font(.system(size: 11, weight: .medium))
                    .foregroundStyle(.orange)
                    .padding(.bottom, 8)
                    .transition(.opacity)
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    ForEach(appState.proxyRegions) { region in
                        RegionGroupView(
                            region: region,
                            selectedNodeId: appState.selectedNodeId,
                            onToggleExpand: {
                                withAnimation(.easeInOut(duration: 0.25)) {
                                    appState.toggleRegion(region.id)
                                }
                            },
                            onSelectNode: { node in
                                withAnimation(.easeInOut(duration: 0.2)) {
                                    appState.selectNode(node.id)
                                }
                            }
                        )
                    }
                }
            }
            .scrollIndicators(.hidden)
        }
        .padding(.horizontal, 32)
        .padding(.vertical, 16)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .overlay {
            if showingAddNode {
                AddNodeSheet(isPresented: $showingAddNode) { node in
                    appState.addNode(node)
                }
                .transition(.opacity)
            }
        }
        .sheet(isPresented: $showConfigEditor) {
            ConfigEditorSheet()
        }
    }

    // MARK: - Header

    private var headerRow: some View {
        HStack(alignment: .center) {
            HStack(spacing: 12) {
                Text("Proxies")
                    .font(.system(size: 24, weight: .semibold))
                    .foregroundStyle(.primary)

                // Subscriptions toggle
                Button {
                    withAnimation(.easeInOut(duration: 0.25)) {
                        showSubscriptionBar.toggle()
                    }
                } label: {
                    HStack(spacing: 5) {
                        Image(systemName: "antenna.radiowaves.left.and.right")
                            .font(.system(size: 11))
                        Text("Subs")
                            .font(.system(size: 12, weight: .semibold))
                    }
                    .foregroundStyle(.white)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 6)
                    .background(
                        Color(hex: showSubscriptionBar ? "3A5AE0" : "4B6EFF"),
                        in: Capsule()
                    )
                    .shadow(color: Color(hex: "4B6EFF").opacity(0.3), radius: 4, y: 2)
                }
                .buttonStyle(.plain)
                .fixedSize()
            }

            Spacer()

            HStack(spacing: 10) {
                Button {
                    withAnimation(.easeOut(duration: 0.25)) {
                        showingAddNode = true
                    }
                } label: {
                    HStack(spacing: 5) {
                        Image(systemName: "plus")
                            .font(.system(size: 11, weight: .bold))
                        Text("Add Node")
                            .font(.system(size: 12, weight: .semibold))
                    }
                    .foregroundStyle(.white)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 8)
                    .background(
                        LinearGradient(
                            colors: [Color(hex: "FF6E52"), Color(hex: "C34AC2")],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        ),
                        in: Capsule()
                    )
                }
                .buttonStyle(.plain)
                .fixedSize()
                .shadow(color: Color(hex: "FF6E52").opacity(0.25), radius: 8, y: 3)

                Button {
                    guard !isTesting else { return }
                    guard appState.isConnected else {
                        withAnimation { toastMessage = String(localized: "Connect first to test latency") }
                        Task {
                            try? await Task.sleep(for: .seconds(3))
                            await MainActor.run { withAnimation { toastMessage = nil } }
                        }
                        return
                    }
                    isTesting = true
                    Task {
                        await appState.testAllLatency()
                        isTesting = false
                    }
                } label: {
                    HStack(spacing: 5) {
                        if isTesting {
                            ProgressView()
                                .controlSize(.mini)
                        } else {
                            Image(systemName: "bolt.fill")
                                .font(.system(size: 11))
                        }
                        Text("Test All")
                            .font(.system(size: 12, weight: .semibold))
                    }
                    .foregroundStyle(Color(hex: "4B6EFF"))
                    .padding(.horizontal, 16)
                    .padding(.vertical, 8)
                }
                .buttonStyle(.plain)
                .fixedSize()
                .glassEffect(
                    .regular.tint(.white.opacity(0.08)),
                    in: Capsule()
                )
            }
        }
    }

    // MARK: - Subscription Panel

    private var subscriptionPanel: some View {
        VStack(alignment: .leading, spacing: 12) {
            // Header: title + Update All
            HStack {
                Text("Subscriptions")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(.primary)

                Text("\(appState.subscriptions.count) sources")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)

                Spacer()

                if !appState.subscriptions.isEmpty {
                    Button {
                        updateAllSubscriptions()
                    } label: {
                        if isUpdatingSubscription {
                            ProgressView()
                                .controlSize(.mini)
                        } else {
                            HStack(spacing: 4) {
                                Image(systemName: "arrow.clockwise")
                                    .font(.system(size: 10, weight: .semibold))
                                Text("Update All")
                                    .font(.system(size: 11, weight: .medium))
                            }
                            .foregroundStyle(Color(hex: "4B6EFF"))
                        }
                    }
                    .buttonStyle(.plain)
                    .disabled(isUpdatingSubscription)
                }
            }

            // Existing subscriptions list
            ForEach(appState.subscriptions) { sub in
                VStack(alignment: .leading, spacing: 6) {
                    HStack(spacing: 8) {
                        Circle()
                            .fill(sub.nodeCount > 0 ? Color(hex: "30D158") : Color(hex: "FF3B30"))
                            .frame(width: 6, height: 6)
                        VStack(alignment: .leading, spacing: 1) {
                            if editingSubscriptionId == sub.id {
                                TextField("Name", text: $editingSubscriptionName, onCommit: {
                                    appState.renameSubscription(sub.id, name: editingSubscriptionName)
                                    editingSubscriptionId = nil
                                })
                                .textFieldStyle(.plain)
                                .font(.system(size: 12, weight: .medium))
                                .onExitCommand { editingSubscriptionId = nil }
                            } else {
                                Text(sub.name)
                                    .font(.system(size: 12, weight: .medium))
                                    .foregroundStyle(.primary)
                                    .onTapGesture {
                                        editingSubscriptionId = sub.id
                                        editingSubscriptionName = sub.name
                                    }
                            }
                            Text("\(sub.nodeCount) nodes")
                                .font(.system(size: 10))
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button {
                            showConfigEditor = true
                        } label: {
                            Image(systemName: "doc.text")
                                .font(.system(size: 10))
                                .foregroundStyle(.secondary)
                        }
                        .buttonStyle(.plain)
                        .help("Edit config file")

                        Button {
                            appState.removeSubscription(sub.id)
                        } label: {
                            Image(systemName: "xmark")
                                .font(.system(size: 9, weight: .semibold))
                                .foregroundStyle(.secondary)
                        }
                        .buttonStyle(.plain)
                    }

                    // Traffic usage bar
                    if let total = sub.total, total > 0 {
                        VStack(alignment: .leading, spacing: 3) {
                            GeometryReader { geo in
                                ZStack(alignment: .leading) {
                                    Capsule()
                                        .fill(Color.primary.opacity(0.08))
                                    Capsule()
                                        .fill(sub.usageRatio > 0.9 ? Color(hex: "FF3B30") :
                                              sub.usageRatio > 0.7 ? Color(hex: "FF9F0A") :
                                              Color(hex: "4B6EFF"))
                                        .frame(width: geo.size.width * min(sub.usageRatio, 1.0))
                                }
                            }
                            .frame(height: 4)

                            HStack {
                                Text("\(Self.formatBytes(sub.usedBytes)) / \(Self.formatBytes(total))")
                                    .font(.system(size: 9, design: .monospaced))
                                    .foregroundStyle(.secondary)
                                Spacer()
                                if let expiry = sub.expiryDate {
                                    Text(expiry, style: .date)
                                        .font(.system(size: 9))
                                        .foregroundStyle(expiry < Date() ? Color(hex: "FF3B30") : .secondary)
                                }
                            }
                        }
                        .padding(.leading, 14)
                    }
                }
                .padding(8)
                .background(.white.opacity(colorScheme == .dark ? 0.06 : 0.3), in: RoundedRectangle(cornerRadius: 8))
            }

            // Clear all nodes button (visible when nodes exist)
            if !appState.proxyRegions.isEmpty {
                Button {
                    appState.clearAllNodes()
                    subscriptionStatus = nil
                } label: {
                    HStack(spacing: 4) {
                        Image(systemName: "trash")
                            .font(.system(size: 10))
                        Text("Clear All Nodes")
                            .font(.system(size: 11, weight: .medium))
                    }
                    .foregroundStyle(.red.opacity(0.8))
                }
                .buttonStyle(.plain)
            }

            // Add new subscription — show input directly when empty, otherwise toggle
            if appState.subscriptions.isEmpty || showAddInput {
                HStack(spacing: 8) {
                    TextField("Subscription URL", text: $subscriptionURL)
                        .textFieldStyle(.plain)
                        .font(.system(size: 12))
                        .padding(8)
                        .frame(maxWidth: .infinity)
                        .background(.white.opacity(colorScheme == .dark ? 0.08 : 0.4), in: RoundedRectangle(cornerRadius: 10))
                        .overlay(
                            RoundedRectangle(cornerRadius: 10)
                                .strokeBorder(.white.opacity(colorScheme == .dark ? 0.08 : 0.4), lineWidth: 0.5)
                        )

                    Button {
                        addAndUpdateSubscription()
                    } label: {
                        if isUpdatingSubscription {
                            ProgressView()
                                .controlSize(.small)
                                .padding(.horizontal, 14)
                                .padding(.vertical, 6)
                        } else {
                            Text("Add")
                                .font(.system(size: 12, weight: .semibold))
                                .foregroundStyle(.white)
                                .padding(.horizontal, 18)
                                .padding(.vertical, 8)
                                .background(
                                    LinearGradient(
                                        colors: [Color(hex: "4B6EFF"), Color(hex: "6B8CFF")],
                                        startPoint: .topLeading,
                                        endPoint: .bottomTrailing
                                    ),
                                    in: Capsule()
                                )
                                .shadow(color: Color(hex: "4B6EFF").opacity(0.4), radius: 6, y: 2)
                        }
                    }
                    .buttonStyle(.plain)
                    .disabled(subscriptionURL.isEmpty || isUpdatingSubscription)

                    // File import button
                    Button {
                        showingFilePicker = true
                    } label: {
                        Image(systemName: "doc.badge.plus")
                            .font(.system(size: 12, weight: .medium))
                            .foregroundStyle(Color(hex: "4B6EFF"))
                            .padding(8)
                    }
                    .buttonStyle(.plain)
                    .help("Import YAML config from file")
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
                .transition(.opacity.combined(with: .move(edge: .top)))

                // Import from Clash Verge button
                if Self.clashVergeProfilesExist {
                    Button {
                        importFromClashVerge()
                    } label: {
                        HStack(spacing: 5) {
                            Image(systemName: "arrow.down.circle")
                                .font(.system(size: 11))
                            Text("Import from Clash Verge")
                                .font(.system(size: 11, weight: .medium))
                        }
                        .foregroundStyle(Color(hex: "4B6EFF"))
                    }
                    .buttonStyle(.plain)
                    .disabled(isUpdatingSubscription)
                }
            } else {
                // Compact "Add" button when subscriptions already exist
                Button {
                    withAnimation(.easeInOut(duration: 0.2)) {
                        showAddInput = true
                    }
                } label: {
                    HStack(spacing: 5) {
                        Image(systemName: "plus")
                            .font(.system(size: 10, weight: .bold))
                        Text("Add Subscription")
                            .font(.system(size: 11, weight: .medium))
                    }
                    .foregroundStyle(Color(hex: "4B6EFF"))
                }
                .buttonStyle(.plain)
            }

            // Status message
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

    // MARK: - Subscription Actions

    private func addAndUpdateSubscription() {
        guard !subscriptionURL.isEmpty else { return }
        isUpdatingSubscription = true
        subscriptionStatus = nil

        appState.addSubscription(url: subscriptionURL, name: "")

        Task {
            do {
                try await appState.updateAllSubscriptions()
                await MainActor.run {
                    isUpdatingSubscription = false
                    subscriptionStatus = String(localized: "✓ Updated \(appState.totalNodes) nodes")
                    subscriptionURL = ""
                    withAnimation(.easeInOut(duration: 0.2)) { showAddInput = false }
                }
            } catch {
                await MainActor.run {
                    isUpdatingSubscription = false
                    subscriptionStatus = error.localizedDescription
                }
            }
        }
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

                // Parse rules from YAML
                let parsedRules = content.contains("rules:") ? ConfigParser.parseClashYAMLRules(content) : []

                await MainActor.run {
                    appState.proxyRegions = regions
                    appState.selectedNodeId = regions.first?.nodes.first?.id
                    appState.activeNode = regions.first?.nodes.first
                    if !parsedRules.isEmpty { appState.rules = parsedRules }
                    appState.saveState()
                    ConfigStorage.shared.saveProxyRegions(regions)
                    ConfigStorage.shared.saveRawSubscriptionYAML(content)
                    isUpdatingSubscription = false
                    subscriptionStatus = String(localized: "✓ Imported \(nodes.count) nodes")
                }
            } catch {
                await MainActor.run {
                    isUpdatingSubscription = false
                    subscriptionStatus = error.localizedDescription
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

                // Parse rules from YAML
                let parsedRules = content.contains("rules:") ? ConfigParser.parseClashYAMLRules(content) : []

                await MainActor.run {
                    appState.proxyRegions = regions
                    appState.selectedNodeId = regions.first?.nodes.first?.id
                    appState.activeNode = regions.first?.nodes.first
                    if !parsedRules.isEmpty { appState.rules = parsedRules }
                    appState.saveState()
                    ConfigStorage.shared.saveProxyRegions(regions)
                    ConfigStorage.shared.saveRawSubscriptionYAML(content)
                    isUpdatingSubscription = false
                    subscriptionStatus = String(localized: "✓ Imported \(nodes.count) nodes from Clash Verge")
                }
            } catch {
                await MainActor.run {
                    isUpdatingSubscription = false
                    subscriptionStatus = error.localizedDescription
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

        // Find the most recently modified YAML file
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

    private static func formatBytes(_ bytes: Int64) -> String {
        let gb = Double(bytes) / 1_073_741_824
        if gb >= 1 { return String(format: "%.1f GB", gb) }
        let mb = Double(bytes) / 1_048_576
        if mb >= 1 { return String(format: "%.0f MB", mb) }
        return String(format: "%.0f KB", Double(bytes) / 1024)
    }

    private func updateAllSubscriptions() {
        isUpdatingSubscription = true
        subscriptionStatus = nil

        Task {
            do {
                try await appState.updateAllSubscriptions()
                await MainActor.run {
                    isUpdatingSubscription = false
                    subscriptionStatus = String(localized: "✓ Updated \(appState.totalNodes) nodes")
                }
            } catch {
                await MainActor.run {
                    isUpdatingSubscription = false
                    subscriptionStatus = error.localizedDescription
                }
            }
        }
    }
}

#Preview {
    ZStack {
        MeshGradientBackground()
        ProxiesView()
    }
    .frame(width: 700, height: 600)
    .environment({
        let state = AppState()
        state.loadMockData()
        return state
    }())
}
