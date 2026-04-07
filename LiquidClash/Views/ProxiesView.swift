import SwiftUI
import UniformTypeIdentifiers

struct ProxiesView: View {
    @Environment(AppState.self) private var appState
    @Environment(\.colorScheme) private var colorScheme
    @State private var showingAddNode = false
    @State private var editingNode: ProxyNode?
    @State private var isTesting = false

    // Subscription management
    @AppStorage(SettingsKey.subscriptionURL) private var subscriptionURL = ""
    @State private var isUpdatingSubscription = false
    @State private var subscriptionStatus: String?
    @State private var showingFilePicker = false
    @State private var editingSubscriptionId: String?
    @State private var editingSubscriptionName = ""

    @State private var showAddInput = false
    @State private var showConfigEditor = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            headerRow
                .padding(.bottom, 16)

            // Subscription management panel — always visible
            subscriptionPanel
                .padding(.bottom, 16)

            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    // Service groups (YouTube, Netflix, etc.)
                    if !serviceGroups.isEmpty {
                        groupTagsSection("APP SERVICES", serviceGroups)
                    }

                    // Region groups (HK, JP, SG, etc.)
                    if !regionGroups.isEmpty {
                        groupTagsSection("REGIONS", regionGroups)
                    }

                    // Individual nodes from mihomo API
                    if !appState.proxyService.nodes.isEmpty {
                        nodesSection
                    }

                    // Legacy local regions (custom nodes)
                    ForEach(appState.proxyRegions.filter { $0.id == "custom" }) { region in
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
                            },
                            onDeleteNode: { node in
                                withAnimation(.easeInOut(duration: 0.2)) {
                                    appState.deleteNode(node.id)
                                }
                            },
                            onEditNode: { node in
                                editingNode = node
                                showingAddNode = true
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
        .onChange(of: showingAddNode) { _, showing in
            if !showing { editingNode = nil }
        }
        .overlay {
            if showingAddNode {
                AddNodeSheet(isPresented: $showingAddNode, onAdd: { node in
                    if editingNode != nil {
                        appState.updateNode(node)
                    } else {
                        appState.addNode(node)
                    }
                }, editingNode: editingNode)
                .transition(.opacity)
            }
        }
        .sheet(isPresented: $showConfigEditor) {
            ConfigEditorSheet()
        }
    }

    // MARK: - Proxy Groups (from mihomo API, split by service/region)

    private let regionGroupNames: Set<String> = [
        "HK", "JP", "SG", "TW", "US", "UK", "KR", "DE", "FR", "CA", "AU", "IN", "RU", "BR", "NL",
        "Auto Select", "PROXY", "Proxies", "Fallback", "GLOBAL",
    ]

    private let serviceIcons: [String: String] = [
        "YouTube": "play.rectangle.fill", "Netflix": "film.fill", "Disney": "sparkles",
        "Spotify": "music.note", "Telegram": "paperplane.fill", "Google": "magnifyingglass",
        "OpenAI": "brain.head.profile.fill", "Apple": "apple.logo", "Microsoft": "desktopcomputer",
        "Steam": "gamecontroller.fill", "HK": "globe.asia.australia.fill", "JP": "globe.asia.australia.fill",
        "SG": "globe.asia.australia.fill", "TW": "globe.asia.australia.fill", "US": "globe.americas.fill",
    ]

    private var serviceGroups: [ProxyService.MihomoGroup] {
        appState.proxyService.groups.filter { !regionGroupNames.contains($0.name) }
    }

    private var regionGroups: [ProxyService.MihomoGroup] {
        appState.proxyService.groups.filter {
            regionGroupNames.contains($0.name) && $0.name != "GLOBAL"
        }
    }

    private func groupTagsSection(_ title: String, _ groups: [ProxyService.MihomoGroup]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.system(size: 11, weight: .semibold))
                .kerning(1.0)
                .foregroundStyle(.secondary)

            let columns = [GridItem(.flexible(), spacing: 8), GridItem(.flexible(), spacing: 8), GridItem(.flexible(), spacing: 8)]
            LazyVGrid(columns: columns, spacing: 8) {
                ForEach(groups) { group in
                    let icon = serviceIcons[group.name] ?? (group.isSelector ? "square.grid.2x2.fill" : "bolt.fill")
                    let target = group.now ?? (group.isSelector ? "Select" : "Auto")
                    let isActive = group.name == appState.proxyService.activeGroupName
                                || group.name == appState.proxyService.activeNodeName
                    Button {
                        if let now = group.now {
                            withAnimation(.easeInOut(duration: 0.2)) {
                                appState.selectNode(now)
                            }
                        }
                    } label: {
                        HStack(spacing: 6) {
                            Image(systemName: icon)
                                .font(.system(size: 11))
                                .foregroundStyle(.secondary)
                                .frame(width: 16)
                            Text(group.name)
                                .font(.system(size: 12, weight: .medium))
                                .foregroundStyle(.primary)
                                .lineLimit(1)
                            Spacer(minLength: 0)
                            Text(target)
                                .font(.system(size: 10))
                                .foregroundStyle(.tertiary)
                                .lineLimit(1)
                        }
                        .padding(.horizontal, 10)
                        .padding(.vertical, 7)
                        .background(.white.opacity(isActive ? 0.7 : 0.35),
                                    in: RoundedRectangle(cornerRadius: 8))
                        .overlay(
                            RoundedRectangle(cornerRadius: 8)
                                .strokeBorder(
                                    isActive
                                        ? Color(hex: "4B6EFF").opacity(0.5)
                                        : .white.opacity(colorScheme == .dark ? 0.1 : 0.5),
                                    lineWidth: 0.5
                                )
                        )
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    // MARK: - Nodes Section (flat list from mihomo API)

    private var nodesSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("NODES")
                .font(.system(size: 11, weight: .semibold))
                .kerning(1.0)
                .foregroundStyle(.secondary)

            let columns = [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)]
            LazyVGrid(columns: columns, spacing: 12) {
                ForEach(appState.proxyService.nodes) { node in
                    nodeCard(node)
                }
            }
        }
    }

    private func nodeCard(_ node: ProxyService.MihomoNode) -> some View {
        let isActive = appState.proxyService.activeNodeName == node.name
        return Button {
            withAnimation(.easeInOut(duration: 0.2)) {
                appState.selectNode(node.name)
            }
        } label: {
            HStack(spacing: 8) {
                Text(node.flag)
                    .font(.system(size: 14))
                VStack(alignment: .leading, spacing: 2) {
                    Text(ConfigParser.extractFlag(from: node.name).cleanName)
                        .font(.system(size: 12, weight: .medium))
                        .foregroundStyle(.primary)
                        .lineLimit(1)
                    Text(node.type)
                        .font(.system(size: 10))
                        .foregroundStyle(.tertiary)
                }
                Spacer(minLength: 0)
                if node.latency > 0 {
                    Text("\(node.latency)ms")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(node.latency < 200 ? Color(hex: "30D158") :
                                        node.latency < 500 ? Color(hex: "FF9F0A") :
                                        Color(hex: "FF3B30"))
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
            .background(.white.opacity(isActive ? 0.7 : 0.35),
                        in: RoundedRectangle(cornerRadius: 10))
            .overlay(
                RoundedRectangle(cornerRadius: 10)
                    .strokeBorder(
                        isActive
                            ? Color(hex: "4B6EFF").opacity(0.5)
                            : .white.opacity(colorScheme == .dark ? 0.1 : 0.5),
                        lineWidth: 0.5
                    )
            )
        }
        .buttonStyle(.plain)
    }

    // MARK: - Header

    private var headerRow: some View {
        HStack(alignment: .center) {
            Text("Proxies")
                .font(.system(size: 24, weight: .semibold))
                .foregroundStyle(.primary)

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
                    isTesting = true
                    Task {
                        await appState.proxyService.testAllLatency()
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
                    let rulesCount = appState.rules.count
                    let msg = rulesCount > 0
                        ? String(localized: "✓ \(appState.totalNodes) nodes, \(rulesCount) rules")
                        : String(localized: "✓ \(appState.totalNodes) nodes (no rules in subscription)")
                    showTemporaryStatus(msg)
                    subscriptionURL = ""
                    withAnimation(.easeInOut(duration: 0.2)) { showAddInput = false }
                }
            } catch {
                await MainActor.run {
                    isUpdatingSubscription = false
                    showTemporaryStatus(error.localizedDescription)
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

                // Parse rules from YAML — merge with user rules
                let parsedRules = content.contains("rules:") ? ConfigParser.parseClashYAMLRules(content, source: .subscription) : []

                await MainActor.run {
                    appState.proxyRegions = regions
                    appState.selectedNodeId = regions.first?.nodes.first?.id
                    appState.activeNode = regions.first?.nodes.first
                    if !parsedRules.isEmpty {
                        let userRules = appState.rules.filter { $0.source == .user }
                        appState.rules = userRules + parsedRules
                    }
                    appState.saveState()
                    ConfigStorage.shared.saveProxyRegions(regions)
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

                // Parse rules from YAML — merge with user rules
                let parsedRules = content.contains("rules:") ? ConfigParser.parseClashYAMLRules(content, source: .subscription) : []

                await MainActor.run {
                    appState.proxyRegions = regions
                    appState.selectedNodeId = regions.first?.nodes.first?.id
                    appState.activeNode = regions.first?.nodes.first
                    if !parsedRules.isEmpty {
                        let userRules = appState.rules.filter { $0.source == .user }
                        appState.rules = userRules + parsedRules
                    }
                    appState.saveState()
                    ConfigStorage.shared.saveProxyRegions(regions)
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
                    let rulesCount = appState.rules.count
                    let msg = rulesCount > 0
                        ? String(localized: "✓ \(appState.totalNodes) nodes, \(rulesCount) rules")
                        : String(localized: "✓ \(appState.totalNodes) nodes")
                    showTemporaryStatus(msg)
                }
            } catch {
                await MainActor.run {
                    isUpdatingSubscription = false
                    showTemporaryStatus(error.localizedDescription)
                }
            }
        }
    }

    private func showTemporaryStatus(_ message: String) {
        withAnimation { subscriptionStatus = message }
        Task {
            try? await Task.sleep(for: .seconds(3))
            await MainActor.run { withAnimation { subscriptionStatus = nil } }
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
