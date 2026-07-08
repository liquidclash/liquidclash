import SwiftUI

struct ProxiesView: View {
    @Environment(AppState.self) private var appState
    @Environment(\.colorScheme) private var colorScheme
    @State private var showingAddNode = false
    @State private var editingNode: ProxyNode?
    @State private var isTesting = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            headerRow
                .padding(.bottom, 16)

            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    if !proxyGroups.isEmpty {
                        proxyGroupsSection(proxyGroups)
                    }

                    nodesSection

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
    }

    // MARK: - Proxy Groups (from mihomo API)

    private let groupIcons: [String: String] = [
        "YouTube": "play.rectangle.fill", "Netflix": "film.fill", "Disney": "sparkles",
        "Spotify": "music.note", "Telegram": "paperplane.fill", "Google": "magnifyingglass",
        "OpenAI": "brain.head.profile.fill", "Apple": "apple.logo", "Microsoft": "desktopcomputer",
        "Steam": "gamecontroller.fill", "HK": "globe.asia.australia.fill", "JP": "globe.asia.australia.fill",
        "SG": "globe.asia.australia.fill", "TW": "globe.asia.australia.fill", "US": "globe.americas.fill",
        "PROXY": "switch.2", "Proxies": "switch.2", "Auto Select": "bolt.fill",
        "Fallback": "arrow.triangle.2.circlepath", "GLOBAL": "globe",
    ]

    private var proxyGroups: [ProxyService.MihomoGroup] {
        if !appState.proxyService.groups.isEmpty {
            return appState.proxyService.groups
        }
        return localProxyGroups
    }

    private var localProxyGroups: [ProxyService.MihomoGroup] {
        guard let yaml = ConfigStorage.shared.loadSubscriptionYAML() else { return [] }
        return ConfigParser.parseClashYAMLProxyGroups(yaml).map { group in
            ProxyService.MihomoGroup(
                id: group.name,
                name: group.name,
                type: runtimeGroupType(from: group.type),
                now: group.proxies.first,
                all: group.proxies,
                latency: 0
            )
        }
    }

    private var groupOnlyNames: Set<String> {
        var names = Set(proxyGroups.map(\.name))
        names.formUnion(["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"])
        return names
    }

    @State private var expandedSections: Set<String> = []

    private func proxyGroupsSection(_ groups: [ProxyService.MihomoGroup]) -> some View {
        let title = "proxy-groups"
        let maxVisible = 9
        let isExpanded = expandedSections.contains(title)
        let visibleGroups = isExpanded ? groups : Array(groups.prefix(maxVisible))

        return VStack(alignment: .leading, spacing: 8) {
            sectionTitle("Proxy Groups", count: groups.count)

            let columns = [GridItem(.flexible(), spacing: 8), GridItem(.flexible(), spacing: 8), GridItem(.flexible(), spacing: 8)]
            LazyVGrid(columns: columns, spacing: 8) {
                ForEach(visibleGroups) { group in
                    let icon = groupIcons[group.name] ?? groupIcon(for: group)
                    let target = groupTarget(for: group)
                    let isActive = group.name == appState.proxyService.activeGroupName
                        || group.name == appState.proxyService.activeNodeName
                    Button {
                        withAnimation(.easeInOut(duration: 0.2)) {
                            appState.selectNode(group.name)
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
                        .contentShape(RoundedRectangle(cornerRadius: 8))
                    }
                    .buttonStyle(.plain)
                }
            }

            if groups.count > maxVisible {
                Button {
                    withAnimation(.easeInOut(duration: 0.2)) {
                        if isExpanded {
                            expandedSections.remove(title)
                        } else {
                            expandedSections.insert(title)
                        }
                    }
                } label: {
                    HStack(spacing: 4) {
                        Text(isExpanded ? String(localized: "Collapse") : moreText(groups.count - maxVisible))
                            .font(.system(size: 11, weight: .medium))
                        Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                            .font(.system(size: 9, weight: .semibold))
                    }
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 5)
                    .contentShape(Capsule())
                }
                .buttonStyle(.plain)
            }
        }
    }

    // MARK: - Nodes Section (flat list from mihomo API)

    private var nodesSection: some View {
        let mihomoNodes = appState.proxyService.nodes.filter { !isGroupOnlyName($0.name) }
        let localNodes = appState.proxyRegions.filter { $0.id != "custom" }
            .flatMap(\.nodes)
            .filter { !isGroupOnlyName($0.name) }
        let hasNodes = !mihomoNodes.isEmpty || !localNodes.isEmpty

        return Group {
            if hasNodes {
                VStack(alignment: .leading, spacing: 8) {
                    sectionTitle("Nodes", count: mihomoNodes.isEmpty ? localNodes.count : mihomoNodes.count)

                    let columns = [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)]
                    LazyVGrid(columns: columns, spacing: 12) {
                        if !mihomoNodes.isEmpty {
                            ForEach(mihomoNodes) { node in
                                nodeCard(node)
                            }
                        } else {
                            ForEach(localNodes) { node in
                                localNodeCard(node)
                            }
                        }
                    }
                }
            }
        }
    }

    private func localNodeCard(_ node: ProxyNode) -> some View {
        let isActive = appState.selectedNodeId == node.id || appState.selectedNodeId == node.name
        return Button {
            withAnimation(.easeInOut(duration: 0.2)) {
                appState.selectNode(node.name)
            }
        } label: {
            HStack(spacing: 8) {
                Text(node.flag)
                    .font(.system(size: 14))
                VStack(alignment: .leading, spacing: 2) {
                    Text(node.name)
                        .font(.system(size: 12, weight: .medium))
                        .foregroundStyle(.primary)
                        .lineLimit(1)
                    Text(node.type.rawValue)
                        .font(.system(size: 10))
                        .foregroundStyle(.tertiary)
                }
                Spacer(minLength: 0)
            }
            .padding(10)
            .background(
                isActive ? Color.accentColor.opacity(0.15) : .white.opacity(colorScheme == .dark ? 0.06 : 0.7),
                in: RoundedRectangle(cornerRadius: 12)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 12)
                    .stroke(isActive ? Color.accentColor.opacity(0.5) : .white.opacity(colorScheme == .dark ? 0.12 : 0.7), lineWidth: 0.5)
            )
            .contentShape(RoundedRectangle(cornerRadius: 12))
        }
        .buttonStyle(.plain)
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
                                        node.latency < 400 ? Color(hex: "FF9F0A") :
                                        Color(hex: "FF3B30"))
                } else if node.lastTestFailed {
                    Text("Timeout")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(Color(hex: "FF3B30").opacity(0.7))
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
            .contentShape(RoundedRectangle(cornerRadius: 10))
        }
        .buttonStyle(.plain)
    }

    private func sectionTitle(_ title: LocalizedStringKey, count: Int) -> some View {
        HStack(spacing: 6) {
            Text(title)
                .font(.system(size: 11, weight: .semibold))
                .kerning(1.0)
                .foregroundStyle(.secondary)

            Text("\(count)")
                .font(.system(size: 10, weight: .medium))
                .foregroundStyle(.tertiary)
        }
    }

    private func groupIcon(for group: ProxyService.MihomoGroup) -> String {
        switch group.type {
        case "Selector":
            return "square.grid.2x2.fill"
        case "URLTest":
            return "bolt.fill"
        case "Fallback":
            return "arrow.triangle.2.circlepath"
        case "LoadBalance":
            return "scalemass.fill"
        case "Relay":
            return "point.3.connected.trianglepath.dotted"
        default:
            return "folder.fill"
        }
    }

    private func groupTarget(for group: ProxyService.MihomoGroup) -> String {
        if let now = group.now, !now.isEmpty {
            return ConfigParser.extractFlag(from: now).cleanName
        }
        return groupTypeName(group.type)
    }

    private func groupTypeName(_ type: String) -> String {
        switch type {
        case "Selector":
            return String(localized: "Selector")
        case "URLTest":
            return String(localized: "URL Test")
        case "Fallback":
            return String(localized: "Fallback")
        case "LoadBalance":
            return String(localized: "Load Balance")
        case "Relay":
            return String(localized: "Relay")
        default:
            return type
        }
    }

    private func runtimeGroupType(from type: String) -> String {
        switch type.lowercased() {
        case "select", "selector":
            return "Selector"
        case "url-test", "urltest":
            return "URLTest"
        case "fallback":
            return "Fallback"
        case "load-balance", "loadbalance":
            return "LoadBalance"
        case "relay":
            return "Relay"
        default:
            return type
        }
    }

    private func isGroupOnlyName(_ name: String) -> Bool {
        let cleanName = ConfigParser.extractFlag(from: name).cleanName
        return groupOnlyNames.contains(name) || groupOnlyNames.contains(cleanName)
    }

    private func moreText(_ count: Int) -> String {
        String(format: String(localized: "%lld more"), Int64(count))
    }

    // MARK: - Header

    private var headerRow: some View {
        HStack(alignment: .center) {
            Text("Proxies")
                .font(.system(size: 24, weight: .semibold))
                .foregroundStyle(.primary)

            Spacer()

            HStack(spacing: 10) {
                GradientAddButton("Add Node") {
                    withAnimation(.easeOut(duration: 0.25)) {
                        showingAddNode = true
                    }
                }

                Button {
                    guard !isTesting else { return }
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
                    .foregroundStyle(.primary)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 8)
                    .contentShape(Capsule())
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
