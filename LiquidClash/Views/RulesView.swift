import SwiftUI
import UniformTypeIdentifiers

struct RulesView: View {
    @Environment(AppState.self) private var appState
    @Environment(\.colorScheme) private var colorScheme
    @State private var showingAddRule = false
    @State private var showingImporter = false
    @State private var showingExporter = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            headerRow
                .padding(.bottom, 24)

            // Rules table container
            VStack(spacing: 0) {
                // Table header
                HStack(spacing: 0) {
                    Text("")
                        .frame(width: 40)
                    Text("TYPE")
                        .frame(width: 150, alignment: .leading)
                    Text("VALUE")
                        .frame(maxWidth: .infinity, alignment: .leading)
                    Text("TARGET POLICY")
                        .frame(width: 150, alignment: .leading)
                    Text("")
                        .frame(width: 60)
                }
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(.secondary)
                .tracking(0.5)
                .padding(.horizontal, 20)
                .padding(.vertical, 14)
                .background(.white.opacity(colorScheme == .dark ? 0.08 : 0.15))

                Divider().opacity(0.3)

                // Rules list
                if appState.rules.isEmpty {
                    VStack(spacing: 8) {
                        Spacer()
                        Text("No rules loaded")
                            .font(.system(size: 14))
                            .foregroundStyle(.secondary)
                        Text("Import a subscription to load rules")
                            .font(.system(size: 12))
                            .foregroundStyle(.tertiary)
                        Spacer()
                    }
                    .frame(maxWidth: .infinity)
                } else {
                    ScrollView {
                        LazyVStack(spacing: 4) {
                            ForEach(appState.rules) { rule in
                                ruleRow(rule)
                            }
                        }
                        .padding(8)
                    }
                    .scrollIndicators(.hidden)
                }
            }
            .background(.white.opacity(colorScheme == .dark ? 0.08 : 0.4), in: RoundedRectangle(cornerRadius: 20))
            .overlay(
                RoundedRectangle(cornerRadius: 20)
                    .strokeBorder(.white.opacity(colorScheme == .dark ? 0.12 : 0.7), lineWidth: 0.5)
            )
        }
        .padding(.horizontal, 32)
        .padding(.vertical, 16)
        .padding(.bottom, 16)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .overlay {
            if showingAddRule {
                AddRuleSheet(isPresented: $showingAddRule) { newRule in
                    appState.addRule(newRule)
                }
                .transition(.opacity)
            }
        }
    }

    // MARK: - Header

    private var headerRow: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Text("Rules Editor")
                        .font(.system(size: 24, weight: .semibold))
                        .foregroundStyle(.primary)

                    if !appState.rules.isEmpty {
                        Text("\(appState.rules.count)")
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundStyle(.secondary)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 3)
                            .background(.secondary.opacity(0.12), in: Capsule())
                    }
                }


            }

            Spacer()

            HStack(spacing: 10) {
                Button {
                    importRules()
                } label: {
                    HStack(spacing: 5) {
                        Image(systemName: "square.and.arrow.down")
                            .font(.system(size: 11))
                        Text("Import")
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

                Button {
                    exportRules()
                } label: {
                    HStack(spacing: 5) {
                        Image(systemName: "square.and.arrow.up")
                            .font(.system(size: 11))
                        Text("Export")
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

                Button {
                    withAnimation(.easeOut(duration: 0.25)) {
                        showingAddRule = true
                    }
                } label: {
                    HStack(spacing: 5) {
                        Image(systemName: "plus")
                            .font(.system(size: 11, weight: .bold))
                        Text("Add Rule")
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
                .shadow(color: Color(hex: "FF6E52").opacity(0.25), radius: 8, y: 3)
                .fixedSize()
                .shadow(color: .black.opacity(0.04), radius: 6, y: 2)
            }
        }
    }

    // MARK: - Rule Row

    private func ruleRow(_ rule: RuleItem) -> some View {
        RuleRowView(rule: rule) {
            appState.deleteRule(rule.id)
        }
    }

    // MARK: - Import / Export

    private func importRules() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.yaml, .plainText]
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false

        guard panel.runModal() == .OK, let url = panel.url else { return }

        if let content = try? String(contentsOf: url, encoding: .utf8) {
            let imported = ConfigParser.parseClashYAMLRules(content)
            if !imported.isEmpty {
                for rule in imported {
                    appState.addRule(rule)
                }
            }
        }
    }

    private func exportRules() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.plainText]
        panel.nameFieldStringValue = "rules.txt"

        guard panel.runModal() == .OK, let url = panel.url else { return }

        let content = "rules:\n" + appState.rules.map { "  - \($0.clashString)" }.joined(separator: "\n")
        try? content.write(to: url, atomically: true, encoding: .utf8)
    }
}

// MARK: - Rule Row (独立 View 支持 hover)

private struct RuleRowView: View {
    @Environment(\.colorScheme) private var colorScheme
    let rule: RuleItem
    var onDelete: () -> Void = {}
    @State private var isHovered = false

    var body: some View {
        HStack(spacing: 0) {
            // Drag handle — 6 dots (2×3)
            VStack(spacing: 3) {
                ForEach(0..<3, id: \.self) { _ in
                    HStack(spacing: 3) {
                        Circle().frame(width: 3, height: 3)
                        Circle().frame(width: 3, height: 3)
                    }
                }
            }
            .foregroundStyle(.secondary)
            .frame(width: 40)

            // Type badge
            Text(rule.type)
                .font(.system(size: 11, weight: .medium, design: .monospaced))
                .foregroundStyle(Color(hex: "C34AC2"))
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(Color(hex: "C34AC2").opacity(0.08), in: RoundedRectangle(cornerRadius: 6))
                .frame(width: 150, alignment: .leading)

            // Value
            Text(rule.value)
                .font(.system(size: 13, design: .monospaced))
                .foregroundStyle(.primary)
                .lineLimit(1)
                .frame(maxWidth: .infinity, alignment: .leading)

            // Policy
            HStack(spacing: 8) {
                Circle()
                    .fill(Color(hex: rule.policy.dotColor))
                    .frame(width: 8, height: 8)
                Text(rule.displayPolicy)
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
            }
            .frame(width: 150, alignment: .leading)

            // Delete action — hover 时显示
            Button { onDelete() } label: {
                Image(systemName: "trash")
                    .font(.system(size: 13))
                    .foregroundStyle(.secondary)
                    .frame(width: 32, height: 32)
                    .contentShape(Circle())
            }
            .buttonStyle(.plain)
            .opacity(isHovered ? 1 : 0)
            .frame(width: 60)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .contentShape(Rectangle())
        .background(
            isHovered
                ? .white.opacity(colorScheme == .dark ? 0.15 : 0.9)
                : .clear,
            in: RoundedRectangle(cornerRadius: 10)
        )
        .onHover { hovering in
            withAnimation(.easeInOut(duration: 0.15)) {
                isHovered = hovering
            }
        }
    }
}

#Preview {
    ZStack {
        MeshGradientBackground()
        RulesView()
    }
    .frame(width: 800, height: 600)
    .environment({
        let state = AppState()
        state.loadMockData()
        return state
    }())
}
