import SwiftUI

struct RulesView: View {
    @State private var rules: [RuleItem] = mockRules
    @State private var showingAddRule = false

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
                .foregroundStyle(Color(hex: "A2A3C4"))
                .tracking(0.5)
                .padding(.horizontal, 20)
                .padding(.vertical, 14)
                .background(.white.opacity(0.15))

                Divider().opacity(0.3)

                // Rules list
                ScrollView {
                    VStack(spacing: 4) {
                        ForEach(rules) { rule in
                            ruleRow(rule)
                        }
                    }
                    .padding(8)
                }
                .scrollIndicators(.hidden)
            }
            .background(.white.opacity(0.4), in: RoundedRectangle(cornerRadius: 20))
            .overlay(
                RoundedRectangle(cornerRadius: 20)
                    .strokeBorder(.white.opacity(0.7), lineWidth: 1)
            )
        }
        .padding(.horizontal, 32)
        .padding(.vertical, 16)
        .padding(.bottom, 16)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .overlay {
            if showingAddRule {
                AddRuleSheet(isPresented: $showingAddRule) { newRule in
                    rules.append(newRule)
                }
                .transition(.opacity)
            }
        }
    }

    // MARK: - Header

    private var headerRow: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Rules Editor")
                    .font(.system(size: 24, weight: .semibold))
                    .foregroundStyle(Color(hex: "383A76"))

                Text("Define how traffic is routed based on hostname, IP, or geography.")
                    .font(.system(size: 13))
                    .foregroundStyle(Color(hex: "7A7B9F"))
            }

            Spacer()

            HStack(spacing: 10) {
                actionButton(icon: "square.and.arrow.down", label: "Import")
                actionButton(icon: "square.and.arrow.up", label: "Export")

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
                    .foregroundStyle(Color(hex: "383A76"))
                    .padding(.horizontal, 16)
                    .padding(.vertical, 8)
                    .background(.white, in: Capsule())
                }
                .buttonStyle(.plain)
                .fixedSize()
                .shadow(color: .black.opacity(0.04), radius: 6, y: 2)
            }
        }
    }

    // MARK: - Action Button

    private func actionButton(icon: String, label: String) -> some View {
        Button { } label: {
            HStack(spacing: 5) {
                Image(systemName: icon)
                    .font(.system(size: 12))
                Text(label)
                    .font(.system(size: 12, weight: .medium))
            }
            .foregroundStyle(Color(hex: "383A76"))
            .padding(.horizontal, 14)
            .padding(.vertical, 8)
            .background(.white.opacity(0.4), in: Capsule())
            .overlay(Capsule().strokeBorder(.white.opacity(0.7), lineWidth: 0.5))
        }
        .buttonStyle(.plain)
        .fixedSize()
    }

    // MARK: - Rule Row

    private func ruleRow(_ rule: RuleItem) -> some View {
        RuleRowView(rule: rule)
    }
}

// MARK: - Rule Row (独立 View 支持 hover)

private struct RuleRowView: View {
    let rule: RuleItem
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
            .foregroundStyle(Color(hex: "A2A3C4"))
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
                .foregroundStyle(Color(hex: "383A76"))
                .lineLimit(1)
                .frame(maxWidth: .infinity, alignment: .leading)

            // Policy
            HStack(spacing: 8) {
                Circle()
                    .fill(Color(hex: rule.policy.dotColor))
                    .frame(width: 8, height: 8)
                Text(rule.policy.rawValue)
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(Color(hex: "383A76"))
            }
            .frame(width: 150, alignment: .leading)

            // Delete action — hover 时显示
            Button { } label: {
                Image(systemName: "trash")
                    .font(.system(size: 13))
                    .foregroundStyle(Color(hex: "A2A3C4"))
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
        .background(isHovered ? .white.opacity(0.9) : .clear, in: RoundedRectangle(cornerRadius: 10))
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
}
