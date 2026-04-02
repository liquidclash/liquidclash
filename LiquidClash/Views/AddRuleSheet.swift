import SwiftUI

struct AddRuleSheet: View {
    @Binding var isPresented: Bool
    var onAdd: ((RuleItem) -> Void)?

    @State private var selectedType = "DOMAIN-SUFFIX"
    @State private var value = ""
    @State private var selectedPolicy = "Proxy"

    private let ruleTypes = [
        "DOMAIN-SUFFIX",
        "DOMAIN-KEYWORD",
        "DOMAIN",
        "IP-CIDR",
        "IP-CIDR6",
        "GEOIP",
        "MATCH"
    ]

    private let policies: [(value: String, label: String, color: String)] = [
        ("Proxy", "Proxy", "4B6EFF"),
        ("Direct", "Direct", "30D158"),
        ("Reject", "Reject", "FF6E52")
    ]

    var body: some View {
        ZStack {
            // Backdrop
            Color.black.opacity(0.2)
                .ignoresSafeArea()
                .onTapGesture { close() }

            // Modal card
            VStack(alignment: .leading, spacing: 0) {
                // Header
                HStack {
                    Text("Add Rule")
                        .font(.system(size: 20, weight: .semibold))
                        .foregroundStyle(.primary)

                    Spacer()

                    Button {
                        close()
                    } label: {
                        Image(systemName: "xmark")
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundStyle(.secondary)
                            .frame(width: 28, height: 28)
                    }
                    .buttonStyle(.plain)
                    .glassEffect(.regular.tint(.white.opacity(0.1)), in: Circle())
                }
                .padding(.bottom, 22)

                // Form fields
                VStack(alignment: .leading, spacing: 14) {
                    // Type + Policy
                    HStack(spacing: 14) {
                        formField(label: "Type") {
                            customPicker(selection: $selectedType, options: ruleTypes.map { ($0, $0) })
                        }

                        formField(label: "Target Policy") {
                            policyPicker
                        }
                        .frame(width: 150)
                    }

                    // Value
                    formField(label: "Value") {
                        glassInput {
                            TextField("e.g. google.com, 192.168.0.0/16, CN", text: $value)
                                .textFieldStyle(.plain)
                        }
                    }
                }

                // Footer
                Divider()
                    .opacity(0.3)
                    .padding(.top, 20)
                    .padding(.bottom, 16)

                HStack {
                    Spacer()

                    Button("Cancel") {
                        close()
                    }
                    .buttonStyle(.plain)
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 18)
                    .padding(.vertical, 9)
                    .glassEffect(.regular.tint(.white.opacity(0.06)), in: Capsule())

                    Button {
                        addRule()
                    } label: {
                        Text("Add Rule")
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundStyle(.white)
                            .padding(.horizontal, 20)
                            .padding(.vertical, 9)
                            .background(
                                LinearGradient(
                                    colors: [Color(hex: "4B6EFF"), Color(hex: "6B8CFF")],
                                    startPoint: .topLeading,
                                    endPoint: .bottomTrailing
                                ),
                                in: Capsule()
                            )
                    }
                    .buttonStyle(.plain)
                    .shadow(color: Color(hex: "4B6EFF").opacity(0.25), radius: 8, y: 3)
                }
            }
            .padding(28)
            .frame(width: 420)
            .fixedSize(horizontal: false, vertical: true)
            .glassEffect(.regular.tint(.white.opacity(0.15)), in: RoundedRectangle(cornerRadius: 20))
            .shadow(color: .black.opacity(0.12), radius: 30, y: 10)
            .opacity(isPresented ? 1 : 0)
        }
    }

    private func close() {
        withAnimation(.easeOut(duration: 0.2)) {
            isPresented = false
        }
    }

    private func addRule() {
        let policy: RulePolicy = switch selectedPolicy {
        case "Direct": .direct
        case "Reject": .reject
        default: .proxy
        }
        let newRule = RuleItem(
            id: "r\(UUID().uuidString.prefix(6))",
            type: selectedType,
            value: value,
            policy: policy
        )
        onAdd?(newRule)
        close()
    }

    // MARK: - Policy Picker with colored dots

    private var policyPicker: some View {
        Menu {
            ForEach(policies, id: \.value) { item in
                Button {
                    selectedPolicy = item.value
                } label: {
                    if selectedPolicy == item.value {
                        Label(item.label, systemImage: "checkmark")
                    } else {
                        Text(item.label)
                    }
                }
            }
        } label: {
            HStack(spacing: 8) {
                Circle()
                    .fill(Color(hex: policies.first(where: { $0.value == selectedPolicy })?.color ?? "4B6EFF"))
                    .frame(width: 8, height: 8)
                Text(selectedPolicy)
                    .font(.system(size: 13))
                    .foregroundStyle(.primary)
                Spacer()
                Image(systemName: "chevron.down")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(.secondary)
            }
            .padding(10)
            .background(.white.opacity(0.35), in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(.white.opacity(0.5), lineWidth: 0.5))
        }
        .buttonStyle(.plain)
    }

    // MARK: - Glass Input Container

    private func glassInput<Content: View>(@ViewBuilder content: () -> Content) -> some View {
        HStack {
            content()
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.white.opacity(0.35), in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(.white.opacity(0.5), lineWidth: 0.5))
    }

    // MARK: - Custom Picker

    private func customPicker(selection: Binding<String>, options: [(String, String)]) -> some View {
        Menu {
            ForEach(Array(options.enumerated()), id: \.offset) { _, item in
                Button {
                    selection.wrappedValue = item.0
                } label: {
                    if selection.wrappedValue == item.0 {
                        Label(item.1, systemImage: "checkmark")
                    } else {
                        Text(item.1)
                    }
                }
            }
        } label: {
            HStack {
                Text(options.first(where: { $0.0 == selection.wrappedValue })?.1 ?? "")
                    .font(.system(size: 13))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                Spacer()
                Image(systemName: "chevron.down")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(.secondary)
            }
            .padding(10)
            .background(.white.opacity(0.35), in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(.white.opacity(0.5), lineWidth: 0.5))
        }
        .buttonStyle(.plain)
    }

    // MARK: - Form Field

    @ViewBuilder
    private func formField<Content: View>(label: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(LocalizedStringKey(label))
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(Color(hex: "7A7B9F"))
            content()
        }
    }
}

#Preview {
    @Previewable @State var show = true
    ZStack {
        MeshGradientBackground()
        AddRuleSheet(isPresented: $show)
    }
    .frame(width: 600, height: 400)
}
