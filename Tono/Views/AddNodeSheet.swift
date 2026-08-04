import SwiftUI

struct AddNodeSheet: View {
    @Environment(AppState.self) private var appState
    @Binding var isPresented: Bool
    var onAdd: ((ProxyNode) -> Void)?
    var editingNode: ProxyNode?

    @State private var nodeName = ""
    @State private var port = "443"
    @State private var server = ""
    @State private var uuid = ""
    @State private var sni = ""
    @State private var enableUDP = true
    @State private var validationError: String?

    private var isEditing: Bool { editingNode != nil }

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
                    Text(isEditing ? "Edit Proxy Node" : "Add Proxy Node")
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
                            .contentShape(Circle())
                    }
                    .buttonStyle(.plain)
                    .glassEffect(.regular.tint(.white.opacity(0.1)), in: Circle())
                }
                .padding(.bottom, 22)

                // Form fields
                VStack(alignment: .leading, spacing: 14) {
                    // Node Name + Type
                    HStack(spacing: 14) {
                        formField(label: "Node Name") {
                            glassInput {
                                TextField("Node Name", text: $nodeName)
                                    .textFieldStyle(.plain)
                            }
                        }

                        formField(label: "Type") {
                            Text("VLESS + TLS")
                                .font(.system(size: 13, weight: .medium))
                                .frame(maxWidth: .infinity, minHeight: 34)
                        }
                        .frame(width: 140)
                    }

                    // Server + Port
                    HStack(spacing: 14) {
                        formField(label: "Server") {
                            glassInput {
                                TextField("Server Address", text: $server)
                                    .textFieldStyle(.plain)
                            }
                        }

                        formField(label: "Port") {
                            glassInput {
                                TextField("5001", text: $port)
                                    .textFieldStyle(.plain)
                            }
                        }
                        .frame(width: 100)
                    }

                    // VLESS identity + authenticated TLS name
                    HStack(spacing: 14) {
                        formField(label: "UUID") {
                            glassInput {
                                TextField("VLESS UUID", text: $uuid)
                                    .textFieldStyle(.plain)
                            }
                        }

                        formField(label: "SNI (optional)") {
                            glassInput {
                                TextField("TLS server name", text: $sni)
                                    .textFieldStyle(.plain)
                            }
                        }
                    }

                    formField(label: " ") {
                        Toggle("Carry UDP through VLESS", isOn: $enableUDP)
                            .toggleStyle(.checkbox)
                            .font(.system(size: 13, weight: .medium))
                            .foregroundStyle(.primary)
                            .frame(maxWidth: .infinity, minHeight: 34, alignment: .leading)
                    }
                }

                if let error = validationError {
                    Text(error)
                        .font(.system(size: 11))
                        .foregroundStyle(.red)
                        .padding(.top, 4)
                }

                // Footer
                Divider()
                    .opacity(0.3)
                    .padding(.top, 20)
                    .padding(.bottom, 16)

                HStack {
                    Spacer()

                    Button {
                        close()
                    } label: {
                        Text("Cancel")
                            .font(.system(size: 13, weight: .medium))
                            .foregroundStyle(.secondary)
                            .padding(.horizontal, 18)
                            .padding(.vertical, 9)
                            .contentShape(Capsule())
                    }
                    .buttonStyle(.plain)
                    .glassEffect(.regular.tint(.white.opacity(0.06)), in: Capsule())

                    Button {
                        addNode()
                    } label: {
                        Text(isEditing ? "Save" : "Add Node")
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
                            .contentShape(Capsule())
                    }
                    .buttonStyle(.plain)
                    .shadow(color: Color(hex: "4B6EFF").opacity(0.25), radius: 8, y: 3)
                }
            }
            .padding(28)
            .frame(width: 440)
            .fixedSize(horizontal: false, vertical: true)
            .glassEffect(.regular.tint(.white.opacity(0.15)), in: RoundedRectangle(cornerRadius: 20))
            .contentShape(Rectangle())
            .onTapGesture { }  // Prevent tap-through to backdrop
            .shadow(color: .black.opacity(0.12), radius: 30, y: 10)
            .opacity(isPresented ? 1 : 0)
            .onAppear {
                if let node = editingNode {
                    nodeName = node.name
                    server = node.server
                    port = String(node.port)
                    uuid = node.uuid ?? ""
                    sni = node.sni ?? ""
                    enableUDP = node.udp
                }
            }
        }
    }

    private func close() {
        withAnimation(.easeOut(duration: 0.2)) {
            isPresented = false
        }
    }

    private func addNode() {
        // Validation
        guard !nodeName.trimmingCharacters(in: .whitespaces).isEmpty else {
            validationError = String(localized: "Node name is required")
            return
        }
        guard !server.trimmingCharacters(in: .whitespaces).isEmpty else {
            validationError = String(localized: "Server address is required")
            return
        }
        guard let portNum = Int(port), portNum > 0, portNum <= 65535 else {
            validationError = String(localized: "Port must be between 1 and 65535")
            return
        }
        guard !uuid.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            validationError = String(localized: "VLESS UUID is required")
            return
        }

        let flag = ConfigParser.guessFlag(from: nodeName)

        var node = editingNode ?? ProxyNode(name: "", type: .vless)
        node.flag = flag.isEmpty ? "🌐" : flag
        node.name = nodeName.trimmingCharacters(in: .whitespaces)
        node.type = .vless
        node.server = server.trimmingCharacters(in: .whitespaces)
        node.port = portNum
        node.relay = "Direct"
        node.uuid = uuid.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalizedSNI = sni.trimmingCharacters(in: .whitespacesAndNewlines)
        node.sni = normalizedSNI.isEmpty ? nil : normalizedSNI
        node.tls = true
        node.network = node.network ?? "tcp"
        node.udp = enableUDP

        do {
            let existing = appState.proxyRegions.flatMap(\.nodes)
                .filter { $0.id != node.id }
            _ = try ConfigPipeline.validatedOwnedNodes(existing + [node])
        } catch {
            validationError = error.localizedDescription
            return
        }

        onAdd?(node)
        close()
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

    // MARK: - Form Field

    @ViewBuilder
    private func formField<Content: View>(label: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(LocalizedStringKey(label))
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(.secondary)
            content()
        }
    }
}

#Preview {
    @Previewable @State var show = true
    ZStack {
        MeshGradientBackground()
        AddNodeSheet(isPresented: $show)
    }
    .frame(width: 600, height: 500)
}
