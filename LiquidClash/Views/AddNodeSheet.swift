import SwiftUI

struct AddNodeSheet: View {
    @Binding var isPresented: Bool

    @State private var nodeName = ""
    @State private var selectedType = "SOCKS5"
    @State private var port = "5001"
    @State private var server = ""
    @State private var username = ""
    @State private var password = ""
    @State private var dialerProxy = ""
    @State private var enableUDP = true

    private let proxyTypes = ["SOCKS5", "HTTP", "Shadowsocks", "Vmess", "Trojan"]
    private let dialerOptions: [(value: String, label: String)] = [
        ("", "None (Direct)"),
        ("japan-01", "🇯🇵 Japan | 01"),
        ("singapore-sg4", "🇸🇬 Singapore - SG-4"),
        ("hongkong-hkt", "🇭🇰 Hong Kong - HKT"),
        ("losangeles-lax", "🇺🇸 Los Angeles - LAX"),
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
                    Text("Add Proxy Node")
                        .font(.system(size: 20, weight: .semibold))
                        .foregroundStyle(Color(hex: "383A76"))

                    Spacer()

                    Button {
                        close()
                    } label: {
                        Image(systemName: "xmark")
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundStyle(Color(hex: "8E8EA0"))
                            .frame(width: 28, height: 28)
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
                            customPicker(selection: $selectedType, options: proxyTypes.map { ($0, $0) })
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

                    // Username + Password
                    HStack(spacing: 14) {
                        formField(label: "Username") {
                            glassInput {
                                TextField("Username", text: $username)
                                    .textFieldStyle(.plain)
                            }
                        }

                        formField(label: "Password") {
                            glassInput {
                                SecureField("Enter password", text: $password)
                                    .textFieldStyle(.plain)
                            }
                        }
                    }

                    // Dialer Proxy + Enable UDP
                    HStack(spacing: 14) {
                        formField(label: "Dialer Proxy") {
                            customPicker(selection: $dialerProxy, options: dialerOptions.map { ($0.value, $0.label) })
                        }

                        formField(label: " ") {
                            Toggle("Enable UDP", isOn: $enableUDP)
                                .toggleStyle(.checkbox)
                                .font(.system(size: 13, weight: .medium))
                                .foregroundStyle(Color(hex: "383A76"))
                                .frame(maxWidth: .infinity, minHeight: 34, alignment: .leading)
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
                    .foregroundStyle(Color(hex: "8E8EA0"))
                    .padding(.horizontal, 18)
                    .padding(.vertical, 9)
                    .glassEffect(.regular.tint(.white.opacity(0.06)), in: Capsule())

                    Button {
                        close()
                    } label: {
                        Text("Add Node")
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
            .frame(width: 440)
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
                    .foregroundStyle(Color(hex: "383A76"))
                    .lineLimit(1)
                Spacer()
                Image(systemName: "chevron.down")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(Color(hex: "8E8EA0"))
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
            Text(label)
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
        AddNodeSheet(isPresented: $show)
    }
    .frame(width: 600, height: 500)
}
