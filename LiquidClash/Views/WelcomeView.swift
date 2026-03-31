import SwiftUI

struct WelcomeView: View {
    var onComplete: () -> Void

    @State private var subscriptionURL = ""
    @State private var isDropTargeted = false
    @State private var appeared = true

    var body: some View {
        ZStack {
            MeshGradientBackground()

            VStack(spacing: 0) {
                // Brand section
                VStack(spacing: 8) {
                    Image(nsImage: NSApp.applicationIconImage)
                        .resizable()
                        .aspectRatio(contentMode: .fit)
                        .frame(width: 64, height: 64)
                        .padding(.bottom, 8)

                    Text("Welcome to LiquidClash")
                        .font(.system(size: 28, weight: .semibold))
                        .foregroundStyle(Color(hex: "383A76"))

                    Text("Import a configuration to get started")
                        .font(.system(size: 15))
                        .foregroundStyle(Color(hex: "7A7B9F"))
                }
                .padding(.bottom, 40)

                // Import section
                VStack(spacing: 24) {
                    // Drop zone
                    dropZone

                    // Divider "or subscribe via url"
                    orDivider

                    // URL input + Import button
                    HStack(spacing: 12) {
                        TextField("", text: $subscriptionURL)
                            .textFieldStyle(.plain)
                            .font(.system(size: 14))
                            .padding(14)
                            .frame(maxWidth: .infinity)
                            .background(.white.opacity(0.3), in: RoundedRectangle(cornerRadius: 12))
                            .overlay(
                                RoundedRectangle(cornerRadius: 12)
                                    .strokeBorder(.white.opacity(0.8), lineWidth: 1)
                            )

                        Button {
                            onComplete()
                        } label: {
                            Text("Import")
                                .font(.system(size: 14, weight: .semibold))
                                .foregroundStyle(.white)
                                .padding(.horizontal, 24)
                                .padding(.vertical, 14)
                                .background(Color(hex: "383A76"), in: RoundedRectangle(cornerRadius: 12))
                        }
                        .buttonStyle(.plain)
                    }
                }

                // Footer
                VStack(spacing: 12) {
                    Button {
                        onComplete()
                    } label: {
                        Text("Skip for now")
                            .font(.system(size: 13, weight: .medium))
                            .foregroundStyle(Color(hex: "7A7B9F"))
                    }
                    .buttonStyle(.plain)

                    HStack(spacing: 0) {
                        Text("Need help? Check our ")
                            .foregroundStyle(Color(hex: "A2A3C4"))
                        Text("Documentation")
                            .underline()
                            .foregroundStyle(Color(hex: "A2A3C4"))
                    }
                    .font(.system(size: 12))
                }
                .padding(.top, 32)
            }
            .padding(48)
            .frame(width: 560)
            .background(.white.opacity(0.2), in: RoundedRectangle(cornerRadius: 32))
            .overlay(
                RoundedRectangle(cornerRadius: 32)
                    .strokeBorder(.white.opacity(0.8), lineWidth: 1)
            )
            .shadow(color: .black.opacity(0.08), radius: 32, y: 12)
        }
    }

    // MARK: - Drop Zone

    private var dropZone: some View {
        VStack(spacing: 12) {
            Image(systemName: "icloud.and.arrow.up")
                .font(.system(size: 28))
                .foregroundStyle(Color(hex: "A2A3C4"))

            Text("Drag & drop YAML config file here")
                .font(.system(size: 14, weight: .medium))
                .foregroundStyle(Color(hex: "7A7B9F"))
        }
        .frame(maxWidth: .infinity)
        .frame(height: 160)
        .background(
            .white.opacity(isDropTargeted ? 0.25 : 0.15),
            in: RoundedRectangle(cornerRadius: 20)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 20)
                .strokeBorder(
                    isDropTargeted ? Color(hex: "4B6EFF") : .white.opacity(0.5),
                    style: StrokeStyle(lineWidth: 2, dash: [8, 6])
                )
        )
        .onTapGesture {
            onComplete()
        }
    }

    // MARK: - Or Divider

    private var orDivider: some View {
        HStack(spacing: 16) {
            Rectangle()
                .fill(.white.opacity(0.3))
                .frame(height: 1)
            Text("OR SUBSCRIBE VIA URL")
                .font(.system(size: 10, weight: .medium))
                .foregroundStyle(Color(hex: "A2A3C4"))
                .tracking(1)
            Rectangle()
                .fill(.white.opacity(0.3))
                .frame(height: 1)
        }
    }
}

#Preview {
    WelcomeView(onComplete: {})
        .frame(width: 700, height: 550)
}
