import SwiftUI

struct ConnectPill: View {
    @Binding var isConnected: Bool
    @State private var glowPhase = false
    @Environment(\.colorScheme) private var colorScheme

    private var accentColor: Color {
        isConnected ? Color(hex: "2ED573") : Color(hex: "E83B3B")
    }

    var body: some View {
        Button {
            withAnimation(.spring(duration: 0.6, bounce: 0.2)) {
                isConnected.toggle()
            }
        } label: {
            HStack(spacing: 4) {
                iconWithGlow
                textBlock
                Spacer(minLength: 0)
            }
            .padding(.leading, 4)
            .padding(.trailing, 16)
            .frame(width: 300, height: 72)
        }
        .buttonStyle(.plain)
        .glassEffect(
            .regular.tint(pillTint),
            in: Capsule()
        )
        .shadow(
            color: isConnected
                ? Color(hex: "2ED573").opacity(0.25)
                : Color.black.opacity(colorScheme == .dark ? 0.35 : 0.10),
            radius: 15, y: 5
        )
        .onAppear {
            glowPhase = true
        }
    }

    // Glass tint adapts to color scheme
    private var pillTint: Color {
        colorScheme == .dark
            ? .black.opacity(0.55)
            : .white.opacity(0.06)
    }

    // MARK: - Icon with Glow

    private var iconWithGlow: some View {
        ZStack {
            // Pulsing glow behind icon
            Circle()
                .fill(
                    RadialGradient(
                        colors: [
                            accentColor.opacity(0.7),
                            accentColor.opacity(0.5),
                            accentColor.opacity(0.2),
                            .clear,
                        ],
                        center: .center,
                        startRadius: 12,
                        endRadius: 44
                    )
                )
                .frame(width: 96, height: 96)
                .opacity(glowPhase ? 0.9 : 0.4)
                .scaleEffect(glowPhase ? 1.2 : 0.9)
                .blur(radius: 12)
                .blendMode(colorScheme == .dark ? .plusLighter : .normal)
                .animation(
                    .easeInOut(duration: 3).repeatForever(autoreverses: true),
                    value: glowPhase
                )

            // Clash logo
            LiquidClashLogo(isConnected: isConnected)
                .frame(width: 52, height: 52)
                .shadow(
                    color: isConnected ? accentColor.opacity(0.4) : .clear,
                    radius: 8
                )
        }
        .frame(width: 70, height: 70)
    }

    // MARK: - Text Block

    private var textBlock: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(isConnected ? "Connected" : "Connect")
                .font(.system(size: 22, weight: .semibold))
                .foregroundStyle(
                    isConnected
                        ? Color(hex: "2ED573")
                        : Color.primary
                )

            HStack(spacing: 6) {
                Circle()
                    .fill(accentColor)
                    .frame(width: 6, height: 6)
                    .shadow(color: accentColor.opacity(0.5), radius: 3)

                Text(isConnected ? "Secure Node" : "Disconnected")
                    .font(.system(size: 11, weight: .medium))
                    .kerning(1.1)
                    .textCase(.uppercase)
                    .foregroundStyle(.secondary)
            }
        }
    }
}

// MARK: - Previews

#Preview("Dark - Disconnected") {
    @Previewable @State var connected = false

    ZStack {
        MeshGradientBackground()
        ConnectPill(isConnected: $connected)
    }
    .frame(width: 400, height: 200)
    .preferredColorScheme(.dark)
}

#Preview("Dark - Connected") {
    @Previewable @State var connected = true

    ZStack {
        MeshGradientBackground()
        ConnectPill(isConnected: $connected)
    }
    .frame(width: 400, height: 200)
    .preferredColorScheme(.dark)
}

#Preview("Light - Disconnected") {
    @Previewable @State var connected = false

    ZStack {
        MeshGradientBackground()
        ConnectPill(isConnected: $connected)
    }
    .frame(width: 400, height: 200)
    .preferredColorScheme(.light)
}

#Preview("Light - Connected") {
    @Previewable @State var connected = true

    ZStack {
        MeshGradientBackground()
        ConnectPill(isConnected: $connected)
    }
    .frame(width: 400, height: 200)
    .preferredColorScheme(.light)
}
