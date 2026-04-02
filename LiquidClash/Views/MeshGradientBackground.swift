import SwiftUI

extension Color {
    init(hex: String) {
        let hex = hex.trimmingCharacters(in: CharacterSet.alphanumerics.inverted)
        var int: UInt64 = 0
        Scanner(string: hex).scanHexInt64(&int)
        let r = Double((int >> 16) & 0xFF) / 255
        let g = Double((int >> 8) & 0xFF) / 255
        let b = Double(int & 0xFF) / 255
        self.init(red: r, green: g, blue: b)
    }
}

/// Frosted glass background: blur is always on, slider controls the opaque tint overlay.
/// 0 = pure frosted glass (blurred desktop colors visible), 100 = fully opaque background.
struct MeshGradientBackground: View {
    @AppStorage(SettingsKey.glassTransparency) private var glassTransparency: Double = 50

    var body: some View {
        ZStack {
            // Layer 1: always-on behind-window blur
            FrostedGlassView()
                .ignoresSafeArea()

            // Layer 2: tint overlay controlled by slider
            Rectangle()
                .fill(.background)
                .opacity(glassTransparency / 100.0)
                .ignoresSafeArea()
        }
    }
}

struct FrostedGlassView: NSViewRepresentable {
    func makeNSView(context: Context) -> NSVisualEffectView {
        let view = NSVisualEffectView()
        view.material = .hudWindow
        view.blendingMode = .behindWindow
        view.state = .active
        return view
    }

    func updateNSView(_ nsView: NSVisualEffectView, context: Context) {}
}

#Preview("Dark") {
    MeshGradientBackground()
        .frame(width: 600, height: 400)
        .preferredColorScheme(.dark)
}

#Preview("Light") {
    MeshGradientBackground()
        .frame(width: 600, height: 400)
        .preferredColorScheme(.light)
}
