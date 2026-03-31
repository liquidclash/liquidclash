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

struct MeshGradientBackground: View {
    @Environment(\.colorScheme) private var colorScheme

    // Each inner point has its own drift parameters (amplitude, speed, phase offset)
    // Format: (dx amplitude, dy amplitude, x speed, y speed, x phase, y phase)
    private let drifts: [(Float, Float, Float, Float, Float, Float)] = [
        // Row 0: corners fixed, top-center drifts
        (0, 0, 0, 0, 0, 0),              // [0,0] fixed
        (0.15, 0.08, 0.8, 0.6, 0, 1.2),  // [1,0] top center
        (0, 0, 0, 0, 0, 0),              // [2,0] fixed

        // Row 1: left/right edges drift a bit, center drifts most
        (0.06, 0.12, 0.5, 0.7, 2.0, 0.5),  // [0,1] left
        (0.18, 0.18, 0.6, 0.5, 0.8, 2.5),  // [1,1] center — most movement
        (0.06, 0.12, 0.7, 0.5, 3.0, 1.0),  // [2,1] right

        // Row 2: corners fixed, bottom-center drifts
        (0, 0, 0, 0, 0, 0),              // [0,2] fixed
        (0.15, 0.08, 0.9, 0.7, 1.5, 0.3),// [1,2] bottom center
        (0, 0, 0, 0, 0, 0),              // [2,2] fixed
    ]

    private let basePoints: [SIMD2<Float>] = [
        SIMD2(0.0, 0.0),  SIMD2(0.5, 0.0),  SIMD2(1.0, 0.0),
        SIMD2(0.0, 0.5),  SIMD2(0.5, 0.5),  SIMD2(1.0, 0.5),
        SIMD2(0.0, 1.0),  SIMD2(0.5, 1.0),  SIMD2(1.0, 1.0),
    ]

    var body: some View {
        TimelineView(.animation) { context in
            let t = Float(context.date.timeIntervalSinceReferenceDate)
            let points = computePoints(t: t)

            ZStack {
                Rectangle()
                    .fill(.windowBackground)

                MeshGradient(
                    width: 3, height: 3,
                    points: points,
                    colors: meshColors
                )
                .opacity(colorScheme == .dark ? 0.35 : 0.25)
                .blur(radius: 30)

                LinearGradient(
                    colors: [
                        .white.opacity(colorScheme == .dark ? 0.04 : 0.08),
                        .clear,
                    ],
                    startPoint: .topLeading,
                    endPoint: .center
                )
            }
        }
        .ignoresSafeArea()
    }

    private func computePoints(t: Float) -> [SIMD2<Float>] {
        zip(basePoints, drifts).map { base, drift in
            let (ax, ay, sx, sy, px, py) = drift
            let dx = ax * sin(t * sx + px)
            let dy = ay * sin(t * sy + py)
            return SIMD2(base.x + dx, base.y + dy)
        }
    }

    // MARK: - Colors

    private var meshColors: [Color] {
        if colorScheme == .dark {
            return [
                Color(hex: "4A1C8A"),  Color(hex: "1E3A8A"),  Color(hex: "1A1040"),
                Color(hex: "7C3AED"),  Color(hex: "1E1B4B"),  Color(hex: "2563EB"),
                Color(hex: "9333EA"),  Color(hex: "3B82F6"),  Color(hex: "6D28D9"),
            ]
        } else {
            return [
                Color(hex: "DDB4F2"),  Color(hex: "93C5FD"),  Color(hex: "A5B4FC"),
                Color(hex: "F9A8D4"),  Color(hex: "EDE9FE"),  Color(hex: "7DD3FC"),
                Color(hex: "C084FC"),  Color(hex: "67E8F9"),  Color(hex: "F0ABFC"),
            ]
        }
    }
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
