import SwiftUI

struct LiquidClashLogo: View {
    var compact: Bool = false
    var isConnected: Bool = false

    var body: some View {
        let symbolShadow = compact ? Color.black.opacity(0.16) : Color.black.opacity(0.35)
        let shadowRadius: CGFloat = compact ? 2.5 : 10
        let shadowYOffset: CGFloat = compact ? 1 : 6
        let centerOuterSize: CGFloat = compact ? 0.17 : 0.13
        let centerInnerSize: CGFloat = compact ? 0.06 : (isConnected ? 0.08 : 0.05)

        let secondaryColors: [Color] = isConnected
            ? [Color(hex: "0E5A2B"), Color(hex: "1B9A4C"), Color(hex: "2ED573"), Color(hex: "7BED9F")]
            : [Color(hex: "6E0B0B"), Color(hex: "CC1F1F"), Color(hex: "E83B3B"), Color(hex: "FFA6A6")]

        let eyeOuterColors: [Color] = isConnected
            ? [Color(hex: "E0F8E9"), Color(hex: "B8F0CC"), Color(hex: "7BED9F")]
            : [Color.white, Color(hex: "EAEAEA"), Color(hex: "8B8B8D")]

        let eyeInnerColor: Color = isConnected ? .white : Color(hex: "121214")

        ZStack {
            ClashWhiteShape()
                .fill(
                    LinearGradient(
                        colors: [Color.white, Color(hex: "EAEAEA"), Color(hex: "8B8B8D")],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
                .shadow(color: symbolShadow, radius: shadowRadius, y: shadowYOffset)

            ClashRedShape()
                .fill(
                    LinearGradient(
                        colors: secondaryColors,
                        startPoint: .bottomLeading,
                        endPoint: .topTrailing
                    )
                )
                .shadow(color: symbolShadow, radius: shadowRadius, y: shadowYOffset)

            Circle()
                .fill(
                    LinearGradient(
                        colors: eyeOuterColors,
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .scaleEffect(centerOuterSize)
                .shadow(color: symbolShadow, radius: shadowRadius, y: shadowYOffset)

            Circle()
                .fill(eyeInnerColor)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .scaleEffect(centerInnerSize)
                .shadow(
                    color: isConnected ? Color.white.opacity(0.8) : .clear,
                    radius: isConnected ? 4 : 0
                )
        }
        .aspectRatio(1, contentMode: .fit)
    }
}

private struct ClashWhiteShape: Shape {
    func path(in rect: CGRect) -> Path {
        var path = Path()

        func point(_ x: CGFloat, _ y: CGFloat) -> CGPoint {
            CGPoint(x: rect.minX + rect.width * x, y: rect.minY + rect.height * y)
        }

        path.move(to: point(0.1953, 0.2734))
        path.addCurve(
            to: point(0.5078, 0.6250),
            control1: point(0.3516, 0.2734),
            control2: point(0.4688, 0.3906)
        )
        path.addLine(to: point(0.6641, 0.6250))
        path.addCurve(
            to: point(0.1953, 0.1563),
            control1: point(0.6250, 0.3125),
            control2: point(0.4688, 0.1563)
        )
        path.closeSubpath()
        return path
    }
}

private struct ClashRedShape: Shape {
    func path(in rect: CGRect) -> Path {
        var path = Path()

        func point(_ x: CGFloat, _ y: CGFloat) -> CGPoint {
            CGPoint(x: rect.minX + rect.width * x, y: rect.minY + rect.height * y)
        }

        path.move(to: point(0.1953, 0.7422))
        path.addCurve(
            to: point(0.5859, 0.3125),
            control1: point(0.3906, 0.7422),
            control2: point(0.5078, 0.5859)
        )
        path.addLine(to: point(0.7422, 0.3125))
        path.addCurve(
            to: point(0.1953, 0.8594),
            control1: point(0.6641, 0.7031),
            control2: point(0.4688, 0.8594)
        )
        path.closeSubpath()
        return path
    }
}

#Preview("Logo") {
    ZStack {
        LinearGradient(
            colors: [Color(hex: "F0F3FA"), Color(hex: "D9E0EF")],
            startPoint: .topLeading,
            endPoint: .bottomTrailing
        )
        LiquidClashLogo()
            .frame(width: 220, height: 220)
    }
    .frame(width: 360, height: 360)
}
