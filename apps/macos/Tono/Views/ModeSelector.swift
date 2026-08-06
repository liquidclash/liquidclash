import SwiftUI

private struct ModeFrameKey: PreferenceKey {
    static var defaultValue: [ProxyMode: CGRect] = [:]
    static func reduce(value: inout [ProxyMode: CGRect], nextValue: () -> [ProxyMode: CGRect]) {
        value.merge(nextValue()) { $1 }
    }
}

struct ModeSelector: View {
    @Binding var selectedMode: ProxyMode
    @State private var frames: [ProxyMode: CGRect] = [:]
    @State private var isDragging = false
    @State private var dragOffsetX: CGFloat = 0

    private let springAnim: Animation = .spring(duration: 0.45, bounce: 0.15)

    var body: some View {
        GlassEffectContainer(spacing: 10) {
            tabBar
                .overlay(alignment: .topLeading) { slidingPill }
                .contentShape(Rectangle())
                .highPriorityGesture(dragOrTapGesture)
        }
        .glassEffect(.regular.tint(.white.opacity(0.02)), in: Capsule())
    }

    // MARK: - Shared Label

    private func tabLabel(_ mode: ProxyMode, bold: Bool) -> some View {
        Text(LocalizedStringKey(mode.rawValue))
            .font(.system(size: 12.5, weight: bold ? .bold : .semibold))
            .padding(.horizontal, 22)
            .padding(.vertical, 8)
            .frame(minWidth: 80)
    }

    // MARK: - Subviews

    private var tabBar: some View {
        HStack(spacing: 0) {
            ForEach(ProxyMode.allCases, id: \.self) { mode in
                tabLabel(mode, bold: false)
                    .foregroundStyle(.primary.opacity(0.35))
                    .background { frameReader(for: mode) }
                    .contentShape(Rectangle())
            }
        }
        .padding(3)
        .coordinateSpace(name: "modeBar")
        .onPreferenceChange(ModeFrameKey.self) { frames = $0 }
    }

    private var slidingPill: some View {
        let mode = isDragging ? nearestMode(to: pillX) : selectedMode
        return tabLabel(mode, bold: true)
            .foregroundStyle(.white)
            .glassEffect(.regular.tint(Color.accentColor), in: Capsule())
            .offset(x: pillX, y: pillFrame.minY)
            .allowsHitTesting(false)
    }

    private func frameReader(for mode: ProxyMode) -> some View {
        GeometryReader { geo in
            Color.clear.preference(
                key: ModeFrameKey.self,
                value: [mode: geo.frame(in: .named("modeBar"))]
            )
        }
    }

    // MARK: - Gesture

    private var dragOrTapGesture: some Gesture {
        DragGesture(minimumDistance: 0)
            .onChanged { value in
                if !isDragging, isOnPill(value.startLocation),
                   abs(value.translation.width) > 8 {
                    withAnimation(.easeOut(duration: 0.15)) { isDragging = true }
                }
                if isDragging { dragOffsetX = value.translation.width }
            }
            .onEnded { value in
                if isDragging {
                    let target = nearestMode(to: pillX)
                    withAnimation(springAnim) {
                        isDragging = false
                        dragOffsetX = 0
                        selectedMode = target
                    }
                } else if let tapped = modeAt(value.startLocation), tapped != selectedMode {
                    withAnimation(springAnim) { selectedMode = tapped }
                }
            }
    }

    // MARK: - Geometry Helpers

    private var pillFrame: CGRect { frames[selectedMode] ?? .zero }

    private var pillX: CGFloat {
        let raw = pillFrame.minX + (isDragging ? dragOffsetX : 0)
        guard let first = frames[ProxyMode.allCases.first!],
              let last = frames[ProxyMode.allCases.last!] else { return raw }
        return min(max(raw, first.minX), last.minX)
    }

    private func nearestMode(to x: CGFloat) -> ProxyMode {
        let center = x + pillFrame.width / 2
        return ProxyMode.allCases.min { a, b in
            abs((frames[a]?.midX ?? 0) - center) < abs((frames[b]?.midX ?? 0) - center)
        } ?? selectedMode
    }

    private func isOnPill(_ pt: CGPoint) -> Bool {
        pillFrame.contains(pt)
    }

    private func modeAt(_ pt: CGPoint) -> ProxyMode? {
        ProxyMode.allCases.first { frames[$0]?.contains(pt) == true }
    }
}

#Preview {
    @Previewable @State var mode: ProxyMode = .rule
    ZStack {
        MeshGradientBackground()
        ModeSelector(selectedMode: $mode)
    }
    .frame(width: 900, height: 600)
}
