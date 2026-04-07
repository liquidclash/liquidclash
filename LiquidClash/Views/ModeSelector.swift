import SwiftUI

struct ModeSelector: View {
    @Binding var selectedMode: ProxyMode
    @Namespace private var namespace

    var body: some View {
        GlassEffectContainer(spacing: 10) {
            HStack(spacing: 0) {
                ForEach(ProxyMode.allCases, id: \.self) { mode in
                    let isSelected = selectedMode == mode
                    Button {
                        withAnimation(.smooth(duration: 0.22)) {
                            selectedMode = mode
                        }
                    } label: {
                        Text(LocalizedStringKey(mode.rawValue))
                            .font(.system(size: 12.5, weight: isSelected ? .bold : .medium))
                            .foregroundStyle(
                                isSelected
                                ? Color.white
                                : Color.primary.opacity(0.35)
                            )
                            .padding(.horizontal, 22)
                            .padding(.vertical, 8)
                            .frame(minWidth: 80)
                    }
                    .buttonStyle(.plain)
                    .glassEffect(
                        isSelected
                            ? .regular.tint(Color(hex: "4B6EFF").opacity(0.45))
                            : .identity,
                        in: Capsule()
                    )
                    .glassEffectID(mode.rawValue, in: namespace)
                }
            }
            .padding(3)
        }
        .glassEffect(.regular.tint(.white.opacity(0.02)), in: Capsule())
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
