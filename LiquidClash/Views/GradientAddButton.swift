import SwiftUI

struct GradientAddButton: View {
    let title: LocalizedStringKey
    let isDisabled: Bool
    let action: () -> Void

    init(_ title: LocalizedStringKey, isDisabled: Bool = false, action: @escaping () -> Void) {
        self.title = title
        self.isDisabled = isDisabled
        self.action = action
    }

    var body: some View {
        Button(action: action) {
            HStack(spacing: 6) {
                Image(systemName: "plus")
                    .font(.system(size: 12, weight: .bold))
                Text(title)
                    .font(.system(size: 13, weight: .semibold))
            }
            .foregroundStyle(.white)
            .padding(.horizontal, 17)
            .padding(.vertical, 8)
            .frame(minHeight: 36)
            .background(
                LinearGradient(
                    colors: [Color(hex: "FF6E52"), Color(hex: "C34AC2")],
                    startPoint: .leading,
                    endPoint: .trailing
                ),
                in: Capsule()
            )
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .fixedSize()
        .disabled(isDisabled)
        .opacity(isDisabled ? 0.65 : 1)
        .shadow(color: Color(hex: "FF6E52").opacity(0.28), radius: 9, y: 4)
    }
}

#Preview {
    GradientAddButton("Add Rule") {}
        .padding(24)
}
