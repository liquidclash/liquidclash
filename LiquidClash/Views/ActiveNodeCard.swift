import SwiftUI

struct ActiveNodeCard: View {
    let node: ProxyNode
    var onSwitch: (() -> Void)?

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("ACTIVE NODE")
                    .font(.system(size: 10, weight: .semibold))
                    .fontWeight(.semibold)
                    .foregroundStyle(Color(hex: "8E8E93"))
                    .kerning(0.6)
                Spacer()
                Button("Switch") { onSwitch?() }
                    .buttonStyle(.plain)
                    .font(.system(size: 12, weight: .medium))
                    .fontWeight(.medium)
                    .foregroundStyle(Color(hex: "8E8E93"))
            }
            .padding(.horizontal, 16)
            .padding(.top, 12)
            .padding(.bottom, 8)

            HStack {
                HStack(spacing: 10) {
                    Text(node.flag)
                        .font(.system(size: 16))
                        .frame(width: 28, height: 28)
                        .background(.white.opacity(0.28), in: Circle())
                    VStack(alignment: .leading, spacing: 2) {
                        Text(node.name)
                            .font(.system(size: 13, weight: .semibold))
                            .fontWeight(.semibold)
                            .foregroundStyle(.primary)
                        Text(node.protocolType)
                            .font(.system(size: 11))
                            .foregroundStyle(Color(hex: "8E8E93"))
                    }
                }
                Spacer()
                Text("\(node.latency)ms")
                    .font(.system(size: 12, weight: .semibold))
                    .fontWeight(.semibold)
                    .foregroundStyle(Color(hex: "30D158"))
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(Color(hex: "30D158").opacity(0.15), in: RoundedRectangle(cornerRadius: 6))
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 12)
            .background(.white.opacity(0.24), in: RoundedRectangle(cornerRadius: 10))
            .overlay {
                RoundedRectangle(cornerRadius: 10)
                    .strokeBorder(.white.opacity(0.45), lineWidth: 1)
            }
            .glassEffect(in: RoundedRectangle(cornerRadius: 10))
            .padding(.horizontal, 12)
            .padding(.bottom, 12)
        }
        .frame(width: 480)
        .background(.white.opacity(0.12), in: RoundedRectangle(cornerRadius: 12))
        .overlay {
            RoundedRectangle(cornerRadius: 12)
                .strokeBorder(.white.opacity(0.4), lineWidth: 1)
        }
        .glassEffect(in: RoundedRectangle(cornerRadius: 12))
    }
}

#Preview {
    ZStack {
        MeshGradientBackground()
        ActiveNodeCard(node: mockProxyRegions[0].nodes[0])
    }
    .frame(width: 900, height: 600)
}
