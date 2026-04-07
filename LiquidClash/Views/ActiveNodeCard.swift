import SwiftUI

struct ActiveNodeCard: View {
    let nodeName: String
    var groupName: String?
    var onSwitch: (() -> Void)?

    private var flag: String {
        ConfigParser.extractFlag(from: nodeName).flag
    }

    private var cleanName: String {
        ConfigParser.extractFlag(from: nodeName).cleanName
    }

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
                    Text(flag)
                        .font(.system(size: 16))
                        .frame(width: 28, height: 28)
                        .background(.white.opacity(0.28), in: Circle())
                    VStack(alignment: .leading, spacing: 2) {
                        Text(cleanName)
                            .font(.system(size: 13, weight: .semibold))
                            .fontWeight(.semibold)
                            .foregroundStyle(.primary)
                        if let group = groupName {
                            Text(group)
                                .font(.system(size: 11))
                                .foregroundStyle(Color(hex: "8E8E93"))
                        }
                    }
                }
                Spacer()
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
        ActiveNodeCard(nodeName: "🇯🇵 Tokyo 01", groupName: "PROXY")
    }
    .frame(width: 900, height: 600)
}
