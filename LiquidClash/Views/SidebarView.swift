import SwiftUI

struct SidebarView: View {
    @Binding var selectedPage: AppPage

    // 主导航项（排除 settings）
    private let mainPages: [AppPage] = [.dashboard, .proxies, .rules, .activity]

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // 品牌区
            HStack(spacing: 10) {
                LiquidClashLogo(compact: true)
                    .frame(width: 22, height: 22)
                Text("LiquidClash")
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(Color(hex: "4A4A6A"))
            }
            .padding(.horizontal, 14)
            .padding(.top, 10)
            .padding(.bottom, 16)

            // 主导航
            ForEach(mainPages) { page in
                navigationItem(for: page)
            }

            Spacer()

            // Settings 推至底部
            navigationItem(for: .settings)
        }
        .padding(.bottom, 12)
        .padding(.horizontal, 6)
        .navigationSplitViewColumnWidth(220)
    }

    @ViewBuilder
    private func navigationItem(for page: AppPage) -> some View {
        Button {
            selectedPage = page
        } label: {
            HStack(spacing: 10) {
                Image(systemName: page.icon)
                    .font(.system(size: 14))
                    .frame(width: 20, alignment: .center)
                Text(page.rawValue)
                    .font(.system(size: 14, weight: selectedPage == page ? .semibold : .medium))
                    .lineLimit(1)
                    .fixedSize(horizontal: true, vertical: false)
            }
            .symbolRenderingMode(.monochrome)
            .foregroundStyle(
                selectedPage == page
                    ? Color(hex: "4A4A6A")
                    : Color(hex: "8E8EA0")
            )
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(
                selectedPage == page
                    ? .white.opacity(0.5)
                    : .clear,
                in: RoundedRectangle(cornerRadius: 8)
            )
        }
        .buttonStyle(.plain)
    }
}

#Preview {
    @Previewable @State var page: AppPage = .dashboard
    SidebarView(selectedPage: $page)
        .frame(width: 220, height: 600)
}
