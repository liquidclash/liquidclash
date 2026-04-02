import SwiftUI

struct SidebarView: View {
    @Binding var selectedPage: AppPage
    @AppStorage(SettingsKey.logsEnabled) private var logsEnabled = true

    // 主导航项（排除 settings），根据 logsEnabled 动态过滤
    private var mainPages: [AppPage] {
        [.dashboard, .proxies, .rules, .activity, .logs].filter { page in
            if page == .logs { return logsEnabled }
            return true
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // 品牌区
            HStack(spacing: 10) {
                LiquidClashLogo(compact: true)
                    .frame(width: 22, height: 22)
                Text("LiquidClash")
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(.primary)
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
        .navigationSplitViewColumnWidth(min: 220, ideal: 220, max: 280)
        .onChange(of: logsEnabled) { _, newValue in
            if !newValue && selectedPage == .logs {
                selectedPage = .dashboard
            }
        }
    }

    @ViewBuilder
    private func navigationItem(for page: AppPage) -> some View {
        let isSelected = selectedPage == page
        Button {
            selectedPage = page
        } label: {
            HStack(spacing: 8) {
                Image(systemName: page.icon)
                    .font(.system(size: 12))
                    .frame(width: 18, alignment: .center)
                Text(page.displayName)
                    .font(.system(size: 13, weight: .regular))
                    .lineLimit(1)
                    .fixedSize(horizontal: true, vertical: false)
            }
            .symbolRenderingMode(.monochrome)
            .foregroundStyle(isSelected ? .white : .primary)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(
                isSelected
                    ? Color.accentColor
                    : .clear,
                in: RoundedRectangle(cornerRadius: 6)
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
