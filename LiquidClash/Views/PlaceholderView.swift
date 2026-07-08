import SwiftUI

struct PlaceholderView: View {
    let page: AppPage

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: page.icon)
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
            Text(page.rawValue)
                .font(.title2)
                .fontWeight(.semibold)
            Text("Coming Soon")
                .font(.subheadline)
                .foregroundStyle(.tertiary)
        }
        .padding(40)
        .glassEffect(in: RoundedRectangle(cornerRadius: 20))
    }
}

#Preview {
    ZStack {
        MeshGradientBackground()
        PlaceholderView(page: .proxies)
    }
    .frame(width: 900, height: 600)
}
