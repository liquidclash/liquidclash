import SwiftUI

struct SubscriptionsView: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            SubscriptionSourcesPanel()

            Spacer(minLength: 0)
        }
        .padding(.horizontal, 32)
        .padding(.vertical, 16)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

#Preview {
    ZStack {
        MeshGradientBackground()
        SubscriptionsView()
    }
    .frame(width: 760, height: 560)
    .environment({
        let state = AppState()
        state.loadMockData()
        return state
    }())
}
