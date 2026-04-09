import SwiftUI
import UniformTypeIdentifiers

struct WelcomeView: View {
    var onComplete: () -> Void
    @State private var subscriptionURL = ""
    @State private var isDropTargeted = false
    @State private var isImporting = false
    @State private var importError: String?
    @State private var importSuccess = false
    @State private var appeared = true

    var body: some View {
        ZStack {
            MeshGradientBackground()

            VStack(spacing: 0) {
                Spacer()

                // App Icon
                Image(nsImage: NSApplication.shared.applicationIconImage)
                    .resizable()
                    .aspectRatio(contentMode: .fit)
                    .frame(width: 80, height: 80)
                    .padding(.bottom, 16)

                // Title
                Text("Welcome to LiquidClash")
                    .font(.system(size: 28, weight: .bold))
                    .foregroundStyle(.primary)
                    .padding(.bottom, 6)

                Text("Import your proxy configuration to get started.")
                    .font(.system(size: 14))
                    .foregroundStyle(.secondary)
                    .padding(.bottom, 32)

                // Drop zone
                dropZone
                    .padding(.horizontal, 60)
                    .padding(.bottom, 20)

                // URL input
                HStack(spacing: 12) {
                    TextField("Subscription URL", text: $subscriptionURL)
                        .textFieldStyle(.plain)
                        .font(.system(size: 13))
                        .padding(12)
                        .frame(maxWidth: 360)
                        .background(.white.opacity(0.4), in: RoundedRectangle(cornerRadius: 12))
                        .overlay(
                            RoundedRectangle(cornerRadius: 12)
                                .strokeBorder(.white.opacity(0.4), lineWidth: 0.5)
                        )

                    Button {
                        importFromURL()
                    } label: {
                        if isImporting {
                            ProgressView()
                                .controlSize(.small)
                                .padding(.horizontal, 20)
                                .padding(.vertical, 10)
                        } else {
                            Text("Import")
                                .font(.system(size: 13, weight: .semibold))
                                .foregroundStyle(.white)
                                .padding(.horizontal, 20)
                                .padding(.vertical, 10)
                                .background(
                                    LinearGradient(
                                        colors: [Color(hex: "4B6EFF"), Color(hex: "6B8CFF")],
                                        startPoint: .topLeading,
                                        endPoint: .bottomTrailing
                                    ),
                                    in: Capsule()
                                )
                        }
                    }
                    .buttonStyle(.plain)
                    .disabled(subscriptionURL.isEmpty || isImporting)
                }
                .padding(.bottom, 12)

                // Status messages
                if let error = importError {
                    Text(error)
                        .font(.system(size: 12))
                        .foregroundStyle(.red)
                        .padding(.bottom, 8)
                }

                if importSuccess {
                    Text("Import successful! Launching app...")
                        .font(.system(size: 12))
                        .foregroundStyle(Color(hex: "30D158"))
                        .padding(.bottom, 8)
                }

                // Skip
                Button {
                    onComplete()
                } label: {
                    Text("Skip for now")
                        .font(.system(size: 12, weight: .medium))
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .padding(.bottom, 8)

                Spacer()

                // Documentation link
                HStack(spacing: 4) {
                    Image(systemName: "book")
                        .font(.system(size: 11))
                    Text("View Documentation")
                        .font(.system(size: 12, weight: .medium))
                }
                .foregroundStyle(.secondary)
                .padding(.bottom, 24)
            }
            .frame(maxWidth: 600)
        }
    }

    // MARK: - Drop Zone

    private var dropZone: some View {
        VStack(spacing: 12) {
            Image(systemName: "arrow.down.doc")
                .font(.system(size: 28, weight: .light))
                .foregroundStyle(Color(hex: isDropTargeted ? "4B6EFF" : "A2A3C4"))

            Text("Drop YAML config file here")
                .font(.system(size: 13, weight: .medium))
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
        .frame(height: 120)
        .background(
            (isDropTargeted ? Color(hex: "4B6EFF").opacity(0.06) : .white.opacity(0.3)),
            in: RoundedRectangle(cornerRadius: 20)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 20)
                .strokeBorder(
                    isDropTargeted ? Color(hex: "4B6EFF").opacity(0.5) : .white.opacity(0.5),
                    style: StrokeStyle(lineWidth: 1.5, dash: [8, 6])
                )
        )
        .dropDestination(for: URL.self) { items, _ in
            guard let fileURL = items.first else { return false }
            importFromFile(fileURL)
            return true
        } isTargeted: { targeted in
            withAnimation(.easeInOut(duration: 0.15)) {
                isDropTargeted = targeted
            }
        }
    }

    // MARK: - Import Actions

    private func importFromURL() {
        guard !subscriptionURL.isEmpty else { return }
        isImporting = true
        importError = nil

        Task {
            do {
                let manager = SubscriptionManager()
                let (regions, rawYAML, _) = try await manager.fetchAndOrganize(url: subscriptionURL)

                await MainActor.run {
                    // Save to storage
                    ConfigStorage.shared.saveProxyRegions(regions)
                    ConfigStorage.shared.saveRawSubscriptionYAML(rawYAML)
                    isImporting = false
                    importSuccess = true
                }

                // Save subscription info
                await manager.saveSubscriptionInfo(
                    SubscriptionInfo(
                        url: subscriptionURL,
                        name: "Default",
                        lastUpdate: Date(),
                        nodeCount: regions.flatMap(\.nodes).count
                    )
                )

                // Delay then complete
                try? await Task.sleep(for: .seconds(1))
                await MainActor.run { onComplete() }
            } catch {
                await MainActor.run {
                    isImporting = false
                    importError = error.localizedDescription
                }
            }
        }
    }

    private func importFromFile(_ fileURL: URL) {
        isImporting = true
        importError = nil

        Task {
            do {
                let content = try String(contentsOf: fileURL, encoding: .utf8)
                let nodes = ConfigParser.parseSubscription(content)
                guard !nodes.isEmpty else {
                    throw SubscriptionError.noNodesFound
                }

                let manager = SubscriptionManager()
                let regions = await manager.organizeIntoRegions(nodes)

                await MainActor.run {
                    ConfigStorage.shared.saveProxyRegions(regions)
                    // Save raw YAML for mihomo to use directly
                    ConfigStorage.shared.saveRawSubscriptionYAML(content)
                    isImporting = false
                    importSuccess = true
                }

                // Also parse rules if present
                let rules = ConfigParser.parseClashYAMLRules(content)
                if !rules.isEmpty {
                    await MainActor.run {
                        ConfigStorage.shared.saveRules(rules)
                    }
                }

                try? await Task.sleep(for: .seconds(1))
                await MainActor.run { onComplete() }
            } catch {
                await MainActor.run {
                    isImporting = false
                    importError = error.localizedDescription
                }
            }
        }
    }
}

#Preview {
    WelcomeView { }
        .frame(width: 700, height: 550)
}
