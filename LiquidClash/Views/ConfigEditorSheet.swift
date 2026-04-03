import SwiftUI
import AppKit

struct ConfigEditorSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.colorScheme) private var colorScheme
    @State private var content: String = ""
    @State private var isLoading = true
    @State private var saveStatus: String?

    private let fileURL = ConfigStorage.shared.appSupportDirectory
        .appendingPathComponent("subscription_raw.yaml")

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Config Editor")
                        .font(.system(size: 15, weight: .semibold))
                    Text("subscription_raw.yaml")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(.secondary)
                }

                Spacer()

                if let status = saveStatus {
                    Text(status)
                        .font(.system(size: 11))
                        .foregroundStyle(status.contains("✓") ? .green : .red)
                        .transition(.opacity)
                }

                Button("Save") {
                    save()
                }
                .keyboardShortcut("s", modifiers: .command)

                Button("Close") {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)

            Divider()

            // Editor
            if isLoading {
                ProgressView()
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                YAMLTextEditor(text: $content)
            }
        }
        .frame(width: 700, height: 500)
        .task {
            loadFile()
        }
    }

    private func loadFile() {
        if let data = try? String(contentsOf: fileURL, encoding: .utf8) {
            content = data
        } else {
            content = "# No config file found"
        }
        isLoading = false
    }

    private func save() {
        do {
            try content.write(to: fileURL, atomically: true, encoding: .utf8)
            withAnimation { saveStatus = "✓ Saved" }
            Task {
                try? await Task.sleep(for: .seconds(2))
                await MainActor.run { withAnimation { saveStatus = nil } }
            }
        } catch {
            withAnimation { saveStatus = "Failed: \(error.localizedDescription)" }
        }
    }
}

/// NSTextView wrapper with YAML syntax highlighting
struct YAMLTextEditor: NSViewRepresentable {
    @Binding var text: String

    func makeNSView(context: Context) -> NSScrollView {
        let scrollView = NSTextView.scrollableTextView()
        let textView = scrollView.documentView as! NSTextView

        textView.isEditable = true
        textView.isSelectable = true
        textView.allowsUndo = true
        textView.isAutomaticQuoteSubstitutionEnabled = false
        textView.isAutomaticDashSubstitutionEnabled = false
        textView.isAutomaticTextReplacementEnabled = false
        textView.isRichText = false
        textView.usesFontPanel = false

        textView.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        textView.textColor = .labelColor
        textView.backgroundColor = .clear
        textView.textContainerInset = NSSize(width: 12, height: 12)

        textView.string = text
        textView.delegate = context.coordinator

        // Apply initial syntax highlighting
        YAMLHighlighter.highlight(textView.textStorage!)

        return scrollView
    }

    func updateNSView(_ nsView: NSScrollView, context: Context) {
        let textView = nsView.documentView as! NSTextView
        if textView.string != text {
            textView.string = text
            YAMLHighlighter.highlight(textView.textStorage!)
        }
    }

    func makeCoordinator() -> Coordinator {
        Coordinator(text: $text)
    }

    class Coordinator: NSObject, NSTextViewDelegate {
        var text: Binding<String>

        init(text: Binding<String>) {
            self.text = text
        }

        func textDidChange(_ notification: Notification) {
            guard let textView = notification.object as? NSTextView else { return }
            text.wrappedValue = textView.string
            // Re-highlight the edited range efficiently
            YAMLHighlighter.highlight(textView.textStorage!)
        }
    }
}

// MARK: - YAML Syntax Highlighter

private enum YAMLHighlighter {
    static let baseFont = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)

    // Colors (work in both light and dark mode)
    static let keyColor = NSColor.systemBlue
    static let stringColor = NSColor.systemGreen
    static let commentColor = NSColor.systemGray
    static let numberColor = NSColor.systemOrange
    static let boolColor = NSColor.systemPurple
    static let defaultColor = NSColor.labelColor

    // Regex patterns (compiled once)
    static let commentPattern = try! NSRegularExpression(pattern: "#.*$", options: .anchorsMatchLines)
    static let keyPattern = try! NSRegularExpression(pattern: "^(\\s*-?\\s*)([\\w][\\w\\s.-]*)(?=\\s*:)", options: .anchorsMatchLines)
    static let stringDoublePattern = try! NSRegularExpression(pattern: "\"[^\"\\\\]*(?:\\\\.[^\"\\\\]*)*\"")
    static let stringSinglePattern = try! NSRegularExpression(pattern: "'[^']*'")
    static let numberPattern = try! NSRegularExpression(pattern: "(?<=:\\s)\\d+(?:\\.\\d+)?\\s*$", options: .anchorsMatchLines)
    static let boolPattern = try! NSRegularExpression(pattern: "(?<=:\\s)(true|false|yes|no|null)\\s*$", options: [.anchorsMatchLines, .caseInsensitive])

    static func highlight(_ textStorage: NSTextStorage) {
        let fullRange = NSRange(location: 0, length: textStorage.length)
        let string = textStorage.string

        textStorage.beginEditing()

        // Reset to default
        textStorage.addAttributes([
            .font: baseFont,
            .foregroundColor: defaultColor,
        ], range: fullRange)

        // Keys (before colon)
        keyPattern.enumerateMatches(in: string, range: fullRange) { match, _, _ in
            guard let match, match.numberOfRanges > 2 else { return }
            textStorage.addAttribute(.foregroundColor, value: keyColor, range: match.range(at: 2))
        }

        // Double-quoted strings
        stringDoublePattern.enumerateMatches(in: string, range: fullRange) { match, _, _ in
            guard let match else { return }
            textStorage.addAttribute(.foregroundColor, value: stringColor, range: match.range)
        }

        // Single-quoted strings
        stringSinglePattern.enumerateMatches(in: string, range: fullRange) { match, _, _ in
            guard let match else { return }
            textStorage.addAttribute(.foregroundColor, value: stringColor, range: match.range)
        }

        // Numbers (after colon)
        numberPattern.enumerateMatches(in: string, range: fullRange) { match, _, _ in
            guard let match else { return }
            textStorage.addAttribute(.foregroundColor, value: numberColor, range: match.range)
        }

        // Booleans/null (after colon)
        boolPattern.enumerateMatches(in: string, range: fullRange) { match, _, _ in
            guard let match else { return }
            textStorage.addAttribute(.foregroundColor, value: boolColor, range: match.range)
        }

        // Comments (last — overrides everything)
        commentPattern.enumerateMatches(in: string, range: fullRange) { match, _, _ in
            guard let match else { return }
            textStorage.addAttribute(.foregroundColor, value: commentColor, range: match.range)
        }

        textStorage.endEditing()
    }
}
