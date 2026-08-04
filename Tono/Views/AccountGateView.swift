#if DEBUG
import AuthenticationServices
#endif
import SwiftUI
import AppKit

struct AccountGateView<Content: View>: View {
    @Bindable var session: AccountSession
    @ViewBuilder let content: () -> Content

    var body: some View {
        Group {
            if session.state == .ready {
                // ContentView owns its background. Keeping the account-gate
                // visual-effect view underneath it doubled the live desktop
                // blur cost for the entire connected session.
                content()
            } else if session.state == .restoring {
                ZStack {
                    // Paint the real application shell immediately while the
                    // authenticated session is validated. Controls stay inert,
                    // but launch no longer feels like a blank blocking screen.
                    content()
                        .allowsHitTesting(false)
                        .accessibilityHidden(true)

                    Rectangle()
                        .fill(.black.opacity(0.08))
                        .ignoresSafeArea()

                    HStack(spacing: 10) {
                        ProgressView()
                            .controlSize(.small)
                        Text("Restoring your Tono session…")
                            .font(.system(size: 13, weight: .medium))
                    }
                    .padding(.horizontal, 18)
                    .padding(.vertical, 12)
                    .glassEffect(.regular, in: Capsule())
                    .shadow(color: .black.opacity(0.12), radius: 18, y: 8)
                }
            } else {
                ZStack {
                    // Account states are displayed before ContentView exists,
                    // so they need their own full-window background.
                    MeshGradientBackground()

                    Group {
                        switch session.state {
                        case .restoring:
                            EmptyView()
                        case .signedOut, .authenticating, .error:
                            LoginView(session: session)
                        case .enrolling:
                            ProgressView("Enrolling this Mac with Tono…")
                        case .suspended:
                            ContentUnavailableView(
                                "Tono account suspended",
                                systemImage: "exclamationmark.shield",
                                description: Text("Contact your administrator to restore access.")
                            )
                        case .ready:
                            EmptyView()
                        }
                    }
                }
            }
        }
    }
}

struct LoginView: View {
    @Bindable var session: AccountSession
    @State private var email = ""
    @State private var emailCode = ""
    @State private var deviceName = Host.current().localizedName ?? "Mac"
    @State private var restoredInternetFromGate = false

    private var busy: Bool { session.state == .authenticating }
    private var error: String? { if case let .error(message) = session.state { message } else { nil } }
    private var methods: TonoAuthMethodsResponse? { session.authMethods }
    private var nativeAppleSignInEnabled: Bool {
        #if DEBUG
        methods?.apple.enabled == true
        #else
        false
        #endif
    }
    private var nativeGoogleSignInEnabled: Bool {
        #if DEBUG
        methods?.google.enabled == true
        #else
        false
        #endif
    }

    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "network.badge.shield.half.filled").font(.system(size: 42)).foregroundStyle(.tint)
            Text("Welcome to Tono").font(.title.bold())
            Text("Sign in with a verified email to continue. No password is required.")
                .foregroundStyle(.secondary).multilineTextAlignment(.center)

            if session.isAtDeviceLimit {
                Label("Your \(session.deviceLimit)-device allowance is full. Sign in and revoke another device if needed.", systemImage: "desktopcomputer.trianglebadge.exclamationmark")
                    .font(.callout).foregroundStyle(.orange)
            }
            if let error { Text(error).font(.callout).foregroundStyle(.red).multilineTextAlignment(.center) }

            if session.user != nil {
                Button("Retry Tono connection") { Task { await session.retryRuntime() } }
                    .buttonStyle(.borderedProminent)
                Button("Sign Out", role: .destructive) { Task { await session.logout() } }
            } else {
                Form {
                    TextField("Device name", text: $deviceName)
                }

                if let methods {
                    if methods.email.enabled {
                        VStack(spacing: 10) {
                            TextField("Email", text: $email)
                            if session.emailChallenge != nil {
                                TextField("Six-digit email code", text: $emailCode)
                                    .textContentType(.oneTimeCode)
                                Button {
                                    Task { await session.verifyEmailCode(emailCode) }
                                } label: {
                                    busyLabel("Verify email code")
                                }
                                .buttonStyle(.borderedProminent)
                                .controlSize(.large)
                                .disabled(busy)
                            }
                            Button(session.emailChallenge == nil ? "Email me a sign-in code" : "Send a new code") {
                                Task {
                                    await session.requestEmailCode(
                                        email: email,
                                        deviceName: deviceName
                                    )
                                }
                            }
                            .buttonStyle(.borderedProminent)
                            .controlSize(.large)
                            .disabled(busy)
                            if session.emailChallenge != nil {
                                Text("If this address is eligible, the code is valid for 10 minutes.")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }

                    if nativeAppleSignInEnabled || nativeGoogleSignInEnabled {
                        HStack {
                            Divider()
                            Text("or").font(.caption).foregroundStyle(.secondary)
                            Divider()
                        }
                        .frame(height: 18)
                    }

                    #if DEBUG
                    if nativeAppleSignInEnabled {
                        TonoAppleSignInButton {
                            Task {
                                await session.signInWithApple(
                                    deviceName: deviceName
                                )
                            }
                        }
                        .frame(height: 42)
                        .disabled(busy)
                    }

                    if nativeGoogleSignInEnabled {
                        Button {
                            Task {
                                await session.signInWithGoogle(
                                    deviceName: deviceName
                                )
                            }
                        } label: {
                            HStack {
                                Image(systemName: "globe")
                                busyLabel("Sign in with Google")
                            }
                            .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.large)
                        .disabled(busy)
                    }
                    #endif

                    if !methods.email.enabled && !nativeAppleSignInEnabled && !nativeGoogleSignInEnabled {
                        ContentUnavailableView(
                            "No sign-in method configured",
                            systemImage: "person.crop.circle.badge.exclamationmark",
                            description: Text("Configure email sign-in in the Tono control plane.")
                        )
                    }
                } else {
                    if error == nil {
                        ProgressView("Loading secure sign-in options…")
                    } else {
                        Label("Secure sign-in service is unavailable", systemImage: "network.slash")
                            .font(.callout.weight(.medium))
                            .foregroundStyle(.secondary)
                    }
                    Button("Retry") { Task { await session.retryRestore() } }
                        .disabled(busy || error == nil)
                    if error != nil {
                        // A launch failure at the gate is exactly when runtime
                        // logs don't exist yet; the local audit log is the only
                        // record of what went wrong and needs no network or
                        // signed-in session to share with support.
                        Button("Show Diagnostics Log in Finder") {
                            let url = LocalTrafficAudit.shared.prepareForReveal()
                            NSWorkspace.shared.activateFileViewerSelecting([url])
                        }
                        .buttonStyle(.link)
                        .font(.caption)
                    }
                }
                if KillSwitchService.isArmed, !restoredInternetFromGate {
                    // A fail-closed host whose session cannot reach .ready
                    // (crash recovery + unreachable control plane) previously
                    // had NO restore-internet control anywhere: the dashboard
                    // needs .ready and the menu-bar toggle is disabled. This
                    // is the explicit escape hatch. isArmed is a plain static
                    // (not observable), so the local flag forces the section
                    // to update once the restore completes.
                    Divider().padding(.vertical, 4)
                    Label(
                        "Kill Switch is blocking direct Internet from an earlier session.",
                        systemImage: "shield.slash"
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    Button("Restore internet (turn off protection)") {
                        Task {
                            await session.restoreDirectInternet()
                            restoredInternetFromGate = !KillSwitchService.isArmed
                        }
                    }
                    .disabled(busy)
                }
            }
        }
        .padding(32)
        .frame(width: 470)
        .task {
            if session.authMethods == nil && session.user == nil {
                await session.loadAuthMethods()
            }
        }
    }

    @ViewBuilder
    private func busyLabel(_ title: String) -> some View {
        HStack {
            if busy { ProgressView().controlSize(.small) }
            Text(title)
        }
        .frame(maxWidth: .infinity)
    }
}

#if DEBUG
@MainActor
private struct TonoAppleSignInButton: NSViewRepresentable {
    typealias Action = @MainActor @Sendable () -> Void
    let action: Action

    func makeCoordinator() -> Coordinator {
        Coordinator(action: action)
    }

    func makeNSView(context: Context) -> ASAuthorizationAppleIDButton {
        let button = ASAuthorizationAppleIDButton(type: .signIn, style: .black)
        button.target = context.coordinator
        button.action = #selector(Coordinator.performAction)
        return button
    }

    func updateNSView(_ nsView: ASAuthorizationAppleIDButton, context: Context) {
        context.coordinator.action = action
    }

    @MainActor
    final class Coordinator: NSObject {
        var action: Action

        init(action: @escaping Action) {
            self.action = action
        }

        @objc func performAction() {
            action()
        }
    }
}
#endif
