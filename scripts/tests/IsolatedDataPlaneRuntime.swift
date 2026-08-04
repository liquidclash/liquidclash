import Foundation

// ConfigPipeline only needs this value contract; the product definition lives
// in TonoSidecarService.swift.
nonisolated struct TonoTransportDescriptor: Sendable, Equatable {
    let host: String
    let port: UInt16
    let username: String?
    let password: String?
    let udp: Bool

    init(
        host: String = "127.0.0.1",
        port: UInt16,
        username: String? = nil,
        password: String? = nil,
        udp: Bool = true
    ) {
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.udp = udp
    }
}

private struct TestFailure: LocalizedError {
    let errorDescription: String?
    init(_ message: String) { errorDescription = message }
}

@main
struct IsolatedDataPlaneRuntime {
    static func main() throws {
        guard CommandLine.arguments.count == 4 else {
            throw TestFailure(
                "usage: isolated-runtime input.yaml output.yaml preferred-node"
            )
        }
        let input = URL(fileURLWithPath: CommandLine.arguments[1])
        let output = URL(fileURLWithPath: CommandLine.arguments[2])
        let preferredNode = CommandLine.arguments[3]
        let values = try input.resourceValues(
            forKeys: [.isRegularFileKey, .fileSizeKey]
        )
        guard values.isRegularFile == true,
              let size = values.fileSize,
              size > 0,
              size <= 8 * 1_024 * 1_024 else {
            throw TestFailure("input must be a bounded regular YAML file")
        }

        let source = try String(contentsOf: input, encoding: .utf8)
        let parsed = ConfigParser.parseSubscription(source)
            .filter { $0.type == .vless }
        let nodes = try ConfigPipeline.validatedOwnedNodes(parsed)
        guard !nodes.isEmpty,
              let selected = ConfigPipeline.preferredCloudExit(
                in: nodes,
                named: preferredNode
              ) else {
            throw TestFailure("no validated Reality exit is available")
        }

        let overlay = ConfigPipeline.OverlayConfig(
            mixedPort: 28_790,
            externalController: "127.0.0.1:29090",
            secret: "tono-isolated-test",
            mode: "rule",
            logLevel: "info",
            allowLan: false,
            tunEnabled: false,
            selectedNodeName: selected.name,
            tonoTransport: nil
        )
        let productionRuntime = try ConfigPipeline.buildOwnedTonoRuntime(
            subscriptionYAML: "",
            overlay: overlay,
            transport: nil,
            customNodes: nodes
        )
        let isolatedRuntime = productionRuntime.replacingOccurrences(
            of: "listen: \(ProtectedDNSContract.listener)",
            with: "listen: 127.0.0.1:21053"
        )
        guard !isolatedRuntime.contains("\ntun:"),
              isolatedRuntime.contains("\n  listen: 127.0.0.1:21053\n"),
              isolatedRuntime.contains("\n  - MATCH,Tono-Exit") else {
            throw TestFailure("isolated runtime retained a system-network mutation")
        }
        try Data(isolatedRuntime.utf8).write(to: output, options: .atomic)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: output.path
        )
        print("isolated runtime selected: \(selected.name)")
    }
}
