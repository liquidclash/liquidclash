import Foundation
import Observation

// MARK: - Clash Manager

@Observable
final class ClashManager {
    var isRunning = false
    var logOutput: [String] = []

    private var process: Process?
    private var outputPipe: Pipe?
    private var privilegedMode = false
    private var privilegedPID: Int32?

    /// Possible binary locations (checked in order)
    private var binarySearchPaths: [URL] {
        let appSupport = ConfigStorage.shared.appSupportDirectory
        var paths = [
            appSupport.appendingPathComponent("bin/mihomo"),
            appSupport.appendingPathComponent("bin/clash"),
        ]
        // Also check in app bundle
        if let bundled = Bundle.main.url(forResource: "mihomo", withExtension: nil) {
            paths.insert(bundled, at: 0)
        }
        if let bundled = Bundle.main.url(forResource: "clash", withExtension: nil) {
            paths.insert(bundled, at: 1)
        }
        // Check /usr/local/bin as fallback
        paths.append(URL(fileURLWithPath: "/usr/local/bin/mihomo"))
        paths.append(URL(fileURLWithPath: "/usr/local/bin/clash"))
        return paths
    }

    /// Find the mihomo/clash binary
    func findBinary() -> URL? {
        let fm = FileManager.default
        for path in binarySearchPaths {
            if fm.isExecutableFile(atPath: path.path) {
                return path
            }
        }
        return nil
    }

    /// Config directory for mihomo
    var configDirectory: URL {
        let dir = ConfigStorage.shared.appSupportDirectory.appendingPathComponent("config", isDirectory: true)
        if !FileManager.default.fileExists(atPath: dir.path) {
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        }
        return dir
    }

    /// Main config file path
    var configFilePath: URL {
        configDirectory.appendingPathComponent("config.yaml")
    }

    // MARK: - Geodata

    /// Copy bundled geodata files (MMDB, geoip.dat, geosite.dat) to config directory
    /// so mihomo doesn't need to download them on first launch.
    private func ensureGeodataFiles() {
        let fm = FileManager.default
        let geodataFiles = ["country.mmdb", "geoip.dat", "geosite.dat"]
        for filename in geodataFiles {
            let dest = configDirectory.appendingPathComponent(filename)
            guard !fm.fileExists(atPath: dest.path) else { continue }
            if let bundled = Bundle.main.url(forResource: filename.components(separatedBy: ".").first,
                                              withExtension: filename.components(separatedBy: ".").last) {
                try? fm.copyItem(at: bundled, to: dest)
            }
        }
    }

    // MARK: - Start

    /// Start mihomo with raw subscription YAML (preferred) or generated config
    func start(config: ClashConfig, rawSubscriptionYAML: String? = nil) throws {
        guard !isRunning else { return }

        guard let binary = findBinary() else {
            throw ClashError.binaryNotFound
        }

        ensureGeodataFiles()

        // Write config file: prefer raw YAML with settings overlay
        if let rawYAML = rawSubscriptionYAML, !rawYAML.isEmpty {
            try writeConfigFromRawYAML(rawYAML, config: config)
        } else {
            try writeConfigYAML(config)
        }

        let proc = Process()
        proc.executableURL = binary
        proc.arguments = ["-d", configDirectory.path]

        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = pipe

        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty, let line = String(data: data, encoding: .utf8) else { return }
            DispatchQueue.main.async {
                self?.logOutput.append(contentsOf: line.components(separatedBy: .newlines).filter { !$0.isEmpty })
                // Keep only last 500 lines
                if let count = self?.logOutput.count, count > 500 {
                    self?.logOutput.removeFirst(count - 500)
                }
            }
        }

        proc.terminationHandler = { [weak self] _ in
            DispatchQueue.main.async {
                self?.isRunning = false
                self?.process = nil
            }
        }

        try proc.run()
        process = proc
        outputPipe = pipe
        isRunning = true
    }

    // MARK: - Start with Privileges (for TUN mode)

    /// Start mihomo with root privileges via osascript (required for TUN)
    func startWithPrivileges(config: ClashConfig, rawSubscriptionYAML: String? = nil) throws {
        guard !isRunning else { return }

        guard let binary = findBinary() else {
            throw ClashError.binaryNotFound
        }

        ensureGeodataFiles()

        // Write config file with TUN enabled
        var tunConfig = config
        tunConfig.tunEnabled = true
        if let rawYAML = rawSubscriptionYAML, !rawYAML.isEmpty {
            try writeConfigFromRawYAML(rawYAML, config: tunConfig)
        } else {
            try writeConfigYAML(tunConfig)
        }

        // Launch with admin privileges via osascript
        let binaryPath = binary.path.replacingOccurrences(of: "'", with: "'\\''")
        let configDir = configDirectory.path.replacingOccurrences(of: "'", with: "'\\''")
        let shellCmd = "'\(binaryPath)' -d '\(configDir)' &> /dev/null & echo $!"

        let script = "do shell script \"\(shellCmd.replacingOccurrences(of: "\"", with: "\\\""))\" with administrator privileges"

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        proc.arguments = ["-e", script]
        let outPipe = Pipe()
        let errPipe = Pipe()
        proc.standardOutput = outPipe
        proc.standardError = errPipe
        try proc.run()
        proc.waitUntilExit()

        if proc.terminationStatus != 0 {
            let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
            let errMsg = String(data: errData, encoding: .utf8) ?? ""
            if errMsg.contains("canceled") || errMsg.contains("User canceled") {
                throw ClashError.startFailed("Administrator privileges denied")
            }
            throw ClashError.startFailed(errMsg.trimmingCharacters(in: .whitespacesAndNewlines))
        }

        // Read the PID from osascript output (from "echo $!")
        let pidData = outPipe.fileHandleForReading.readDataToEndOfFile()
        if let pidStr = String(data: pidData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
           let pid = Int32(pidStr) {
            privilegedPID = pid
        }

        privilegedMode = true
        isRunning = true
    }

    // MARK: - Stop

    func stop() {
        if privilegedMode {
            // TUN mode: process runs as root, kill by PID or fallback to pkill
            if let pid = privilegedPID {
                kill(pid, SIGTERM)
                // Brief wait for graceful shutdown
                usleep(500_000)
                // Force kill if still alive
                kill(pid, SIGKILL)
            } else {
                // Fallback: pkill (less precise)
                let proc = Process()
                proc.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
                proc.arguments = ["-f", "mihomo"]
                proc.standardOutput = FileHandle.nullDevice
                proc.standardError = FileHandle.nullDevice
                try? proc.run()
                proc.waitUntilExit()
            }
            privilegedPID = nil
            privilegedMode = false
        } else if let proc = process {
            proc.terminate()
            proc.waitUntilExit()
        }
        outputPipe?.fileHandleForReading.readabilityHandler = nil
        process = nil
        outputPipe = nil
        isRunning = false
    }

    // MARK: - Rewrite Config (for hot reload without restarting process)

    /// Rewrite config.yaml on disk without restarting the process.
    /// Used together with ClashAPI.reloadConfig() for hot reloading.
    func rewriteConfig(config: ClashConfig, rawSubscriptionYAML: String? = nil) throws {
        if let rawYAML = rawSubscriptionYAML, !rawYAML.isEmpty {
            try writeConfigFromRawYAML(rawYAML, config: config)
        } else {
            try writeConfigYAML(config)
        }
    }

    // MARK: - Write Config from Raw Subscription YAML

    /// Merge raw subscription YAML with local settings and write to config file.
    /// The raw YAML already has proxies, proxy-groups, and rules from the subscription.
    /// We only override network settings (port, allow-lan, external-controller, mode).
    private func writeConfigFromRawYAML(_ rawYAML: String, config: ClashConfig) throws {
        var lines = rawYAML.components(separatedBy: .newlines)

        // Settings to override in the raw YAML
        let overrides: [String: String] = [
            "port": "\(config.port)",
            "socks-port": "\(config.socksPort)",
            "mixed-port": "\(config.mixedPort)",
            "allow-lan": "\(config.allowLan)",
            "mode": config.mode,
            "log-level": config.logLevel,
            "external-controller": "'\(config.externalController)'",
        ]

        // Replace existing TOP-LEVEL settings only (lines with no leading whitespace)
        var appliedKeys: Set<String> = []
        for i in lines.indices {
            let line = lines[i]
            // Skip indented lines (nested YAML keys like proxy port, ws-opts port, etc.)
            guard !line.isEmpty, !line.hasPrefix(" "), !line.hasPrefix("\t") else { continue }
            for (key, value) in overrides {
                if line.hasPrefix("\(key):") {
                    lines[i] = "\(key): \(value)"
                    appliedKeys.insert(key)
                }
            }
        }

        // Prepend any settings not found in the raw YAML
        var header = "# LiquidClash config overlay\n"
        for (key, value) in overrides where !appliedKeys.contains(key) {
            header += "\(key): \(value)\n"
        }

        // Add secret if needed
        if !config.secret.isEmpty && !rawYAML.contains("secret:") {
            header += "secret: '\(config.secret)'\n"
        }

        // Add TUN config if enabled
        if config.tunEnabled && !rawYAML.contains("tun:") {
            header += """
            tun:
              enable: true
              stack: system
              auto-route: true
              auto-detect-interface: true
            
            """
        }

        let finalYAML = header + "\n" + lines.joined(separator: "\n")
        try finalYAML.write(to: configFilePath, atomically: true, encoding: .utf8)
    }

    // MARK: - Write Config YAML (fallback for manual nodes)

    private func writeConfigYAML(_ config: ClashConfig) throws {
        var yaml = """
        # LiquidClash generated config
        port: \(config.port)
        socks-port: \(config.socksPort)
        mixed-port: \(config.mixedPort)
        allow-lan: \(config.allowLan)
        mode: \(config.mode)
        log-level: \(config.logLevel)
        external-controller: '\(config.externalController)'
        
        """

        if !config.secret.isEmpty {
            yaml += "secret: '\(config.secret)'\n"
        }

        if config.tunEnabled {
            yaml += """
            tun:
              enable: true
              stack: system
              auto-route: true
              auto-detect-interface: true
            
            """
        }

        // Proxies
        if !config.proxies.isEmpty {
            yaml += "\nproxies:\n"
            for node in config.proxies {
                yaml += "  - name: \"\(node.name)\"\n"
                yaml += "    type: \(node.type.rawValue)\n"
                yaml += "    server: \(node.server)\n"
                yaml += "    port: \(node.port)\n"
                if let password = node.password, !password.isEmpty {
                    yaml += "    password: \"\(password)\"\n"
                }
                if let uuid = node.uuid, !uuid.isEmpty {
                    yaml += "    uuid: \(uuid)\n"
                }
                if let cipher = node.cipher, !cipher.isEmpty {
                    yaml += "    cipher: \(cipher)\n"
                }
                if let alterId = node.alterId {
                    yaml += "    alterId: \(alterId)\n"
                }
                yaml += "    udp: \(node.udp)\n"
                // TLS / transport parameters
                if let sni = node.sni, !sni.isEmpty {
                    yaml += "    sni: \(sni)\n"
                }
                if let scv = node.skipCertVerify, scv {
                    yaml += "    skip-cert-verify: true\n"
                }
                if let tls = node.tls, tls {
                    yaml += "    tls: true\n"
                }
                if let net = node.network, !net.isEmpty {
                    yaml += "    network: \(net)\n"
                    if net == "ws" {
                        yaml += "    ws-opts:\n"
                        if let path = node.wsPath, !path.isEmpty {
                            yaml += "      path: \"\(path)\"\n"
                        }
                        if let host = node.wsHost, !host.isEmpty {
                            yaml += "      headers:\n"
                            yaml += "        Host: \(host)\n"
                        }
                    }
                }
            }
        }

        // Proxy Groups
        if !config.proxyGroups.isEmpty {
            yaml += "\nproxy-groups:\n"
            for group in config.proxyGroups {
                yaml += "  - name: \"\(group.name)\"\n"
                yaml += "    type: \(group.type.rawValue)\n"
                if let url = group.url {
                    yaml += "    url: \"\(url)\"\n"
                }
                if let interval = group.interval {
                    yaml += "    interval: \(interval)\n"
                }
                yaml += "    proxies:\n"
                for proxy in group.proxies {
                    yaml += "      - \"\(proxy)\"\n"
                }
            }
        }

        // Rules
        if !config.rules.isEmpty {
            yaml += "\nrules:\n"
            for rule in config.rules {
                yaml += "  - \(rule)\n"
            }
        }

        try yaml.write(to: configFilePath, atomically: true, encoding: .utf8)
    }
}

// MARK: - Clash Error

enum ClashError: LocalizedError {
    case binaryNotFound
    case configWriteFailed
    case startFailed(String)

    var errorDescription: String? {
        switch self {
        case .binaryNotFound:
            "找不到 mihomo 核心文件"
        case .configWriteFailed:
            "配置文件写入失败"
        case .startFailed(let msg):
            "核心启动失败：\(msg)"
        }
    }
}
