import Foundation

private var failures = 0

private func expectAllowed(_ raw: String) {
    let result = SubscriptionURLPolicy.validate(raw)
    guard case .success = result else {
        failures += 1
        FileHandle.standardError.write(Data("expected allowed: \(raw), got \(result)\n".utf8))
        return
    }
}

private func expectBlocked(_ raw: String) {
    guard case .failure = SubscriptionURLPolicy.validate(raw) else {
        failures += 1
        FileHandle.standardError.write(Data("expected blocked: \(raw)\n".utf8))
        return
    }
}

expectAllowed("https://subscriptions.example.com/path?token=secret")
expectAllowed("HTTPS://EXAMPLE.COM.:443/subscription")
expectAllowed("https://8.8.8.8/subscription")
expectAllowed("https://[2606:4700:4700::1111]/subscription")
expectAllowed("https://xn--bcher-kva.example/subscription")

[
    "",
    "not a URL",
    "http://example.com/subscription",
    "https://user:password@example.com/subscription",
    "https://example.com:8443/subscription",
    "https://localhost/subscription",
    "https://service.local/subscription",
    "https://service.internal/subscription",
    "https://router.lan/subscription",
    "https://host.home.arpa/subscription",
    "https://singlelabel/subscription",
    "https://-bad.example/subscription",
    "https://bad-.example/subscription",
    "https://bad..example/subscription",
    "https://[fe80::1%25en0]/subscription",
].forEach(expectBlocked)

[
    "0.0.0.0", "0.1.2.3", "10.0.0.1", "100.64.0.1", "100.127.255.254",
    "127.0.0.1", "169.254.169.254", "172.16.0.1", "172.31.255.255",
    "192.0.0.1", "192.0.2.1", "192.88.99.1", "192.168.1.1",
    "198.18.0.1", "198.19.255.255", "198.51.100.1", "203.0.113.1",
    "224.0.0.1", "240.0.0.1", "255.255.255.255",
].forEach { expectBlocked("https://\($0)/subscription") }

[
    "::", "::1", "::ffff:127.0.0.1", "::ffff:169.254.169.254",
    "::ffff:192.168.1.1", "64:ff9b::c0a8:101", "100::1",
    "2001::1", "2001:db8::1", "2002:c0a8:101::1", "3fff::1",
    "fc00::1", "fd00::1", "fe80::1", "ff02::1",
].forEach { expectBlocked("https://[\($0)]/subscription") }

guard failures == 0 else {
    exit(1)
}
print("SubscriptionURLPolicy tests passed")
