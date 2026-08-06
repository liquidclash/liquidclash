# Tono — Agent Handoff (2026-07-29)

## Paths

- Repository/worktree: `/Users/rw/Downloads/Project/liquidclash`
- macOS app source: `/Users/rw/Downloads/Project/liquidclash/Tono`
- Xcode project: `/Users/rw/Downloads/Project/liquidclash/LiquidClash.xcodeproj`
- Privileged helper source: `/Users/rw/Downloads/Project/liquidclash/scripts/core-helper`
- Cloudflare control plane: `/Users/rw/Downloads/Project/liquidclash/cloudflare`
- Current notarized test DMG:
  `/Users/rw/Downloads/Tono-0.0.1-build13-arm64.dmg`
- DMG SHA-256:
  `bc1022151e38ef59b157f990374af6a5d6e3bd09885f1e8bcd81c51e649a9140`

The project is **not** `/Users/rw/Downloads/Project/tono`. `Tono` is the app
source subdirectory inside the `liquidclash` repository.

## Product requirements from the user

1. Use VLESS Reality only for now.
2. Disable Home-US/Tailscale completely until its bugs are addressed.
3. US Reality must be the default.
4. Both US Reality and JP Reality must be selectable and usable.
5. Startup should be fast.
6. Connection must be fail-closed: a crash, packet loss, timeout, or killed
   core must not expose the real IP or UDP.
7. The friend-test package must be Developer ID signed and Apple notarized.

## Resolved build 12 and build 13 connection bugs

Build 11 installed its helper and started Mihomo successfully, but both Reality
health checks returned HTTP 503. Live debug logs showed:

`remote error: tls: internal error`

The authenticated catalog exactly matched the original US and JP fixtures.
`ConfigParser` retained the Reality server name in `ProxyNode.sni`, but
`ConfigPipeline.ownedNodeYAML` serialized it as `sni`. Mihomo accepts that YAML
syntactically but its VLESS Reality implementation requires `servername`, so
the server rejected authentication.

Build 12 emits `servername`, and the same real health checks then passed:
US Reality 176 ms and JP Reality 446 ms during the final source-generated
runtime verification.

The installed build 12 still failed after creating its TUN because Mihomo's
own selected Reality socket followed the new auto-route into `utun199`. That
recursively sent the proxy's transport back through itself. Build 13 emits an
exact `route-exclude-address` entry for only the selected cloud endpoint.
This is not a direct-network bypass: the root helper's PF policy still permits
only the root-owned Mihomo process to that exact endpoint and port.

Build 13 also retries transactional health checks up to three times. This
prevents a cold Reality handshake from tearing down an otherwise healthy
tunnel. Mihomo `unified-delay` is enabled so the UI reports comparable network
RTT rather than the full protocol handshake duration.

## Changes already made

- Xcode build number is `13`.
- Privileged helper version is `3.2.5`.
- Protected VLESS runtime serialization now emits Mihomo's required
  `servername` field. Generic developer serializers use `servername` for
  VLESS and retain `sni` for other supported protocols.
- The multi-exit regression test rejects a protected runtime that omits
  `servername` or reintroduces `sni`.
- Connection-stage errors now distinguish core failure, protection startup
  failure, and post-start connection-check failure.
- Transactional health checks for initial connect, server switch, and catalog
  replacement use three bounded attempts; steady-state monitoring remains
  fail-closed.
- The selected cloud endpoint is excluded from Mihomo's TUN route. Regression
  tests verify that no unselected server receives that exclusion.
- `unified-delay: true` makes JP report its measured Tokyo RTT (about
  106–108 ms) instead of 448–495 ms of combined Reality and TLS handshakes.
- `HelperManager.installIfNeeded()` tolerates transient
  `launchctl bootstrap` error 5 and polls the authenticated helper version.
- Kill Switch PF rules now include both:

  ```text
  pass in quick on lo0 all keep state
  pass out quick on lo0 all keep state
  ```

- The rule change is limited to the local loopback interface. No inbound
  pass rule was added to Wi-Fi/Ethernet, so the external fail-closed boundary
  was not widened.
- Helper self-tests assert both loopback rules and reject a broad inbound
  rule on an external interface.

Relevant files:

- `scripts/core-helper/KillSwitchManager.swift`
- `scripts/core-helper/main.swift`
- `Tono/Core/HelperManager.swift`
- `Tono/Core/ClashAPI.swift`
- `Tono/Services/AppState.swift`
- `Tono/Core/ConfigPipeline.swift`
- `LiquidClash.xcodeproj/project.pbxproj`

## Diagnostics completed

### Confirmed original PF bug

With the old helper and PF armed, root Mihomo created `utun199` but
`127.0.0.1:9090` was unreachable. With PF disarmed, the controller was
immediately reachable. The original child anchor allowed only outbound
loopback, so the controller response was blocked.

### Confirmed build 9/helper 3.2.4 behavior

After installing helper 3.2.4, a controlled test using the same generated
config and the real Kill Switch succeeded:

- PF armed successfully.
- Root Mihomo started successfully.
- Controller returned
  `{"meta":true,"version":"v1.19.21"}` on polling sample 2 (under one second).
- `utun199` existed and was UP.
- An exact Swift `URLSessionConfiguration.default` reproduction of
  `ClashAPI.waitUntilReady()` also received HTTP 200.
- Test cleanup stopped the core and disarmed PF.

At the last explicit safety check:

- helper version: `3.2.4`
- core running: `false`
- Kill Switch armed/live/wanted: all `false`

### What happened during the user's failed build 9 attempt

Unified logs for 05:47 show Tono made all controller requests on `lo0`, but
each failed with `Connection refused` rather than a PF timeout. No process
was listening on 9090 during that first attempt.

That attempt coincided with the one-time helper replacement:

- old helper bootout at `05:46:48.307`
- helper 3.2.4 launched as PID 56162 immediately afterward

The same config works after the upgrade is complete. This suggests a
first-run helper-upgrade/core lifecycle race or stale child process issue,
not a VLESS configuration failure.

The helper currently sends Mihomo stdout/stderr to `/dev/null`, which makes
an early child failure unnecessarily opaque.

## Another confirmed issue: default node ordering

The generated config after the failed attempt placed JP first:

```yaml
proxy-groups:
  - name: "Tono-Exit"
    type: select
    proxies:
      - "JP-VLESS-Reality"
      - "US-VLESS-Reality"
```

This violates the requirement that US Reality be the default. Correct the
selection/default logic; do not merely rename the UI.

## Tests already passing

```text
./scripts/test-multi-exit-policy.sh \
  /Users/rw/Downloads/Project/liquidclash/scripts/tests/fixtures/multi-vless-reality.yaml
```

Passed for both US Reality and JP Reality, including Mihomo config
validation, one exact selected route exclusion, and unified-delay policy.

Real build 13 validation on the target Mac:

- US Reality reached Connected by the 8-second checkpoint and stayed connected
  through 18 seconds in a controlled 30-second test.
- JP Reality reached Connected by the 8-second checkpoint and stayed connected
  through the 18- and 26-second checkpoints in a controlled 30-second test.
- Reality authentication was true for both selected endpoints.
- Direct JP route measurement reached JPNAP Tokyo at about 105 ms. The
  third-party GeoIP label `Mumbai, IN` is stale for this newly routed prefix.
- Isolated JP tests measured 106–108 ms with Mihomo unified delay. A brand-new
  HTTPS request still takes about 445–472 ms because TCP, Reality, and target
  TLS each add cross-Pacific round trips.
- `smux` was rejected by the current XTLS Vision server and therefore was not
  shipped. TCP Fast Open was compatible but did not reduce measured time.
- Every controlled test automatically stopped Tono/Mihomo and restored direct
  Internet access; the final recovery check returned HTTP 204.

Also passed:

- `./scripts/test-helper-peer-authorization.sh`
- `./scripts/test-subscription-url-policy.sh`
- `npm test` in `cloudflare` — 39/39 tests
- helper `--self-test`
- Xcode Debug build
- Xcode Release archive
- Developer ID signing
- Apple notarization
- stapler validation
- Gatekeeper assessment (`source=Notarized Developer ID`)
- DMG checksum verification, fresh mount, and verification again after a fresh
  app copy

## Recommended next steps

1. Delete build 12, install build 13 from the DMG, and launch only
   `/Applications/Tono.app`.
2. Perform the complete installed-App acceptance flow: connect US, switch to
   JP, disconnect, reconnect, and verify public IP/DNS/IPv6 and fail-closed
   behavior.
3. Preserve the build 13 DMG hash in any distribution message. Do not
   distribute builds 1–12.

## Important worktree warning

The worktree is intentionally dirty. The app source was moved/renamed from
`LiquidClash/` to `Tono/`, so Git currently reports many deleted
`LiquidClash/*` files and an untracked `Tono/` directory. These are existing
user/project changes. Do not reset, checkout, clean, or delete them.

There are multiple old Tono copies under `/Applications` and
`/Users/rw/Documents/Tono Builds`. Always launch and inspect the exact build
path; LaunchServices previously opened an older build unexpectedly.

## Handoff objective

Install build 13 and verify the complete friend-test flow on another Apple
Silicon Mac. Both real nodes now pass live authentication and controlled
30-second connection tests. The build 13 DMG is Developer ID signed, notarized
at both app and DMG layers, stapled, mounted, fresh-copied, checksum-verified,
and Gatekeeper accepted.
