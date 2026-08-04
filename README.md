# Tono 0.0.1

Tono is a native Apple Silicon macOS client for authenticated, cloud-managed
VLESS Reality exits. It owns the complete Mihomo runtime and combines a
mandatory TUN with a persistent macOS PF Kill Switch.

The current production profile is intentionally narrow:

- US Reality is the deterministic default; US and JP Reality remain
  independently selectable.
- Only TCP-carried VLESS Reality nodes with a public IPv4 endpoint, valid UUID,
  SNI, Reality public key, and short ID are accepted.
- Home-US, Tailscale enrollment, third-party subscriptions, custom nodes, and
  editable production rules are disabled.
- The app bundle embeds only the signed Mihomo executable and Tono's signed
  privileged helper. It does not embed `tailscale` or `tailscaled`.
- TUN, Rule mode, and `allow-lan: false` are enforced by the owned runtime.

## Runtime contract

After email-code authentication, Tono loads the last verified encrypted-control-
plane catalog cache immediately and refreshes it in the background. Catalog
updates are bounded, SHA-256 verified, monotonic by revision, parsed outside the
main actor, and re-serialized into Tono's own runtime policy. Imported YAML
cannot supply TUN, DNS, controller, rules, or direct-fallback policy.

A normal signed-in launch waits for an explicit Connect action. If a prior
process crashed while protection was armed, PF remains fail-closed and Tono
automatically resumes the previously selected protected exit after validating
the account and cached catalog.

The connection sequence is:

1. Arm PF for only the selected public IPv4/TCP endpoint.
2. Generate, hash, and securely copy the owned runtime through the authenticated
   root helper. Its TUN route exclusions contain the bounded, validated cloud
   catalog so the route fingerprint stays stable across node selections; those
   routes grant no egress permission by themselves.
3. Start Mihomo and wait for its local controller.
4. Verify the exact owned `utun199`, then allow only that TUN plus the selected
   endpoint.
5. Probe the selected Reality route. The UI becomes Connected only after the
   probe succeeds.

Node switching first replaces the PF endpoint, then changes Mihomo's selector,
closes old connections, and verifies the new route. A failed switch stops the
core and keeps PF armed; it never falls back to the old node or direct Internet.

## Fail-closed behavior

| Event | Mihomo/TUN | Kill Switch | Host network |
|---|---|---|---|
| Connect succeeds | Running | Armed | Selected Reality exit |
| Connect or switch fails | Stopped | Armed | Blocked |
| TUN disappears | Stopped/retried | Armed | Blocked |
| Reality health fails twice | Stopped/retried | Armed | Blocked |
| Force-quit while connected | Stopped by recovery | Armed | Blocked until protected recovery |
| User Disconnect / Sign Out / Quit | Stopped first | Disarmed | Normal |
| Core refuses to stop | May remain running | Armed | Blocked; error shown |

The helper authenticates the caller's kernel audit token, bundle identifier
`com.raydocs.tono`, Team ID `YY57758GS7`, and configured user UID. Runtime YAML
is bound to an in-memory SHA-256 and copied to a root-owned directory before
Mihomo can use it. PF exceptions are exact public IPv4/TCP endpoint tuples;
IPv6 and broad UDP/443 exceptions are not opened.

Emergency recovery:

```sh
sudo /Library/PrivilegedHelperTools/tono-core-helper --emergency-disarm
```

This stops Tono's owned core and removes only Tono's PF state and managed host
mappings.

## Performance and UI behavior

- Disk parsing, catalog validation, runtime generation, persistence, helper
  calls, PF changes, and system-proxy work run away from SwiftUI's main actor.
- The real application shell paints while session restoration is in progress.
- Catalog and account requests use bounded launch-time timeouts; device
  inventory and catalog refresh do not hold the first usable dashboard.
- Connections and logs stream only while their pages are visible. Log mutations
  are coalesced to at most ten UI updates per second.
- Node switches replace the exact PF endpoint and update Mihomo's live selector;
  they preserve the existing gVisor/TUN instance instead of synchronously
  rewriting and reloading the full runtime.
- The current experimental Mihomo build replaces its fixed 20 KiB gVisor TCP
  buffers with a bounded adaptive 4 KiB / 32 KiB / 128 KiB range. The exact
  upstream build and one-command rollback are documented in
  `scripts/mihomo-adaptive/README.md`.
- There are no perpetual decorative animations. Expensive blur/transparency
  changes are committed when slider interaction finishes.

## Repository layout

- `Tono/` — SwiftUI app, owned runtime generator, helper client, and UI
- `scripts/core-helper/main.swift` — privileged helper implementation
- `scripts/tests/` — Reality policy and helper tests
- `cloudflare/` — staging account and encrypted catalog control plane
- `home-agent/` — retained legacy Home usage-agent source; not part of the
  current app path or bundle

Legacy Home/Tailscale source remains in the repository for audit history and
future isolated development. `AppProfile.homeExitEnabled` is false and the
Release bundle must contain none of its executables.

## Build and verify

The current project version is build 37. It targets Apple Silicon and macOS
26.3 or newer.

Build 37 is a seven-day, remotely reversible exact-host China direct trial. A
reviewed Tencent endpoint is eligible for native WeChat only when Mihomo
attributes the socket to WeChat's exact official `/Applications` executable
path. Sixteen exact web hostnames for Bilibili, Tencent Video, iQIYI, and Youku
are also eligible for browser DIRECT; there are no suffix, wildcard, GEOIP-CN,
or general domestic-web DIRECT rules. Claude App/Code and Anthropic's official
domains retain explicit proxy precedence, but a browser cannot isolate traffic
by tab, so an opened trial video hostname may see the mainland exit. The cloud
policy can disable the web trial independently or stop all exact China DIRECT
without a client update. The opted-in research snapshot reports aggregate
WeChat and exact-web direct counts alongside a dedicated protected-Claude DIRECT
violation count for this canary. The PF helper retains build 36's root-only
Tailscale DERP restriction and exact direct endpoint boundary.

Build 37 retains build 36's separately opted-in Claude research snapshot with
global proxy/direct/blocked counts, process-attribution coverage, TUN/Kill
Switch/protected-DNS state, and two fixed leak probes. One compares the ordinary
system-TUN exit to Mihomo's explicit proxy; the other uses Darwin `IP_BOUND_IF`
to verify that a baseline-reachable HTTPS endpoint cannot be reached through
the physical interface. Only strict verdict enums go to the control plane;
raw probe IPs stay in the local mode-0600 audit. The channel still accepts no
scripts, commands, URLs, paths, or general parameters; results are device-bound,
expiring and capped at 2 KiB. Sleep pauses both this channel and catalog/policy
polling. Build 37 also retains build 35's bounded helper socket probe retry and
root-owned helper version fallback.

Build 34 embeds Sparkle 2.9.4 for in-app updates. Release builds check the
Cloudflare-hosted appcast every six hours, notify the user before installation,
and accept only an archive signed by Tono's private Ed25519 update key. Sparkle
does not start in Debug builds or when the Release app is opened outside
`/Applications`, and silent automatic installation is disabled so Tono's
ordered core, DNS, and Kill Switch shutdown remains visible and fail-closed.
The application menu and Settings About card both expose a manual update check.

It retains build 33's dedicated 30-second timeout for the remaining synchronous
catalog/policy config reloads and one bounded, idempotent retry after an
ambiguous local controller timeout. Ordinary node selections now bypass that
reload entirely through the stable TUN route contract. Build 34 also retains
build 32's redesigned high-contrast Tono app icon
and is distributed as a drag-to-Applications disk image. Its Release app does
not start account restoration, the proxy core, update checks, or network
configuration outside `/Applications`; instead, it asks the user to install the
app first.

Build 33 gives Mihomo's synchronous TUN/config reload a dedicated 30-second
timeout and performs one bounded, idempotent retry after an ambiguous local
controller timeout. This prevents a successfully applied node switch from
being misreported as failed while preserving fail-closed behavior for genuine
errors. It also extends control-plane timeouts for mainland cross-border networks,
waits through brief connectivity transitions, and retries failed requests only
when replay is safe. It retains build 29's visible weak-network transitions
instead of presenting an
indefinite loading state: the dashboard shows each protection step, per-step
and total elapsed time, the exact failed step, retry attempt/countdown, and
explicit retry or normal-network recovery actions. Exit and signed-in-user TUN
checks overlap where safe, but both remain mandatory before Connected; sleep,
wake, hotspot changes, and automatic retries continue to retain fail-closed PF
and protected DNS semantics.

```sh
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer

xcodebuild -project LiquidClash.xcodeproj -scheme LiquidClash \
  -configuration Debug -destination 'platform=macOS,arch=arm64' \
  SWIFT_STRICT_CONCURRENCY=complete build

scripts/test-multi-exit-policy.sh \
  "$PWD/scripts/tests/fixtures/multi-vless-reality.yaml"
scripts/test-subscription-url-policy.sh
Tono/Resources/liquidclash-helper --self-test
scripts/test-helper-peer-authorization.sh

(cd cloudflare && npm test && npm run typecheck)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s home-agent -p 'test_*.py' -v
```

Before sharing a friend build:

1. Archive with Developer ID Application signing and the `Tono Developer ID
   2026` provisioning profile.
2. Verify the app, helper, and Mihomo signatures, hardened runtime, Team ID,
   arm64 architecture, and Release entitlements.
3. Reject any bundle containing `tailscale`, `tailscaled`,
   `AuthenticationServices`, `get-task-allow`, or Apple sign-in entitlements.
4. Submit the app to Apple notarization and staple its accepted ticket. Package
   that app in a Developer ID-signed DMG, notarize and staple the DMG too, then
   run Gatekeeper assessment against both layers.
5. Mount the final DMG, copy out a fresh app, repeat strict signature and
   bundle-content checks, and publish the final DMG SHA-256 alongside
   [FRIEND_TESTING.md](FRIEND_TESTING.md).
6. Sign the final update archive with Sparkle's `sign_update` or
   `generate_appcast`, publish it in a non-draft GitHub Release, and deploy the
   generated appcast to `https://api.afk.ccwu.cc/appcast.xml`. Never export the
   private Ed25519 key from the release Mac into this repository.
7. Test both a no-update check and a real update from the previous notarized
   build before publishing the appcast.
8. Complete the clean-Mac crash/reboot, IPv4/IPv6, DNS, disconnect, and US↔JP
   live matrix before treating the candidate as production-ready.

The configured client points to the Cloudflare Business custom domain at
`https://api.afk.ccwu.cc`. Release builds expose email one-time-code sign-in
only; native Apple and Google implementations are Debug-only.

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for bundled dependency
licenses.
