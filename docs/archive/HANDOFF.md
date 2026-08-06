# Tono 0.0.1 engineering handoff

Last reviewed: 2026-07-29 (build 3 r4 catalog retry and diagnostics)

## Read this first

This worktree is intentionally **uncommitted** and no production deployment,
commit, or PR has been created. A staging-only Worker/D1 deployment now exists
at `tono-control-plane-staging.xwwelsamqg.workers.dev`; its secrets are stored
only in Cloudflare and the local macOS Keychain. The repository ACL artifact is
applied to the `ruiruiwan2019@gmail.com` staging tailnet. The designated Mac
Studio is online, tagged `tag:exit-home`, allowed as an exit node, and configured
in `TonoExitNode`. No privileged helper has been installed. Preserve all
existing user changes.

The Worker state machine and client fail-closed paths are substantially
hardened, but this is **not a production-ready release**. The remaining
privileged install/PF, live-tailnet, home-agent deployment, and clean-Mac work
is listed below. A current helper 3.2.2 Developer ID build is notarized only as
a clean-Mac staging test candidate; older notarized artifacts remain
superseded and must not be distributed.

## Product contract (locked)

- macOS-only SwiftUI app **Tono** `0.0.1`, bundle `com.raydocs.tono`.
- Bundled Mihomo + Tailscale userspace sidecar. A signed-in user chooses
  `Home-US` or one authenticated cloud-managed VLESS TLS/Reality exit in the
  owned `Tono-Exit` group; ordinary traffic must enter Mihomo's owned TUN and
  never fall back to direct Internet.
- Allowlisted test-stage accounts are created directly after verified email OTP
  or trusted Apple/Google OIDC; at most two pending/active devices per user.
- Worker + D1 is a control plane only and never relays user proxy traffic.
- **Kill Switch is required:** while armed, a path failure must not fall back to
  direct Internet. Intentional disconnect, logout, or quit may disarm.

## Completed code work

### Control plane and D1

- Tailscale inventory resolution separates the management `id`, API `nodeId`,
  and local stable node ID. Client IDs are never used as Device API path IDs.
- Confirm requires stable ID, public key, and exact address set; the Worker
  verifies pending tag and server inventory before tag promotion.
- Confirm uses a lease plus durable ownership generation, a pre-promotion
  revocation guard, conditional activation, and fenced cleanup jobs.
- Device/user/quota revocation changes D1 state and sessions first, then retries
  Tailscale deletion through the durable outbox. Disabled users cannot be
  re-enabled while live devices or unfinished jobs remain.
- Access authentication re-reads the authoritative user, session, device, and
  installation from D1; signed JWT device/install claims are not trusted as the
  authorization source.
- Password authentication has been replaced with email OTP, Sign in with Apple,
  and Google OIDC. Migration `0009` destroys legacy password verifiers and
  backfills email identities; retired password routes return 410.
- Email codes are server-peppered hashes, expire in ten minutes, allow five
  attempts, bind the installation/device request, and are consumed atomically.
  First sign-in creates an allowlisted account directly after verification;
  start responses do not disclose allowlist membership or whether an existing
  account is disabled.
- Apple/Google ID tokens are verified against fixed provider JWKS endpoints with
  issuer, audience, expiry, issue-time, nonce, subject, and verified-email
  checks. OIDC challenges are single-use; ID tokens are never stored.
- Passwordless start/verify rate limits use atomic D1 updates and hashed
  IP/email/installation/challenge keys.
- Enrollment key issuance is atomic, releases its cooldown after transient
  upstream failure, and is restricted to a short-lived, one-use, ephemeral
  pending tag. Each issuance is bound to an unguessable hostname; signing is
  blocked while a confirm claim is live, and cron deletes superseded pending
  hostnames. A replacement enrollment is not issued until every prior identity
  revocation for that device is durably acknowledged, preventing active-tag
  node accumulation during an upstream DELETE outage.
- Revocation resolves the current ownership generation inside the same D1 batch
  as the outbox/device/session transition, so a concurrent confirm cannot turn a
  successful-looking revoke into a no-op.
- Usage report IDs are immutable idempotency keys: exact replay succeeds,
  conflicting reuse returns 409, and user totals advance monotonically.
- Migration `0010` adds a singleton, revisioned managed-exit catalog. The full
  YAML is AES-256-GCM encrypted with a Worker-only key; authenticated clients
  receive plaintext plus its SHA-256, while the admin API exposes only metadata
  on GET and uses optimistic revision checks for full replacement.
- Migrations `0004`–`0010` cover identity/rate limits, durable claim ownership,
  immutable usage reports, enrollment possession binding, and the indexed
  replacement-enrollment revocation fence, plus passwordless identities and
  one-time challenges and the encrypted catalog.

### Client security boundaries

- Production external-subscription and Add Node UI paths are disabled.
  `tono://install-config` is rejected without retaining or fetching its
  credential-bearing URL. The only production external-node source is the
  authenticated control-plane catalog.
- Catalog responses are streamed into a 2 MiB client bound, verified against
  their SHA-256 and monotonic revision, parsed under the protected node policy,
  and cached only as a regular same-uid `0600` file. A failed, malformed, or
  rolled-back update preserves the last verified cache.
- Tono generates an owned Mihomo runtime; imported YAML cannot supply TUN, DNS,
  rules, controller, or final routing policy. The owned runtime has top-level
  `ipv6: false`; PF independently blocks all non-allowlisted IPv4/IPv6 egress.
- Cloud catalog application atomically replaces the managed region while
  retaining locally existing custom entries for non-destructive migration.
  If the selected cloud node disappears, Mihomo stops, PF remains armed, and
  automatic Home-US fallback is blocked until the user explicitly chooses an
  available node. A safe connected update re-arms PF and reloads the owned
  runtime. Protected mode is intentionally limited to
  at most 200 uniquely named TCP-carried VLESS-over-TLS/Reality nodes with public IPv4
  literal endpoints; it rejects private/reserved/IPv6/hostname servers,
  plaintext VLESS, `skip-cert-verify`, and unaudited protocols.
- The owned `Tono-Exit` selector contains the built-in Home-US SOCKS route plus
  imported nodes. A connected switch re-arms PF for the new exact endpoint
  before selecting it, closes existing Mihomo connections, and stops Mihomo
  while retaining the Kill Switch if the HTTPS health check fails.
- Device enrollment/confirm remains mandatory, but Home-US data-plane health is
  not a gate for the independently managed cloud exits. The authenticated
  catalog is fetched after PF arm and before Home-US startup. If its SOCKS
  health check fails at startup or later, Tono clears the home descriptor,
  stops the sidecar, retains PF, omits Home-US from the owned runtime, and
  selects a validated cloud node. An unavailable catalog/cache still fails
  closed.
- TUN is mandatory and automatically starts once authenticated sidecar state
  and local configuration are both ready. A five-second monitor checks the
  exact Mihomo-owned `utun199`; failure removes the TUN
  exception, keeps PF armed, and retries the same selected exit with bounded
  backoff. Closing the window leaves the menu-bar process running. Explicit
  Disconnect, Sign Out, or Quit still disarms under the locked product
  contract; keeping TUN alive after full process exit requires a future
  background-service lifecycle.
- Enrollment keys are passed to the Tailscale CLI through stdin
  (`--auth-key=file:/dev/stdin`), not argv, environment, or disk.
- Sidecar readiness performs a complete SOCKS5 greeting and CONNECT response,
  with bounded exact reads and a timeout. CLI output/error capture is bounded,
  watchdog-terminated, and closes pipe endpoints if process launch/input fails
  so an unavailable binary cannot hang the sidecar actor.
- One signed native root helper owns both Mihomo and PF. It validates the Unix
  peer's kernel audit token against exact bundle ID `com.raydocs.tono`, Team
  `YY57758GS7`, and the configured UID; same-UID unsigned/wrong-ID clients are
  rejected by an executable integration test.
- The app binds every generated owned runtime to an in-memory SHA-256 digest
  sent over that authenticated channel. The helper hashes the same bytes while
  copying them into its root-owned runtime, so another same-UID process cannot
  substitute YAML before root Mihomo starts or reloads it.
- Kill Switch paths arm before enrollment/core startup, retain protection on
  health failure, and disarm only for explicit disconnect/logout/quit.
- Kill Switch management is native Swift with no Python dependency. It fetches
  and bounds the official DERP map before arm, persists exact public
  TCP/443/UDP3478 endpoints, blocks arbitrary UDP/direct WireGuard, and never
  opens a global `*:443` exception. A marked, exact `/etc/hosts` block pins
  control names while armed so reboot bootstrap does not require a host-wide
  DNS exception; disarm removes only that managed block. The main PF ruleset is
  reloaded only when installing or recovering the anchor; ordinary arm/reassert
  operations replace only Tono's child anchor. Imported-node exceptions are
  root-only, exact public IPv4/TCP/port tuples; proxy UDP targets are rejected,
  and every arm flushes PF states so a prior selected endpoint cannot retain a
  durable connection.
- Account/restoring/enrolling/suspended screens render the same full-window
  material background as the app. The appearance slider retains at least a
  68% opaque tint, so the translucent NSWindow cannot become visually clear.
- Release builds expose email-code login only. Native Apple and Google OAuth
  paths are enclosed in `#if DEBUG`, so they are absent from the Developer ID
  binary even if the Worker advertises them. Debug keeps the existing Apple
  AuthenticationServices nonce/state flow and Google loopback/state/S256-PKCE
  flow for future development.
- Release uses `Tono/Tono-Release.entitlements`, which contains no native Apple
  sign-in or debug entitlement. Debug continues to use
  `Tono/LiquidClash.entitlements`.

### ACL and home usage artifacts

- `cloudflare/policy/tailnet-acl.hujson` leaves the pending tag grantless and
  permits the active client tag to reach only `autogroup:internet` via
  `tag:exit-home`.
- `GET /api/v1/home/inventory` exposes only verified public key, stable-ID audit
  metadata, user/status, and usage floor to the home-agent token. The reporter
  attributes per-peer rx/tx by the public key already verified during confirm;
  it does not trust a client-reported stable ID as the account boundary. It
  handles daemon counter resets, refuses cross-user reuse, and retains
  HTTPS/no-redirect delivery, private atomic state, monotonic totals, and exact
  replay.

## Verification completed locally

```text
cd cloudflare && npm test && npm run typecheck
→ 37 tests pass; typecheck passes; no abandoned-stream warning

cd cloudflare && npm audit
→ 0 vulnerabilities, including dev dependencies. Tests use Vitest 4.1.10 and
  @cloudflare/vitest-pool-workers 0.18.8. Worker route fixtures reset D1 for
  every test. Passwordless tests exercise direct verified signup, atomic OTP
  consumption, limits, Google/Apple OIDC validation, nonce, audience, and
  replay. Catalog tests cover AES-GCM round-trip/tamper rejection, ciphertext
  at rest, authenticated reads, revision conflicts, and replacement.

PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s home-agent -p 'test_*.py' -v
→ 10 tests pass

scripts/test-subscription-url-policy.sh
→ pass

scripts/test-multi-exit-policy.sh <YAML>
→ the real Japan `199.30.91.172` file, real US `198.12.84.154` file, and a
  two-node Reality fixture each parse under the protected VLESS contract and
  produce a sanitized owned runtime accepted by Mihomo

Tono/Resources/mihomo -t -f <real YAML>
→ both real files pass native Mihomo syntax validation; TCP/443 is reachable
  on both servers. Credentials were not printed or copied into the repository.

scripts/build-core-helper.sh
→ arm64 helper builds; ad-hoc signature verifies for local build purposes

scripts/test-helper-peer-authorization.sh
→ correctly signed Tono client accepted; ad-hoc same-ID and signed wrong-ID
  clients rejected

Tono/Resources/liquidclash-helper --network-self-test
→ current official DERP map parses into bounded TCP/443 and UDP/3478 endpoints

export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
xcodebuild -project LiquidClash.xcodeproj -scheme LiquidClash \
  -configuration Debug -destination 'platform=macOS' build
→ BUILD SUCCEEDED

xcodebuild ... -configuration Release \
  CODE_SIGN_IDENTITY='Developer ID Application' \
  PROVISIONING_PROFILE_SPECIFIER='Tono Developer ID 2026' archive
→ ARCHIVE SUCCEEDED

codesign --verify --deep --strict .../Tono.app
→ Developer ID signature passes for the app, mihomo, tailscale, tailscaled,
  and liquidclash-helper; all are arm64, hardened runtime, Team YY57758GS7,
  and carry trusted timestamps. Release has no Apple sign-in/get-task-allow
  entitlement and does not link AuthenticationServices.

The Release target explicitly sets `CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO`.
The current helper 3.2.2 Developer ID Release after the
multi-exit/automatic-TUN changes passed strict deep verification, contains
neither `get-task-allow` nor the Apple sign-in entitlement, and does not link
AuthenticationServices. Apple accepted notarization submission
`37119603-AFDC-49DE-99D0-59B83A5AB9FA` for build 3 r4; the exported app is
stapled and passes Gatekeeper. This verifies offline packaging only; it was not
launched on the build Mac.

The clean-Mac package is
`/Users/rw/Documents/Tono Builds/Tono-0.0.1-build3-Staging-Notarized-Test-20260729-r4.zip`
with SHA-256
`69b88a39f78599bcbe49170b949cbf3a9e8fd7c03a03f210a9da719a267f771b`.
After extraction, strict deep signature verification, stapler validation, and
Gatekeeper assessment all pass as `Notarized Developer ID`. A convenience DMG
with SHA-256
`621aaa06f9bc51ca10edecce8364ac9b79d6cba1b5b59833d5f0f45b25ac4f2a`
is Developer ID signed and contains the same accepted app, but the outer DMG
container is not separately notarized; use the ZIP for testing.
```

## Staging verification completed

- Cloudflare Business account: D1 `tono-control-plane`, migrations
  `0001`–`0010` applied; Worker `tono-control-plane-staging` version
  `f28bfb7a-0b05-4ac0-b3ad-39e5c63cc3e8` deployed. Direct staging signup
  currently allows `ruiruiwan2019@gmail.com` and `ruiruiwan8@gmail.com`.
  `CATALOG_ENCRYPTION_KEY` is a Worker-only secret and the encrypted initial
  US/Japan catalog is revision 1. The upload combined both mode-0600 source
  files in memory; neither credentials nor a combined plaintext artifact were
  printed or written.
- Worker health and auth-method endpoints return 200; email is enabled while
  Apple and Google remain disabled until their client IDs are configured.
- CORS accepts only the exact staging origin (native clients may omit Origin);
  the static admin UI is Worker-first and receives CSP, no-store,
  `X-Frame-Options: DENY`, `nosniff`, permissions, and referrer headers.
- A least-privilege Tailscale trust credential (`auth_keys` and
  `devices:core`, restricted to `tag:tono-controller`) successfully exchanged
  an OAuth token and accessed the staging inventory.
- The ACL policy artifact was saved in the staging tailnet and its policy tests
  passed. A legacy unredeemed invitation may remain in staging, but the current
  test-stage authentication path neither reads nor consumes invitations.
- The home Mac Studio (`100.115.160.62`) is connected, advertises Exit Node,
  reports UDP connectivity, is owned by `tag:exit-home`, and its route is
  allowed. The staging app configuration points to that Tailscale IP.
- Resend accepted a real staging OTP send. The smoke challenge was immediately
  invalidated afterward, so both device slots remain unused.
- Apple Developer Team `YY57758GS7` has an explicit `com.raydocs.tono` App ID
  with Sign in with Apple enabled for development. Debug uses the native Apple
  entitlement; Developer ID Release cannot, so the Release UI ignores the
  staging Apple advertisement and presents email only.
- Xcode is signed in to that team, the Mac Studio is registered for development,
  and Xcode generated a matching Mac Team provisioning profile. A Debug build
  succeeded with the Apple Development identity and Apple sign-in entitlement.

A new G2 `Developer ID Application` identity is installed in this Mac's login
Keychain. A signed staging archive is stored at
`/Users/rw/Documents/Tono Builds/Tono-0.0.1-Staging-Developer-ID-20260728.xcarchive`.
Every nested executable passed strict Developer ID signature verification.
Apple notarization submission `738A535A-8730-4106-BA0E-CD764F0E5B3C` was
accepted. Xcode exported the stapled app to
`/Users/rw/Documents/Tono Builds/Tono-0.0.1-Staging-Notarized-20260728.app`
and a `ditto` ZIP is beside it. Strict signature verification, stapler
validation, Gatekeeper assessment of the exported app, and the same checks
after ZIP extraction all pass as `Notarized Developer ID`. The ZIP SHA-256 is
`7e598fffd755416d79304b3d7452f97d84d2874855a41720c07f020a173e265e`.
Real privileged-helper installation and live client network behavior have
**not** been claimed or verified. That accepted artifact predates helper
version 3.2.0, native PF management, DERP-map/bootstrap and selected-VLESS
endpoint enforcement, config-digest binding, multi-node selection, and the
account-window rendering fix. It is retained only as evidence that the
signing/notarization pipeline worked, not as a distributable build.

## Residual ship blockers

1. **Privileged install/lifecycle validation:** caller identity, native PF
   management, root-owned runtime, and config-content binding are implemented.
   The current installer is still an administrator-approved LaunchDaemon path,
   not SMAppService. Exercise install/upgrade/reboot/uninstall and PF recovery
   on a disposable Mac; decide whether SMAppService migration is required for
   the distribution target.
2. **Kill Switch live bootstrap:** exact DERP/STUN allowlisting is implemented
   and the current public map parses locally. Arbitrary direct WireGuard UDP is
   deliberately blocked, so protected mode is DERP-only. Prove regional DERP
   connectivity plus crash/reboot/path-loss behavior, and make an explicit
   product decision whether DERP-only performance is acceptable.
3. **Live Tailscale client-device contract:** the home exit machine proves the
   tailnet can host a real device, but a Tono-enrolled client has not exercised
   the three-ID/public-key confirm contract. Run enroll → confirm → exit-IP →
   revoke, including concurrent confirm and API outage recovery.
4. **Live home-exit traffic:** the Mac Studio is online, tagged, advertised, and
   approved, but a Tono client has not yet proved its public traffic exits
   through the home public IP or that the policy remains correct during failure.
5. **Managed catalog live multi-exit traffic:** migration `0010`, the catalog
   encryption secret, current Worker, and encrypted US/Japan revision 1 are
   deployed to staging. Both source files parse, pass Mihomo syntax validation,
   and have reachable TCP/443 listeners. Still prove authenticated catalog
   fetch, VLESS handshakes, observed US/Japan exit IPs, safe live switching,
   revision sync, and fail-closed selected-node deletion while PF admits only
   the selected root/TCP endpoint.
6. **Usage attribution deployment:** server-verified public-key mapping,
   stable-ID audit metadata, and per-peer counter accumulation are implemented
   and tested, but the new Worker inventory route is not deployed and the
   reporter is not installed on the Mac Studio. Verify real exit traffic
   attribution, resets, revocation timing, and service packaging before quota
   is considered operational.
7. **Production configuration:** staging D1/Worker/Tailscale/Resend and exit-node
   configuration is complete, but production resources, origin, API URL, and
   exit-node value still need a separate controlled rollout.
8. **Passwordless providers:** the 0.0.1 Developer ID Release is intentionally
   email-only. Complete a user-visible email OTP sign-in check. Native Apple
   remains Debug-only because Apple does not support its entitlement for
   Developer ID distribution; web-based Apple and Google are deferred.
9. **Apple distribution:** a new G2 `Developer ID Application` certificate and
   matching private key are installed in this Mac's login Keychain (Team
   `YY57758GS7`, expires 2031-07-29). Its identity and a timestamped
   hardened-runtime archive are verified, including all nested executables. An
   encrypted `.p12` backup is stored outside the repository in the user's
   Documents folder; its password was entered by the user and was not recorded
   in the repository or handoff. The old accepted submission
   `738A535A-8730-4106-BA0E-CD764F0E5B3C` is superseded. Apple accepted the
   current helper 3.2.2 submission
   `37119603-AFDC-49DE-99D0-59B83A5AB9FA`; its build 3 r4 exported app is
   stapled and passes Gatekeeper. The custom DMG is
   Developer ID signed and contains that accepted app, but the DMG container
   itself has not been separately notarized; use the ZIP for current clean-Mac
   testing. The prior r2/r3 packages are superseded by the cloud-only fallback
   and authenticated-catalog retry fixes. Restore testing on a separate
   keychain/Mac and clean-Mac live
   verification remain pending. The existing Apple Distribution certificate
   is unrelated to this Developer ID path and still has no matching private key
   on this Mac.

## Human execution order

1. Install the current Development build's signed helper on a disposable/test
   Mac and run the PF install/upgrade/reboot/recovery matrix.
2. Test the DERP-only Kill Switch bootstrap and decide whether direct
   WireGuard performance is a 0.0.1 requirement.
3. Complete the pending email OTP and administrator-approved helper install,
   then run the current Tono client through Home-US, US, and Japan; verify each
   observed public IP, cloud revision syncing, node switching, deletion, and
   failure behavior.
4. Smoke-test the Release email OTP flow; defer web Apple/Google integration.
5. Run the full live tailnet enrollment, exit-IP, failure, and revocation matrix.
6. Deploy the new staging home inventory route, install the reporter with a
   protected token/CLI path, and validate per-user usage attribution.
7. Install the notarized `20260729-r4` build 3 ZIP on a separate clean Mac for the
   acceptance matrix. Only after those checks, create the production-configured
   release and separately notarize every distribution container.

## Definition of done for 0.0.1

- One verified account can enroll two Macs; a third is rejected even under race.
- Email OTP activates/signs into the account without a reusable password;
  expired, replayed, or mismatched challenges cannot authenticate. Web
  Apple/Google login is a post-0.0.1 feature.
- A pending node has no Internet, LAN, SSH, or exit-host access.
- Confirm is identity-safe and concurrent retries cannot delete a winner.
- Public traffic is verified through Home-US and each cloud-managed VLESS endpoint;
  switching or endpoint failure cannot fall back to another node or clearnet.
- Sidecar, Mihomo, exit-node, app-crash, and reboot failures do not leak direct
  traffic while armed; explicit disconnect/logout/quit restores normal access.
- The owned runtime contains top-level `ipv6: false`, while PF remains the
  fail-closed IPv4/IPv6 boundary when Mihomo or its TUN is unavailable.
- Catalog fetch remains authenticated and occurs after enrollment/confirm while
  PF is already fail-closed, before selecting Home-US or a cloud-only data path.
  DNS and latency traffic follows the selected `Tono-Exit`;
  managed proxy endpoints are exact public IPv4/TCP tuples and private
  destinations remain unavailable.
- Revocation closes sessions immediately and eventually removes the exact
  tailnet node after upstream recovery.
- Usage counters are attributable, monotonic, durable, and enforce quota.
- Worker tests, fresh Swift builds, signed archive validation, notarization,
  stapling, and disposable-Mac acceptance all pass.

## Secrets (never commit)

```text
JWT_SECRET
ADMIN_API_TOKEN
HOME_AGENT_TOKEN
TAILSCALE_OAUTH_CLIENT_ID
TAILSCALE_OAUTH_CLIENT_SECRET
CATALOG_ENCRYPTION_KEY
RESEND_API_KEY
```

`APPLE_CLIENT_ID` and `GOOGLE_CLIENT_ID` are public Worker vars, not secrets.
