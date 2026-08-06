# Tono for Windows

Native Windows client for **Tono** — authenticated accounts, cloud-managed
VLESS Reality exits, and a fail-closed kill switch.

Tono for Windows is built on a hardened fork of **Clash Verge Rev** (React +
Tauri + Rust + Mihomo) and its Windows service, into which the complete Tono
product and security model from the macOS client is transplanted. It replaces
Clash Verge's open, user-configurable proxy-client model with Tono's closed,
server-managed, fail-closed model.

It is **not** a port of the macOS SwiftUI client, and **not** a rebranded
Clash Verge. The GUI, IPC, service, and installer infrastructure comes from
the fork; every security decision comes from Tono.

- macOS client: `../Tono` (SwiftUI, PF kill switch, privileged helper)
- Windows base client: fork of `clash-verge-rev` (`app/`)
- Windows base service: fork of `clash-verge-service-ipc` (`service/`)
- Kill switch references: Proton VPN (`ProtonVPN/win-app`) and Mullvad
  (`mullvadvpn-app` `winfw`) — see `docs/wfp-kill-switch.md`

## Design goals

1. **Same product as macOS Tono.** Same backend, same account, same catalog,
   same connect semantics. A Mac and a PC signed in with one email share the
   same device list and the same device limit.
2. **Fail-closed at the OS packet layer.** Protection intent lives in the
   LocalSystem service and in persistent WFP objects. It survives GUI crashes,
   Mihomo crashes, user sign-out of the session, sleep/wake, adapter changes,
   service restarts, and reboots.
3. **No trust in server-delivered config.** The cloud catalog contributes
   only whitelisted node fields. DNS, TUN, rules, mode, and the controller
   are generated locally and are never influenced by server YAML.
4. **No unprivileged fallback.** If the service cannot run, Tono does not
   run. There is no sidecar mode, no system-proxy-only mode, no way to reach
   the Internet through Tono without the kill switch.

Non-goals: third-party subscriptions, user-defined nodes, scripting/merge,
non-TUN modes, LAN exposure, streaming-unlock checkers, WebDAV backup.

## Signed Windows updates

Release builds use only the Tono-owned static updater feed at
`https://github.com/raydocs/tono/releases/latest/download/latest.json`. The
normal developer build does not configure an updater endpoint. The manually
dispatched `Windows release` workflow builds the App and all three Windows
Service binaries from the same commit, generates signed NSIS updater
artifacts, runs the release preflight, and creates a **draft** GitHub Release.
Publishing the reviewed draft makes its generated `latest.json` available to
installed clients.

Before the first updater-enabled release, an operator must generate one Tauri
updater signing keypair outside this repository and configure:

- repository variable `TONO_UPDATER_PUBLIC_KEY` with the complete outer-Base64
  public-key value emitted by Tauri (copy the generated `.pub` content unchanged);
- repository secrets `TAURI_SIGNING_PRIVATE_KEY` and
  `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`.

Never commit the private key. Losing or rotating it without a signed migration
release prevents already-installed clients from accepting future updates.

## Architecture

```text
Standard user session
┌────────────────────────────────────────────────────────┐
│ Tono UI (React + Tauri, from CVR fork, reduced)        │
│ Login · Connect · Server picker · Status · Diagnostics │
└──────────────────────┬─────────────────────────────────┘
                       │ Tauri IPC
┌──────────────────────▼─────────────────────────────────┐
│ Tono product layer (Rust, inside src-tauri)            │
│ auth · catalog verify/cache · owned config generation  │
│ connect transaction · protected reconnect · state      │
└──────────────────────┬─────────────────────────────────┘
                       │ authenticated HTTP over named pipe
                       │ \\.\pipe\tono-service (protocol rev 5)
┌──────────────────────▼─────────────────────────────────┐
│ TonoService.exe (LocalSystem, from service fork)       │
│ durable intent · WFP kill switch · DNS snapshot/restore│
│ Mihomo supervision · power/network events · recovery   │
└────────────┬──────────────────────────────┬────────────┘
             │                              │
     ┌───────▼────────┐            ┌────────▼─────────┐
     │ mihomo.exe     │            │ Windows Filtering │
     │ WinTUN (fixed  │            │ Platform (BFE)    │
     │ device name)   │            │ single sublayer,  │
     └────────────────┘            │ weighted rules    │
                                   └───────────────────┘
```

Trust boundaries:

- The **UI** holds the account session (access token in memory, refresh token
  in Windows Credential Manager / DPAPI) and never touches WFP, DNS, or
  privileged process control.
- The **service** is the sole fail-closed authority. It owns WFP objects,
  DNS state, the root-readable runtime config copy, and the protection
  intent record.
- The **catalog** is verified (monotonic revision + SHA-256) before it can
  influence anything; the last verified catalog is kept on any failure.

## What the Clash Verge base already solves

Reused as-is from the forks (this is most of the hard Windows plumbing):

- React/Tauri shell: window, tray, i18n (13 locales), SWR data layer, theming
- NSIS per-machine installer with embedded WebView2 bootstrapper and service
  management; Tauri updater pipeline; scheduled-task auto-start
- UAC elevation and Windows service install/uninstall/repair flow, with
  SHA-256-verified service binary staging into `C:\ProgramData\...`
- LocalSystem service with SCM recovery actions (5s/10s/30s restart)
- Named-pipe IPC with a three-layer trust model:
  pipe SDDL (LocalSystem + Administrators full, Authenticated Users
  read/write, no Everyone), owner authentication via user SID +
  ACL-verified owner token file, and per-connection session tokens with
  generation counters; the client additionally verifies the pipe server PID
  belongs to the SCM-registered service
- Mihomo lifecycle: start/stop, runtime staging (hot config swap without
  restart), exponential-backoff watchdog with fatal-state cap, crash
  forensics, log ring buffer + file snapshots
- Desired-state persistence: the service re-establishes the last requested
  core state after its own restart
- TUN support via WinTUN, system proxy machinery (kept but unused by Tono),
  and the runstate state machine
- The fork's macOS PF kill switch, whose semantics (wanted/live reporting,
  preflight, release-on-explicit-stop only, emergency disarm, watchdog
  re-verification) are the template for the Windows WFP port

## What Tono adds (stronger than Clash Verge)

| Area | Clash Verge Rev | Tono for Windows |
|---|---|---|
| Config source | user profiles + merge + JS scripts | catalog-validated nodes only; fully owned runtime |
| DIRECT fallback | present in groups/rules | impossible: single `Tono-Exit` group, `MATCH,Tono-Exit` |
| Service | optional, sidecar fallback | mandatory; no sidecar path exists |
| Kill switch | none on Windows (opt-in PF on macOS) | always-on during sessions; persistent WFP floor survives reboot |
| Controller secret | stored in config file | random per start, never persisted |
| Mode / LAN | user-selectable | locked `rule`, `allow-lan: false`, no override surface |
| Node trust | any subscription/URL | VLESS+Reality+TCP, public IPv4 literal only, SHA-256-pinned catalog |
| Connected truth | core API reachable | controller + WinTUN + protected DNS + egress probe all verified |
| Node switch | best effort | WFP endpoint permit is swapped before the selector changes; failure never falls back to direct |

## What gets removed from the fork

Profiles/subscriptions and their editor/importer/QR/auto-update, the entire
enhance chain (merge, script/boa, seq, templates), `clash://` deep-link
import, WebDAV + local backup, the unlock page, external-controller and port
configuration UI, core selection (Mihomo is fixed), sidecar fallback
(`service_required = true`, unconditionally), user rules page, allow-LAN,
mode selector, and any UI that mutates DNS/TUN/rules.

Proxy detail, traffic, connections, and logs components are kept as a
read-only **Advanced / Diagnostics** area. They may display state; they may
not change policy.

## Account and catalog sync with macOS Tono

Same backend, no server changes required (`https://api.afk.ccwu.cc/api/v1`):

- `auth/email/start` → `auth/email/verify` (6-digit code), `auth/refresh`
  with rotating refresh tokens, `auth/logout`, `me`, `devices`,
  `exit-catalog`, `devices/{id}` revocation.
- `installationId` is a per-install UUID, stored next to the refresh token;
  the device registers as a normal Tono device (default name "Windows PC").
  The account-wide device limit (default 2) is shared with the macOS client —
  signing in on a PC counts against the same limit.
- Access token lives in memory only; refresh token lives in Windows
  Credential Manager (DPAPI-scoped to the user), mirroring the macOS
  Keychain split.
- Catalog contract is identical: monotonic `revision` (regressions and
  same-revision/different-digest are rejected), SHA-256 of the YAML as
  base64url-no-padding, ≤ 1 MiB, ≤ 200 nodes, full node whitelist
  validation, last-verified-copy caching, 300 s sync cadence with bounded
  retries. A Windows client must never accept a catalog the Mac client
  would reject.
- Node admission contract (ported verbatim): `vless` + TLS, 43-char
  base64url Reality public key, required SNI, even-length hex short ID ≤ 16
  chars, `flow: xtls-rprx-vision`, `network: tcp` only, `skip-cert-verify`
  rejected, and `server` must be a **public IPv4 literal**.

## Owned runtime configuration

Generated locally for every connect, identical in spirit to
`ConfigPipeline.buildOwnedTonoRuntime` on macOS:

- `allow-lan: false`, `ipv6: false`, `mode: rule`, `profile.store-selected:
  false`, `find-process-mode: strict`
- `external-controller: 127.0.0.1:9090` with a per-start random secret that
  is never written to the on-disk copy
- TUN enabled, fixed WinTUN device name, `auto-route`, `strict-route`,
  `route-exclude-address: <selected node IP>/32` (so Mihomo's own Reality
  socket is never recaptured by the tunnel)
- DNS: fake-ip `198.18.0.1/16`, listen `127.0.0.1:53`, `dns-hijack:
  any:53`, IP-literal DoH upstreams pinned to the `Tono-Exit` group
- Rules: loopback directs only, then `MATCH,Tono-Exit`. Nothing else.
- The service holds the only copy Mihomo reads; the UI-side file never
  contains the controller secret.

## Connect transaction (fail-closed ordering)

Mirrors the macOS transaction; the service performs the privileged steps:

1. UI validates the catalog and builds the owned runtime for one selected
   node.
2. UI sends one connect request: runtime bytes + SHA-256, selected public
   IPv4/TCP endpoint, expected Mihomo identity, kill-switch parameters.
3. Service **atomically persists protection intent** (fail-closed floor).
4. Service installs bootstrap WFP policy: block all outbound (v4+v6),
   permit loopback/DHCP/NDP, permit Mihomo→endpoint, plus a bounded
   bootstrap permit for the API host.
5. Service writes the runtime copy and starts the verified Mihomo binary.
6. Service waits for the controller, then the expected WinTUN adapter.
7. **Lock phase**: service permits the TUN interface and retracts the API
   bootstrap permit; control plane now rides the tunnel.
8. Service snapshots adapter DNS, points the system resolver at
   `127.0.0.1`, and verifies protected resolution actually returns fake-ip.
9. Service probes egress through the selected Reality path. Only now does
   the UI show **Connected**.

Any failure after step 3 stops Mihomo where possible and **retains WFP
blocking** (`Protected Offline`); automatic reconnect runs behind the
barrier with 2/5/10/20/30 s backoff. Only an explicit Disconnect, Sign Out,
or Quit releases the kill switch. Node switches swap the WFP endpoint
permit *before* moving the selector, and never fall back to direct.

## Kill switch (WFP)

Designed from Proton VPN's proven model, hardened with Mullvad's
simplicity and Tono's PF semantics. Summary (full rule tables in
`docs/wfp-kill-switch.md`):

- One fixed-GUID persistent provider; one persistent sublayer
  (**tono-kill-switch**, Mullvad-style) holding every rule, layered purely by
  filter weight: loopback/DHCP/NDP permits (8/7) and endpoint/TUN/API permits
  (8/8/7) over the block-all pair (1). The default-deny floor already blocks
  physical DNS leaks; there is deliberately no extra port-53 block, because
  Windows resolver traffic transitions between loopback and the TUN path.
  WFP arbitrates sublayer-first, so "weighted permits over a floor block" is
  only sound inside a single sublayer (see `docs/wfp-kill-switch.md` §2).
- `ALE_AUTH_CONNECT_V4/V6` for the outbound fail-closed boundary; IPv6 is
  blocked wholesale at WFP (no adapter reconfiguration needed).
- Persistent flags only on the condition-free block-all pair; every rule
  carrying volatile data (app path, interface index, endpoint IP) is
  non-persistent and rebuilt by the service on start — the Proton
  upgrade/reboot lessons.
- Status is reported as `wanted / live / mode / allowed endpoints / last
  error`; a watchdog re-verifies live objects by key after every transition
  and on a timer.
- `TonoService.exe --emergency-disarm` removes only Tono-owned WFP objects
  (provider, sublayer, filters) — never any other firewall policy. The
  uninstaller disarms before removing the service.

## Repository layout

```text
app/        Tono UI + product layer (fork of clash-verge-rev, reduced)
service/    TonoService (fork of clash-verge-service-ipc, + WFP/DNS/events)
docs/       architecture.md · product-contract.md · wfp-kill-switch.md ·
            roadmap.md (phases + acceptance matrix)
SECURITY.md security invariants and disclosure
```

The forks are imported as source trees (not git submodules) so the product
can diverge freely; upstream sync is a deliberate, reviewed operation.

## Development

Windows 10 22H2 / Windows 11, x64 and ARM64.

- Rust stable (MSVC toolchain), Node.js LTS + pnpm
- Tauri 2.x prerequisites (WebView2, VS C++ build tools)
- A Windows VM or machine with second NIC/Wi-Fi for the network-change
  matrix, plus packet capture (Wireshark/`pktmon`) for leak verification

No production token, node UUID, Reality key material, signing key, or live
endpoint may be committed.

Real-Windows integration builds use `--features windows-integration-test`.
That feature injects 1000 ms of synthetic mainland-like latency into marked
remote operations by default while production builds compile the hook to a
no-op. Set `TONO_WINDOWS_INTEGRATION_LATENCY_MS=0` for a no-delay diagnostic,
or choose another value from 0 through 5000 ms. Acceptance still requires a
real connect, ordinary App/browser traffic, disconnect, and exact DNS restore;
the synthetic delay supplements that loop and never replaces it.

## Status

Foundation implemented (see `REPORT.md` for evidence and the remaining
Windows-only verification list):

- `crates/tono-core` — portable product layer (node admission, catalog
  validation + secure cache, owned runtime generation, API client, connect
  FSM, credential abstraction); 121 unit tests + clippy clean on macOS.
- `service/` — WFP kill switch (single-sublayer weighted model with an
  arbitration-simulation test suite), DNS snapshot/set/verify/restore,
  network/power event feed, IPC protocol rev 5, emergency disarm; host
  tests green and `cargo check` clean for `x86_64-pc-windows-msvc`.
- `app/` — Tono branding, path dependency on the local service crate,
  `tono/*` Tauri backend (11 commands, full §6 connect orchestration),
  minimal product UI (login / dashboard / servers / account) with the
  Clash Verge pages kept under an "Advanced" group.

Not yet done: real Windows runtime verification (WFP/DNS/leak tests),
the CVR feature strip (profiles/scripts/etc. still present behind
"Advanced"), settings reduction, signing/updater channel, and the Phase-4
acceptance matrix.
