# Tono 0.0.1 build 13 — Reality-only friend test

This is a staging test build, not a production release. Use it first on a
spare Apple Silicon Mac where the tester has administrator access.

Only distribute a DMG whose filename includes `build13` and whose release
checklist says that Apple notarization, stapling, Gatekeeper assessment, and
the published SHA-256 all passed for both the DMG and its app. The approved
SHA-256 is
`bc1022151e38ef59b157f990374af6a5d6e3bd09885f1e8bcd81c51e649a9140`.
Builds 1–12 and every older r2/r3/r4 package are superseded.

## Requirements

- Apple Silicon Mac (M1 or newer)
- macOS 26.3 or newer
- Administrator password for the first signed network-helper installation
- An email address on the staging allowlist

The friend build uses email one-time-code sign-in. It does not include native
Apple/Google sign-in.

## Install and connect

1. Open the build 13 DMG and drag `Tono.app` onto its Applications shortcut.
2. Open Tono from `/Applications`.
3. Enter the allowlisted email address, then the six-digit email code.
4. On the first connection, approve the macOS administrator prompt for Tono's
   signed network helper.
5. Confirm that **US Reality** is selected by default.
6. Press Connect. Tono reports Connected only after Mihomo, the owned TUN,
   the Kill Switch, and the selected Reality server all pass their checks.
7. Open Nodes and switch to **JP Reality**. The existing connections should be
   closed and the public IP should change without falling back to the Mac's
   direct connection.

Build 13 is VLESS Reality-only. It retains the build 12 Reality `servername`
fix and also excludes only the selected Reality server from Mihomo's own TUN
route, preventing the core from recursively capturing its outbound socket.
The root helper and PF still allow only that exact selected server endpoint.
Cold Reality health checks use bounded retry, and Mihomo unified delay reports
network RTT instead of presenting the full Reality/TLS handshake as node
latency. Home-US and Tailscale are disabled, absent from the production UI,
and absent from the app bundle. TUN and Rule mode are mandatory; LAN sharing
is disabled.

On the release Mac, US Reality remained Connected for a 30-second test. JP
Reality also remained Connected at the 8-, 18-, and 26-second checks before
the automatic 30-second shutdown. The measured JP route reached JPNAP Tokyo
at about 105 ms; the old 450–495 ms display included several Reality and TLS
handshake round trips. A GeoIP service may temporarily label this newly routed
address block as Mumbai; the measured network route is Tokyo.

A normal launch does not connect without the user's choice. If Tono or Mihomo
was force-terminated while protection was active, the persistent Kill Switch
keeps the Mac offline and Tono automatically resumes the previously selected
protected server after account recovery.

Closing the window does not quit Tono; the menu-bar item remains available.
Use Disconnect, Sign Out, or Quit for a normal end to the test.

## Acceptance checks

Test both US Reality and JP Reality:

- The first window paints immediately and remains responsive while the session
  is restored.
- Connect, cancel during connect, disconnect, reconnect, and server switching
  do not freeze the UI.
- The dashboard public IPv4 belongs to the selected server, not the tester's
  normal ISP.
- IPv6 and DNS do not expose the tester's normal network.
- Disconnect restores ordinary Internet access.
- Force-quit while connected leaves Internet blocked; reopening Tono restores
  the protected route.
- Killing the protected core or removing the TUN leaves Internet blocked and
  triggers bounded reconnect attempts.
- An invalid or unavailable catalog update does not replace the last verified
  server list.
- Launch at Startup accurately matches macOS Login Items.

Record the macOS version, Mac model, selected server, approximate operation
time, and a screenshot of any visible error. Do not include catalog YAML,
server credentials, email codes, or tokens in a report.

## Emergency network recovery

First reopen Tono from the menu bar and use Disconnect, Sign Out, or Quit.

If the UI cannot open, run this exact command in Terminal:

```sh
sudo /Library/PrivilegedHelperTools/tono-core-helper --emergency-disarm
```

On success it prints:

```text
Tono network protection is disarmed.
```

The command stops only Tono's owned Mihomo runtime and removes only Tono's PF
state and managed host mappings. Do not delete helper files or edit system PF
rules manually.
