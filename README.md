# Tono

Cloud-managed VPN clients.

| Directory | Platform |
|-----------|----------|
| [`tono-win/`](./tono-win/) | Windows (Tauri + Service + WFP) |
| [`tono-mac/`](./tono-mac/) | macOS (SwiftUI + privileged helper) |

Other top-level folders (`cloudflare/`, `scripts/`, …) are shared backend, tooling, and docs.

## Windows quick start

```powershell
cd tono-win
# see tono-win/README.md and scripts/build-windows-release.ps1
```

## macOS quick start

Open `tono-mac/LiquidClash.xcodeproj` in Xcode. App sources live in `tono-mac/Tono/`.

## Releases

Windows pre-release installers are published as GitHub Releases (`tono-windows-*` tags).
