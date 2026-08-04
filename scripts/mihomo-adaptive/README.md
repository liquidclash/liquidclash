# Tono adaptive gVisor core

This experiment keeps Tono on upstream Mihomo `v1.19.29` and its existing
`github.com/metacubex/sing-tun v0.4.21` dependency. The only runtime change is
the gVisor TCP send/receive range:

- stock: fixed `20 KiB`
- experiment: `4 KiB` minimum, `32 KiB` default, `128 KiB` maximum
- gVisor receive-buffer moderation remains enabled

The values follow the bounded adaptive policy evaluated by
[TokenPLS/Hako](https://github.com/TokenPLS/Hako). Tono does not import Hako's
SDK, binding layer, Network Extension lifecycle, or other fork changes.

Build and install the experiment:

```sh
scripts/build-mihomo-adaptive.sh --install-adaptive
scripts/build-mihomo-adaptive.sh --install-adaptive-windows
```

Restore the exact official MetaCubeX release:

```sh
scripts/build-mihomo-adaptive.sh --restore-stock
scripts/build-mihomo-adaptive.sh --restore-stock-windows
```

The script pins the Mihomo tag and commit, requires Go 1.26.5, tests the live
gVisor stack options before building, and verifies the official compressed and
decompressed SHA-256 values during rollback. The Windows build keeps the
official release's `GOAMD64=v2` baseline and installs the same verified binary
into both Tauri sidecar slots. Xcode applies the normal Tono Developer ID
signature when embedding the macOS executable in the app.
