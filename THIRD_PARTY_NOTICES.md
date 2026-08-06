# Third-party notices

## Tailscale

The optional Tono userspace sidecar is built from Tailscale, pinned by
`tooling/scripts/build-tailscale-sidecar.sh`. Tailscale is copyright Tailscale Inc. and
contributors and is distributed under the BSD 3-Clause License. The complete
license is available in the pinned source at `LICENSE` and at
<https://github.com/tailscale/tailscale/blob/main/LICENSE>.

No binary is committed by this integration. Build both executables from the
pinned, verified source, then codesign them with the same team used for the app
before signing/archiving the outer app. Hardened-runtime, entitlement and
notarization validation must include both nested executables. Tono runs them as
an unprivileged app child; it is separate from LiquidClash's root Mihomo helper.

## Sparkle

Tono embeds Sparkle 2.9.4 to deliver signed application updates outside the Mac
App Store. Sparkle and its bundled third-party components are distributed under
the licenses reproduced in `apps/macos/Tono/Resources/Sparkle-LICENSE.txt`; that file is
also embedded in the final application bundle. Tono requires both Sparkle
Ed25519 archive verification and the existing Apple Developer ID trust chain
before installing an update.
