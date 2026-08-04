#!/bin/sh
set -eu

# Reproducible source pin. Update only after reviewing upstream changes and notices.
TAILSCALE_TAG="v1.86.2"
TAILSCALE_COMMIT="d72494bac7a2fb6b6a01715cfc5bcc903dbd7594"
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD=$(mktemp -d "${TMPDIR:-/tmp}/tono-tailscale.XXXXXX")
trap 'rm -rf "$BUILD"' EXIT INT TERM

git clone --filter=blob:none --no-checkout https://github.com/tailscale/tailscale.git "$BUILD/src"
git -C "$BUILD/src" fetch --depth 1 origin "refs/tags/$TAILSCALE_TAG:refs/tags/$TAILSCALE_TAG"
git -C "$BUILD/src" checkout --detach "$TAILSCALE_TAG"
test "$(git -C "$BUILD/src" rev-parse HEAD)" = "$TAILSCALE_COMMIT" || { echo "Source commit mismatch" >&2; exit 1; }

mkdir -p "$ROOT/Tono/Resources"
(cd "$BUILD/src" && CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o "$ROOT/Tono/Resources/tailscaled" ./cmd/tailscaled)
(cd "$BUILD/src" && CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o "$ROOT/Tono/Resources/tailscale" ./cmd/tailscale)
chmod 755 "$ROOT/Tono/Resources/tailscaled" "$ROOT/Tono/Resources/tailscale"
echo "Built $TAILSCALE_TAG ($TAILSCALE_COMMIT). Sign both binaries with the app's Developer ID/team before archive/notarization."
