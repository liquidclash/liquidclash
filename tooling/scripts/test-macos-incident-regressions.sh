#!/bin/zsh
set -euo pipefail

if [[ $(uname -s) != Darwin ]]; then
  echo "this validation requires a macOS runner with Xcode" >&2
  exit 2
fi

repo_root=${0:A:h:h:h}
developer_dir=${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}
if [[ ! -x /usr/bin/xcodebuild || ! -x /usr/bin/xcrun || ! -d $developer_dir ]]; then
  echo "Xcode is unavailable; set DEVELOPER_DIR to a complete Xcode installation" >&2
  exit 2
fi

test_dir=$(mktemp -d /tmp/tono-macos-incident.XXXXXX)
trap 'rm -rf "$test_dir"' EXIT

# Use inert, deterministic material. The policy harness parses this fixture,
# sanitizes every credential/address before writing generated runtimes, and
# validates those runtimes with the bundled Mihomo binary.
fixture=$test_dir/nodes.yaml
cat >"$fixture" <<'YAML'
proxies:
  - name: Incident-Regression-Reality
    type: vless
    server: 8.8.4.4
    port: 443
    uuid: 00000000-0000-4000-8000-000000000099
    network: tcp
    tls: true
    servername: regression.example.com
    reality-opts:
      public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
      short-id: 0011223344556677
YAML

echo "[1/2] Building the macOS app without signing"
DEVELOPER_DIR=$developer_dir /usr/bin/xcodebuild \
  -project "$repo_root/apps/macos/LiquidClash.xcodeproj" \
  -scheme LiquidClash \
  -configuration Debug \
  -derivedDataPath "$test_dir/DerivedData" \
  CODE_SIGNING_ALLOWED=NO \
  build

echo "[2/2] Validating owned routing, Claude precedence, and Mihomo syntax"
DEVELOPER_DIR=$developer_dir \
  "$repo_root/tooling/scripts/test-multi-exit-policy.sh" "$fixture"

echo "macOS incident regressions passed"
