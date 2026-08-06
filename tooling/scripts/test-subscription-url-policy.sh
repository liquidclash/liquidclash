#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/tono-url-policy.XXXXXX")
test_binary="$test_dir/test-url-policy"
trap 'rm -rf "$test_dir"' EXIT

export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
xcrun swiftc \
  -module-cache-path "$test_dir/module-cache" \
  "$repo_dir/apps/macos/Tono/Support/SubscriptionURLPolicy.swift" \
  "$repo_dir/tooling/scripts/tests/subscription-url-policy/main.swift" \
  -o "$test_binary"
"$test_binary"
