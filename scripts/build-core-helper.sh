#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
source_file="$repo_dir/scripts/core-helper/main.swift"
kill_switch_source="$repo_dir/scripts/core-helper/KillSwitchManager.swift"
protected_dns_source="$repo_dir/scripts/core-helper/ProtectedDNSManager.swift"
peer_authorization_source="$repo_dir/scripts/helper-shared/PeerAuthorization.swift"
protocol_version_source="$repo_dir/Tono/Core/HelperProtocolVersion.swift"
output_file="$repo_dir/Tono/Resources/liquidclash-helper"
temporary_file="$output_file.new"
module_cache_dir=$(mktemp -d /tmp/tono-helper-module-cache.XXXXXX)

trap 'rm -f "$temporary_file"; rm -rf "$module_cache_dir"' EXIT
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
xcrun swiftc \
  -O \
  -whole-module-optimization \
  -module-cache-path "$module_cache_dir" \
  -target arm64-apple-macosx26.3 \
  "$source_file" \
  "$kill_switch_source" \
  "$protected_dns_source" \
  "$peer_authorization_source" \
  "$protocol_version_source" \
  -framework IOKit \
  -framework Security \
  -o "$temporary_file"
codesign --force --sign - --identifier com.raydocs.tono.helper "$temporary_file"
chmod 0755 "$temporary_file"
"$temporary_file" --self-test
"$temporary_file" --version
mv -f "$temporary_file" "$output_file"
rm -rf "$module_cache_dir"
trap - EXIT
