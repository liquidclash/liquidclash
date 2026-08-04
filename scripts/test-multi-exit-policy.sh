#!/bin/zsh
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 /absolute/path/to/nodes.yaml [...]" >&2
  exit 2
fi

for fixture in "$@"; do
  if [[ $fixture != /* || ! -f $fixture ]]; then
    echo "every fixture must be an absolute regular-file path" >&2
    exit 2
  fi
done

repo_root=${0:A:h:h}
mihomo_path=${TONO_TEST_MIHOMO_PATH:-"$repo_root/Tono/Resources/mihomo"}
if [[ $mihomo_path != /* || ! -x $mihomo_path ]]; then
  echo "TONO_TEST_MIHOMO_PATH must be an absolute executable path" >&2
  exit 2
fi
test_dir=$(mktemp -d /tmp/tono-multi-exit.XXXXXX)
trap 'rm -rf "$test_dir"' EXIT

tono_developer_dir=/Applications/Xcode.app/Contents/Developer
DEVELOPER_DIR="$tono_developer_dir" /usr/bin/xcrun swiftc \
  -module-cache-path "$test_dir/module-cache" \
  "$repo_root/Tono/Models/ProxyNode.swift" \
  "$repo_root/Tono/Models/RuleEntry.swift" \
  "$repo_root/Tono/Services/ConfigParser.swift" \
  "$repo_root/Tono/Core/HelperProtocolVersion.swift" \
  "$repo_root/Tono/Core/ConfigPipeline.swift" \
  "$repo_root/scripts/tests/MultiExitPolicyTests.swift" \
  -o "$test_dir/test-multi-exit"

runtime_dir="$test_dir/runtimes"
mkdir -p "$runtime_dir"
"$test_dir/test-multi-exit" "$@" "$runtime_dir"

for runtime_file in "$runtime_dir"/*.yaml; do
  "$mihomo_path" -t -d "$test_dir" -f "$runtime_file" >/dev/null
done
echo "every selected Reality exit passed mihomo config validation"
