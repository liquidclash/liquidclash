#!/bin/zsh
set -euo pipefail

if [[ ($# -lt 1 || $# -gt 3) || $1 != /* || ! -f $1 ]]; then
  echo "usage: $0 /absolute/path/to/existing-runtime.yaml [preferred-node] [expected-exit-ipv4]" >&2
  echo "optional: set TONO_TEST_SWITCH_NODE to an exact second node name for a live selector test" >&2
  exit 2
fi

repo_root=${0:A:h:h:h}
mihomo_path=${TONO_TEST_MIHOMO_PATH:-"$repo_root/apps/macos/Tono/Resources/mihomo"}
if [[ $mihomo_path != /* || ! -x $mihomo_path ]]; then
  echo "TONO_TEST_MIHOMO_PATH must be an absolute executable path" >&2
  exit 2
fi
switch_node=${TONO_TEST_SWITCH_NODE:-}
if [[ ${#switch_node} -gt 128 || $switch_node == *$'\n'* || $switch_node == *$'\r'* ]]; then
  echo "TONO_TEST_SWITCH_NODE must be a bounded single-line exact node name" >&2
  exit 2
fi
test_dir=$(mktemp -d /tmp/tono-isolated-data-plane.XXXXXX)
core_pid=""
cleanup() {
  if [[ -n $core_pid ]] && kill -0 "$core_pid" 2>/dev/null; then
    kill "$core_pid" 2>/dev/null || true
    wait "$core_pid" 2>/dev/null || true
  fi
  rm -rf "$test_dir"
}
trap cleanup EXIT

for port in 21053 28790 29090; do
  if /usr/sbin/lsof -nP -iTCP:"$port" -iUDP:"$port" 2>/dev/null | /usr/bin/grep -q .; then
    echo "isolated test port $port is already in use" >&2
    exit 1
  fi
done

tono_developer_dir=/Applications/Xcode.app/Contents/Developer
DEVELOPER_DIR="$tono_developer_dir" /usr/bin/xcrun swiftc \
  -module-cache-path "$test_dir/module-cache" \
  "$repo_root/apps/macos/Tono/Models/ProxyNode.swift" \
  "$repo_root/apps/macos/Tono/Models/RuleEntry.swift" \
  "$repo_root/apps/macos/Tono/Services/ConfigParser.swift" \
  "$repo_root/apps/macos/Tono/Core/HelperProtocolVersion.swift" \
  "$repo_root/apps/macos/Tono/Core/ConfigPipeline.swift" \
  "$repo_root/tooling/scripts/tests/IsolatedDataPlaneRuntime.swift" \
  -o "$test_dir/isolated-runtime"

preferred_node=${2:-"US Reality"}
"$test_dir/isolated-runtime" "$1" "$test_dir/config.yaml" "$preferred_node"
"$mihomo_path" \
  -t -d "$test_dir" -f "$test_dir/config.yaml" >/dev/null

"$mihomo_path" \
  -d "$test_dir" -f "$test_dir/config.yaml" \
  >"$test_dir/mihomo.log" 2>&1 &
core_pid=$!

dns_answer=""
for _ in {1..50}; do
  if ! kill -0 "$core_pid" 2>/dev/null; then
    /usr/bin/tail -n 20 "$test_dir/mihomo.log" >&2
    exit 1
  fi
  dns_answer=$(
    /usr/bin/dig @127.0.0.1 -p 21053 www.gstatic.com A \
      +short +time=1 +tries=1 2>/dev/null || true
  )
  if [[ $dns_answer == *"198.18."* ]]; then
    break
  fi
  /bin/sleep 0.1
done
if [[ $dns_answer != *"198.18."* ]]; then
  /usr/bin/tail -n 20 "$test_dir/mihomo.log" >&2
  echo "isolated protected DNS did not return a fake IP" >&2
  exit 1
fi

google_result=$(
  /usr/bin/curl --silent --show-error --output /dev/null \
    --write-out '%{http_code} %{time_connect} %{time_appconnect} %{time_total}' \
    --max-time 8 --noproxy "" \
    --proxy http://127.0.0.1:28790 \
    https://www.gstatic.com/generate_204
)
google_search_result=$(
  /usr/bin/curl --silent --show-error --output /dev/null \
    --write-out '%{http_code} %{time_connect} %{time_appconnect} %{time_total}' \
    --max-time 8 --noproxy "" \
    --proxy http://127.0.0.1:28790 \
    https://www.google.com/generate_204
)
youtube_result=$(
  /usr/bin/curl --silent --show-error --output /dev/null \
    --write-out '%{http_code} %{time_connect} %{time_appconnect} %{time_total}' \
    --max-time 8 --noproxy "" \
    --proxy http://127.0.0.1:28790 \
    https://www.youtube.com/generate_204
)
google_status=${google_result%% *}
google_search_status=${google_search_result%% *}
youtube_status=${youtube_result%% *}
[[ $google_status == 204 ]]
[[ $google_search_status == 204 ]]
[[ $youtube_status == 204 || $youtube_status == 200 ]]

exit_ipv4=$(
  /usr/bin/curl --silent --show-error --fail \
    --max-time 8 --noproxy "" \
    --proxy http://127.0.0.1:28790 \
    https://api.ipify.org
)
if [[ ! $exit_ipv4 =~ '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' ]]; then
  echo "isolated egress check did not return an IPv4 address" >&2
  exit 1
fi
if [[ $# -eq 3 && $exit_ipv4 != $3 ]]; then
  echo "isolated egress mismatch: expected $3, observed $exit_ipv4" >&2
  exit 1
fi

switch_google_result=""
switch_exit_ipv4=""
if [[ -n $switch_node ]]; then
  controller_url="http://127.0.0.1:29090"
  authorization="Authorization: Bearer tono-isolated-test"
  group_state=$(
    /usr/bin/curl --silent --show-error --fail --max-time 3 \
      --header "$authorization" \
      "$controller_url/proxies/Tono-Exit"
  )
  current_node=$(
    printf '%s' "$group_state" \
      | /usr/bin/plutil -extract now raw -o - -- -
  )
  if [[ $current_node == $switch_node ]]; then
    echo "TONO_TEST_SWITCH_NODE must differ from the initial selection" >&2
    exit 2
  fi

  switch_body="$test_dir/switch.json"
  /usr/bin/plutil -create xml1 "$switch_body"
  /usr/bin/plutil -insert name -string "$switch_node" "$switch_body"
  /usr/bin/plutil -convert json "$switch_body"
  /usr/bin/curl --silent --show-error --fail --output /dev/null --max-time 3 \
    --request PUT \
    --header "$authorization" \
    --header 'Content-Type: application/json' \
    --data-binary "@$switch_body" \
    "$controller_url/proxies/Tono-Exit"
  /usr/bin/curl --silent --show-error --fail --output /dev/null --max-time 3 \
    --request DELETE \
    --header "$authorization" \
    "$controller_url/connections"

  group_state=$(
    /usr/bin/curl --silent --show-error --fail --max-time 3 \
      --header "$authorization" \
      "$controller_url/proxies/Tono-Exit"
  )
  selected_after_switch=$(
    printf '%s' "$group_state" \
      | /usr/bin/plutil -extract now raw -o - -- -
  )
  if [[ $selected_after_switch != $switch_node ]]; then
    echo "live selector did not commit the requested node" >&2
    exit 1
  fi
  if ! kill -0 "$core_pid" 2>/dev/null; then
    echo "mihomo exited during selector-only switch" >&2
    exit 1
  fi

  switch_google_result=$(
    /usr/bin/curl --silent --show-error --output /dev/null \
      --write-out '%{http_code} %{time_connect} %{time_appconnect} %{time_total}' \
      --max-time 10 --noproxy "" \
      --proxy http://127.0.0.1:28790 \
      https://www.gstatic.com/generate_204
  )
  [[ ${switch_google_result%% *} == 204 ]]
  switch_exit_ipv4=$(
    /usr/bin/curl --silent --show-error --fail \
      --max-time 10 --noproxy "" \
      --proxy http://127.0.0.1:28790 \
      https://api.ipify.org
  )
  if [[ ! $switch_exit_ipv4 =~ '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' ]]; then
    echo "switched isolated egress check did not return an IPv4 address" >&2
    exit 1
  fi
fi

echo "isolated DNS, Google, Google Search, and YouTube passed without TUN, PF, or system DNS changes"
echo "Google connectivity http/connect/tls/total: $google_result"
echo "Google Search http/connect/tls/total: $google_search_result"
echo "YouTube http/connect/tls/total: $youtube_result"
echo "Observed isolated exit IPv4: $exit_ipv4"
if [[ -n $switch_node ]]; then
  echo "Live selector switched the same Mihomo process to: $switch_node"
  echo "Switched Google http/connect/tls/total: $switch_google_result"
  echo "Observed switched exit IPv4: $switch_exit_ipv4"
fi
