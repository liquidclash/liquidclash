#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
temporary_dir=$(mktemp -d "/tmp/tono-peer-auth.XXXXXX")
case "$temporary_dir" in
  /tmp/tono-peer-auth.*) ;;
  *) echo "unexpected temporary directory" >&2; exit 2 ;;
esac
cleanup() {
  status=$?
  trap - EXIT
  find "$temporary_dir" -depth -delete
  exit "$status"
}
trap cleanup EXIT

export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
server="$temporary_dir/auth-server"
client="$temporary_dir/auth-client"
xcrun swiftc \
  -module-cache-path "$temporary_dir/module-cache" \
  "$repo_dir/tooling/scripts/helper-tests/auth-server/main.swift" \
  "$repo_dir/tooling/scripts/helper-shared/PeerAuthorization.swift" \
  -framework Security \
  -o "$server"
xcrun swiftc \
  -module-cache-path "$temporary_dir/module-cache" \
  "$repo_dir/tooling/scripts/helper-tests/auth-client/main.swift" \
  -o "$client"

identity=$(
  security find-identity -v -p codesigning |
    awk '/Apple Development: Ruirui Wan/ { print $2; exit }'
)
if [ -z "$identity" ]; then
  echo "SKIP: no Apple Development identity for the Tono team" >&2
  exit 0
fi

run_case() {
  expected=$1
  identifier=$2
  signing_identity=$3
  socket_path="$temporary_dir/$expected-$identifier.sock"
  codesign --force --sign "$signing_identity" --identifier "$identifier" "$client"
  "$server" "$socket_path" "$expected" &
  server_pid=$!
  attempts=0
  while [ ! -S "$socket_path" ]; do
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 100 ]; then
      kill "$server_pid" 2>/dev/null || true
      wait "$server_pid" 2>/dev/null || true
      echo "authorization test server did not start" >&2
      exit 1
    fi
    sleep 0.01
  done
  "$client" "$socket_path"
  wait "$server_pid"
}

run_case allow com.raydocs.tono "$identity"
run_case reject com.raydocs.tono -
run_case reject com.raydocs.not-tono "$identity"
echo "helper peer authorization tests passed"
