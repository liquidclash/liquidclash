#!/bin/bash
set -euo pipefail

umask 077

SERVICE_NAME="tono-xray.service"
SERVICE_PATH="/etc/systemd/system/$SERVICE_NAME"
INSTALL_ROOT="/opt/tono-xray"
SERVICE_USER="tono-xray"

fail() {
  printf 'Tono node operation failed: %s\n' "$1" >&2
  exit 1
}

require_root() {
  [[ $(id -u) -eq 0 ]] || fail "root or passwordless sudo is required"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command is unavailable: $1"
}

validate_port() {
  [[ $1 =~ ^[0-9]+$ ]] && ((10#$1 >= 1 && 10#$1 <= 65535)) || fail "invalid TCP port"
}

validate_target() {
  [[ ${#1} -le 253 && $1 =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ && $1 == *.* ]] ||
    fail "Reality target must be a bounded DNS hostname"
}

platform() {
  [[ -r /etc/os-release ]] || fail "missing /etc/os-release"
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}:${VERSION_ID:-}" in
    ubuntu:22.04|ubuntu:24.04|debian:12) ;;
    *) fail "only Ubuntu 22.04/24.04 and Debian 12 are supported" ;;
  esac
  case "$(uname -m)" in
    x86_64|aarch64) ;;
    *) fail "only x86_64 and aarch64 hosts are supported" ;;
  esac
  [[ -d /run/systemd/system ]] || fail "systemd is not running"
}

port_in_use() {
  ss -H -ltn "sport = :$1" 2>/dev/null | grep -q .
}

target_supports_tls13() {
  local target=$1
  timeout 10 openssl s_client \
    -connect "$target:443" \
    -servername "$target" \
    -tls1_3 \
    -verify_hostname "$target" \
    -verify_return_error \
    </dev/null >/dev/null 2>&1
}

preflight() {
  require_root
  local port=${1:-}
  local target=${2:-}
  validate_port "$port"
  validate_target "$target"
  platform
  for command_name in getent grep install openssl sha256sum ss systemctl timeout; do
    require_command "$command_name"
  done

  local os_id arch available_kib occupied existing tls13 ufw_active
  # shellcheck disable=SC1091
  . /etc/os-release
  os_id="${ID}-${VERSION_ID}"
  arch=$(uname -m)
  available_kib=$(df -Pk / | awk 'NR == 2 { print $4 }')
  [[ $available_kib =~ ^[0-9]+$ ]] || fail "could not determine free disk space"
  ((available_kib >= 131072)) || fail "at least 128 MiB of free disk is required"

  occupied=false
  port_in_use "$port" && occupied=true
  existing=false
  if [[ -e "$SERVICE_PATH" || -e "$INSTALL_ROOT/current" ]]; then
    existing=true
  fi
  tls13=false
  target_supports_tls13 "$target" && tls13=true
  ufw_active=false
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw_active=true
  fi

  printf '{"os":"%s","arch":"%s","availableKiB":%s,"port":%s,"portInUse":%s,"existingTono":%s,"targetTLS13":%s,"ufwActive":%s}\n' \
    "$os_id" "$arch" "$available_kib" "$port" "$occupied" "$existing" "$tls13" "$ufw_active"
}

rollback_deployment() {
  require_root
  local deployment_id=${1:-}
  [[ $deployment_id =~ ^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$ ]] || fail "invalid deployment identifier"
  local release="$INSTALL_ROOT/releases/$deployment_id"
  local current=""
  if [[ -L "$INSTALL_ROOT/current" ]]; then
    current=$(readlink -f "$INSTALL_ROOT/current")
  fi
  if [[ -z $current && ! -e $release && ! -e $SERVICE_PATH ]]; then
    printf '{"rolledBack":true,"deploymentId":"%s"}\n' "$deployment_id"
    return
  fi
  if [[ -n $current && $current != "$release" ]]; then
    fail "refusing to roll back a deployment that is not current"
  fi
  if [[ -z $current && ! -e $release ]]; then
    fail "refusing to remove a service that cannot be tied to this deployment"
  fi

  systemctl disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
  rm -f "$SERVICE_PATH" "$SERVICE_PATH.new" "$INSTALL_ROOT/current" "$INSTALL_ROOT/current.new"
  rm -rf "$release"
  systemctl daemon-reload
  systemctl reset-failed "$SERVICE_NAME" >/dev/null 2>&1 || true
  rmdir "$INSTALL_ROOT/releases" "$INSTALL_ROOT" 2>/dev/null || true
  printf '{"rolledBack":true,"deploymentId":"%s"}\n' "$deployment_id"
}

apply_deployment() {
  require_root
  local deployment_id=${1:-}
  local version=${2:-}
  local artifact=${3:-}
  local expected_sha256=${4:-}
  local port=${5:-}
  local target=${6:-}
  [[ $deployment_id =~ ^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}$ ]] || fail "invalid deployment identifier"
  [[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "invalid pinned Xray version"
  [[ $artifact =~ ^/tmp/tono-xray-artifact-[a-f0-9]{24}$ ]] || fail "invalid uploaded artifact path"
  [[ $expected_sha256 =~ ^[a-f0-9]{64}$ ]] || fail "invalid artifact digest"
  validate_port "$port"
  validate_target "$target"
  platform
  for command_name in awk chmod chown getent groupadd grep install ln mv openssl readlink sed seq sha256sum ss systemctl timeout useradd; do
    require_command "$command_name"
  done
  [[ -f $artifact && ! -L $artifact ]] || fail "uploaded Xray artifact is not a regular file"
  [[ $(sha256sum "$artifact" | awk '{ print $1 }') == "$expected_sha256" ]] || fail "uploaded Xray artifact digest mismatch"
  [[ ! -e $SERVICE_PATH && ! -e $INSTALL_ROOT/current ]] || fail "an existing Tono Xray installation requires an explicit rotation workflow"
  ! port_in_use "$port" || fail "the selected TCP port is already in use"
  target_supports_tls13 "$target" || fail "the Reality target did not complete a verified TLS 1.3 handshake from this VPS"

  local release committed=0
  release="$INSTALL_ROOT/releases/$deployment_id"

  cleanup_apply() {
    local status=$?
    rm -f "$artifact"
    if ((status != 0 && committed == 0)); then
      systemctl disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
      rm -f "$SERVICE_PATH" "$SERVICE_PATH.new" "$INSTALL_ROOT/current" "$INSTALL_ROOT/current.new"
      rm -rf "$release"
      systemctl daemon-reload >/dev/null 2>&1 || true
      systemctl reset-failed "$SERVICE_NAME" >/dev/null 2>&1 || true
    fi
    trap - EXIT
    exit "$status"
  }
  trap cleanup_apply EXIT

  if ! getent group "$SERVICE_USER" >/dev/null; then
    groupadd --system "$SERVICE_USER"
  fi
  if ! getent passwd "$SERVICE_USER" >/dev/null; then
    useradd --system --gid "$SERVICE_USER" --home-dir /nonexistent --shell /usr/sbin/nologin "$SERVICE_USER"
  fi

  install -d -m 0755 -o root -g root "$INSTALL_ROOT" "$INSTALL_ROOT/releases"
  install -d -m 0750 -o root -g "$SERVICE_USER" "$release"
  install -m 0755 -o root -g root "$artifact" "$release/xray"

  local uuid key_output private_key public_key short_id
  uuid=$("$release/xray" uuid)
  [[ $uuid =~ ^[a-f0-9-]{36}$ ]] || fail "Xray returned an invalid UUID"
  key_output=$("$release/xray" x25519)
  private_key=$(printf '%s\n' "$key_output" | sed -n 's/^PrivateKey:[[:space:]]*//p')
  public_key=$(printf '%s\n' "$key_output" | sed -n 's/^Password (PublicKey):[[:space:]]*//p')
  [[ $private_key =~ ^[A-Za-z0-9_-]{43}$ && $public_key =~ ^[A-Za-z0-9_-]{43}$ ]] ||
    fail "Xray returned an invalid Reality keypair"
  short_id=$(openssl rand -hex 8)

  cat >"$release/config.json" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [{
    "listen": "0.0.0.0",
    "port": $port,
    "protocol": "vless",
    "settings": {
      "clients": [{ "id": "$uuid", "flow": "xtls-rprx-vision" }],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "raw",
      "security": "reality",
      "realitySettings": {
        "target": "$target:443",
        "serverNames": ["$target"],
        "privateKey": "$private_key",
        "shortIds": ["$short_id"]
      }
    }
  }],
  "outbounds": [{ "protocol": "freedom" }]
}
EOF
  chown root:"$SERVICE_USER" "$release/config.json"
  chmod 0640 "$release/config.json"
  "$release/xray" run -test -config "$release/config.json" >/dev/null 2>&1 || fail "Xray rejected the generated configuration"

  cat >"$SERVICE_PATH.new" <<EOF
[Unit]
Description=Tono managed Xray Reality node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
ExecStart=$INSTALL_ROOT/current/xray run -config $INSTALL_ROOT/current/config.json
Restart=on-failure
RestartSec=2s
TimeoutStopSec=15s
LimitNOFILE=1048576
UMask=0077
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateDevices=true
PrivateTmp=true
ProtectControlGroups=true
ProtectHome=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectSystem=strict
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF
  chown root:root "$SERVICE_PATH.new"
  chmod 0644 "$SERVICE_PATH.new"
  mv "$SERVICE_PATH.new" "$SERVICE_PATH"
  ln -s "$release" "$INSTALL_ROOT/current.new"
  mv -T "$INSTALL_ROOT/current.new" "$INSTALL_ROOT/current"
  systemctl daemon-reload
  systemctl enable --now "$SERVICE_NAME" >/dev/null

  local ready=false
  for _ in $(seq 1 50); do
    if systemctl is-active --quiet "$SERVICE_NAME" && port_in_use "$port"; then
      ready=true
      break
    fi
    sleep 0.2
  done
  [[ $ready == true ]] || fail "Xray did not become active and listen on the selected TCP port"

  committed=1
  # EXIT traps run after this function's local variables leave scope. Clean the
  # uploaded artifact and disarm the failure trap while those variables still
  # exist, otherwise `set -u` turns a successful install into a false failure.
  rm -f "$artifact"
  trap - EXIT
  printf '{"deploymentId":"%s","version":"%s","port":%s,"uuid":"%s","publicKey":"%s","shortId":"%s"}\n' \
    "$deployment_id" "$version" "$port" "$uuid" "$public_key" "$short_id"
}

mode=${1:-}
shift || true
case "$mode" in
  preflight) preflight "$@" ;;
  apply) apply_deployment "$@" ;;
  rollback) rollback_deployment "$@" ;;
  *) fail "expected preflight, apply, or rollback mode" ;;
esac
