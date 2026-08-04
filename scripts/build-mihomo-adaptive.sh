#!/bin/zsh
set -euo pipefail

repo_root=${0:A:h:h}
mac_target="$repo_root/Tono/Resources/mihomo"
windows_target="$repo_root/Tono-win/app/src-tauri/sidecar/verge-mihomo-x86_64-pc-windows-msvc.exe"
windows_alpha_target="$repo_root/Tono-win/app/src-tauri/sidecar/verge-mihomo-alpha-x86_64-pc-windows-msvc.exe"
patch_file="$repo_root/scripts/mihomo-adaptive/gvisor-adaptive-buffer.patch"
mode=${1:---install-adaptive}

upstream_tag="v1.19.29"
upstream_commit="e26714a181ac0e2fa803453c0a8e9a9ce94e31cb"
sing_tun_version="v0.4.21"
adaptive_version="v1.19.29-tono-gvisor-adaptive.1"
stock_archive_sha256="4dc25df9e899f14161911302a8ee5fc9e202ed9c976fc405bf82c50ff27466ca"
stock_binary_sha256="ec66e3e883bdc3fca06753784e324e08921e13239f8e945587cb1bfbf4c6b936"
stock_url="https://github.com/MetaCubeX/mihomo/releases/download/v1.19.29/mihomo-darwin-arm64-v1.19.29.gz"
windows_stock_archive_sha256="55feeada4feed7b86edf7c853fb37e498d646400acc37b7cc5905bb5d1f77899"
windows_stock_binary_sha256="98986b574e41f92b22ed65aa42a61ad8cadf886cc7b3f76b722cd73a3a52d878"
windows_stock_url="https://github.com/MetaCubeX/mihomo/releases/download/v1.19.29/mihomo-windows-amd64-v2-v1.19.29.zip"

work_dir=$(mktemp -d /tmp/tono-mihomo-adaptive.XXXXXX)
install_tmp=""
cleanup() {
  if [[ -n $install_tmp && -f $install_tmp ]]; then
    rm -f "$install_tmp"
  fi
  rm -rf "$work_dir"
}
trap cleanup EXIT

sha256() {
  /usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{print $1}'
}

atomic_install() {
  local source=$1
  local target=$2
  local target_dir=${target:h}
  install_tmp=$(mktemp "$target_dir/.mihomo.install.XXXXXX")
  /usr/bin/install -m 755 "$source" "$install_tmp"
  /bin/mv -f "$install_tmp" "$target"
  install_tmp=""
}

restore_stock() {
  local archive="$work_dir/mihomo-darwin-arm64-v1.19.29.gz"
  /usr/bin/curl --fail --location --retry 3 --silent --show-error \
    --output "$archive" "$stock_url"
  local archive_digest=$(sha256 "$archive")
  if [[ $archive_digest != $stock_archive_sha256 ]]; then
    echo "stock archive checksum mismatch: $archive_digest" >&2
    exit 1
  fi
  /usr/bin/gzip -dk "$archive"
  local binary=${archive%.gz}
  local binary_digest=$(sha256 "$binary")
  if [[ $binary_digest != $stock_binary_sha256 ]]; then
    echo "stock binary checksum mismatch: $binary_digest" >&2
    exit 1
  fi
  atomic_install "$binary" "$mac_target"
  echo "restored official Mihomo $upstream_tag: $binary_digest"
}

restore_windows_stock() {
  local archive="$work_dir/mihomo-windows-amd64-v2-v1.19.29.zip"
  /usr/bin/curl --fail --location --retry 3 --silent --show-error \
    --output "$archive" "$windows_stock_url"
  local archive_digest=$(sha256 "$archive")
  if [[ $archive_digest != $windows_stock_archive_sha256 ]]; then
    echo "Windows stock archive checksum mismatch: $archive_digest" >&2
    exit 1
  fi
  /usr/bin/unzip -q "$archive" -d "$work_dir/windows-stock"
  local binary="$work_dir/windows-stock/mihomo-windows-amd64-v2.exe"
  local binary_digest=$(sha256 "$binary")
  if [[ $binary_digest != $windows_stock_binary_sha256 ]]; then
    echo "Windows stock binary checksum mismatch: $binary_digest" >&2
    exit 1
  fi
  atomic_install "$binary" "$windows_target"
  atomic_install "$binary" "$windows_alpha_target"
  echo "restored official Windows Mihomo $upstream_tag: $binary_digest"
}

install_adaptive() {
  local platform=${1:-mac}
  local go_binary=$(command -v go)
  local git_binary=$(command -v git)
  if [[ -z $go_binary || -z $git_binary || ! -f $patch_file ]]; then
    echo "Go, Git, and the adaptive patch are required" >&2
    exit 1
  fi
  local go_version=$($go_binary env GOVERSION)
  if [[ $go_version != "go1.26.5" ]]; then
    echo "adaptive core requires go1.26.5; found $go_version" >&2
    exit 1
  fi

  local source_dir="$work_dir/mihomo"
  $git_binary clone --quiet --depth 1 --branch "$upstream_tag" \
    https://github.com/MetaCubeX/mihomo.git "$source_dir"
  local source_commit=$($git_binary -C "$source_dir" rev-parse HEAD)
  if [[ $source_commit != $upstream_commit ]]; then
    echo "unexpected Mihomo source commit: $source_commit" >&2
    exit 1
  fi

  (
    cd "$source_dir"
    $go_binary mod download "github.com/metacubex/sing-tun@$sing_tun_version"
  )
  local module_dir=$(
    cd "$source_dir"
    $go_binary list -mod=mod -m -f '{{.Dir}}' github.com/metacubex/sing-tun
  )
  local patched_tun="$work_dir/sing-tun"
  /bin/cp -R "$module_dir" "$patched_tun"
  /bin/chmod -R u+w "$patched_tun"
  /usr/bin/patch -s -d "$patched_tun" -p1 -i "$patch_file"

  (
    cd "$patched_tun"
    $go_binary test -tags with_gvisor .
  )
  (
    cd "$source_dir"
    $go_binary mod edit \
      -replace="github.com/metacubex/sing-tun=$patched_tun"
  )

  local output="$work_dir/mihomo-adaptive"
  local build_time=$(/bin/date -u '+%Y-%m-%dT%H:%M:%SZ')
  local ldflags="-X github.com/metacubex/mihomo/constant.Version=$adaptive_version -X github.com/metacubex/mihomo/constant.BuildTime=$build_time -w -s -buildid="
  if [[ $platform == windows ]]; then
    output="$output.exe"
    (
      cd "$source_dir"
      CGO_ENABLED=0 GOOS=windows GOARCH=amd64 GOAMD64=v2 \
        $go_binary build -tags with_gvisor -trimpath \
        -ldflags "$ldflags" -o "$output" .
    )

    local file_description=$(/usr/bin/file "$output")
    local build_info=$($go_binary version -m "$output")
    local has_adaptive_version=false
    if /usr/bin/strings "$output" | /usr/bin/grep -F "$adaptive_version" >/dev/null; then
      has_adaptive_version=true
    fi
    if [[ $file_description != *"PE32+ executable"* ||
          $file_description != *"x86-64"* ||
          $build_info != *$'\tbuild\t-tags=with_gvisor'* ||
          $build_info != *$'\tbuild\tGOAMD64=v2'* ||
          $has_adaptive_version != true ]]; then
      echo "adaptive Windows binary verification failed" >&2
      echo "$file_description" >&2
      echo "$build_info" >&2
      exit 1
    fi
    atomic_install "$output" "$windows_target"
    atomic_install "$output" "$windows_alpha_target"
    echo "adaptive Windows Mihomo SHA-256: $(sha256 "$windows_target")"
  else
    (
      cd "$source_dir"
      CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 \
        $go_binary build -tags with_gvisor -trimpath \
        -ldflags "$ldflags" -o "$output" .
    )

    local file_description=$(/usr/bin/file "$output")
    local version_output=$($output -v)
    if [[ $file_description != *"Mach-O 64-bit executable arm64"* ||
          $version_output != *"$adaptive_version"* ||
          $version_output != *"Use tags: with_gvisor"* ]]; then
      echo "adaptive binary verification failed" >&2
      echo "$file_description" >&2
      echo "$version_output" >&2
      exit 1
    fi
    atomic_install "$output" "$mac_target"
    echo "$version_output"
    echo "adaptive Mihomo SHA-256: $(sha256 "$mac_target")"
  fi
}

case $mode in
  --install-adaptive)
    install_adaptive
    ;;
  --install-adaptive-windows)
    install_adaptive windows
    ;;
  --restore-stock)
    restore_stock
    ;;
  --restore-stock-windows)
    restore_windows_stock
    ;;
  *)
    echo "usage: $0 [--install-adaptive|--install-adaptive-windows|--restore-stock|--restore-stock-windows]" >&2
    exit 2
    ;;
esac
