#!/bin/zsh
set -euo pipefail

repo_root=${0:A:h:h}
windows_root="$repo_root/Tono-win"
app_root="$windows_root/app"
toolchain_root="$windows_root/.toolchain"
version=${1:-}

if [[ ! $version =~ '^[0-9]+\.[0-9]+\.[0-9]+$' ]]; then
  echo "usage: $0 <major.minor.patch>" >&2
  exit 2
fi
if [[ ! -x "$toolchain_root/cargo/bin/cargo" ||
      ! -x "$toolchain_root/cargo/bin/cargo-xwin" ||
      ! -x "$toolchain_root/bin/pnpm" ]]; then
  echo "the pinned Tono-win toolchain is incomplete" >&2
  exit 1
fi

export CARGO_HOME="$toolchain_root/cargo"
export RUSTUP_HOME="$toolchain_root/rustup"
export XWIN_CACHE_DIR="$toolchain_root/xwin"
export PATH="$CARGO_HOME/bin:$toolchain_root/xwin:/opt/homebrew/opt/llvm/bin:$PATH"

(
  cd "$app_root"
  "$toolchain_root/bin/pnpm" release-version "$version"
  # Fail before the multi-hour Windows build if packaging still looks like Test 5
  # (dual Mihomo / whole-directory resources that pull Unix helpers).
  "$toolchain_root/bin/pnpm" release:preflight --config-only
)

"$repo_root/scripts/build-mihomo-adaptive.sh" --install-adaptive-windows

(
  cd "$windows_root"
  cargo xwin build --manifest-path service/Cargo.toml --release \
    --target x86_64-pc-windows-msvc --features standalone,client \
    --bin tono-service --bin tono-service-install --bin tono-service-uninstall
)
for name in tono-service tono-service-install tono-service-uninstall; do
  /usr/bin/install -m 755 \
    "$windows_root/service/target/x86_64-pc-windows-msvc/release/$name.exe" \
    "$app_root/src-tauri/resources/$name.exe"
done

(
  cd "$app_root"
  eval "$(cargo xwin env --target x86_64-pc-windows-msvc)"
  # cargo-xwin's environment replaces PATH; restore the local pnpm shim for
  # Tauri's beforeBuildCommand.
  export PATH="$toolchain_root/bin:$PATH"
  cargo tauri build --target x86_64-pc-windows-msvc
)

installer="$app_root/target/x86_64-pc-windows-msvc/release/bundle/nsis/Tono_${version}_x64-setup.exe"
if [[ ! -f $installer ]]; then
  echo "installer not found: $installer" >&2
  exit 1
fi
/usr/bin/file "$installer"
/usr/bin/shasum -a 256 "$installer"

# Payload truth for Test 6: list the NSIS archive and refuse dual Mihomo / Unix junk.
# Full tag+manifest preflight still runs after commit/tag; this is the unpack gate that
# must pass on every candidate installer before anyone installs it.
if command -v 7zz >/dev/null 2>&1; then
  listing=$(/usr/bin/mktemp)
  7zz l -ba "$installer" >"$listing"
  if /usr/bin/grep -Eiq 'verge-mihomo-alpha|clash-verge-service|set_dns\.sh|unset_dns\.sh' "$listing"; then
    echo "installer payload still contains Test 5 junk (alpha Mihomo / Unix helpers):" >&2
    /usr/bin/grep -Ei 'verge-mihomo|clash-verge-service|set_dns|unset_dns|tono-service|Tono\.exe' "$listing" >&2 || true
    /bin/rm -f "$listing"
    exit 1
  fi
  if ! /usr/bin/grep -Eiq 'verge-mihomo([.-]|$)' "$listing"; then
    echo "installer payload is missing stable Mihomo" >&2
    /bin/rm -f "$listing"
    exit 1
  fi
  /bin/rm -f "$listing"
  echo "NSIS payload smoke check OK (no alpha / Unix helpers)"
else
  echo "warning: 7zz not found; skipped NSIS payload smoke check" >&2
fi
