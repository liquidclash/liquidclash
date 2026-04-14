# Privileged Helper Daemon for TUN Hot-Switching

## Problem

TUN mode requires root privileges. Currently LiquidClash uses `osascript with administrator privileges` every time — starting TUN asks for password, stopping TUN asks for password, toggling TUN asks twice (stop + start). This makes TUN unusable in practice.

Clash Verge solves this with a persistent LaunchDaemon that manages mihomo with root privileges. Password is requested once at service installation.

## Architecture

```
LiquidClash App (user privileges)
    ↕ HTTP over Unix Socket (/tmp/liquidclash/service.sock)
LiquidClashHelper (LaunchDaemon, root, persistent)
    ↓ manages process lifecycle
mihomo (root privileges, always has TUN capability)
```

## Components

### 1. LiquidClashHelper (new binary)

A lightweight Swift command-line tool that:
- Listens on Unix socket `/tmp/liquidclash/service.sock`
- Accepts HTTP requests to start/stop mihomo
- Captures mihomo stdout/stderr for log retrieval
- Runs as LaunchDaemon with root privileges

**Endpoints:**

| Method | Path | Body | Response |
|--------|------|------|----------|
| GET | /version | - | `{"version": "1.0"}` |
| POST | /core/start | `{"configDir": "..."}` | `{"code": 200}` |
| DELETE | /core/stop | - | `{"code": 200}` |
| GET | /core/status | - | `{"running": true, "pid": 1234}` |

**Security:**
- `binaryPath` NOT accepted from client — helper resolves mihomo from the app bundle that installed it
- Socket created with `0o777` (like Verge) but helper validates caller via `getpeereid()`
- `/core/start` only accepts `configDir`, never arbitrary executables

**Implementation:** Single-file `main.swift` using raw Unix socket + minimal HTTP parsing. No external dependencies.

### 2. HelperManager (new, in app)

Manages helper lifecycle from the app side:
- `installIfNeeded()` — check socket, install via osascript if missing
- `startCore(configDir:)` — POST /core/start
- `stopCore()` — DELETE /core/stop
- `isRunning()` — GET /core/status

**Communication:** Raw Unix socket HTTP client (Foundation `FileHandle` or `SocketPort`).

### 3. ClashManager (refactored)

Remove all osascript/Process logic. Delegate to HelperManager:

```swift
// Before: two paths + osascript
func start(...)              // normal user
func startWithPrivileges(...) // osascript root
func stop() -> Bool          // two stop paths

// After: single path via helper
func start(configDir:)  // via HelperManager
func stop()             // via HelperManager
```

### 4. AppState (modified)

- `connect()` — single path, always through helper
- TUN toggle — `PATCH /configs` to mihomo API, no reconnect needed
- Remove `reconnect()`, `isProxyDegraded` TUN-specific logic

### 5. Views (modified)

SettingsView/MenuBarView TUN toggle: call `appState.applySettingChange(key: "tun", value: ...)` directly. No error messages, no reconnect.

## File Layout

```
App bundle:
  LiquidClash.app/Contents/Resources/liquidclash-helper

Installed (by osascript, once):
  /Library/PrivilegedHelperTools/liquidclash-helper     (755 root:wheel)
  /Library/LaunchDaemons/liquidclash.helper.plist        (644 root:wheel)

Runtime:
  /tmp/liquidclash/service.sock                          (Unix socket)
```

## LaunchDaemon plist

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>liquidclash.helper</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Library/PrivilegedHelperTools/liquidclash-helper</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

## Installation Flow (once)

```
App launches
→ try connect to /tmp/liquidclash/service.sock
→ fails (not installed)
→ osascript "do shell script '...' with administrator privileges"
  → cp helper to /Library/PrivilegedHelperTools/
  → write plist to /Library/LaunchDaemons/
  → launchctl load plist
→ helper starts, listens on socket
→ app connects successfully
```

## Data Flow

**Connect:**
```
App → HelperManager.startCore(configDir)
    → POST /core/start → Helper spawns mihomo as root
    → App polls mihomo API until ready
    → onCoreStarted()
```

**Toggle TUN (hot):**
```
User toggles TUN in Settings
→ appState.applySettingChange(key: "tun", value: {"enable": true})
→ PATCH /configs to mihomo REST API (port 9090)
→ mihomo enables/disables TUN immediately
→ If enabling TUN: also set system proxy off (TUN handles routing)
→ If disabling TUN: also set system proxy on
```

**Disconnect:**
```
App → HelperManager.stopCore()
    → DELETE /core/stop → Helper kills mihomo
    → App cleans up state
```

## Files Changed

| File | Change |
|------|--------|
| **New** `LiquidClashHelper/main.swift` | Helper daemon (~150 lines) |
| **New** `LiquidClash/Core/HelperManager.swift` | Install + IPC client (~120 lines) |
| **Refactor** `LiquidClash/Core/ClashManager.swift` | Remove osascript, delegate to HelperManager |
| **Modify** `LiquidClash/Services/AppState.swift` | Unified connect, TUN hot-switch via PATCH |
| **Modify** `LiquidClash/Views/SettingsView.swift` | TUN toggle instant |
| **Modify** `LiquidClash/Views/MenuBarView.swift` | TUN toggle instant |
| **Modify** `LiquidClash.xcodeproj/project.pbxproj` | Add helper to bundle resources |

## Edge Cases

- **Helper crashes:** launchd auto-restarts (KeepAlive=true)
- **App crashes while connected:** mihomo keeps running under helper; next app launch reconnects
- **Helper version mismatch:** Check /version on connect, reinstall if outdated
- **Socket stale:** Helper cleans up socket on startup
