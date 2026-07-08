# Contributing to LiquidClash

Thanks for your interest in contributing!

## Project Structure

```
LiquidClash/
├── LiquidClashApp.swift              # App entry point with menu bar
├── ContentView.swift                 # Main layout with NavigationSplitView
├── Core/
│   ├── ClashAPI.swift                # Clash RESTful API client
│   ├── ClashManager.swift            # Core process lifecycle management
│   ├── ClashWebSocket.swift          # WebSocket for real-time updates
│   └── SystemProxy.swift             # macOS system proxy configuration
├── Models/
│   ├── AppSettings.swift             # User preferences model
│   ├── ClashConfig.swift             # Clash configuration model
│   ├── ProxyNode.swift               # Proxy node model
│   ├── ProxyGroup.swift              # Proxy group model
│   ├── RuleEntry.swift               # Rule entry model
│   ├── ConnectionLog.swift           # Connection log model
│   ├── LogEntry.swift                # Log entry model
│   └── MockData.swift                # Preview mock data
├── Services/
│   ├── AppState.swift                # Global app state management
│   ├── ConfigParser.swift            # YAML config parser
│   ├── ConfigStorage.swift           # Config persistence
│   └── SubscriptionManager.swift     # Subscription management
├── Views/
│   ├── DashboardView.swift           # Dashboard page
│   ├── ProxiesView.swift             # Proxies page
│   ├── RulesView.swift               # Rules editor page
│   ├── ActivityView.swift            # Connection log page
│   ├── LogsView.swift                # Core log page
│   ├── SettingsView.swift            # Settings page
│   ├── WelcomeView.swift             # First-launch onboarding
│   ├── MenuBarView.swift             # Menu bar popover
│   ├── SidebarView.swift             # Navigation sidebar
│   ├── MeshGradientBackground.swift  # Animated background
│   └── ...                           # Component views
├── Resources/
│   ├── mihomo                        # mihomo core binary
│   ├── country.mmdb                  # GeoIP database (MaxMind)
│   ├── geoip.dat                     # GeoIP rules
│   └── geosite.dat                   # GeoSite rules
└── Assets.xcassets/                  # App icons and image assets
```

## Build from Source

```bash
git clone https://github.com/liquidclash/liquidclash.git
cd liquidclash
open LiquidClash.xcodeproj
```

Build and run with `⌘R` in Xcode. Requires macOS 26.0+ and Xcode 26.0+.
