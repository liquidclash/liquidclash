# Contributing to Tono

Thanks for your interest in contributing!

## Project Structure

```text
tono/
├── apps/
│   ├── macos/                 SwiftUI client and privileged helper resources
│   └── windows/               Tauri client, Windows Service, and WFP support
├── services/
│   ├── control-plane/         Cloudflare Worker, static assets, and D1 schema
│   └── home-agent/            Home exit-node usage reporter
├── tooling/scripts/           Shared build, release, test, and operations tools
├── docs/                      Screenshots and archived project handoffs
└── .agents/                   Repository-specific automation guidance
```

## Build from Source

```bash
git clone https://github.com/raydocs/liquidclash.git tono
cd tono
open apps/macos/LiquidClash.xcodeproj
```

Build and run the macOS client with `⌘R` in Xcode. Requires macOS 26.0+ and
Xcode 26.0+. See `apps/windows/README.md` for Windows prerequisites and build
instructions.
