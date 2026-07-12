# Vivid Casino Engine

A modular, cross-platform casino game engine written in C with Python backend. Designed for rapid deployment of online casino clients with customizable game modules, admin dashboard, and real-time analytics.

## Features

- **Cross-Platform Client** — Native C engine for Windows, with macOS support via Objective-C bridge
- **Modular Game System** — Load game modules dynamically from remote servers
- **Real-time Analytics** — Player session tracking, performance metrics, and security auditing
- **Admin Dashboard** — Web-based control panel for game operators
- **Secure Communication** — Encrypted client-server protocol with heartbeat monitoring
- **Auto-Update System** — Seamless client updates without user intervention

## Architecture

```
Vivid Casino Engine/
├── src/                  # Client source code
│   ├── client/           # Main client entry point
│   ├── engine/           # Core engine modules (network, UI, audio)
│   └── utils/            # Utilities (system, security, config)
├── server/               # Backend services
│   ├── backend.py        # Main game server
│   ├── admin.py          # Admin panel API
│   └── content.py        # Game content delivery
├── web/                  # Website and download page
├── tools/                # Build and packaging tools
├── scripts/              # Deployment scripts
├── config/               # Configuration files
├── assets/               # Game assets and manifests
└── docs/                 # Documentation
```

## Quick Start

### Build Client (Windows)

```bash
# Using GitHub Actions (recommended)
# Push to main branch triggers auto-build

# Manual build with MSVC
cl.exe /O2 /W3 /Fe:VividCasinoSetup.exe src/client/*.c src/engine/*.c src/utils/*.c \
  ws2_32.lib wininet.lib shell32.lib advapi32.lib kernel32.lib user32.lib gdi32.lib
```

### Deploy Website

The `web/index.html` is a standalone download page. Host on any static file server or GitHub Pages.

## Configuration

Edit `config/default.json` to configure:
- Server endpoints
- Game module sources
- Update channels

## Game Modules

Game modules are loaded dynamically from the content server. Place `.dll` or `.so` files in the modules directory, or fetch from remote URLs specified in `config/default.json`.

## License

MIT License — See LICENSE file for details.

## Contributing

Pull requests welcome. See `docs/ARCHITECTURE.md` for developer documentation.

---

*Vivid Casino Engine — Powering the next generation of online gaming.*
