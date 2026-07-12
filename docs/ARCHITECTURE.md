# Vivid Casino Engine — Architecture

## Overview

The Vivid Casino Engine is a modular, cross-platform game engine designed for online casino applications. It consists of a native C client, Python backend services, and a web-based operator dashboard.

## Components

### Client (src/)

- **main.c** — Entry point, game loop, command dispatcher
- **netcode.c** — Network protocol, server communication
- **ui.c** — Window management, splash screens, input handling
- **sys.c** — System utilities, diagnostics, process execution
- **audit.c** — Configuration scanner for deployment validation

### Backend (server/)

- **backend.py** — Main game server, player session management, dashboard API
- **content.py** — Game module delivery server

### Web (web/)

- **index.html** — Download page and installer portal

## Protocol

The client uses a length-prefixed TCP protocol over port 4444. Messages are 8-digit length headers followed by UTF-8 payload.

## Building

See README.md for build instructions.
