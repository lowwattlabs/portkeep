# PortKeep

Port management + security for self-hosted infrastructure.

Know every port. Claim every port. Secure every port.

PortKeep is a lightweight, self-hosted, bare-metal-first CLI that gives you full visibility and control over every listening port across your infrastructure. No Docker dependency. No cloud. No guesswork.

## What it does

- **Discovers** every listening port across multiple nodes (local + SSH)
- **Claims** ports into a registry — no more "I think 3002 was free"
- **Detects drift** — declared vs actual, rogue ports, bind mismatches
- **Audits security** — exposure score, risk flags, firewall cross-reference
- **Alerts** — Telegram/webhook/email when something changes
- **Tracks history** — git-log style timeline of every port change

## Quick start

```bash
portkeep config init       # 4 questions, you're running
portkeep scan               # see every port on this host
portkeep audit              # security score + risk flags
portkeep drift              # declared vs actual — exits 1 on drift
portkeep claim next          # suggests next available port
```

## Install

```bash
# Binary (when released)
curl -sSL https://github.com/jchandler187/portkeep/releases/latest/download/portkeep-linux-amd64 -o /usr/local/bin/portkeep
chmod +x /usr/local/bin/portkeep

# npm
npm install -g portkeep

# Docker
docker run --rm -p 9091:9091 lowwattlabs/portkeep scan
```

## Documentation

- [SPEC.md](SPEC.md) — Full feature specification (every command, every flag, every behavior)
- [CLI.md](CLI.md) — CLI design document (what you type, what you see)

## Project status

**Pre-build.** Spec and CLI design complete. Implementation starting.

## License

MIT

## Author

Jason Chandler · [Low Watt Labs](https://github.com/jchandler187)