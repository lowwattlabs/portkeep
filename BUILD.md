# PortKeep — Build Plan

## Architecture

Single Go binary. SQLite (WAL mode) for local storage. No CGO (pure Go SQLite via modernc.org/sqlite). Cross-compiled for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64.

## Repository Structure

```
portkeep/
├── README.md
├── SPEC.md                  # Full feature specification
├── CLI.md                   # CLI design document
├── BUILD.md                 # This file — build plan + architecture
├── LICENSE
├── package.json             # npm distribution metadata
├── .github/
│   └── workflows/
│       └── release.yml      # GoReleaser on tag push
├── cmd/
│   └── portkeep/
│       └── main.go          # Entrypoint
├── internal/
│   ├── cli/
│   │   ├── root.go          # Cobra root command
│   │   ├── scan.go          # scan command
│   │   ├── ports.go         # ports list/show
│   │   ├── claim.go         # claim/unclaim/next
│   │   ├── drift.go         # drift detection
│   │   ├── audit.go         # security audit + scoring
│   │   ├── firewall.go      # UFW/iptables cross-ref
│   │   ├── fingerprint.go   # service fingerprinting
│   │   ├── cve.go           # NVD CVE lookup
│   │   ├── shodan.go        # Shodan internet exposure check
│   │   ├── history.go       # change timeline + diffs
│   │   ├── snapshot.go      # save/compare snapshots
│   │   ├── alert.go         # alert config + rules
│   │   ├── node.go          # multi-node management
│   │   ├── network.go       # network segment analysis
│   │   ├── compliance.go    # policy-based audits
│   │   ├── export.go        # prometheus/grafana/markdown/json
│   │   ├── daemon.go        # background service mode
│   │   └── config.go        # config init/show/set
│   ├── scan/
│   │   ├── scanner.go       # port discovery engine
│   │   ├── local.go         # local host scanning (ss/netstat)
│   │   ├── remote.go        # SSH remote scanning
│   │   └── docker.go        # Docker container port discovery
│   ├── db/
│   │   ├── db.go            # SQLite connection + migration
│   │   ├── models.go        # data models
│   │   ├── ports.go         # port CRUD
│   │   ├── claims.go        # claim CRUD
│   │   ├── history.go       # history event logging
│   │   ├── alerts.go        # alert rule storage
│   │   ├── nodes.go         # node registry
│   │   └── snapshots.go     # snapshot storage
│   ├── audit/
│   │   ├── scorer.go        # exposure score calculation
│   │   ├── risk.go          # bind address risk assessment
│   │   ├── firewall.go     # firewall rule analysis (UFW/iptables/nftables/firewalld)
│   │   └── cve.go           # NVD cache + lookup
│   ├── alert/
│   │   ├── dispatcher.go    # alert routing
│   │   ├── telegram.go      # Telegram notifier
│   │   ├── webhook.go       # generic webhook notifier
│   │   ├── email.go         # SMTP notifier
│   │   └── script.go        # local script executor
│   ├── ssh/
│   │   └── client.go        # SSH key-only client for remote nodes
│   ├── config/
│   │   └── config.go        # Viper config loading + validation
│   └── version/
│       └── version.go      # build version info
├── configs/
│   └── config.example.yaml  # example config
├── compliance/
│   ├── cis-benchmark-l1.yaml
│   └── cisa-smb-baseline.yaml
└── scripts/
    └── install.sh           # curl | sh installer
```

## Dependencies

| Package | Purpose |
|---------|---------|
| github.com/spf13/cobra | CLI framework |
| github.com/spf13/viper | Config (YAML + env vars) |
| modernc.org/sqlite | Pure Go SQLite (no CGO) |
| golang.org/x/crypto/ssh | SSH remote scanning |
| github.com/charmbracelet/bubbletea | Interactive mode (optional) |
| github.com/charmbracelet/lipgloss | Styled output |
| github.com/prometheus/client_golang | /metrics endpoint |

## Database Schema

```sql
-- Core tables
CREATE TABLE nodes (
    name TEXT PRIMARY KEY,
    host TEXT NOT NULL,
    ssh_key TEXT,
    labels TEXT, -- JSON array
    last_scan_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_name TEXT NOT NULL REFERENCES nodes(name),
    port INTEGER NOT NULL,
    protocol TEXT DEFAULT 'tcp',
    bind_addr TEXT NOT NULL,
    scope TEXT NOT NULL, -- loopback/lan/wan/wildcard
    pid INTEGER,
    process_name TEXT,
    binary_path TEXT,
    systemd_unit TEXT,
    docker_container TEXT,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(node_name, port, bind_addr)
);

CREATE TABLE claims (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_name TEXT NOT NULL REFERENCES nodes(name),
    port INTEGER NOT NULL,
    service_name TEXT NOT NULL,
    declared_bind TEXT,
    port_range TEXT, -- system/reserved/dashboard/ephemeral
    owner TEXT,
    note TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(node_name, port)
);

CREATE TABLE history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_name TEXT NOT NULL REFERENCES nodes(name),
    event_type TEXT NOT NULL, -- appear/disappear/bind_change/process_change/claim/unclaim
    port INTEGER NOT NULL,
    detail TEXT, -- JSON blob with before/after
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    trigger_type TEXT NOT NULL, -- rogue/bind_change/score_change/appear/disappear
    destination TEXT NOT NULL, -- telegram/webhook/email/script
    destination_config TEXT, -- JSON
    threshold INTEGER, -- for score_change
    enabled BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE snapshots (
    name TEXT PRIMARY KEY,
    node_name TEXT NOT NULL REFERENCES nodes(name),
    data TEXT NOT NULL, -- JSON snapshot of all ports + claims
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE compliance_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_name TEXT NOT NULL REFERENCES nodes(name),
    template TEXT NOT NULL,
    passed INTEGER NOT NULL,
    failed INTEGER NOT NULL,
    results TEXT NOT NULL, -- JSON
    ran_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

## Build Phases

### Phase 1 — MVP (v0.1.0)

Core functionality. Dogfood on Node-1 + Node-2.

| # | Feature | Commands | Est. LOC |
|---|---------|----------|----------|
| 1 | Config init | `config init/show/set` | ~300 |
| 2 | Port scanning | `scan` (local + SSH) | ~500 |
| 3 | Port listing | `ports list/show` | ~300 |
| 4 | Port claims | `claim/unclaim/next/import/export` | ~400 |
| 5 | Drift detection | `drift/drift watch` | ~350 |
| 6 | Security audit | `audit` (score + risk flags) | ~400 |
| 7 | Firewall check | `firewall check` (UFW/iptables) | ~350 |
| 8 | History | `history/history diff` | ~300 |
| 9 | Alerting | `alert config/rules/test` (Telegram) | ~400 |
| 10 | Multi-node | `node add/remove/list/scan/health` | ~250 |
| 11 | Daemon mode | `daemon start/stop/install/status` | ~200 |
| 12 | DB layer | SQLite setup + all models + migrations | ~500 |

**Total MVP: ~4,350 LOC**

### Phase 2 — Hardening (v0.2.0)

| # | Feature | Commands | Est. LOC |
|---|---------|----------|----------|
| 13 | CVE correlation | `cve/cve --all` | ~400 |
| 14 | Shodan check | `shodan` | ~200 |
| 15 | Service fingerprint | `fingerprint` | ~350 |
| 16 | Network segments | `network map` | ~300 |
| 17 | Compliance templates | `compliance list/check` | ~400 |
| 18 | Prometheus export | `export prometheus` | ~200 |
| 19 | Grafana dashboard | `export grafana` | ~150 |
| 20 | Markdown runbook | `export markdown` | ~100 |

### Phase 3 — Polish (v1.0.0)

| # | Feature | Est. LOC |
|---|---------|----------|
| 21 | Docker container discovery | ~250 |
| 22 | Interactive mode (Bubble Tea) | ~400 |
| 23 | Shell completions (bash/zsh/fish) | ~150 |
| 24 | Custom compliance policies | ~200 |
| 25 | Snapshot/restore | ~200 |
| 26 | Full test suite + CI | ~800 |

## Release Pipeline

- GitHub Actions + GoReleaser
- On tag push `v*`: build binaries for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64
- Publish to GitHub Releases + npm (via GoReleaser npm section)
- Docker image to `lowwattlabs/portkeep`
- Homebrew tap at `jchandler187/homebrew-tap`

## Testing Strategy

- Unit tests per package (`internal/scan`, `internal/audit`, etc.)
- Integration tests against a real SQLite DB
- CLI end-to-end tests via `cobra/test` utilities
- Test matrix: Go 1.22+ on linux/darwin

## Performance Targets

- `scan` on a single node: <2 seconds
- `drift` on 2 nodes: <5 seconds
- `audit` on 2 nodes: <5 seconds
- Daemon memory footprint: <50MB
- DB size: <10MB for 10 nodes, 500 ports, 1 year of history