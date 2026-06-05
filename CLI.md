# PortKeep — CLI Design

The interface is the product. Every command should feel obvious after using it once.

---

## Design Rules

1. **Defaults are smart.** Zero flags for 90% of use. `portkeep scan` just works.
2. **Output is skimmable.** Tables for lists, color for severity, one line per port.
3. **Errors are actionable.** Not "connection refused" — "Node-2 (192.168.1.86) unreachable on SSH. Key at ~/.ssh/id_ed25519. Diagnose: `ssh node2`"
4. **Pipes work.** `--json` on everything. `--quiet` kills all output except errors. Exit codes: 0=good, 1=issues, 2=error.
5. **Learn in 30 seconds.** `portkeep help` fits one screen. Every subcommand has `--example`.

---

## First Run

```
$ portkeep config init

PortKeep — initial setup

  Node name [node1]: █
  Scan this host? [Y/n]: 
  Add remote nodes? [y/N]: n
  Alert destination: [telegram/webhook/email/none] telegram
  Telegram chat ID: 6148810724
  Bot token (env var or literal) [$TELEGRAM_BOT_TOKEN]: 

  ✓ Config written to ~/.portkeep/config.yaml
  ✓ First scan complete — 18 ports found on node1
  ✓ 2 ports on 0.0.0.0 flagged for review

  Next steps:
    portkeep audit          — full security review
    portkeep drift           — check declared vs actual
    portkeep claim next      — find an open port
```

---

## Daily Use — The Big Five

### 1. scan

```
$ portkeep scan

node1 — 18 ports (6 loopback · 7 LAN · 3 WAN · 2 wildcard)

PORT   SERVICE            BIND          SCOPE     PID    BINARY
22     ssh                0.0.0.0       WAN       1517   /usr/sbin/sshd
53     pihole-dns          0.0.0.0       WAN       1489   /usr/bin/pihole-FTL
18789  openclaw-gateway    127.0.0.1     loopback   1497   /usr/local/bin/openclaw
1880   calendar-dash       127.0.0.1     loopback   1491   node
1881   bills-dash          127.0.0.1     loopback   1484   node
2222   ssh-tunnel          127.0.0.1     loopback   1517   /usr/sbin/sshd
3000   homelab-dash        *             wildcard  1498   node
3001   void-proxy         0.0.0.0       WAN       1502   node
3200   —                   0.0.0.0       WAN       1518   python3
6333   qdrant-api          0.0.0.0       WAN       1410   /usr/bin/qdrant
6334   qdrant-grpc         0.0.0.0       WAN       1410   /usr/bin/qdrant
7860   lfit-server         127.0.0.1     loopback   1515   sd-server
8053   pihole-dns-alt      0.0.0.0       WAN       1489   /usr/bin/pihole-FTL
8799   dig-agent           127.0.0.1     loopback   1518   python3
9090   prometheus          127.0.0.1     loopback   1490   prometheus
9100   node-exporter       *             wildcard  1499   node_exporter
11434  ollama              127.0.0.1     loopback   1507   llama-server
44707  —                   127.0.0.1     loopback   —      —

⚠ 2 unclaimed ports: 3200, 44707
⚠ 2 wildcard binds: 3000, 9100
```

Remote node:
```
$ portkeep scan --node node2

node2 — 8 ports (1 loopback · 3 LAN · 2 WAN · 2 wildcard)

PORT   SERVICE            BIND          SCOPE     PID    BINARY
22     ssh                0.0.0.0       WAN       892    /usr/sbin/sshd
3000   netdata            0.0.0.0       WAN       901    /usr/sbin/netdata
5678   n8n                0.0.0.0       WAN       912    node
8080   template-store     0.0.0.0       WAN       920    node
9080   —                  *             wildcard  930    python3
9100   node-exporter      *             wildcard  905    node_exporter

⚠ 1 unclaimed port: 9080
⚠ 2 wildcard binds: 9080, 9100
```

All nodes at once:
```
$ portkeep scan --all

node1  18 ports  score: 38  ⚠ 2 rogue · 2 wildcard
node2   8 ports  score: 52  ⚠ 1 rogue · 2 wildcard

TOTAL  26 ports across 2 nodes · 3 rogue · 4 wildcard · exposure score: 45
```

### 2. claim

```
$ portkeep claim 3200 --service python-monitor --note "Prometheus python exporter"

✓ Port 3200 claimed by python-monitor on node1
  Bind: 0.0.0.0 (WAN) — ⚠ consider restricting to loopback or LAN

$ portkeep claim next --range reserved

Next available port in reserved range (1024-4999):
  1024  ← available
  1025  ← available
  1026  ← available

  Suggested: 1024

$ portkeep claim 3001 --service void-game

✗ Port 3001 already claimed by void-proxy (node1)
  Use --force to override, or choose a different port.
  Next available in dashboard range: 5002
```

### 3. drift

```
$ portkeep drift

node1 — 2 drift events

  ⛔ ROGUE   port 44707 listening, not declared  (process: —)
  🟡 BIND    port 3000 declared loopback, actually * (wildcard)

node2 — 1 drift event

  🟡 BIND    port 5678 declared LAN, actually 0.0.0.0 (WAN)

3 total drift events · exit 1
```

Clean run:
```
$ portkeep drift

node1 — clean
node2 — clean

0 drift events · exit 0
```

In cron (exit code does the work):
```
$ portkeep drift --quiet && echo "all clean" || echo "DRIFT DETECTED"
```

### 4. audit

```
$ portkeep audit

╔══════════════════════════════════════════════════╗
║  PortKeep — Security Audit  ·  node1        ║
║  Exposure Score: 38/100  ████████░░░░░░░░ MODERATE ║
╚══════════════════════════════════════════════════╝

BIND SCOPE BREAKDOWN
  🟢 Loopback    6 ports  (safe)
  🟡 LAN          0 ports
  🔴 WAN          7 ports  (needs review)
  ⛔ Wildcard     2 ports  (dangerous)

CRITICAL FINDINGS
  ⛔ port 3000 (homelab-dash) bound on * — any interface
     Fix: bind to 127.0.0.1 or 192.168.1.230
  ⛔ port 9100 (node-exporter) bound on * — any interface
     Fix: bind to 127.0.0.1 or restrict via UFW
  🔴 port 3200 (python3) — unclaimed, unknown service on WAN
     Fix: `portkeep claim 3200 --service <name>`
  🔴 port 44707 — unclaimed, unknown service on loopback
     Fix: investigate or `portkeep claim 44707 --service <name>`

FIREWALL GAPS
  ⚠ port 3200 (WAN) — no UFW rule found
  ⚠ port 6333 (WAN) — no UFW rule found
  ⚠ port 6334 (WAN) — no UFW rule found
  ✗ port 3000 (*) — UFW allows from 0.0.0.0 (too permissive)

SUMMARY
  2 critical · 2 high · 4 warnings
  Score improved from 42 → 38 since last audit (Jun 2)
```

Quick check (just the score):
```
$ portkeep audit --score
38
```

### 5. history

```
$ portkeep history

Jun 5 10:22  +port 44707 (—) appeared on node1, loopback
Jun 4 18:01  -port 8081 (lfit-quick) disappeared on node1
Jun 4 17:45  ~port 3000 bind changed 127.0.0.1 → * on node1
Jun 3 14:22  +port 3200 (python3) appeared on node1, WAN
Jun 2 09:00  +claim 8799 dig-agent on node1
Jun 1 20:15  +port 8081 (lfit-quick) appeared on node1

$ portkeep history --since yesterday --type appear

Jun 5 10:22  +port 44707 (—) appeared on node1, loopback
Jun 4 18:01  +port 8081 (lfit-quick) appeared briefly on node1

$ portkeep history diff --from "2 days ago" --to now

  +port 44707  (new, loopback, unclaimed)
  -port 8081   (gone)
  ~port 3000   bind: 127.0.0.1 → *
```

---

## Alerting

```
$ portkeep alert config add telegram --chat-id 6148810724 --bot-token $TELEGRAM_BOT_TOKEN

✓ Telegram alert destination added

$ portkeep alert rules add --on rogue --destination telegram

✓ Alert rule added: notify telegram when unclaimed port appears

$ portkeep alert rules add --on bind-change --destination telegram

✓ Alert rule added: notify telegram when bind address widens

$ portkeep alert rules list

ID  ON              DESTINATION  ENABLED
1   rogue           telegram     yes
2   bind-change      telegram     yes
3   score-above-50   telegram     yes

$ portkeep alert test

✓ Test alert sent to telegram
```

What hits your Telegram:
```
⚠ PORT WARDEN ALERT — rogue port

node1: port 44707 appeared on 127.0.0.1
Process: unknown
No claim found for this port.

Investigate: portkeep ports show 44707
Claim it:    portkeep claim 44707 --service <name>
```

---

## Multi-Node

```
$ portkeep node add node2 --host 192.168.1.86 --ssh-key ~/.ssh/id_ed25519 --label dev

✓ Node node2 registered
  Testing SSH... ✓ connected
  First scan... 8 ports found

$ portkeep node list

NODE    HOST             PORTS  SCORE  LAST SCAN         STATUS
node1   127.0.0.1        18     38    5 min ago          ✓ online
node2   192.168.1.86      8     52    2 min ago          ✓ online

$ portkeep node health

node1  ✓ SSH ✓ ping   load 0.42   temp 46°C   uptime 14d
node2  ✓ SSH ✓ ping   load 0.31   temp 39°C   uptime 3d
```

---

## Daemon Mode

```
$ portkeep daemon install

✓ systemd unit written to ~/.config/systemd/user/portkeep.service
✓ enabled on user.slice
  Start: systemctl --user start portkeep
  Logs:  journalctl --user -u portkeep -f

$ systemctl --user start portkeep

$ portkeep daemon status

daemon: running (PID 2891, 2m uptime)
interval: 300s
nodes: node1 ✓, node2 ✓
alerts: 3 rules active
last scan: 10:51:02 — no drift
next scan: 10:56:02
```

---

## Export

```
$ portkeep export markdown > /srv/dashboard/ports.md

✓ Markdown runbook exported (26 ports, 2 nodes)

$ portkeep export prometheus

✓ Metrics endpoint running on :9091/metrics
  Add to your prometheus scrape config:
    - targets: ['localhost:9091']

$ portkeep export grafana > portkeep-dashboard.json

✓ Grafana dashboard JSON exported
  Import at: http://localhost:3001/dashboard/import
```

---

## Compliance

```
$ portkeep compliance check cisa-smb

CISA SMB Baseline — node1

  ✓ SSH key-only authentication
  ✓ Firewall enabled (UFW)
  ✗ 2 services on wildcard bind (3000, 9100)
  ✗ No UFW rate limiting
  ✓ No root SSH login
  ✗ 2 unclaimed ports

3/6 passed · 3 failures
Remediation: portkeep compliance check cisa-smb --fix

$ portkeep compliance check cisa-smb --fix

FAIL: 2 wildcard binds
  Fix: Add UFW deny rules or rebind services
    portkeep ports show 3000 --fix
    portkeep ports show 9100 --fix

FAIL: No UFW rate limiting
  Fix: ufw limit 22/tcp
  ⚠ This is a state change. Review before applying.

FAIL: 2 unclaimed ports
  Fix: Claim or investigate
    portkeep claim 44707 --service <name>
    portkeep claim 3200 --service <name>
```

---

## Quick Reference (help output)

```
$ portkeep help

PortKeep — port management + security for self-hosted infra

Usage: portkeep <command> [flags]

Commands:
  scan           Discover listening ports
  ports          List, show, search ports
  claim          Register/unregister ports
  drift          Check declared vs actual
  audit          Security scoring + risk flags
  fingerprint    Identify service on a port
  firewall       Cross-reference firewall rules
  cve            Check CVEs for services
  shodan         Check internet exposure
  history        Change timeline + diffs
  snapshot       Save/compare port states
  alert          Configure alerts + rules
  node           Manage remote nodes
  network        Network segment analysis
  compliance     Policy-based audits
  export         Prometheus / Grafana / Markdown / JSON
  daemon         Background service mode
  config         Settings + initialization

Flags:
  --json     Machine-readable output
  --quiet    Errors only
  --no-color No ANSI colors
  --help     Show help for any command

Examples:
  portkeep scan                    # scan this host
  portkeep audit                   # security score
  portkeep drift --all             # check all nodes
  portkeep claim next --range dev   # find open port
  portkeep history --since 1d      # last day's changes

Docs: https://github.com/jchandler187/portkeep
```

---

## Keyboard Shortcuts (interactive mode)

`portkeep` with no command enters interactive mode:

```
$ portkeep

PortKeep v0.1.0 — node1 (18 ports, score 38)

> scan       audit       drift       ports       claim
> history    alert       node        export      quit

: █
```

- Tab: autocomplete commands + port numbers
- Up/Down: command history
- `q`: quit
- Interactive mode is optional — every command works directly from shell

---

## Output Color Convention

- 🟢 Green / dim — safe (loopback, claimed, passed)
- 🟡 Yellow — moderate (LAN, warning)
- 🔴 Red — needs attention (WAN, unclaimed, drift)
- ⛔ Bold red — critical (wildcard, CVE, exposed)
- Cyan — port numbers (always, for scan-ability)
- Gray — metadata (PID, timestamps, paths)