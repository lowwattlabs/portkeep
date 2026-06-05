// Package scoring computes per-port and aggregate attack surface scores.
package scoring

import (
	"sort"
	"time"

	"github.com/jchandler187/portkeep/internal/portscanner"
	"github.com/jchandler187/portkeep/internal/registry"
	"github.com/jchandler187/portkeep/internal/threatintel"
)

// PortScore holds the scored result for a single open port.
type PortScore struct {
	Port        int      `json:"port"`
	Protocol    string   `json:"protocol"`
	Score       int      `json:"score"`        // 0–100, higher = riskier
	ThreatLevel string   `json:"threat_level"` // "critical","high","medium","low","info"
	Registered  bool     `json:"registered"`
	Reasons     []string `json:"reasons"`
}

// SurfaceReport is the top-level output of a full scoring run.
type SurfaceReport struct {
	Timestamp      string      `json:"timestamp"`
	ThreatIntelAge string      `json:"threat_intel_age"`
	TotalScore     int         `json:"total_score"`
	OpenPorts      int         `json:"open_ports"`
	Unregistered   int         `json:"unregistered"`
	Scores         []PortScore `json:"scores"`
}

// riskyPorts maps well-known dangerous ports to a base score and reason.
// These reflect commonly-exploited services with long CVE histories.
var riskyPorts = map[int]struct {
	score  int
	reason string
}{
	21:    {30, "FTP: cleartext credentials, common brute-force target"},
	23:    {45, "Telnet: cleartext protocol, no encryption"},
	25:    {20, "SMTP: verify relay is authenticated"},
	111:   {25, "RPC portmapper: common exploitation vector"},
	135:   {30, "MSRPC: multiple high-severity CVEs historically"},
	139:   {25, "NetBIOS: legacy, prefer SMB over TCP"},
	445:   {40, "SMB: EternalBlue/WannaCry attack vector"},
	512:   {35, "rexec: legacy unauthenticated remote execution"},
	513:   {35, "rlogin: legacy cleartext remote login"},
	514:   {35, "rsh: legacy unauthenticated remote shell"},
	1433:  {25, "MSSQL: database port should not be internet-facing"},
	1521:  {25, "Oracle DB: database port should not be internet-facing"},
	3306:  {25, "MySQL: database port should not be internet-facing"},
	3389:  {35, "RDP: BlueKeep and many other exploits"},
	5432:  {20, "PostgreSQL: verify authentication is required"},
	5900:  {30, "VNC: often unauthenticated by default"},
	6379:  {30, "Redis: unauthenticated by default in older versions"},
	8080:  {15, "Alt-HTTP: common for unpatched admin/dev interfaces"},
	8443:  {10, "Alt-HTTPS: verify TLS certificate and authentication"},
	9200:  {30, "Elasticsearch: unauthenticated by default historically"},
	27017: {30, "MongoDB: unauthenticated by default in older versions"},
}

// Score computes a PortScore for each open port.
func Score(
	ports []portscanner.OpenPort,
	reg *registry.Registry,
	db *threatintel.DB,
) []PortScore {
	scores := make([]PortScore, 0, len(ports))

	for _, p := range ports {
		ps := scorePort(p, reg, db)
		scores = append(scores, ps)
	}

	// Sort by score descending for readability.
	sort.Slice(scores, func(i, j int) bool {
		return scores[i].Score > scores[j].Score
	})

	return scores
}

func scorePort(p portscanner.OpenPort, reg *registry.Registry, db *threatintel.DB) PortScore {
	ps := PortScore{
		Port:       p.Port,
		Protocol:   p.Protocol,
		Registered: reg.IsRegistered(p.Port, p.Protocol),
	}

	// 1. Unregistered penalty
	if !ps.Registered {
		ps.Score += 15
		ps.Reasons = append(ps.Reasons, "unregistered: not in port registry")
	}

	// 2. Inherently risky port (static list)
	if r, ok := riskyPorts[p.Port]; ok {
		ps.Score += r.score
		ps.Reasons = append(ps.Reasons, r.reason)
	}

	// 3. Known C2 port from threat intel
	if db != nil {
		if entries := db.C2Entries(p.Port); len(entries) > 0 {
			ps.Score += 45
			malware := entries[0].Malware
			if malware == "" {
				malware = "unknown malware"
			}
			ps.Reasons = append(ps.Reasons,
				"threat-intel: port matches known C2 port ("+malware+", source: "+entries[0].Source+")")
		}
	}

	// 4. CISA-KEV product on this port
	if db != nil {
		if matches := db.KEVMatchesForPort(p.Port); len(matches) > 0 {
			ps.Score += 25
			ps.Reasons = append(ps.Reasons,
				"CISA-KEV: port associated with actively-exploited product ("+matches[0]+")")
		}
	}

	// Cap at 100
	if ps.Score > 100 {
		ps.Score = 100
	}

	ps.ThreatLevel = ScoreLevel(ps.Score)
	return ps
}

// ScoreLevel maps a 0–100 score to a named threat level.
func ScoreLevel(score int) string {
	switch {
	case score >= 90:
		return "critical"
	case score >= 75:
		return "high"
	case score >= 50:
		return "medium"
	case score >= 25:
		return "low"
	default:
		return "info"
	}
}

// SurfaceScore returns the max score across all ports (worst-case posture).
func SurfaceScore(scores []PortScore) int {
	max := 0
	for _, s := range scores {
		if s.Score > max {
			max = s.Score
		}
	}
	return max
}

// BuildReport assembles a SurfaceReport from port scores.
func BuildReport(scores []PortScore) SurfaceReport {
	unreg := 0
	for _, s := range scores {
		if !s.Registered {
			unreg++
		}
	}
	return SurfaceReport{
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		TotalScore:   SurfaceScore(scores),
		OpenPorts:    len(scores),
		Unregistered: unreg,
		Scores:       scores,
	}
}
