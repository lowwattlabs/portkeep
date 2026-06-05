package cmd

import (
	"fmt"
	"time"

	"github.com/jchandler187/portkeep/internal/config"
	"github.com/jchandler187/portkeep/internal/threatintel"
	"github.com/spf13/cobra"
)

var syncTimeout int

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync threat-intel from all 9 sources",
	Long: `Fetch and cache threat intelligence from:
  1. CISA-KEV   — CISA Known Exploited Vulnerabilities catalog
  2. EPSS        — Exploit Prediction Scoring System
  3. OSV         — Open Source Vulnerability database
  4. ThreatFox   — Abuse.ch malware C2 indicators
  5. URLhaus     — Abuse.ch malicious URL tracker
  6. MalwareBazaar — Abuse.ch malware samples with network IOCs
  7. Feodo       — Abuse.ch botnet C2 IP/port tracker
  8. Semgrep     — Semgrep security rules catalog
  9. YARA        — Community YARA rules index

Results are cached in ~/.portkeep/cache/ and used by 'portkeep score'.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		timeout := time.Duration(syncTimeout) * time.Second
		cacheDir := config.CacheDir()

		fmt.Println("Syncing threat intel...")
		fmt.Println()

		results := threatintel.SyncAll(cacheDir, timeout)

		for _, r := range results {
			status := colorGreen("OK")
			detail := r.Detail
			if r.Err != nil {
				status = colorRed("FAIL")
				detail = r.Err.Error()
			}
			fmt.Printf("  %-20s %s  %s\n", r.Source, status, detail)
		}

		ok := 0
		for _, r := range results {
			if r.Err == nil {
				ok++
			}
		}
		fmt.Printf("\n%d/%d sources synced successfully\n", ok, len(results))
		if ok < len(results) {
			fmt.Println("Tip: run with --timeout 60 if sources are slow.")
		}
		return nil
	},
}

func init() {
	syncCmd.Flags().IntVar(&syncTimeout, "timeout", 30, "Per-source timeout in seconds")
}

// ANSI color helpers (no external deps).
func colorRed(s string) string    { return "\033[31m" + s + "\033[0m" }
func colorGreen(s string) string  { return "\033[32m" + s + "\033[0m" }
func colorYellow(s string) string { return "\033[33m" + s + "\033[0m" }
func colorBold(s string) string   { return "\033[1m" + s + "\033[0m" }
