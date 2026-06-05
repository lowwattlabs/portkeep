package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/jchandler187/portkeep/internal/config"
	"github.com/jchandler187/portkeep/internal/portscanner"
	"github.com/jchandler187/portkeep/internal/registry"
	"github.com/jchandler187/portkeep/internal/scoring"
	"github.com/jchandler187/portkeep/internal/threatintel"
	"github.com/spf13/cobra"
)

var scoreJSON bool

var scoreCmd = &cobra.Command{
	Use:   "score",
	Short: "Score the current attack surface",
	Long: `Scan open ports, check the registry, and score each port using
cached threat-intel. Run 'portkeep sync' first to refresh intel.

Score scale:
  0–24   Info      — standard, low-risk service
  25–49  Low       — review recommended
  50–74  Medium    — reduce exposure if possible
  75–89  High      — actively investigate
  90–100 Critical  — close or firewall immediately`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ports, err := portscanner.Scan()
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}

		reg, err := registry.Load(config.RegistryPath())
		if err != nil {
			return fmt.Errorf("loading registry: %w", err)
		}

		db, err := threatintel.Load(config.CacheDir())
		if err != nil {
			// Non-fatal: score without threat intel, warn user
			fmt.Fprintln(os.Stderr, colorYellow("Warning: threat intel not synced. Run 'portkeep sync' for full scoring."))
			db = threatintel.EmptyDB()
		}

		scores := scoring.Score(ports, reg, db)

		if scoreJSON {
			report := scoring.BuildReport(scores)
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(report)
		}

		printScoreTable(scores)
		return nil
	},
}

func printScoreTable(scores []scoring.PortScore) {
	if len(scores) == 0 {
		fmt.Println("No open ports found.")
		return
	}

	fmt.Printf("\n%-10s %-8s %-12s %-12s %s\n",
		"PORT", "PROTO", "SCORE", "LEVEL", "REASONS")
	fmt.Printf("%-10s %-8s %-12s %-12s %s\n",
		"----", "-----", "-----", "-----", "-------")

	for _, s := range scores {
		level := colorLevel(s.ThreatLevel, fmt.Sprintf("%-8s", s.ThreatLevel))
		scoreStr := colorLevel(s.ThreatLevel, fmt.Sprintf("%-6d", s.Score))
		reg := ""
		if !s.Registered {
			reg = colorYellow(" [unregistered]")
		}

		reasons := ""
		if len(s.Reasons) > 0 {
			reasons = s.Reasons[0]
			if len(s.Reasons) > 1 {
				reasons += fmt.Sprintf(" (+%d more)", len(s.Reasons)-1)
			}
		}

		fmt.Printf("%-10d %-8s %s  %s  %s%s\n",
			s.Port, s.Protocol, scoreStr, level, reasons, reg)
	}

	total := scoring.SurfaceScore(scores)
	fmt.Printf("\n%s  Overall attack surface score: %s\n",
		colorBold("→"), colorLevel(scoring.ScoreLevel(total), fmt.Sprintf("%d/100", total)))
}

func colorLevel(level, s string) string {
	switch level {
	case "critical":
		return "\033[31;1m" + s + "\033[0m"
	case "high":
		return "\033[31m" + s + "\033[0m"
	case "medium":
		return "\033[33m" + s + "\033[0m"
	case "low":
		return "\033[36m" + s + "\033[0m"
	default:
		return "\033[32m" + s + "\033[0m"
	}
}

func init() {
	scoreCmd.Flags().BoolVar(&scoreJSON, "json", false, "Output as JSON")
}
