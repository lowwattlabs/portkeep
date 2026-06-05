package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/jchandler187/portkeep/internal/config"
	"github.com/jchandler187/portkeep/internal/portscanner"
	"github.com/jchandler187/portkeep/internal/registry"
	"github.com/jchandler187/portkeep/internal/scoring"
	"github.com/jchandler187/portkeep/internal/threatintel"
	"github.com/spf13/cobra"
)

var reportJSON bool

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Full attack surface report (scan + diff + score)",
	Long:  `Generates a complete report: live scan, registry drift, and scored findings.`,
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
			fmt.Fprintln(os.Stderr, colorYellow("Warning: threat intel not synced. Run 'portkeep sync'."))
			db = threatintel.EmptyDB()
		}

		scores := scoring.Score(ports, reg, db)
		report := scoring.BuildReport(scores)
		report.Timestamp = time.Now().UTC().Format(time.RFC3339)
		report.ThreatIntelAge = db.AgeString()

		if reportJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(report)
		}

		printFullReport(report, ports, reg)
		return nil
	},
}

func printFullReport(report scoring.SurfaceReport, ports []portscanner.OpenPort, reg *registry.Registry) {
	fmt.Printf("\n%s\n", colorBold("═══ PortKeep Attack Surface Report ═══"))
	fmt.Printf("Generated : %s\n", report.Timestamp)
	fmt.Printf("Intel age : %s\n\n", report.ThreatIntelAge)

	fmt.Printf("%s  Open ports : %d\n", colorBold("→"), report.OpenPorts)
	fmt.Printf("%s  Registered : %d\n", colorBold("→"), report.OpenPorts-report.Unregistered)
	fmt.Printf("%s  Unregistered: %d\n", colorBold("→"), report.Unregistered)
	fmt.Printf("%s  Surface score: %s\n\n",
		colorBold("→"),
		colorLevel(scoring.ScoreLevel(report.TotalScore),
			fmt.Sprintf("%d/100 (%s)", report.TotalScore, scoring.ScoreLevel(report.TotalScore))))

	if len(report.Scores) > 0 {
		fmt.Println(colorBold("Findings (sorted by score):"))
		printScoreTable(report.Scores)
	}
}

func init() {
	reportCmd.Flags().BoolVar(&reportJSON, "json", false, "Output as JSON")
}
