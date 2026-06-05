package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const version = "0.1.0"

var rootCmd = &cobra.Command{
	Use:   "portkeep",
	Short: "PortKeep — self-hosted port registry with live threat-intel scoring",
	Long: `PortKeep registers every port your machines expose, prevents conflicts,
and scores your attack surface against 9 live threat-intel feeds:
CISA-KEV, EPSS, OSV, ThreatFox, URLhaus, MalwareBazaar, Feodo,
Semgrep rules, and YARA rules.

No cloud account. No agent. One binary.`,
	SilenceUsage: true,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print PortKeep version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("portkeep v%s\n", version)
	},
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(registerCmd)
	rootCmd.AddCommand(unregisterCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(scoreCmd)
	rootCmd.AddCommand(syncCmd)
	rootCmd.AddCommand(diffCmd)
	rootCmd.AddCommand(reportCmd)
}
