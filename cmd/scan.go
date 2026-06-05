package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/jchandler187/portkeep/internal/portscanner"
	"github.com/spf13/cobra"
)

var scanJSON bool

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan open listening ports on this host",
	Long: `Scan all TCP and UDP ports currently listening on this host.
On Linux, reads /proc/net/tcp and /proc/net/tcp6.
On other platforms, calls netstat -an.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ports, err := portscanner.Scan()
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}

		if scanJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(ports)
		}

		if len(ports) == 0 {
			fmt.Println("No listening ports found.")
			return nil
		}

		fmt.Printf("\n%-10s %-8s %-20s %s\n", "PORT", "PROTO", "ADDRESS", "PROCESS")
		fmt.Printf("%-10s %-8s %-20s %s\n", "----", "-----", "-------", "-------")
		for _, p := range ports {
			proc := p.Process
			if proc == "" {
				proc = "-"
			}
			fmt.Printf("%-10d %-8s %-20s %s\n", p.Port, p.Protocol, p.Address, proc)
		}
		fmt.Printf("\n%d port(s) listening\n", len(ports))
		return nil
	},
}

func init() {
	scanCmd.Flags().BoolVar(&scanJSON, "json", false, "Output as JSON")
}
