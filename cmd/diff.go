package cmd

import (
	"fmt"

	"github.com/jchandler187/portkeep/internal/config"
	"github.com/jchandler187/portkeep/internal/portscanner"
	"github.com/jchandler187/portkeep/internal/registry"
	"github.com/spf13/cobra"
)

var diffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Show drift between registry and actual open ports",
	Long: `Compare your registry against live port scan results:
  - OPEN_NOT_REGISTERED: port is listening but not in your registry (surprise exposure)
  - REGISTERED_NOT_OPEN: port is in your registry but not currently listening (service down?)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ports, err := portscanner.Scan()
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}

		reg, err := registry.Load(config.RegistryPath())
		if err != nil {
			return fmt.Errorf("loading registry: %w", err)
		}

		// Build lookup sets
		openSet := make(map[string]bool) // "port/proto"
		for _, p := range ports {
			openSet[fmt.Sprintf("%d/%s", p.Port, p.Protocol)] = true
		}

		regSet := make(map[string]bool)
		for _, e := range reg.Entries {
			regSet[fmt.Sprintf("%d/%s", e.Port, e.Protocol)] = true
		}

		var unexpected []string
		var missing []string

		for _, p := range ports {
			key := fmt.Sprintf("%d/%s", p.Port, p.Protocol)
			if !regSet[key] {
				unexpected = append(unexpected, key)
			}
		}

		for _, e := range reg.Entries {
			key := fmt.Sprintf("%d/%s", e.Port, e.Protocol)
			if !openSet[key] {
				missing = append(missing, key)
			}
		}

		if len(unexpected) == 0 && len(missing) == 0 {
			fmt.Println(colorGreen("✓ No drift detected. Registry matches live ports."))
			return nil
		}

		if len(unexpected) > 0 {
			fmt.Printf("\n%s  Ports open but NOT in registry:\n", colorRed("!"))
			for _, p := range unexpected {
				fmt.Printf("  %s  %s\n", colorRed("OPEN_NOT_REGISTERED"), p)
			}
		}

		if len(missing) > 0 {
			fmt.Printf("\n%s  Ports in registry but NOT open:\n", colorYellow("~"))
			for _, p := range missing {
				fmt.Printf("  %s  %s\n", colorYellow("REGISTERED_NOT_OPEN"), p)
			}
		}

		fmt.Printf("\nSummary: %d unexpected, %d missing\n",
			len(unexpected), len(missing))
		return nil
	},
}
