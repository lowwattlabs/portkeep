package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/jchandler187/portkeep/internal/config"
	"github.com/jchandler187/portkeep/internal/registry"
	"github.com/spf13/cobra"
)

var listJSON bool

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all registered ports",
	RunE: func(cmd *cobra.Command, args []string) error {
		reg, err := registry.Load(config.RegistryPath())
		if err != nil {
			return fmt.Errorf("loading registry: %w", err)
		}

		if listJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(reg.Entries)
		}

		if len(reg.Entries) == 0 {
			fmt.Println("Registry is empty. Use 'portkeep register <port> <service>' to add entries.")
			return nil
		}

		fmt.Printf("\n%-10s %-8s %-20s %-30s %s\n",
			"PORT", "PROTO", "SERVICE", "DESCRIPTION", "REGISTERED")
		fmt.Printf("%-10s %-8s %-20s %-30s %s\n",
			"----", "-----", "-------", "-----------", "----------")

		for _, e := range reg.Entries {
			desc := e.Description
			if len(desc) > 28 {
				desc = desc[:25] + "..."
			}
			fmt.Printf("%-10d %-8s %-20s %-30s %s\n",
				e.Port, e.Protocol, e.Service, desc, e.RegisteredAt[:10])
		}
		fmt.Printf("\n%d registered port(s)\n", len(reg.Entries))
		return nil
	},
}

func init() {
	listCmd.Flags().BoolVar(&listJSON, "json", false, "Output as JSON")
}
