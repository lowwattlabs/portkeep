package cmd

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jchandler187/portkeep/internal/config"
	"github.com/jchandler187/portkeep/internal/registry"
	"github.com/spf13/cobra"
)

var unregisterProto string

var unregisterCmd = &cobra.Command{
	Use:   "unregister <port>",
	Short: "Remove a port from the registry",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		port, err := parsePort(args[0])
		if err != nil {
			return err
		}

		proto := strings.ToLower(unregisterProto)

		reg, err := registry.Load(config.RegistryPath())
		if err != nil {
			return fmt.Errorf("loading registry: %w", err)
		}

		removed := reg.Remove(port, proto)
		if !removed {
			fmt.Printf("Port %d/%s not found in registry.\n", port, proto)
			return nil
		}

		if err := registry.Save(config.RegistryPath(), reg); err != nil {
			return fmt.Errorf("saving registry: %w", err)
		}

		fmt.Printf("Unregistered: %d/%s\n", port, proto)
		return nil
	},
}

func init() {
	unregisterCmd.Flags().StringVar(&unregisterProto, "proto", "tcp", "Protocol (tcp or udp)")
}

// parsePort is a shared helper for port argument validation.
func parsePort(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q: must be a number", s)
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("invalid port %d: must be between 1 and 65535", n)
	}
	return n, nil
}
