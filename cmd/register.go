package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/jchandler187/portkeep/internal/config"
	"github.com/jchandler187/portkeep/internal/registry"
	"github.com/spf13/cobra"
)

var (
	registerProto string
	registerDesc  string
	registerTags  string
)

var registerCmd = &cobra.Command{
	Use:   "register <port> <service>",
	Short: "Register a port as known/expected",
	Long: `Register a port in the local registry so it is considered expected.
Ports not in the registry are flagged as unregistered during scoring.

Example:
  portkeep register 8080 my-api --description "Internal API server" --tags "internal,api"
  portkeep register 22 sshd --proto tcp`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		port, err := parsePort(args[0])
		if err != nil {
			return err
		}
		service := args[1]

		reg, err := registry.Load(config.RegistryPath())
		if err != nil {
			return fmt.Errorf("loading registry: %w", err)
		}

		proto := strings.ToLower(registerProto)
		if proto != "tcp" && proto != "udp" {
			return fmt.Errorf("protocol must be 'tcp' or 'udp', got %q", proto)
		}

		if reg.IsRegistered(port, proto) {
			fmt.Printf("Port %d/%s (%s) is already registered.\n", port, proto, service)
			return nil
		}

		var tags []string
		if registerTags != "" {
			for _, t := range strings.Split(registerTags, ",") {
				if t = strings.TrimSpace(t); t != "" {
					tags = append(tags, t)
				}
			}
		}

		entry := registry.PortEntry{
			Port:         port,
			Protocol:     proto,
			Service:      service,
			Description:  registerDesc,
			Tags:         tags,
			RegisteredAt: time.Now().UTC().Format(time.RFC3339),
		}

		reg.Add(entry)
		if err := registry.Save(config.RegistryPath(), reg); err != nil {
			return fmt.Errorf("saving registry: %w", err)
		}

		fmt.Printf("Registered: %d/%s → %s\n", port, proto, service)
		return nil
	},
}

func init() {
	registerCmd.Flags().StringVar(&registerProto, "proto", "tcp", "Protocol (tcp or udp)")
	registerCmd.Flags().StringVar(&registerDesc, "description", "", "Human-readable description")
	registerCmd.Flags().StringVar(&registerTags, "tags", "", "Comma-separated tags")
}
