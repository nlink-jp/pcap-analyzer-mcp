package cmd

import (
	"errors"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/config"
	"github.com/spf13/cobra"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check podman, the analysis image, and the configuration",
	Long: `Diagnose the local environment.

Checks: podman on PATH, podman machine state (macOS), presence of the
analysis image, config.toml parse, and whether the configured evidence
locations sit under a Podman Machine shared path — a mount outside
/Users, /private/tmp or /var/folders cannot be passed through virtiofs
(phase1-plan.md §5 Q5-2, architecture.md §7).`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := config.Load(configPath)
		if err != nil {
			return err
		}
		_ = cfg
		return errors.New("doctor: not implemented yet (Phase 1 Track C)")
	},
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}
