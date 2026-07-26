package cmd

import (
	"errors"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/config"
	"github.com/spf13/cobra"
)

var buildRuntimeCmd = &cobra.Command{
	Use:   "build-runtime",
	Short: "Build the tshark analysis container image locally",
	Long: `Build the analysis image from the Dockerfile embedded in this binary.

The image is never pushed to a registry (ADR-0003); every user builds it
locally. The base image is digest-pinned so the tshark version is fixed
independently of whatever is installed on the host.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := config.Load(configPath)
		if err != nil {
			return err
		}
		_ = cfg
		// Track C unpacks runtime/Dockerfile (go:embed) and calls podman build.
		return errors.New("build-runtime: not implemented yet (Phase 1 Track C)")
	},
}

func init() {
	rootCmd.AddCommand(buildRuntimeCmd)
}
