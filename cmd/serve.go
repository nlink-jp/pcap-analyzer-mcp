package cmd

import (
	"errors"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/config"
	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the MCP stdio server",
	Long: `Start the MCP server on stdio.

Transport is stdio only; HTTP/SSE is out of scope (architecture.md §8).`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := config.Load(configPath)
		if err != nil {
			return err
		}
		_ = cfg
		// Track B wires internal/transport + internal/mcpserver here;
		// Track E onward registers the tool handlers.
		return errors.New("serve: not implemented yet (Phase 1 Track B)")
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}
