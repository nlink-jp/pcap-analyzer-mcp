package cmd

import (
	"os"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/config"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/job"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/logging"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/mcpserver"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/podman"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/tools"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/transport"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/workspace"
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

		// stdout is the protocol channel; diagnostics go to stderr, or to
		// log.file when one is configured. Anything printed to stdout by
		// accident corrupts the JSON-RPC stream.
		logger, closer, err := logging.New(cfg.Log)
		if err != nil {
			return err
		}
		if closer != nil {
			defer closer.Close()
		}

		pc := podman.New()
		srv := mcpserver.New("pcap-analyzer-mcp", Version,
			transport.NewStdioTransport(os.Stdin, os.Stdout), logger)

		tools.Register(srv, &tools.Deps{
			Cfg:       cfg,
			Podman:    pc,
			Workspace: workspace.NewManager(cfg, pc),
			Jobs:      job.NewManager(cfg.Jobs.MaxConcurrent),
			// Background jobs must outlive the request that started them, so
			// they run under the command's context rather than a request one.
			ServerCtx: cmd.Context(),
		})

		logger.Info("serving", "version", Version, "image", cfg.Container.Image)
		return srv.Serve(cmd.Context())
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}
