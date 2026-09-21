package cmd

import (
	"context"
	"log/slog"
	"os"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/config"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/logging"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/mcpserver"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/podman"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/tools"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/transport"
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

		// Background jobs must outlive the request that started them, so they
		// run under the command's context rather than a request one.
		srv := newServer(cmd.Context(), cfg, podman.New(), configPath,
			transport.NewStdioTransport(os.Stdin, os.Stdout), logger)

		logger.Info("serving", "version", Version, "image", cfg.Container.Image)
		return srv.Serve(cmd.Context())
	},
}

// newServer builds the MCP server exactly as serve runs it: the instructions a
// client's model reads at initialize, and every tool wired to the deps
// newToolDeps assembles. It is separate from RunE so a test can drive the
// served server over a transport of its own.
func newServer(serverCtx context.Context, cfg config.Config, pc tools.ContainerRunner, cfgPath string,
	tr *transport.StdioTransport, logger *slog.Logger) *mcpserver.Server {
	srv := mcpserver.New("pcap-analyzer-mcp", Version, tr, logger)
	srv.SetInstructions(tools.Instructions)
	tools.Register(srv, newToolDeps(serverCtx, cfg, pc, cfgPath))
	return srv
}

func init() {
	rootCmd.AddCommand(serveCmd)
}
