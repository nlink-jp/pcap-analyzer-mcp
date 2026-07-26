package cmd

import (
	"log/slog"
	"os"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/config"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/job"
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

		// stdout is the protocol channel, so diagnostics go to stderr. Anything
		// printed to stdout by accident corrupts the JSON-RPC stream.
		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: logLevel(cfg.Log.Level),
		}))

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

func logLevel(name string) slog.Level {
	switch name {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func init() {
	rootCmd.AddCommand(serveCmd)
}
