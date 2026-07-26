// Package cmd implements the pcap-analyzer-mcp command line surface.
//
// The binary hosts four subcommands (CONVENTIONS.md §Build Conventions,
// architecture.md §0): serve, build-runtime, doctor, version.
package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

// Version is injected at build time by the Makefile via
// -ldflags "-X github.com/nlink-jp/pcap-analyzer-mcp/cmd.Version=$(VERSION)".
var Version = "dev"

// configPath is the --config value shared by every subcommand that reads
// configuration.
var configPath string

var rootCmd = &cobra.Command{
	Use:   "pcap-analyzer-mcp",
	Short: "MCP server for pcap/pcapng analysis via a version-pinned tshark container",
	Long: `pcap-analyzer-mcp analyses packet captures on behalf of an LLM agent.

Captures are read by a version-pinned tshark inside a rootless, network-less
container; the capture itself is mounted read-only and never copied. Results
are returned inline when small and written to the workspace as JSONL when
large.

See docs/{en,ja}/ for the RFP, the ADRs, and the architecture document.`,
	SilenceUsage: true,
}

// Execute runs the root command and exits non-zero on failure. cobra has
// already printed the error, so this only sets the exit status.
//
// The context is signal-aware and is what every subcommand sees through
// cmd.Context(). cobra's plain Execute() would hand them context.Background(),
// which never cancels — and since background jobs run under that same context
// (ADR-0006), an uncancellable context means an uncancellable analysis.
func Execute() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "",
		"path to config.toml (default: search the standard locations)")
}
