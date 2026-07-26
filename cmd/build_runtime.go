package cmd

import (
	"fmt"
	"strings"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/config"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/podman"
	"github.com/nlink-jp/pcap-analyzer-mcp/runtime"
	"github.com/spf13/cobra"
)

var buildRuntimeForce bool

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
		out := cmd.OutOrStdout()
		pc := podman.New()
		ctx := cmd.Context()

		if _, err := pc.Version(ctx); err != nil {
			return err
		}

		tag := cfg.Container.Image
		if !buildRuntimeForce {
			exists, err := pc.ImageExists(ctx, tag)
			if err != nil {
				return err
			}
			if exists {
				id, err := pc.ImageID(ctx, tag)
				if err != nil {
					return err
				}
				fmt.Fprintf(out, "%s already exists (%s)\nPass --force to rebuild.\n", tag, short(id))
				return nil
			}
		}

		fmt.Fprintf(out, "Building %s from %s@%s...\n", tag, runtime.BaseImage, runtime.BaseImageDigest)
		if err := pc.Build(ctx, out, tag, runtime.Dockerfile); err != nil {
			return err
		}

		id, err := pc.ImageID(ctx, tag)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "\nBuilt %s (%s), tshark %s\n", tag, short(id), runtime.TsharkVersion)
		return nil
	},
}

// short trims a podman image ID to the 12 characters podman itself displays.
func short(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func init() {
	buildRuntimeCmd.Flags().BoolVar(&buildRuntimeForce, "force", false,
		"rebuild even if the image already exists")
	rootCmd.AddCommand(buildRuntimeCmd)
}
