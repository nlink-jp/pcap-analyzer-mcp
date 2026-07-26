package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		fmt.Fprintln(cmd.OutOrStdout(), Version)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

// setVersion keeps rootCmd.Version in step with the linker-injected value.
//
// The var initialiser for rootCmd captures Version before -ldflags has any
// effect on package-level init order, so it is assigned again here.
func init() { rootCmd.Version = Version }
