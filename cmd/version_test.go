package cmd

import (
	"bytes"
	"strings"
	"testing"
)

// The homebrew formula template — shared by every tool in the org — tests
// `<binary> --version`. Without the flag the tap's test block fails, which is
// how this was found.
func TestVersionFlagAndSubcommandBothWork(t *testing.T) {
	Version = "v9.9.9"
	rootCmd.Version = Version

	for _, args := range [][]string{{"--version"}, {"version"}} {
		var out bytes.Buffer
		rootCmd.SetOut(&out)
		rootCmd.SetErr(&out)
		rootCmd.SetArgs(args)
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if !strings.Contains(out.String(), "v9.9.9") {
			t.Errorf("%v printed %q, want the version", args, out.String())
		}
	}
}
