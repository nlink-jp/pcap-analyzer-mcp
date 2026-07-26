package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/config"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/podman"
	rt "github.com/nlink-jp/pcap-analyzer-mcp/runtime"
	"github.com/spf13/cobra"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check podman, the analysis image, and the configuration",
	Long: `Diagnose the local environment.

Checks podman, the podman machine (macOS), the analysis image, the config
file, and — the one that actually bites on macOS — whether the directories
you intend to analyse can be bind-mounted at all. The machine is a VM, and
only paths inside its virtiofs shares are reachable; podman does not expose
the share list, so this attempts a real read-only mount and reports what
happened.`,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		out := cmd.OutOrStdout()
		d := &diagnosis{out: out}

		cfg, err := config.Load(configPath)
		if err != nil {
			d.fail("config", err.Error())
			// Everything below reads cfg, so there is nothing further to check.
			return d.summarize()
		}
		d.pass("config", describeConfigSource(configPath))

		ctx := cmd.Context()
		pc := podman.New()

		version, err := pc.Version(ctx)
		if err != nil {
			var missing *podman.ErrNotInstalled
			if errors.As(err, &missing) {
				d.fail("podman", "not found on PATH — install it from https://podman.io/")
			} else {
				d.fail("podman", err.Error())
			}
			return d.summarize()
		}
		d.pass("podman", version)

		machine, err := pc.MachineState(ctx)
		switch {
		case err != nil:
			d.warn("podman machine", err.Error())
		case machine == "":
			d.pass("podman machine", "not applicable (native containers)")
		case machine == "running":
			d.pass("podman machine", "running")
		default:
			d.fail("podman machine", machine+" — run `podman machine start`")
		}

		tag := cfg.Container.Image
		imageOK, err := pc.ImageExists(ctx, tag)
		switch {
		case err != nil:
			d.fail("analysis image", err.Error())
		case !imageOK:
			d.fail("analysis image", tag+" not built — run `pcap-analyzer-mcp build-runtime`")
		default:
			id, idErr := pc.ImageID(ctx, tag)
			if idErr != nil {
				d.warn("analysis image", idErr.Error())
			} else {
				d.pass("analysis image", fmt.Sprintf("%s (%s), expecting tshark %s",
					tag, short(id), rt.TsharkVersion))
			}
		}

		// The mount probe needs a working image to run in.
		if imageOK {
			d.checkMounts(ctx, pc, tag, cfg.Workspace.AllowedPaths)
		}

		return d.summarize()
	},
}

// mountProber is the slice of the podman client checkMounts needs, so the
// branching below can be tested without a container runtime.
type mountProber interface {
	CanMount(ctx context.Context, image, hostPath string) (bool, string, error)
}

// checkMounts reports which host directories can actually be bind-mounted.
//
// With allowed_paths configured, those are the directories that matter. With
// it empty — the default — any readable file may be opened, so the useful
// answer is which of the conventional macOS shares are reachable, i.e. where
// a capture has to live.
func (d *diagnosis) checkMounts(ctx context.Context, pc mountProber, image string, allowed []string) {
	paths := allowed
	label := "mount (allowed_paths)"
	if len(paths) == 0 {
		if runtime.GOOS != "darwin" {
			d.pass("mount", "allowed_paths is empty; bind mounts are unrestricted on this host")
			return
		}
		paths = []string{"/Users", "/private/tmp", "/var/folders"}
		label = "mount (default shares)"
	}

	for _, p := range paths {
		ok, reason, err := pc.CanMount(ctx, image, p)
		switch {
		case err != nil:
			d.warn(label, p+": "+err.Error())
		case ok:
			d.pass(label, p)
		case len(allowed) > 0:
			// The operator named this path, so an unreachable one is a fault.
			d.fail(label, p+" cannot be bind-mounted"+reasonSuffix(reason))
		default:
			d.warn(label, p+" is not reachable"+reasonSuffix(reason))
		}
	}
}

func reasonSuffix(reason string) string {
	if reason == "" {
		return ""
	}
	return " — " + reason
}

func describeConfigSource(path string) string {
	if path == "" {
		return "using defaults (no config file given)"
	}
	return "loaded " + path
}

type diagnosis struct {
	out            io.Writer
	failed, warned int
}

func (d *diagnosis) pass(check, detail string) { d.line("ok  ", check, detail) }

func (d *diagnosis) warn(check, detail string) {
	d.warned++
	d.line("warn", check, detail)
}

func (d *diagnosis) fail(check, detail string) {
	d.failed++
	d.line("FAIL", check, detail)
}

func (d *diagnosis) line(status, check, detail string) {
	fmt.Fprintf(d.out, "  [%s] %-22s %s\n", status, check, detail)
}

func (d *diagnosis) summarize() error {
	if d.failed > 0 {
		return fmt.Errorf("%d check(s) failed", d.failed)
	}
	if d.warned > 0 {
		fmt.Fprintf(d.out, "\n%d warning(s); the server should still work.\n", d.warned)
	} else {
		fmt.Fprintln(d.out, "\nAll checks passed.")
	}
	return nil
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}
