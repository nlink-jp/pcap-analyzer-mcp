//go:build integration

package workspace

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/config"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/podman"
	"github.com/nlink-jp/pcap-analyzer-mcp/runtime"
)

// These tests drive real podman and the real analysis image:
//
//	make runtime-image && go test -tags integration ./internal/workspace/
//
// They live behind a build tag because they need a container runtime; the
// unit tests cover the same logic against a fake runner.

func requireImage(t *testing.T) (*podman.Client, config.Config) {
	t.Helper()
	pc := podman.New()
	ctx := context.Background()

	if _, err := pc.Version(ctx); err != nil {
		t.Skipf("podman unavailable: %v", err)
	}
	cfg := config.Default()
	ok, err := pc.ImageExists(ctx, cfg.Container.Image)
	if err != nil || !ok {
		t.Skipf("%s not built; run `make runtime-image`", cfg.Container.Image)
	}
	return pc, cfg
}

// synthCapture builds a real pcapng using text2pcap and mergecap from inside
// the analysis image, so the fixture needs no host-side tooling and no
// third-party binary in the repository.
func synthCapture(t *testing.T, pc *podman.Client, cfg config.Config, dir string) string {
	t.Helper()

	hex := "0000  47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a\n0010  0d 0a\n"
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte(hex), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := pc.RunOnce(context.Background(), podman.RunOnceOpts{
		Image:       cfg.Container.Image,
		Network:     "none",
		DropAllCaps: true,
		Userns:      DefaultUserns(),
		Mounts:      []podman.Mount{{HostPath: dir, ContainerPath: "/work"}},
		Cmd: []string{"sh", "-c", `cd /work &&
			text2pcap -T 1234,80 a.txt s1.pcap &&
			text2pcap -T 5678,443 a.txt s2.pcap &&
			mergecap -w capture.pcapng s1.pcap s2.pcap`},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("fixture generation failed (%d): %s", res.ExitCode, res.Stderr)
	}
	return filepath.Join(dir, "capture.pcapng")
}

func TestIntegrationCreateAgainstRealImage(t *testing.T) {
	pc, cfg := requireImage(t)

	// Podman Machine can only reach its virtiofs shares, and /private/tmp is
	// one; Go's default TMPDIR on macOS is not.
	work, err := os.MkdirTemp("/private/tmp", "pcap-analyzer-it-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(work) })

	capDir := filepath.Join(work, "evidence")
	if err := os.MkdirAll(capDir, 0o700); err != nil {
		t.Fatal(err)
	}
	pcap := synthCapture(t, pc, cfg, capDir)

	// Evidence files are routinely owner-only; keep-id has to make that work.
	if err := os.Chmod(pcap, 0o600); err != nil {
		t.Fatal(err)
	}

	m := NewManager(cfg, pc)
	start := time.Now()
	ws, err := m.Create(context.Background(), pcap, filepath.Join(work, "ws"))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Create took %s for a %d byte capture", elapsed, ws.Meta.Capture.Size)

	if ws.Meta.Info.PacketCount != 2 {
		t.Errorf("PacketCount = %d, want 2", ws.Meta.Info.PacketCount)
	}
	if ws.Meta.Info.Format != "pcapng" {
		t.Errorf("Format = %q", ws.Meta.Info.Format)
	}
	if ws.Meta.Info.Truncated {
		t.Error("a freshly merged capture is not truncated")
	}
	if ws.Meta.Runtime.TsharkVersion == "" {
		t.Error("tshark version not captured")
	}
	if ws.Meta.Runtime.TsharkVersion != "" &&
		!strings.Contains(ws.Meta.Runtime.TsharkVersion, runtime.TsharkVersion) {
		t.Errorf("running tshark %q disagrees with the manifest's %q",
			ws.Meta.Runtime.TsharkVersion, runtime.TsharkVersion)
	}

	// capinfos hashes the file independently of the host-side computation;
	// the two must agree or the mount is not showing what we think it is.
	if ws.Meta.Info.SHA256 != "" && ws.Meta.Info.SHA256 != ws.Meta.Capture.SHA256 {
		t.Errorf("host SHA-256 %s != capinfos %s", ws.Meta.Capture.SHA256, ws.Meta.Info.SHA256)
	}
	if out, err := exec.Command("shasum", "-a", "256", pcap).Output(); err == nil {
		if want := string(out[:64]); want != ws.Meta.Capture.SHA256 {
			t.Errorf("SHA-256 %s does not match shasum %s", ws.Meta.Capture.SHA256, want)
		}
	}
}

// The truncation verdict has to hold against a genuinely truncated file, not
// just against recorded output.
func TestIntegrationTruncatedCaptureIsDetected(t *testing.T) {
	pc, cfg := requireImage(t)

	work, err := os.MkdirTemp("/private/tmp", "pcap-analyzer-it-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(work) })

	capDir := filepath.Join(work, "evidence")
	if err := os.MkdirAll(capDir, 0o700); err != nil {
		t.Fatal(err)
	}
	full := synthCapture(t, pc, cfg, capDir)

	res, err := pc.RunOnce(context.Background(), podman.RunOnceOpts{
		Image:       cfg.Container.Image,
		Network:     "none",
		DropAllCaps: true,
		Userns:      DefaultUserns(),
		Mounts:      []podman.Mount{{HostPath: capDir, ContainerPath: "/work"}},
		Cmd:         []string{"editcap", "-s", "40", "/work/capture.pcapng", "/work/trunc.pcapng"},
	})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("editcap failed: %v %s", err, res.Stderr)
	}
	_ = full

	m := NewManager(cfg, pc)
	ws, err := m.Create(context.Background(), filepath.Join(capDir, "trunc.pcapng"),
		filepath.Join(work, "ws"))
	if err != nil {
		t.Fatal(err)
	}

	if !ws.Meta.Info.Truncated {
		t.Errorf("editcap -s 40 must be detected as truncated; snaplen_header=%q min=%v max=%v",
			ws.Meta.Info.SnaplenHeader, ws.Meta.Info.SnaplenInferredMin, ws.Meta.Info.SnaplenInferredMax)
	}
	if ws.Meta.Info.SnaplenHeader != "(not set)" {
		t.Logf("note: header snaplen is %q on this tshark", ws.Meta.Info.SnaplenHeader)
	}
}
