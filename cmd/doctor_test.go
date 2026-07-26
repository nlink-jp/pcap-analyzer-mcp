package cmd

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
)

type fakeProber struct {
	// reachable lists the paths that mount successfully; everything else fails.
	reachable map[string]bool
	err       error
	probed    []string
}

func (f *fakeProber) CanMount(_ context.Context, _, hostPath string) (bool, string, error) {
	f.probed = append(f.probed, hostPath)
	if f.err != nil {
		return false, "", f.err
	}
	if f.reachable[hostPath] {
		return true, "", nil
	}
	return false, "statfs " + hostPath + ": no such file or directory", nil
}

func newDiagnosis() (*diagnosis, *bytes.Buffer) {
	var buf bytes.Buffer
	return &diagnosis{out: &buf}, &buf
}

// A path the operator explicitly listed in allowed_paths is one they intend to
// analyse, so an unreachable one is a fault, not a note.
func TestCheckMountsUnreachableAllowedPathFails(t *testing.T) {
	d, buf := newDiagnosis()
	p := &fakeProber{reachable: map[string]bool{"/Users/x/captures": true}}

	d.checkMounts(context.Background(), p, "img",
		[]string{"/Users/x/captures", "/Volumes/external"})

	if d.failed != 1 {
		t.Errorf("failed = %d, want 1", d.failed)
	}
	out := buf.String()
	if !strings.Contains(out, "[FAIL]") || !strings.Contains(out, "/Volumes/external") {
		t.Errorf("unreachable allowed_path not reported as a failure:\n%s", out)
	}
	if !strings.Contains(out, "no such file") {
		t.Errorf("podman's reason should be surfaced:\n%s", out)
	}
}

// With allowed_paths empty the probe is advisory: it is telling the user where
// captures have to live, not judging a choice they made.
func TestCheckMountsDefaultSharesOnlyWarn(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("default-share probing only applies to the macOS VM")
	}
	d, buf := newDiagnosis()
	p := &fakeProber{reachable: map[string]bool{"/Users": true, "/private/tmp": true}}

	d.checkMounts(context.Background(), p, "img", nil)

	if d.failed != 0 {
		t.Errorf("an unreachable default share must not fail the run; failed = %d", d.failed)
	}
	if d.warned == 0 {
		t.Error("an unreachable default share should warn")
	}
	if !strings.Contains(buf.String(), "/var/folders") {
		t.Errorf("expected the conventional shares to be probed:\n%s", buf.String())
	}
	if got, want := len(p.probed), 3; got != want {
		t.Errorf("probed %d paths, want %d", got, want)
	}
}

// Off the macOS VM there are no virtiofs shares to fall foul of, so probing
// arbitrary conventional paths would be noise.
func TestCheckMountsSkipsDefaultProbeOffDarwin(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("this is the non-darwin path")
	}
	d, buf := newDiagnosis()
	p := &fakeProber{}

	d.checkMounts(context.Background(), p, "img", nil)

	if len(p.probed) != 0 {
		t.Errorf("should not probe conventional paths off darwin, probed %v", p.probed)
	}
	if !strings.Contains(buf.String(), "unrestricted") {
		t.Errorf("expected an explanatory line:\n%s", buf.String())
	}
}

func TestCheckMountsProbeErrorWarns(t *testing.T) {
	d, _ := newDiagnosis()
	p := &fakeProber{err: errors.New("podman exploded")}

	d.checkMounts(context.Background(), p, "img", []string{"/Users/x"})

	if d.warned != 1 || d.failed != 0 {
		t.Errorf("a probe that could not run is a warning, not a verdict: warned=%d failed=%d",
			d.warned, d.failed)
	}
}

func TestSummarizeFailsOnlyWhenSomethingFailed(t *testing.T) {
	d, buf := newDiagnosis()
	d.pass("a", "fine")
	if err := d.summarize(); err != nil {
		t.Errorf("all-pass must not error: %v", err)
	}
	if !strings.Contains(buf.String(), "All checks passed") {
		t.Errorf("missing summary line:\n%s", buf.String())
	}

	d2, _ := newDiagnosis()
	d2.warn("a", "hmm")
	if err := d2.summarize(); err != nil {
		t.Errorf("warnings alone must not fail the command: %v", err)
	}

	d3, _ := newDiagnosis()
	d3.fail("a", "nope")
	if err := d3.summarize(); err == nil {
		t.Error("a failed check must produce a non-zero exit")
	}
}

func TestShortImageID(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"sha256:b93c340385cfd88069f8e1d4d8a77059145f163b", "b93c340385cf"},
		{"b93c340385cfd88069f8e1d4d8a77059145f163b", "b93c340385cf"},
		{"abc", "abc"},
	} {
		if got := short(tt.in); got != tt.want {
			t.Errorf("short(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestDescribeConfigSource(t *testing.T) {
	if got := describeConfigSource(""); !strings.Contains(got, "defaults") {
		t.Errorf("no config path should say so plainly, got %q", got)
	}
	if got := describeConfigSource("/etc/x.toml"); !strings.Contains(got, "/etc/x.toml") {
		t.Errorf("an explicit path should be echoed, got %q", got)
	}
}
