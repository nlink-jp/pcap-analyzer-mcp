package podman

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
	"testing"
)

// fakeRunner records the argv it was handed and replays a canned result.
type fakeRunner struct {
	calls    [][]string
	stdout   string
	stderr   string
	exitCode int
	err      error
	streamed string
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, []byte, int, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	return []byte(f.stdout), []byte(f.stderr), f.exitCode, f.err
}

func (f *fakeRunner) RunStreaming(_ context.Context, stdout, _ io.Writer, name string, args ...string) (int, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	_, _ = io.WriteString(stdout, f.streamed)
	return f.exitCode, f.err
}

func (f *fakeRunner) lastCall() string { return strings.Join(f.calls[len(f.calls)-1], " ") }

func TestVersion(t *testing.T) {
	f := &fakeRunner{stdout: "podman version 6.0.2\n"}
	got, err := NewWithRunner("podman", f).Version(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got != "podman version 6.0.2" {
		t.Errorf("got %q", got)
	}
}

// exec reports a missing binary as exit code -1; that must surface as
// ErrNotInstalled so doctor can tell "podman is absent" from "podman said no".
func TestVersionMissingBinary(t *testing.T) {
	f := &fakeRunner{exitCode: -1, err: exec.ErrNotFound}
	_, err := NewWithRunner("podman", f).Version(context.Background())

	var notInstalled *ErrNotInstalled
	if !errors.As(err, &notInstalled) {
		t.Fatalf("want ErrNotInstalled, got %v", err)
	}
	if !errors.Is(err, exec.ErrNotFound) {
		t.Errorf("ErrNotInstalled must unwrap to the cause")
	}
}

// `podman machine` fails on a host with no machine configured, which is the
// normal case on native Linux. That is a fact, not a failure.
func TestMachineStateAbsentIsNotAnError(t *testing.T) {
	f := &fakeRunner{exitCode: 125, stderr: "Error: no machine"}
	state, err := NewWithRunner("podman", f).MachineState(context.Background())
	if err != nil {
		t.Fatalf("absent machine must not be an error: %v", err)
	}
	if state != "" {
		t.Errorf("state = %q, want empty", state)
	}
}

func TestMachineStateRunning(t *testing.T) {
	f := &fakeRunner{stdout: "running\n"}
	state, err := NewWithRunner("podman", f).MachineState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if state != "running" {
		t.Errorf("state = %q", state)
	}
}

// `podman image exists` answers through its exit code and prints nothing.
func TestImageExists(t *testing.T) {
	for _, tt := range []struct {
		code int
		want bool
	}{{0, true}, {1, false}} {
		f := &fakeRunner{exitCode: tt.code}
		got, err := NewWithRunner("podman", f).ImageExists(context.Background(), "img")
		if err != nil {
			t.Fatal(err)
		}
		if got != tt.want {
			t.Errorf("exit %d: got %v, want %v", tt.code, got, tt.want)
		}
	}
}

func TestImageIDErrorCarriesStderr(t *testing.T) {
	f := &fakeRunner{exitCode: 125, stderr: "no such image\n"}
	_, err := NewWithRunner("podman", f).ImageID(context.Background(), "missing")
	if err == nil {
		t.Fatal("want error")
	}
	if !strings.Contains(err.Error(), "no such image") {
		t.Errorf("error must surface podman's stderr, got: %v", err)
	}
}

// The build context must be a directory holding only the Dockerfile — never
// the working directory, which podman would tar up wholesale.
func TestBuildUsesAnIsolatedContext(t *testing.T) {
	f := &fakeRunner{streamed: "STEP 1/7\n"}
	var out strings.Builder

	if err := NewWithRunner("podman", f).Build(context.Background(), &out, "img:tag", "FROM scratch\n"); err != nil {
		t.Fatal(err)
	}

	call := f.lastCall()
	if !strings.Contains(call, "build -t img:tag -f ") {
		t.Errorf("unexpected argv: %s", call)
	}
	if strings.HasSuffix(call, " .") {
		t.Errorf("build context must not be the working directory: %s", call)
	}
	if out.String() != "STEP 1/7\n" {
		t.Errorf("build progress not streamed through: %q", out.String())
	}
}

func TestBuildNonZeroExit(t *testing.T) {
	f := &fakeRunner{exitCode: 1}
	err := NewWithRunner("podman", f).Build(context.Background(), io.Discard, "img", "FROM scratch\n")
	if err == nil {
		t.Fatal("want error on non-zero exit")
	}
}

// The mount probe must itself be harmless: read-only, no network, no
// capabilities. It runs against paths the operator named, but the whole point
// is to find out whether they are reachable at all.
func TestCanMountProbeIsRestricted(t *testing.T) {
	f := &fakeRunner{exitCode: 0}
	ok, _, err := NewWithRunner("podman", f).CanMount(context.Background(), "img", "/some/dir")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("exit 0 means the path is mountable")
	}

	call := f.lastCall()
	for _, want := range []string{"--rm", "--network=none", "--cap-drop=ALL", "/some/dir:/probe:ro"} {
		if !strings.Contains(call, want) {
			t.Errorf("probe missing %q: %s", want, call)
		}
	}
}

func TestCanMountFailureReturnsStderr(t *testing.T) {
	f := &fakeRunner{exitCode: 126, stderr: "statfs /some/dir: no such file or directory\n"}
	ok, reason, err := NewWithRunner("podman", f).CanMount(context.Background(), "img", "/some/dir")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("non-zero exit means not mountable")
	}
	if !strings.Contains(reason, "no such file") {
		t.Errorf("reason should carry podman's stderr, got %q", reason)
	}
}
