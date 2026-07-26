// Package podman wraps the podman CLI.
//
// Podman is fixed; there is no container-engine abstraction. The Runner
// interface exists purely as a seam for exec.Command so tests can drive the
// client without a container runtime.
package podman

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Runner executes an external command. Implementations must not interpret the
// arguments.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (stdout, stderr []byte, exitCode int, err error)
	RunStreaming(ctx context.Context, stdout, stderr io.Writer, name string, args ...string) (exitCode int, err error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitCode := 0
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}
	return stdout.Bytes(), stderr.Bytes(), exitCode, err
}

func (execRunner) RunStreaming(ctx context.Context, stdout, stderr io.Writer, name string, args ...string) (int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	exitCode := 0
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}
	return exitCode, err
}

// Client calls the podman binary.
type Client struct {
	binary string
	runner Runner
}

// New returns a Client that invokes `podman` from PATH.
func New() *Client { return &Client{binary: "podman", runner: execRunner{}} }

// NewWithRunner returns a Client backed by a caller-supplied runner, for tests.
func NewWithRunner(binary string, r Runner) *Client { return &Client{binary: binary, runner: r} }

// ErrNotInstalled reports that the podman binary could not be executed.
type ErrNotInstalled struct{ Err error }

func (e *ErrNotInstalled) Error() string { return "podman not available: " + e.Err.Error() }
func (e *ErrNotInstalled) Unwrap() error { return e.Err }

// Version returns podman's version string.
func (c *Client) Version(ctx context.Context) (string, error) {
	stdout, stderr, code, err := c.runner.Run(ctx, c.binary, "--version")
	if err != nil && code == -1 {
		return "", &ErrNotInstalled{Err: err}
	}
	if code != 0 {
		return "", fmt.Errorf("podman --version (exit %d): %s", code, strings.TrimSpace(string(stderr)))
	}
	return strings.TrimSpace(string(stdout)), nil
}

// MachineState returns the podman machine's state ("running", "stopped", ...).
// An empty string means no machine is configured, which is the normal case on
// native Linux.
func (c *Client) MachineState(ctx context.Context) (string, error) {
	stdout, _, code, err := c.runner.Run(ctx, c.binary, "machine", "inspect", "--format", "{{.State}}")
	if err != nil && code == -1 {
		return "", &ErrNotInstalled{Err: err}
	}
	if code != 0 {
		// `podman machine` fails on hosts with no machine configured. That is
		// a fact about the host, not an error to propagate.
		return "", nil
	}
	return strings.TrimSpace(string(stdout)), nil
}

// ImageExists reports whether ref resolves to a local image.
func (c *Client) ImageExists(ctx context.Context, ref string) (bool, error) {
	_, _, code, err := c.runner.Run(ctx, c.binary, "image", "exists", ref)
	if err != nil && code == -1 {
		return false, &ErrNotInstalled{Err: err}
	}
	// `podman image exists` communicates the answer through the exit code:
	// 0 present, 1 absent.
	return code == 0, nil
}

// ImageID returns the local image ID for ref.
func (c *Client) ImageID(ctx context.Context, ref string) (string, error) {
	stdout, stderr, code, err := c.runner.Run(ctx, c.binary, "image", "inspect", ref, "--format", "{{.Id}}")
	if err != nil && code == -1 {
		return "", &ErrNotInstalled{Err: err}
	}
	if code != 0 {
		return "", fmt.Errorf("podman image inspect %s (exit %d): %s",
			ref, code, strings.TrimSpace(string(stderr)))
	}
	return strings.TrimSpace(string(stdout)), nil
}

// Build builds tag from the given Dockerfile contents, streaming podman's
// progress to out.
//
// The Dockerfile is written into an otherwise empty temporary directory that
// serves as the build context: the analysis image has no COPY or ADD, so
// handing podman the working directory would only tar up files it never uses.
func (c *Client) Build(ctx context.Context, out io.Writer, tag, dockerfile string) error {
	dir, err := os.MkdirTemp("", "pcap-analyzer-build-")
	if err != nil {
		return fmt.Errorf("create build context: %w", err)
	}
	defer os.RemoveAll(dir)

	path := filepath.Join(dir, "Dockerfile")
	if err := os.WriteFile(path, []byte(dockerfile), 0o600); err != nil {
		return fmt.Errorf("write Dockerfile: %w", err)
	}

	code, err := c.runner.RunStreaming(ctx, out, out, c.binary, "build", "-t", tag, "-f", path, dir)
	if err != nil && code == -1 {
		return &ErrNotInstalled{Err: err}
	}
	if code != 0 {
		return fmt.Errorf("podman build exited %d", code)
	}
	return nil
}

// Mount is a host→container bind mount.
type Mount struct {
	HostPath      string
	ContainerPath string
	ReadOnly      bool
}

func (m Mount) spec() string {
	s := m.HostPath + ":" + m.ContainerPath
	if m.ReadOnly {
		s += ":ro"
	}
	return s
}

// RunOnceOpts describes a single throwaway container run (ADR-0002).
type RunOnceOpts struct {
	Image  string
	Cmd    []string
	Mounts []Mount

	CPU     string
	Memory  string
	Network string
	Userns  string

	// DropAllCaps adds --cap-drop=ALL. Analysis never needs a capability;
	// leaving this false is only useful in tests.
	DropAllCaps bool

	// Timeout bounds the run in wall-clock time. Zero means no bound and is
	// only for tests: the cgroup caps memory, but a dissector stuck in a
	// pathological loop burns CPU indefinitely, and the stdio server handles
	// requests in order.
	Timeout time.Duration
}

// ErrTimeout reports that a run was killed for exceeding its deadline.
type ErrTimeout struct{ After time.Duration }

func (e *ErrTimeout) Error() string {
	return "container run exceeded its " + e.After.String() + " timeout and was killed"
}

// withTimeout applies opts.Timeout, returning the context and whether a
// deadline was set.
func withTimeout(ctx context.Context, opts RunOnceOpts) (context.Context, context.CancelFunc) {
	if opts.Timeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, opts.Timeout)
}

// runArgs builds everything up to (but not including) the container command.
func runArgs(opts RunOnceOpts) []string {
	args := []string{"run", "--rm"}
	if opts.Network != "" {
		args = append(args, "--network", opts.Network)
	}
	if opts.DropAllCaps {
		args = append(args, "--cap-drop=ALL")
	}
	if opts.CPU != "" {
		args = append(args, "--cpus", opts.CPU)
	}
	if opts.Memory != "" {
		args = append(args, "--memory", opts.Memory)
	}
	if opts.Userns != "" {
		args = append(args, "--userns", opts.Userns)
	}
	for _, m := range opts.Mounts {
		args = append(args, "-v", m.spec())
	}
	return append(args, opts.Image)
}

// Result is the outcome of a single container run.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// RunOnce starts a container, waits for it, and removes it.
//
// A non-zero ExitCode is not an error: tshark uses exit codes to report things
// the caller has to interpret (a bad display filter, an unreadable capture).
// A returned error means podman itself failed.
func (c *Client) RunOnce(ctx context.Context, opts RunOnceOpts) (*Result, error) {
	runCtx, cancel := withTimeout(ctx, opts)
	defer cancel()

	args := append(runArgs(opts), opts.Cmd...)

	stdout, stderr, code, err := c.runner.Run(runCtx, c.binary, args...)
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return nil, &ErrTimeout{After: opts.Timeout}
	}
	if err != nil && code == -1 {
		return nil, &ErrNotInstalled{Err: err}
	}
	return &Result{Stdout: stdout, Stderr: stderr, ExitCode: code}, nil
}

// StreamResult reports how a streamed run ended.
type StreamResult struct {
	ExitCode int
	Stderr   []byte
	// Stopped is true when the consumer finished before the container did and
	// the container was killed on purpose. ExitCode is meaningless then: the
	// process died because we stopped reading, not because it failed.
	Stopped bool
}

// RunOnceStream runs a container and hands its stdout to consume as a stream.
//
// RunOnce buffers stdout, which is fine for a version string or a capinfos
// record but not for a full-capture export. Streaming also lets the consumer
// stop early — a row limit should not mean draining a stream that will be
// discarded — which is why the container is killed once consume returns.
func (c *Client) RunOnceStream(
	ctx context.Context,
	opts RunOnceOpts,
	consume func(io.Reader) error,
) (*StreamResult, error) {
	runCtx, cancel := withTimeout(ctx, opts)
	defer cancel()

	pr, pw := io.Pipe()
	var errBuf bytes.Buffer

	type outcome struct {
		code int
		err  error
	}
	done := make(chan outcome, 1)

	go func() {
		code, runErr := c.runStreaming(runCtx, pw, &errBuf, opts)
		// Closing the write end is what lets consume see EOF.
		_ = pw.CloseWithError(io.EOF)
		done <- outcome{code: code, err: runErr}
	}()

	consumeErr := consume(pr)

	// Whether the container finished on its own decides how to read what
	// follows: if it did not, we are about to kill it and its exit status is
	// our doing.
	var res outcome
	stopped := false
	select {
	case res = <-done:
	default:
		stopped = true
		// Unblock the writer, then stop the container. Without both, cmd.Wait
		// deadlocks: the copy goroutine stops and the child blocks on a full
		// pipe.
		_ = pr.CloseWithError(io.ErrClosedPipe)
		cancel()
		res = <-done
	}

	out := &StreamResult{ExitCode: res.code, Stderr: errBuf.Bytes(), Stopped: stopped}
	if !stopped && errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return out, &ErrTimeout{After: opts.Timeout}
	}
	if consumeErr != nil {
		return out, consumeErr
	}
	if !stopped && res.err != nil && res.code == -1 {
		return out, &ErrNotInstalled{Err: res.err}
	}
	return out, nil
}

func (c *Client) runStreaming(ctx context.Context, stdout, stderr io.Writer, opts RunOnceOpts) (int, error) {
	args := append(runArgs(opts), opts.Cmd...)
	return c.runner.RunStreaming(ctx, stdout, stderr, c.binary, args...)
}

// CanMount reports whether hostPath can be bind-mounted into a container.
//
// On macOS this is the question that matters and the one podman will not
// answer directly: the machine is a VM, and only paths inside its virtiofs
// shares are reachable. `podman machine inspect` does not expose the share
// list, so the honest test is to attempt the mount.
func (c *Client) CanMount(ctx context.Context, image, hostPath string) (bool, string, error) {
	_, stderr, code, err := c.runner.Run(ctx, c.binary, "run", "--rm",
		"--network=none", "--cap-drop=ALL",
		"-v", hostPath+":/probe:ro", image,
		"test", "-e", "/probe")
	if err != nil && code == -1 {
		return false, "", &ErrNotInstalled{Err: err}
	}
	if code == 0 {
		return true, "", nil
	}
	return false, strings.TrimSpace(string(stderr)), nil
}
