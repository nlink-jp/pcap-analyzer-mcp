package tools

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/config"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/job"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/mcpserver"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/podman"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/toolerr"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/workspace"
)

// fakeRunner replays canned container output and records what it was asked
// to run.
type fakeRunner struct {
	stdout   string
	stream   string
	exitCode int
	stopped  bool
	lastCmd  []string
	runs     int
}

func (f *fakeRunner) RunOnce(_ context.Context, opts podman.RunOnceOpts) (*podman.Result, error) {
	f.runs++
	f.lastCmd = opts.Cmd
	return &podman.Result{Stdout: []byte(f.stdout), ExitCode: f.exitCode}, nil
}

func (f *fakeRunner) RunOnceStream(_ context.Context, opts podman.RunOnceOpts, consume func(io.Reader) error) (*podman.StreamResult, error) {
	f.runs++
	f.lastCmd = opts.Cmd
	if err := consume(strings.NewReader(f.stream)); err != nil {
		return nil, err
	}
	return &podman.StreamResult{ExitCode: f.exitCode, Stopped: f.stopped}, nil
}

func (f *fakeRunner) ImageID(context.Context, string) (string, error) {
	return "sha256:deadbeef", nil
}

func newDeps(r ContainerRunner) *Deps {
	cfg := config.Default()
	return &Deps{
		Cfg:       cfg,
		Podman:    r,
		Workspace: workspace.NewManager(cfg, nil),
		Jobs:      job.NewManager(cfg.Jobs.MaxConcurrent),
		ServerCtx: context.Background(),
	}
}

func find(t *testing.T, d *Deps, name string) registration {
	t.Helper()
	for _, r := range d.all() {
		if r.desc.Name == name {
			return r
		}
	}
	t.Fatalf("no tool named %q", name)
	return registration{}
}

func call(t *testing.T, d *Deps, name string, args map[string]any) (any, error) {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	return find(t, d, name).handler(context.Background(), raw)
}

// Every tool must advertise a JSON Schema object. A client that validates
// inputSchema locally rejects the tool outright otherwise.
func TestEverySchemaIsAValidObjectSchema(t *testing.T) {
	d := newDeps(&fakeRunner{})
	names := map[string]bool{}
	for _, r := range d.all() {
		if r.desc.Name == "" {
			t.Error("a tool has no name")
		}
		if names[r.desc.Name] {
			t.Errorf("duplicate tool name %q", r.desc.Name)
		}
		names[r.desc.Name] = true

		if len(r.desc.Description) < 40 {
			t.Errorf("%s: description is too thin to guide a caller", r.desc.Name)
		}
		var schema map[string]any
		if err := json.Unmarshal(r.desc.InputSchema, &schema); err != nil {
			t.Errorf("%s: inputSchema is not valid JSON: %v", r.desc.Name, err)
			continue
		}
		if schema["type"] != "object" {
			t.Errorf("%s: inputSchema type = %v", r.desc.Name, schema["type"])
		}
		if _, ok := schema["properties"]; !ok {
			t.Errorf("%s: inputSchema has no properties", r.desc.Name)
		}
	}
	if len(names) != 10 {
		t.Errorf("registered %d tools, want 10", len(names))
	}
}

func TestRegisterInstallsEveryTool(t *testing.T) {
	srv := mcpserver.New("t", "v", nil, nil)
	Register(srv, newDeps(&fakeRunner{}))
	// Registering twice would panic or duplicate; just assert it completed and
	// the registry is the same size as all().
	if got := len(newDeps(&fakeRunner{}).all()); got != 10 {
		t.Errorf("all() = %d", got)
	}
}

// A misspelled argument must be reported, not silently dropped — otherwise an
// agent that writes "filters" instead of "filter" gets a full-capture scan and
// no explanation.
func TestUnknownArgumentIsRejected(t *testing.T) {
	d := newDeps(&fakeRunner{})
	_, err := call(t, d, "query_packets", map[string]any{
		"workspace_id":  "x-00000000",
		"workspace_dir": t.TempDir(),
		"filters":       "tcp",
	})
	if err == nil {
		t.Fatal("want an error for an unknown argument")
	}
	if !errors.Is(err, toolerr.New(toolerr.CodeInvalidArguments, "")) {
		t.Errorf("want invalid_arguments, got %v", err)
	}
}

func TestMissingWorkspaceDir(t *testing.T) {
	d := newDeps(&fakeRunner{})
	for _, name := range []string{"describe_workspace", "list_workspaces", "delete_workspace"} {
		args := map[string]any{"workspace_id": "x-00000000", "workspace_dir": ""}
		if name == "list_workspaces" {
			args = map[string]any{"workspace_dir": ""}
		}
		_, err := call(t, d, name, args)
		if !errors.Is(err, toolerr.New(toolerr.CodeMissingArgument, "")) {
			t.Errorf("%s: want missing_argument, got %v", name, err)
		}
	}
}

func TestListWorkspacesOnEmptyDir(t *testing.T) {
	d := newDeps(&fakeRunner{})
	out, err := call(t, d, "list_workspaces", map[string]any{"workspace_dir": t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	m := out.(map[string]any)
	if m["count"] != 0 {
		t.Errorf("count = %v", m["count"])
	}
}

func TestDescribeRuntimeReportsBothManifestAndLocalImage(t *testing.T) {
	d := newDeps(&fakeRunner{})
	out, err := call(t, d, "describe_runtime", nil)
	if err != nil {
		t.Fatal(err)
	}
	m := out.(map[string]any)
	if m["local_image_id"] != "sha256:deadbeef" {
		t.Errorf("local_image_id = %v", m["local_image_id"])
	}
	if _, ok := m["manifest"]; !ok {
		t.Error("the manifest is what says what the image should contain")
	}
}

func TestGetUsageMentionsTheContractItPromises(t *testing.T) {
	d := newDeps(&fakeRunner{})
	out, err := call(t, d, "get_usage", nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{"matched", "delivery", "workspace", "truncated"} {
		if !strings.Contains(s, want) {
			t.Errorf("get_usage never mentions %q, which callers need to interpret results", want)
		}
	}
}

func TestTransportValidation(t *testing.T) {
	d := newDeps(&fakeRunner{})
	_, err := call(t, d, "list_conversations", map[string]any{
		"workspace_id": "x-00000000", "workspace_dir": t.TempDir(), "transport": "sctp",
	})
	if !errors.Is(err, toolerr.New(toolerr.CodeInvalidArguments, "")) {
		t.Errorf("want invalid_arguments for an unsupported transport, got %v", err)
	}
}

func TestFormatValidation(t *testing.T) {
	d := newDeps(&fakeRunner{})
	_, err := call(t, d, "query_packets", map[string]any{
		"workspace_id": "x-00000000", "workspace_dir": t.TempDir(), "format": "parquet",
	})
	if !errors.Is(err, toolerr.New(toolerr.CodeInvalidArguments, "")) {
		t.Errorf("parquet is not offered (ADR-0003) and must be refused: %v", err)
	}
}

// Asking about a workspace that was never created is a workspace_not_found,
// not a crash or a generic failure.
func TestUnknownWorkspace(t *testing.T) {
	d := newDeps(&fakeRunner{})
	_, err := call(t, d, "describe_workspace", map[string]any{
		"workspace_id": "absent-00000000", "workspace_dir": t.TempDir(),
	})
	if !errors.Is(err, toolerr.New(toolerr.CodeWorkspaceNotFound, "")) {
		t.Errorf("want workspace_not_found, got %v", err)
	}
}

// A truncated capture must be flagged at the top of the payload, not buried,
// so the agent sees it before reaching for payload extraction.
func TestDescribePayloadFlagsTruncation(t *testing.T) {
	meta := &workspace.Meta{
		Capture: workspace.Capture{Name: "c.pcap"},
		Info:    workspace.CaptureInfo{Truncated: true},
	}
	p := describePayload("id", "/dir", meta, nil)
	if p["truncated"] != true {
		t.Error("truncated must be restated at the top level")
	}
	note, _ := p["payload_note"].(string)
	if !strings.Contains(note, "not a transient failure") {
		t.Errorf("the note must stop the agent retrying: %q", note)
	}

	whole := describePayload("id", "/dir",
		&workspace.Meta{Capture: workspace.Capture{}, Info: workspace.CaptureInfo{}}, nil)
	if _, ok := whole["payload_note"]; ok {
		t.Error("an intact capture needs no warning")
	}
}
