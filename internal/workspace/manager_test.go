package workspace

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/config"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/podman"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/toolerr"
)

// fakeRunner replays a canned probe result and records the run options, so the
// mount and isolation flags can be asserted without a container runtime.
type fakeRunner struct {
	lastOpts podman.RunOnceOpts
	stdout   string
	exitCode int
	runErr   error
	imageID  string
}

func (f *fakeRunner) RunOnce(_ context.Context, opts podman.RunOnceOpts) (*podman.Result, error) {
	f.lastOpts = opts
	if f.runErr != nil {
		return nil, f.runErr
	}
	return &podman.Result{Stdout: []byte(f.stdout), ExitCode: f.exitCode}, nil
}

func (f *fakeRunner) ImageID(_ context.Context, _ string) (string, error) {
	return f.imageID, nil
}

func probeOutput() string {
	return "TShark (Wireshark) 4.0.17\n" + metaProbeDelimiter + "\n" + realCapinfosOutput
}

func newFixture(t *testing.T) (*Manager, *fakeRunner, string, string) {
	t.Helper()
	cfg := config.Default()
	r := &fakeRunner{stdout: probeOutput(), imageID: "sha256:b93c340385cf"}

	capDir := t.TempDir()
	pcap := filepath.Join(capDir, "incident.pcapng")
	if err := os.WriteFile(pcap, []byte("not really a pcap"), 0o600); err != nil {
		t.Fatal(err)
	}
	return NewManager(cfg, r), r, pcap, t.TempDir()
}

func TestCreateWritesMeta(t *testing.T) {
	m, _, pcap, root := newFixture(t)

	ws, err := m.Create(context.Background(), pcap, root)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ws.ID, "incident-") {
		t.Errorf("ID = %q", ws.ID)
	}

	// SHA-256 of "not really a pcap", computed independently of the code path.
	if ws.Meta.Capture.SHA256 == "" || len(ws.Meta.Capture.SHA256) != 64 {
		t.Errorf("SHA256 = %q", ws.Meta.Capture.SHA256)
	}
	if ws.Meta.Capture.Size != 17 {
		t.Errorf("Size = %d, want 17", ws.Meta.Capture.Size)
	}
	if ws.Meta.Runtime.TsharkVersion != "TShark (Wireshark) 4.0.17" {
		t.Errorf("TsharkVersion = %q", ws.Meta.Runtime.TsharkVersion)
	}
	if ws.Meta.Runtime.ImageID != "sha256:b93c340385cf" {
		t.Errorf("ImageID = %q", ws.Meta.Runtime.ImageID)
	}
	if ws.Meta.Info.PacketCount != 2 {
		t.Errorf("capinfos not parsed into meta: %+v", ws.Meta.Info)
	}

	if _, err := os.Stat(filepath.Join(ws.Dir, MetaFile)); err != nil {
		t.Errorf("meta.json not written: %v", err)
	}
	for _, d := range []string{ws.WorkDir(), ws.OutDir(), ws.ObjectsDir()} {
		if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
			t.Errorf("missing directory %s", d)
		}
	}
}

// The capture is mounted read-only as a single file at a fixed path, and the
// container gets no network and no capabilities.
func TestCreateMountsCaptureReadOnly(t *testing.T) {
	m, r, pcap, root := newFixture(t)

	if _, err := m.Create(context.Background(), pcap, root); err != nil {
		t.Fatal(err)
	}

	opts := r.lastOpts
	if opts.Network != "none" {
		t.Errorf("Network = %q, want none", opts.Network)
	}
	if !opts.DropAllCaps {
		t.Error("analysis containers must drop all capabilities")
	}
	if opts.Userns == "" {
		t.Error("keep-id is needed so a 0600 capture stays readable inside")
	}

	var evidence, work *podman.Mount
	for i := range opts.Mounts {
		switch opts.Mounts[i].ContainerPath {
		case EvidenceMount:
			evidence = &opts.Mounts[i]
		case WorkMount:
			work = &opts.Mounts[i]
		}
	}
	if evidence == nil {
		t.Fatalf("no mount at %s: %+v", EvidenceMount, opts.Mounts)
	}
	if !evidence.ReadOnly {
		t.Error("the capture must be mounted read-only")
	}
	// The symlink-resolved path is what gets mounted — the same path that was
	// checked against allowed_paths and hashed, so the three cannot disagree.
	resolved, err := filepath.EvalSymlinks(pcap)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.HostPath != resolved {
		t.Errorf("the capture file itself must be mounted, got %q want %q",
			evidence.HostPath, resolved)
	}
	if evidence.HostPath == filepath.Dir(resolved) {
		t.Error("the parent directory must not be mounted; siblings would be exposed")
	}
	if work == nil || work.ReadOnly {
		t.Error("the workspace must be mounted read-write")
	}
}

// The host basename never becomes a container path, so an awkward or hostile
// filename cannot reach an argv.
func TestCreateUsesAFixedContainerPath(t *testing.T) {
	cfg := config.Default()
	r := &fakeRunner{stdout: probeOutput()}
	m := NewManager(cfg, r)

	dir := t.TempDir()
	pcap := filepath.Join(dir, "--not-a-flag.pcap")
	if err := os.WriteFile(pcap, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := m.Create(context.Background(), pcap, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	for _, a := range r.lastOpts.Cmd {
		if strings.Contains(a, "--not-a-flag") {
			t.Errorf("the host filename leaked into argv: %v", r.lastOpts.Cmd)
		}
	}
	if !strings.Contains(strings.Join(r.lastOpts.Cmd, " "), EvidenceMount) {
		t.Errorf("capinfos should target %s: %v", EvidenceMount, r.lastOpts.Cmd)
	}
}

func TestCreateRejectsDirectory(t *testing.T) {
	m, _, _, root := newFixture(t)
	if _, err := m.Create(context.Background(), t.TempDir(), root); err == nil {
		t.Error("a directory is not a capture")
	}
}

func TestCreateSurfacesProbeFailure(t *testing.T) {
	m, r, pcap, root := newFixture(t)
	r.exitCode = 2
	r.stdout = ""

	_, err := m.Create(context.Background(), pcap, root)
	if !errors.Is(err, toolerr.New(toolerr.CodeTsharkFailed, "")) {
		t.Fatalf("want tshark_failed, got %v", err)
	}
	var te *toolerr.Error
	if errors.As(err, &te) {
		if te.Details["exit_code"] != 2 {
			t.Errorf("the exit code should reach the agent: %v", te.Details)
		}
	}
}

func TestLoadRoundTrip(t *testing.T) {
	m, _, pcap, root := newFixture(t)
	created, err := m.Create(context.Background(), pcap, root)
	if err != nil {
		t.Fatal(err)
	}

	loaded, err := m.Load(created.ID, root)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Meta.Capture.SHA256 != created.Meta.Capture.SHA256 {
		t.Error("metadata did not survive the round trip")
	}
	if loaded.Meta.Info.PacketCount != created.Meta.Info.PacketCount {
		t.Error("capinfos data did not survive the round trip")
	}
}

func TestLoadMissingWorkspace(t *testing.T) {
	m, _, _, root := newFixture(t)
	_, err := m.Load("absent-00000000", root)
	if !errors.Is(err, toolerr.New(toolerr.CodeWorkspaceNotFound, "")) {
		t.Errorf("want workspace_not_found, got %v", err)
	}
}

// Disk is the only source of truth, so a fresh Manager must see workspaces a
// previous process created.
func TestListSeesWorkspacesFromAnotherManager(t *testing.T) {
	m, r, pcap, root := newFixture(t)
	if _, err := m.Create(context.Background(), pcap, root); err != nil {
		t.Fatal(err)
	}

	fresh := NewManager(config.Default(), r)
	got, err := fresh.List(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d workspaces, want 1", len(got))
	}
	if got[0].CaptureName != "incident.pcapng" {
		t.Errorf("CaptureName = %q", got[0].CaptureName)
	}
}

func TestListIgnoresUnrelatedDirectories(t *testing.T) {
	m, _, _, root := newFixture(t)
	for _, name := range []string{"not-a-workspace", ".hidden", "a.b"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	got, err := m.List(root)
	if err != nil {
		t.Fatalf("an unrelated directory must not break the listing: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d entries, want 0: %+v", len(got), got)
	}
}

func TestListMissingRootIsEmptyNotAnError(t *testing.T) {
	m, _, _, _ := newFixture(t)
	got, err := m.List(filepath.Join(t.TempDir(), "never-created"))
	if err != nil {
		t.Fatalf("a workspace_dir that does not exist yet is empty, not broken: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %+v", got)
	}
}

// Deleting a workspace must never touch the evidence.
func TestDeleteLeavesTheCaptureAlone(t *testing.T) {
	m, _, pcap, root := newFixture(t)
	ws, err := m.Create(context.Background(), pcap, root)
	if err != nil {
		t.Fatal(err)
	}

	preview, err := m.PreviewDelete(ws.ID, root)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Files == 0 {
		t.Error("preview should count meta.json at least")
	}
	if _, err := os.Stat(ws.Dir); err != nil {
		t.Error("PreviewDelete must not remove anything")
	}

	if _, err := m.Delete(ws.ID, root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ws.Dir); !os.IsNotExist(err) {
		t.Error("workspace directory should be gone")
	}
	if _, err := os.Stat(pcap); err != nil {
		t.Errorf("the capture must survive workspace deletion: %v", err)
	}
}

func TestDeleteRejectsTraversal(t *testing.T) {
	m, _, _, root := newFixture(t)
	if _, err := m.Delete("../..", root); err == nil {
		t.Fatal("a traversing workspace_id must never reach RemoveAll")
	}
}

// Strict decoding: metadata written by a different schema is refused rather
// than half-read.
func TestReadMetaRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, MetaFile),
		[]byte(`{"schema_version":1,"workspace_id":"x","surprise":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadMeta(dir); err == nil {
		t.Error("an unknown key must be refused")
	}
}

func TestReadMetaRejectsNewerSchema(t *testing.T) {
	dir := t.TempDir()
	b, _ := json.Marshal(map[string]any{"schema_version": MetaSchemaVersion + 1, "workspace_id": "x"})
	if err := os.WriteFile(filepath.Join(dir, MetaFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadMeta(dir); err == nil {
		t.Error("a newer schema must be refused, not guessed at")
	}
}
