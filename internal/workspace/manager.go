// Package workspace owns the on-disk state of an analysis.
//
// A workspace is a directory plus a metadata file — nothing else. There is no
// in-memory registry and no long-lived container (ADR-0002), so workspaces
// survive a server restart for free and listing them is a directory scan.
package workspace

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/config"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/podman"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/toolerr"
)

// metaProbeDelimiter separates the two commands run in the single container
// start that populates meta.json.
const metaProbeDelimiter = "---pcap-analyzer-mcp---"

// Runner is the slice of the podman client this package needs.
type Runner interface {
	RunOnce(ctx context.Context, opts podman.RunOnceOpts) (*podman.Result, error)
	ImageID(ctx context.Context, ref string) (string, error)
}

// Manager creates and inspects workspaces.
type Manager struct {
	cfg    config.Config
	podman Runner
}

// NewManager returns a Manager bound to a config and a container runner.
func NewManager(cfg config.Config, r Runner) *Manager {
	return &Manager{cfg: cfg, podman: r}
}

// Workspace is a located workspace on disk.
type Workspace struct {
	ID   string
	Dir  string
	Root string
	Meta *Meta
}

// WorkDir is the writable area mounted at /work.
func (w *Workspace) WorkDir() string { return filepath.Join(w.Dir, "work") }

// OutDir is where query results land.
func (w *Workspace) OutDir() string { return filepath.Join(w.WorkDir(), "out") }

// ObjectsDir holds extracted objects. Its contents are untrusted (ADR-0007).
func (w *Workspace) ObjectsDir() string { return filepath.Join(w.OutDir(), "objects") }

// Mounts returns the two bind mounts every analysis container gets: the
// capture read-only, the workspace writable.
func (w *Workspace) Mounts() []podman.Mount {
	return []podman.Mount{
		{HostPath: w.Meta.Capture.HostPath, ContainerPath: EvidenceMount, ReadOnly: true},
		{HostPath: w.WorkDir(), ContainerPath: WorkMount},
	}
}

// Create binds a capture to a new workspace under root.
//
// Everything expensive happens once here — the host-side SHA-256 and a single
// container start for capinfos — so that describe_workspace afterwards is a
// file read.
func (m *Manager) Create(ctx context.Context, pcapPath, root string) (*Workspace, error) {
	resolved, err := ResolveAndCheck(pcapPath, m.cfg.Workspace.AllowedPaths)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(resolved)
	if err != nil {
		return nil, toolerr.Newf(toolerr.CodePcapUnreadable, "%v", err)
	}
	if st.IsDir() {
		return nil, toolerr.Newf(toolerr.CodePcapUnreadable, "%s is a directory", pcapPath)
	}

	id := DeriveWorkspaceID(resolved)
	dir, err := WorkspacePath(root, id)
	if err != nil {
		return nil, err
	}
	ws := &Workspace{ID: id, Dir: dir, Root: root}

	for _, d := range []string{ws.OutDir(), ws.ObjectsDir(), filepath.Join(ws.WorkDir(), "tmp")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, toolerr.Newf(toolerr.CodeInvalidArguments, "create workspace dir: %v", err)
		}
	}

	sum, err := sha256File(resolved)
	if err != nil {
		return nil, toolerr.Newf(toolerr.CodePcapUnreadable, "hash capture: %v", err)
	}

	info, tsharkVersion, err := m.probe(ctx, resolved, ws.WorkDir())
	if err != nil {
		return nil, err
	}

	imageID, err := m.podman.ImageID(ctx, m.cfg.Container.Image)
	if err != nil {
		// The analysis already ran; not being able to label it is worth
		// recording but not worth discarding the workspace over.
		imageID = ""
	}

	ws.Meta = &Meta{
		SchemaVersion: MetaSchemaVersion,
		WorkspaceID:   id,
		CreatedAt:     NewTimestamp(float64(time.Now().UnixNano()) / 1e9),
		Capture: Capture{
			HostPath: resolved,
			Name:     filepath.Base(resolved),
			SHA256:   sum,
			Size:     st.Size(),
		},
		Info: info,
		Runtime: Runtime{
			Image:         m.cfg.Container.Image,
			ImageID:       imageID,
			TsharkVersion: tsharkVersion,
		},
	}
	if err := ws.Meta.Write(ws.Dir); err != nil {
		return nil, toolerr.Newf(toolerr.CodeInvalidArguments, "%v", err)
	}
	return ws, nil
}

// probe runs capinfos and tshark --version in one container start.
//
// Two starts would be tidier to parse but would double the per-workspace
// container cost for a value that is a single line of text.
func (m *Manager) probe(ctx context.Context, pcapPath, workDir string) (CaptureInfo, string, error) {
	script := strings.Join([]string{
		"tshark --version | head -1",
		"echo " + metaProbeDelimiter,
		strings.Join(CapinfosArgs(EvidenceMount), " "),
	}, "\n")

	res, err := m.podman.RunOnce(ctx, podman.RunOnceOpts{
		Image:       m.cfg.Container.Image,
		Cmd:         []string{"sh", "-c", script},
		Network:     m.cfg.Container.Limits.Network,
		CPU:         m.cfg.Container.Limits.CPU,
		Memory:      m.cfg.Container.Limits.Memory,
		Userns:      DefaultUserns(),
		DropAllCaps: true,
		Mounts: []podman.Mount{
			{HostPath: pcapPath, ContainerPath: EvidenceMount, ReadOnly: true},
			{HostPath: workDir, ContainerPath: WorkMount},
		},
	})
	if err != nil {
		return CaptureInfo{}, "", toolerr.Newf(toolerr.CodeContainerFailed, "%v", err)
	}
	if res.ExitCode != 0 {
		return CaptureInfo{}, "", toolerr.Newf(toolerr.CodeTsharkFailed,
			"capinfos exited %d", res.ExitCode).
			WithDetails(map[string]any{
				"exit_code": res.ExitCode,
				"stderr":    truncateForDetails(string(res.Stderr)),
			})
	}

	version, csvOut, ok := strings.Cut(string(res.Stdout), metaProbeDelimiter)
	if !ok {
		return CaptureInfo{}, "", toolerr.New(toolerr.CodeTsharkFailed,
			"probe output did not contain the expected delimiter")
	}
	info, err := ParseCapinfos([]byte(strings.TrimSpace(csvOut)))
	if err != nil {
		return CaptureInfo{}, "", toolerr.Newf(toolerr.CodeTsharkFailed, "%v", err)
	}
	return info, strings.TrimSpace(version), nil
}

// Load opens an existing workspace.
func (m *Manager) Load(id, root string) (*Workspace, error) {
	dir, err := WorkspacePath(root, id)
	if err != nil {
		return nil, err
	}
	meta, err := ReadMeta(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, toolerr.Newf(toolerr.CodeWorkspaceNotFound,
				"no workspace %q under the given workspace_dir", id).
				WithDetails(map[string]any{"workspace_id": id})
		}
		return nil, toolerr.Newf(toolerr.CodeWorkspaceNotFound, "%v", err)
	}
	return &Workspace{ID: id, Dir: dir, Root: root, Meta: meta}, nil
}

// Summary is one entry in a workspace listing.
type Summary struct {
	WorkspaceID string    `json:"workspace_id"`
	CaptureName string    `json:"capture_name"`
	CapturePath string    `json:"capture_path"`
	SHA256      string    `json:"sha256"`
	PacketCount int64     `json:"packet_count"`
	Truncated   bool      `json:"truncated"`
	CreatedAt   Timestamp `json:"created_at"`
	Dir         string    `json:"dir"`
}

// List enumerates the workspaces under root.
//
// Disk is the only source of truth, so this stays correct across restarts and
// across two servers pointed at the same directory.
func (m *Manager) List(root string) ([]Summary, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return []Summary{}, nil
		}
		return nil, toolerr.Newf(toolerr.CodeInvalidArguments, "read workspace_dir: %v", err)
	}

	out := make([]Summary, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() || ValidateWorkspaceID(e.Name()) != nil {
			continue
		}
		meta, err := ReadMeta(filepath.Join(root, e.Name()))
		if err != nil {
			// A directory without readable metadata is not a workspace. Skipping
			// it keeps an unrelated directory from breaking the whole listing.
			continue
		}
		out = append(out, Summary{
			WorkspaceID: meta.WorkspaceID,
			CaptureName: meta.Capture.Name,
			CapturePath: meta.Capture.HostPath,
			SHA256:      meta.Capture.SHA256,
			PacketCount: meta.Info.PacketCount,
			Truncated:   meta.Info.Truncated,
			CreatedAt:   meta.CreatedAt,
			Dir:         filepath.Join(root, e.Name()),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Epoch > out[j].CreatedAt.Epoch })
	return out, nil
}

// DeletePreview describes what Delete would remove.
type DeletePreview struct {
	WorkspaceID string `json:"workspace_id"`
	Dir         string `json:"dir"`
	Files       int    `json:"files"`
	Bytes       int64  `json:"bytes"`
	// CaptureUntouched restates that the evidence itself is never deleted:
	// the capture was only ever mounted read-only.
	CaptureUntouched string `json:"capture_untouched"`
}

// PreviewDelete reports what Delete would remove, without removing anything.
func (m *Manager) PreviewDelete(id, root string) (*DeletePreview, error) {
	ws, err := m.Load(id, root)
	if err != nil {
		return nil, err
	}
	var files int
	var bytes int64
	_ = filepath.WalkDir(ws.Dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // an unreadable entry should not abort a preview
		}
		files++
		if fi, err := d.Info(); err == nil {
			bytes += fi.Size()
		}
		return nil
	})
	return &DeletePreview{
		WorkspaceID:      ws.ID,
		Dir:              ws.Dir,
		Files:            files,
		Bytes:            bytes,
		CaptureUntouched: ws.Meta.Capture.HostPath,
	}, nil
}

// Delete removes a workspace directory. The capture is never touched.
func (m *Manager) Delete(id, root string) (*DeletePreview, error) {
	preview, err := m.PreviewDelete(id, root)
	if err != nil {
		return nil, err
	}
	if err := os.RemoveAll(preview.Dir); err != nil {
		return nil, toolerr.Newf(toolerr.CodeInvalidArguments, "delete workspace: %v", err)
	}
	return preview, nil
}

// DefaultUserns maps the host user into the container so files written to
// /work are owned by the invoking user, and so a capture readable only by that
// user stays readable inside.
func DefaultUserns() string { return "keep-id:uid=1000,gid=1000" }

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// truncateForDetails bounds stderr echoed into an error. Container stderr is
// tool diagnostics, not payload, but it is still unbounded.
func truncateForDetails(s string) string {
	const max = 2000
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + fmt.Sprintf("... (%d bytes truncated)", len(s)-max)
}
