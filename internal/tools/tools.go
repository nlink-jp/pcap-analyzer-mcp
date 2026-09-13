// Package tools implements the MCP tool handlers.
//
// Every handler that returns rows goes through internal/output, so the result
// contract (ADR-0005) is honoured in one place rather than re-implemented per
// tool.
package tools

import (
	"context"
	"encoding/json"
	"io"
	"strings"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/config"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/job"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/mcpserver"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/podman"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/toolerr"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/workdir"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/workspace"
)

// ContainerRunner is the container surface the tools need.
type ContainerRunner interface {
	RunOnce(ctx context.Context, opts podman.RunOnceOpts) (*podman.Result, error)
	RunOnceStream(ctx context.Context, opts podman.RunOnceOpts, consume func(io.Reader) error) (*podman.StreamResult, error)
	ImageID(ctx context.Context, ref string) (string, error)
}

// Deps carries what the handlers share.
type Deps struct {
	Cfg       config.Config
	Podman    ContainerRunner
	Workspace *workspace.Manager
	Jobs      *job.Manager

	// WorkDir resolves and validates the per-call work directory: the
	// argument, then the request's _meta, then an error (ADR-0008 §2).
	// The zero value works.
	WorkDir workdir.Resolver

	// ServerCtx outlives any single request. Background jobs run under it,
	// because the request context is cancelled as soon as the job id is
	// returned (ADR-0006).
	ServerCtx context.Context
}

// Register installs every tool on the server.
func Register(srv *mcpserver.Server, d *Deps) {
	for _, t := range d.all() {
		srv.RegisterTool(t.desc, t.handler)
	}
}

type registration struct {
	desc    mcpserver.Tool
	handler mcpserver.ToolHandler
}

func (d *Deps) all() []registration {
	return []registration{
		d.getUsage(),
		d.createWorkspace(),
		d.describeWorkspace(),
		d.listWorkspaces(),
		d.deleteWorkspace(),
		d.describeRuntime(),
		d.protocolHierarchy(),
		d.listConversations(),
		d.queryPackets(),
		d.followStream(),
		d.extractObjects(),
		d.checkJob(),
	}
}

// decode unmarshals tool arguments strictly, so a misspelled argument is
// reported instead of silently ignored.
func decode(raw json.RawMessage, dst any) error {
	if len(raw) == 0 {
		raw = json.RawMessage("{}")
	}
	dec := json.NewDecoder(bytesReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		msg := err.Error()
		for _, old := range retiredWorkDirNames {
			if strings.Contains(msg, `unknown field "`+old+`"`) {
				return toolerr.Newf(toolerr.CodeWorkDirRequired,
					"%q was renamed to work_dir: pass the absolute path of a directory you can read back", old)
			}
		}
		return toolerr.Newf(toolerr.CodeInvalidArguments, "%v", err)
	}
	return nil
}

// retiredWorkDirNames are the spellings the work-directory argument carried
// across the fleet before organization ADR-021 settled on work_dir. A caller
// working from an older manual is told the new name rather than left to guess
// from "unknown field": the rename is ours.
var retiredWorkDirNames = []string{"workspace_root", "workspaceRoot", "workspace_dir"}

// runOpts builds the container options shared by every analysis run: no
// network, no capabilities, the capture read-only, the workspace writable.
func (d *Deps) runOpts(ws *workspace.Workspace, cmd []string) podman.RunOnceOpts {
	return podman.RunOnceOpts{
		Image:       d.Cfg.Container.Image,
		Cmd:         cmd,
		Mounts:      ws.Mounts(),
		Network:     d.Cfg.Container.Limits.Network,
		CPU:         d.Cfg.Container.Limits.CPU,
		Memory:      d.Cfg.Container.Limits.Memory,
		Userns:      workspace.DefaultUserns(),
		DropAllCaps: true,
		Timeout:     d.Cfg.Container.Limits.Timeout.Duration,
	}
}

// workDirProp is the schema property for the caller's work directory, shared
// by every tool that takes one so the wording cannot drift between them.
//
// Note the collision it does not have: this is the caller's root, while
// Workspace.WorkDir() is <workspace>/work, the writable area mounted at /work
// inside the container. Different levels, deliberately different spellings
// (ADR-0008 §1).
const workDirProp = `"work_dir": {"type": "string", "description": "Absolute path to a directory you can read back \u2014 your session or working directory. The workspace is <work_dir>/<workspace_id>/ and every file this server writes lands under it, so a directory you cannot open leaves you holding a path to nothing. It must already exist, and nothing here expands ~ or resolves a relative path."}`

// loadWorkspace resolves the work_dir / workspace_id pair that addresses a
// workspace. The pair is the address: this server keeps no state across
// restarts, so both travel on every call.
func (d *Deps) loadWorkspace(ctx context.Context, id, dir string) (*workspace.Workspace, error) {
	resolved, err := d.resolveWorkDir(ctx, dir)
	if err != nil {
		return nil, err
	}
	return d.Workspace.Load(id, resolved)
}

// resolveWorkDir validates the caller's work directory for one call. Tools
// that do not address an existing workspace (create, list, delete) call it
// directly.
func (d *Deps) resolveWorkDir(ctx context.Context, dir string) (string, error) {
	return d.WorkDir.Resolve(ctx, dir)
}
