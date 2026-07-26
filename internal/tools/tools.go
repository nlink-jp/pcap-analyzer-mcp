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

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/config"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/job"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/mcpserver"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/podman"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/toolerr"
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
		return toolerr.Newf(toolerr.CodeInvalidArguments, "%v", err)
	}
	return nil
}

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
	}
}

// loadWorkspace resolves the workspace_id / workspace_dir pair every analysis
// tool takes.
func (d *Deps) loadWorkspace(id, dir string) (*workspace.Workspace, error) {
	if dir == "" {
		return nil, toolerr.New(toolerr.CodeMissingArgument, "workspace_dir is required")
	}
	return d.Workspace.Load(id, dir)
}
