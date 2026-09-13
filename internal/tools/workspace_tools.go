package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"io"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/job"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/mcpserver"
	"github.com/nlink-jp/pcap-analyzer-mcp/runtime"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

// --- create_workspace -------------------------------------------------------

type createWorkspaceArgs struct {
	PcapPath string `json:"pcap_path"`
	WorkDir  string `json:"work_dir"`
	Async    bool   `json:"async"`
}

func (d *Deps) createWorkspace() registration {
	return registration{
		desc: mcpserver.Tool{
			Name: "create_workspace",
			Description: "Open a capture for analysis. Reads it once to record packet count, " +
				"time range, snaplen and SHA-256, then every later call is cheap. " +
				"The capture is mounted read-only and never copied or modified. " +
				"Start here; every other tool takes the workspace_id this returns.",
			InputSchema: json.RawMessage(`{
  "type": "object",
  "properties": {
    "pcap_path": {"type": "string", "description": "Absolute host path to a .pcap or .pcapng file."},
    ` + workDirProp + `,
    "async": {"type": "boolean", "description": "Run in the background and return a job_id immediately. Use for large captures: a full pass takes minutes and would otherwise hit your request timeout. Poll with check_job."}
  },
  "required": ["pcap_path", "work_dir"],
  "additionalProperties": false
}`),
		},
		handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a createWorkspaceArgs
			if err := decode(raw, &a); err != nil {
				return nil, err
			}
			// Validation stays synchronous (ADR-0006): a work directory the
			// caller cannot read back must fail now, not inside a job whose
			// id has already been handed out.
			workDir, err := d.resolveWorkDir(ctx, a.WorkDir)
			if err != nil {
				return nil, err
			}
			// Reading a large capture end to end is exactly the case async
			// exists for, so it is offered here too.
			return d.dispatch(ctx, a.Async, "create_workspace",
				func(runCtx context.Context, report func(job.Progress)) (any, error) {
					report(job.Progress{Phase: "reading", Note: "hashing and reading capture metadata"})
					ws, err := d.Workspace.Create(runCtx, a.PcapPath, workDir)
					if err != nil {
						return nil, err
					}
					return describePayload(ws, nil), nil
				})
		},
	}
}

// --- describe_workspace -----------------------------------------------------

type workspaceRefArgs struct {
	WorkspaceID string `json:"workspace_id"`
	WorkDir     string `json:"work_dir"`
}

func (d *Deps) describeWorkspace() registration {
	return registration{
		desc: mcpserver.Tool{
			Name: "describe_workspace",
			Description: "Everything known about a capture: packet count, time range, encapsulation, " +
				"snaplen, SHA-256, and the tshark that read it. Free — it reads a cached " +
				"record and starts no container. Check `truncated` here before attempting " +
				"payload extraction.",
			InputSchema: json.RawMessage(workspaceRefSchema),
		},
		handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a workspaceRefArgs
			if err := decode(raw, &a); err != nil {
				return nil, err
			}
			ws, err := d.loadWorkspace(ctx, a.WorkspaceID, a.WorkDir)
			if err != nil {
				return nil, err
			}
			outputs, _ := listOutputs(ws.OutDir())
			return describePayload(ws, outputs), nil
		},
	}
}

const workspaceRefSchema = `{
  "type": "object",
  "properties": {
    "workspace_id": {"type": "string", "description": "From create_workspace."},
    "work_dir": {"type": "string", "description": "The same work_dir the workspace was created under."}
  },
  "required": ["workspace_id", "work_dir"],
  "additionalProperties": false
}`

// --- list_workspaces --------------------------------------------------------

type listWorkspacesArgs struct {
	WorkDir string `json:"work_dir"`
}

func (d *Deps) listWorkspaces() registration {
	return registration{
		desc: mcpserver.Tool{
			Name: "list_workspaces",
			Description: "List the captures already opened under a work_dir. Workspaces live " +
				"on disk, so this finds ones created in earlier sessions too.",
			InputSchema: json.RawMessage(`{
  "type": "object",
  "properties": {
    "work_dir": {"type": "string", "description": "Absolute host directory to scan."}
  },
  "required": ["work_dir"],
  "additionalProperties": false
}`),
		},
		handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a listWorkspacesArgs
			if err := decode(raw, &a); err != nil {
				return nil, err
			}
			workDir, err := d.resolveWorkDir(ctx, a.WorkDir)
			if err != nil {
				return nil, err
			}
			items, err := d.Workspace.List(workDir)
			if err != nil {
				return nil, err
			}
			return map[string]any{"workspaces": items, "count": len(items)}, nil
		},
	}
}

// --- delete_workspace -------------------------------------------------------

type deleteWorkspaceArgs struct {
	WorkspaceID string `json:"workspace_id"`
	WorkDir     string `json:"work_dir"`
	DryRun      bool   `json:"dry_run"`
}

func (d *Deps) deleteWorkspace() registration {
	return registration{
		desc: mcpserver.Tool{
			Name: "delete_workspace",
			Description: "Delete a workspace and its analysis output. The capture itself is never " +
				"touched — it was only ever mounted read-only. Pass dry_run to preview.",
			InputSchema: json.RawMessage(`{
  "type": "object",
  "properties": {
    "workspace_id": {"type": "string"},
    ` + workDirProp + `,
    "dry_run": {"type": "boolean", "description": "Report what would be removed without removing it."}
  },
  "required": ["workspace_id", "work_dir"],
  "additionalProperties": false
}`),
		},
		handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a deleteWorkspaceArgs
			if err := decode(raw, &a); err != nil {
				return nil, err
			}
			workDir, err := d.resolveWorkDir(ctx, a.WorkDir)
			if err != nil {
				return nil, err
			}
			if a.DryRun {
				p, err := d.Workspace.PreviewDelete(a.WorkspaceID, workDir)
				if err != nil {
					return nil, err
				}
				return map[string]any{"dry_run": true, "would_delete": p}, nil
			}
			p, err := d.Workspace.Delete(a.WorkspaceID, workDir)
			if err != nil {
				return nil, err
			}
			return map[string]any{"dry_run": false, "deleted": p}, nil
		},
	}
}

// --- describe_runtime -------------------------------------------------------

func (d *Deps) describeRuntime() registration {
	return registration{
		desc: mcpserver.Tool{
			Name: "describe_runtime",
			Description: "What the analysis container provides: tshark version, pinned base image, " +
				"available tools, and which protocols extract_objects supports.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
		},
		handler: func(ctx context.Context, _ json.RawMessage) (any, error) {
			m := runtime.Default()
			out := map[string]any{
				"manifest":         m,
				"configured_image": d.Cfg.Container.Image,
				"network":          d.Cfg.Container.Limits.Network,
			}
			// The manifest states what the image should be; the local image ID
			// says what is actually installed. Reporting both makes a stale
			// build visible instead of silently wrong.
			if id, err := d.Podman.ImageID(ctx, d.Cfg.Container.Image); err == nil {
				out["local_image_id"] = id
			} else {
				out["local_image_id_error"] = "image not found; run `pcap-analyzer-mcp build-runtime`"
			}
			return out, nil
		},
	}
}
