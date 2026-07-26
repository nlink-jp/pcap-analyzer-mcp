package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/mcpserver"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/output"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/toolerr"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/tshark"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/workspace"
)

// --- protocol_hierarchy -----------------------------------------------------

type hierarchyArgs struct {
	WorkspaceID  string `json:"workspace_id"`
	WorkspaceDir string `json:"workspace_dir"`
	Filter       string `json:"filter"`
}

func (d *Deps) protocolHierarchy() registration {
	return registration{
		desc: mcpserver.Tool{
			Name: "protocol_hierarchy",
			Description: "What protocols are present in the capture, as a tree with frame and byte " +
				"counts. The usual second call after describe_workspace: it answers " +
				"\"what am I looking at\" before you start filtering. Reads the whole capture.",
			InputSchema: json.RawMessage(`{
  "type": "object",
  "properties": {
    "workspace_id": {"type": "string"},
    "workspace_dir": {"type": "string"},
    "filter": {"type": "string", "description": "Optional Wireshark display filter to scope the statistics."}
  },
  "required": ["workspace_id", "workspace_dir"],
  "additionalProperties": false
}`),
		},
		handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a hierarchyArgs
			if err := decode(raw, &a); err != nil {
				return nil, err
			}
			ws, err := d.loadWorkspace(a.WorkspaceID, a.WorkspaceDir)
			if err != nil {
				return nil, err
			}
			res, err := d.Podman.RunOnce(ctx, d.runOpts(ws, tshark.HierarchyArgs(a.Filter)))
			if err != nil {
				return nil, toolerr.Newf(toolerr.CodeContainerFailed, "%v", err)
			}
			if res.ExitCode != 0 {
				return nil, tshark.ClassifyError(res.ExitCode, string(res.Stderr))
			}
			tree, err := tshark.ParseProtocolHierarchy(string(res.Stdout))
			if err != nil {
				return nil, toolerr.Newf(toolerr.CodeTsharkFailed, "%v", err)
			}
			return map[string]any{
				"workspace_id": ws.ID,
				"filter":       a.Filter,
				"hierarchy":    tree,
			}, nil
		},
	}
}

// --- list_conversations -----------------------------------------------------

type conversationArgs struct {
	WorkspaceID  string `json:"workspace_id"`
	WorkspaceDir string `json:"workspace_dir"`
	Transport    string `json:"transport"`
	Filter       string `json:"filter"`
	SortBy       string `json:"sort_by"`
	TopN         int    `json:"top_n"`
}

func (d *Deps) listConversations() registration {
	return registration{
		desc: mcpserver.Tool{
			Name: "list_conversations",
			Description: "Who talked to whom, with frame and byte counts per direction and — " +
				"crucially — the stream index follow_stream needs. Sorted by bytes by " +
				"default, so the head of the list is the top talkers. Reads the whole capture.",
			InputSchema: json.RawMessage(`{
  "type": "object",
  "properties": {
    "workspace_id": {"type": "string"},
    "workspace_dir": {"type": "string"},
    "transport": {"type": "string", "enum": ["tcp", "udp"], "description": "Default tcp."},
    "filter": {"type": "string", "description": "Optional display filter, ANDed with the transport."},
    "sort_by": {"type": "string", "enum": ["bytes", "frames", "start", "stream"], "description": "Default bytes."},
    "top_n": {"type": "integer", "description": "Keep only the first N after sorting. 0 or absent means all."}
  },
  "required": ["workspace_id", "workspace_dir"],
  "additionalProperties": false
}`),
		},
		handler: func(ctx context.Context, raw json.RawMessage) (any, error) {
			var a conversationArgs
			if err := decode(raw, &a); err != nil {
				return nil, err
			}
			if a.Transport == "" {
				a.Transport = "tcp"
			}
			if a.Transport != "tcp" && a.Transport != "udp" {
				return nil, toolerr.Newf(toolerr.CodeInvalidArguments,
					"transport must be tcp or udp, got %q", a.Transport)
			}
			ws, err := d.loadWorkspace(a.WorkspaceID, a.WorkspaceDir)
			if err != nil {
				return nil, err
			}

			agg := tshark.NewConversationAggregator(a.Transport)
			cmd := tshark.ConversationArgs(a.Transport, a.Filter)
			run, err := d.Podman.RunOnceStream(ctx, d.runOpts(ws, cmd), func(r io.Reader) error {
				return tshark.ParseFields(r, func(row tshark.Row) bool {
					agg.Add(row)
					return true
				})
			})
			if err != nil {
				return nil, toolerr.Newf(toolerr.CodeContainerFailed, "%v", err)
			}
			if run.ExitCode != 0 {
				return nil, tshark.ClassifyError(run.ExitCode, string(run.Stderr))
			}

			convs := agg.Result(a.SortBy, a.TopN)
			return map[string]any{
				"workspace_id":  ws.ID,
				"transport":     a.Transport,
				"filter":        a.Filter,
				"total":         agg.Len(),
				"returned":      len(convs),
				"truncated":     a.TopN > 0 && agg.Len() > len(convs),
				"conversations": convs,
			}, nil
		},
	}
}

// --- query_packets ----------------------------------------------------------

type queryArgs struct {
	WorkspaceID  string   `json:"workspace_id"`
	WorkspaceDir string   `json:"workspace_dir"`
	Filter       string   `json:"filter"`
	Fields       []string `json:"fields"`
	Limit        *int     `json:"limit"`
	Format       string   `json:"format"`
}

// defaultQueryFields is a usable starting set for someone who has not decided
// what to extract yet: enough to see who, when, and roughly what.
var defaultQueryFields = []string{
	"frame.number", "frame.time_epoch", "ip.src", "ip.dst",
	"_ws.col.Protocol", "frame.len", "_ws.col.Info",
}

func (d *Deps) queryPackets() registration {
	return registration{
		desc: mcpserver.Tool{
			Name: "query_packets",
			Description: "The workhorse: select packets with a Wireshark display filter and extract " +
				"named fields. Small results come back inline; large ones are written to " +
				"the workspace as JSONL and only a sample is returned. `matched` always " +
				"reports how many packets the filter hit, so you can tell \"too broad\" " +
				"from \"nothing there\". Set limit to 0 to export everything to a file.",
			InputSchema: json.RawMessage(`{
  "type": "object",
  "properties": {
    "workspace_id": {"type": "string"},
    "workspace_dir": {"type": "string"},
    "filter": {"type": "string", "description": "Wireshark display filter, e.g. \"tcp.flags.reset == 1 && ip.addr == 10.0.0.1\". Empty means every packet."},
    "fields": {"type": "array", "items": {"type": "string"}, "description": "Field names to extract, e.g. [\"frame.number\",\"ip.src\",\"http.host\"]. Defaults to a general-purpose set."},
    "limit": {"type": "integer", "description": "Maximum rows to return. Omit for the configured default; 0 means unlimited and always writes a file."},
    "format": {"type": "string", "enum": ["jsonl", "csv"], "description": "Encoding of the output file. Default jsonl."}
  },
  "required": ["workspace_id", "workspace_dir"],
  "additionalProperties": false
}`),
		},
		handler: d.handleQueryPackets,
	}
}

func (d *Deps) handleQueryPackets(ctx context.Context, raw json.RawMessage) (any, error) {
	var a queryArgs
	if err := decode(raw, &a); err != nil {
		return nil, err
	}
	if a.Format != "" && a.Format != "jsonl" && a.Format != "csv" {
		return nil, toolerr.Newf(toolerr.CodeInvalidArguments,
			"format must be jsonl or csv, got %q", a.Format)
	}
	fields := a.Fields
	if len(fields) == 0 {
		fields = defaultQueryFields
	}
	limit := d.Cfg.Output.DefaultRowLimit
	if a.Limit != nil {
		limit = *a.Limit
	}

	ws, err := d.loadWorkspace(a.WorkspaceID, a.WorkspaceDir)
	if err != nil {
		return nil, err
	}

	w := output.NewWriter(ws.OutDir(), nextResultName(ws.OutDir(), "query"), fields, output.Options{
		InlineMaxBytes: d.Cfg.Output.InlineMaxBytes,
		RowLimit:       limit,
		SampleRows:     d.Cfg.Output.SampleRows,
		Format:         a.Format,
	})

	var addErr error
	cmd := tshark.QueryArgs(a.Filter, fields)
	run, err := d.Podman.RunOnceStream(ctx, d.runOpts(ws, cmd), func(r io.Reader) error {
		return tshark.ParseFields(r, func(row tshark.Row) bool {
			ok, err := w.Add(map[string]string(row))
			if err != nil {
				addErr = err
				return false
			}
			return ok
		})
	})
	if addErr != nil {
		return nil, toolerr.Newf(toolerr.CodeInvalidArguments, "%v", addErr)
	}
	if err != nil {
		return nil, toolerr.Newf(toolerr.CodeContainerFailed, "%v", err)
	}
	// Reaching the row limit kills the container on purpose, so its exit
	// status says nothing about tshark.
	if !run.Stopped && run.ExitCode != 0 {
		return nil, tshark.ClassifyError(run.ExitCode, string(run.Stderr))
	}

	res, err := w.Finish(ws.ID, a.Filter)
	if err != nil {
		return nil, toolerr.Newf(toolerr.CodeInvalidArguments, "%v", err)
	}

	// Only pay for the counting pass when the answer was cut short — knowing
	// the true total is exactly what the agent needs then, and nothing it
	// needs otherwise.
	if res.Truncated {
		if n, err := d.countMatches(ctx, ws, a.Filter); err == nil {
			output.SetMatched(&res, n)
		} else {
			output.SetMatchedUnavailable(&res, err.Error())
		}
	} else {
		output.SetMatched(&res, int64(res.Returned))
	}
	return res, nil
}

// countMatches runs the second pass that answers "how many packets actually
// matched". frame.number is the cheapest field to ask for and the count is the
// number of lines.
func (d *Deps) countMatches(ctx context.Context, ws *workspace.Workspace, filter string) (int64, error) {
	var n int64
	run, err := d.Podman.RunOnceStream(ctx,
		d.runOpts(ws, tshark.CountArgs(filter)),
		func(r io.Reader) error {
			return tshark.ParseFields(r, func(tshark.Row) bool {
				n++
				return true
			})
		})
	if err != nil {
		return 0, fmt.Errorf("count pass failed: %w", err)
	}
	if run.ExitCode != 0 {
		return 0, fmt.Errorf("count pass exited %d: %s",
			run.ExitCode, strings.TrimSpace(string(run.Stderr)))
	}
	return n, nil
}

// nextResultName picks an unused basename so results accumulate rather than
// overwrite each other.
func nextResultName(outDir, prefix string) string {
	for i := 1; ; i++ {
		name := fmt.Sprintf("%s-%03d", prefix, i)
		if _, err := os.Stat(filepath.Join(outDir, name+".jsonl")); os.IsNotExist(err) {
			if _, err := os.Stat(filepath.Join(outDir, name+".csv")); os.IsNotExist(err) {
				return name
			}
		}
		if i > 9999 {
			return fmt.Sprintf("%s-overflow", prefix)
		}
	}
}

// listOutputs enumerates the result files a workspace has accumulated.
func listOutputs(outDir string) ([]map[string]any, error) {
	entries, err := os.ReadDir(outDir)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, map[string]any{
			"path":  filepath.Join(outDir, e.Name()),
			"bytes": info.Size(),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i]["path"].(string) < out[j]["path"].(string)
	})
	return out, nil
}
