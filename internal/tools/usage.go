package tools

import (
	"context"
	"encoding/json"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/mcpserver"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/workspace"
)

// describePayload is the shape describe_workspace returns, and what
// create_workspace echoes back so a freshly created workspace needs no
// follow-up call.
func describePayload(id, dir string, meta *workspace.Meta, outputs []map[string]any) map[string]any {
	payload := map[string]any{
		"workspace_id": id,
		"workspace":    dir,
		"capture":      meta.Capture,
		"info":         meta.Info,
		"runtime":      meta.Runtime,
		"created_at":   meta.CreatedAt,
	}
	if outputs != nil {
		payload["outputs"] = outputs
	}
	// The truncation verdict decides whether payload extraction can work at
	// all, so it is restated at the top level rather than left for the agent
	// to find nested in info.
	payload["truncated"] = meta.Info.Truncated
	if meta.Info.Truncated {
		payload["payload_note"] = "This capture is truncated: packets were cut short when it was " +
			"recorded, so payload bytes are missing. follow_stream and extract_objects " +
			"will come up empty — that is the capture, not a transient failure."
	}
	return payload
}

func (d *Deps) getUsage() registration {
	return registration{
		desc: mcpserver.Tool{
			Name: "get_usage",
			Description: "How this server works: the workspace model, the shape every result takes, " +
				"and what to do when something fails. Worth reading before the first analysis.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
		},
		handler: func(_ context.Context, _ json.RawMessage) (any, error) {
			return usageDoc(d.Cfg.Output.InlineMaxBytes, d.Cfg.Output.DefaultRowLimit), nil
		},
	}
}

func usageDoc(inlineMaxBytes, defaultRowLimit int) map[string]any {
	return map[string]any{
		"model": []string{
			"A workspace binds one capture to one directory. create_workspace opens a " +
				"capture and reads it once; everything after that refers to the workspace_id.",
			"The capture is mounted read-only into a network-less container and is never " +
				"copied or modified. Deleting a workspace never deletes the capture.",
			"Workspaces live on disk, so list_workspaces finds ones from earlier sessions.",
		},
		"suggested_flow": []string{
			"1. create_workspace(pcap_path, workspace_dir)",
			"2. describe_workspace — free; check packet_count, the time range, and truncated",
			"3. protocol_hierarchy — what protocols are in here",
			"4. list_conversations — who talked to whom, and the stream indices",
			"5. query_packets — narrow down with a display filter",
		},
		"async": []string{
			"create_workspace, protocol_hierarchy, list_conversations and query_packets " +
				"accept async: true. They return a job_id immediately; poll check_job.",
			"Use it when the capture is large — a full pass takes minutes and a synchronous " +
				"call would hit your request timeout. describe_workspace reports packet_count " +
				"and file_size, which is what to decide on.",
			"Arguments are still validated before the job is created, so a mistake fails " +
				"immediately rather than as a failed job.",
			"A finished job returns exactly what the synchronous call would have returned.",
		},
		"result_contract": map[string]any{
			"shape": "Every result-returning tool answers with the same keys. `delivery` is " +
				"\"inline\" or \"file\"; nothing else changes between the two.",
			"matched": "The number of packets the filter selected, always reported. Compare it " +
				"with `returned`: if matched is far larger, narrow the filter rather than " +
				"raising the limit. matched == 0 means the filter genuinely found nothing.",
			"file_results": "Large results are written to the workspace as JSONL and `sample` " +
				"carries the leading rows, so you never need a second call just to see the " +
				"shape. Read the file in pieces, or hand it to a SQL tool — it is not meant " +
				"to be read whole.",
			"inline_max_bytes":  inlineMaxBytes,
			"default_row_limit": defaultRowLimit,
			"unlimited_export":  "limit: 0 returns everything as a file, whatever the size.",
			"timestamps":        "Epoch seconds plus a UTC ISO-8601 rendering. Never local time.",
		},
		"errors": map[string]any{
			"invalid_display_filter": "tshark's own message is in details.tshark_message, usually " +
				"with the expression and the column it objected to. Fix and retry.",
			"invalid_arguments":   "For a bad field name, details.invalid_fields lists exactly which ones.",
			"workspace_not_found": "Check workspace_dir; list_workspaces shows what is there.",
			"pcap_unreadable":     "The path does not resolve or cannot be read.",
			"path_not_allowed":    "allowed_paths is configured and the capture is outside it.",
			"container_failed":    "podman could not run. `pcap-analyzer-mcp doctor` diagnoses this.",
			"payload_unavailable_truncated_capture": "The capture has no payload to extract. " +
				"This is a property of the evidence; retrying will not change it.",
			"job_not_found": "Jobs live in memory and do not survive a server restart. " +
				"Re-run the original tool — the capture is read-only, so the result is the same.",
			"analysis_failed": "A background job failed without a more specific cause; " +
				"details carry what is known.",
		},
		"limits": []string{
			"Read-only analysis of capture files. This server cannot capture traffic — the " +
				"container has no network and no capture tool.",
			"One capture per workspace. To compare two captures, create two workspaces.",
		},
	}
}
