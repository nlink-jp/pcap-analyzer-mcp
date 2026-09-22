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
func describePayload(ws *workspace.Workspace, outputs []map[string]any) map[string]any {
	meta := ws.Meta
	payload := map[string]any{
		"workspace_id": ws.ID,
		// work_dir is echoed because a caller whose runtime supplied it
		// through the request _meta (ADR-0008 §6) learns the destination from
		// the result and nowhere else.
		"work_dir":   ws.Root,
		"workspace":  ws.Dir,
		"capture":    meta.Capture,
		"info":       meta.Info,
		"runtime":    meta.Runtime,
		"created_at": meta.CreatedAt,
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

// Instructions is the initialize-time hint (the MCP `instructions` field): the
// first text a client's model reads about this server, before any tool list.
// It states the work-directory contract (organization ADR-021, project
// ADR-0008) and points at get_usage for everything else. Every tool it names
// must be registered, and its list of tools without work_dir must match the
// schemas — instructions_test.go checks both against the registered tools.
const Instructions = "pcap-analyzer-mcp analyses pcap and pcapng captures with tshark in a container; " +
	"the capture is mounted read-only and never copied. " +
	"Every tool except " + toolsWithoutWorkDir + " requires work_dir: the absolute path of a " +
	"directory you can read back (your session or working directory), and there is no default. " +
	"create_workspace opens a capture as the workspace <work_dir>/<workspace_id>/, and every file " +
	"the tools write lands under it: extract_objects returns the paths of the files it recovers " +
	"there, while analysis results come back in the response itself. " +
	"Heavy tools accept async: true for a large capture and return a job_id at once, which you poll " +
	"with check_job. " +
	"Call get_usage before your first analysis to learn the workspace model, the bounds every result " +
	"is held to, and the error recovery table."

// toolsWithoutWorkDir names, in Instructions, the registered tools whose
// schema declares no work_dir. It is a separate constant so the test can hold
// the claim to the schemas in both directions: a tool added without work_dir,
// or one of these gaining it, fails the build instead of leaving the model
// told something untrue.
const toolsWithoutWorkDir = "get_usage, describe_runtime and check_job"

func (d *Deps) getUsage() registration {
	return registration{
		desc: mcpserver.Tool{
			Name: "get_usage",
			Description: "How this server works: the workspace model, the shape every result takes, " +
				"and what to do when something fails. Worth reading before the first analysis.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
		},
		handler: func(_ context.Context, _ json.RawMessage) (any, error) {
			return usageDoc(d.Cfg.Output.MaxBytes, d.Cfg.Output.DefaultRowLimit), nil
		},
	}
}

func usageDoc(maxBytes, defaultRowLimit int) map[string]any {
	return map[string]any{
		"model": []string{
			"A workspace binds one capture to one directory. create_workspace opens a " +
				"capture and reads it once; everything after that refers to the workspace_id.",
			"Every tool except " + toolsWithoutWorkDir + " names work_dir: the absolute path of a directory you can read back, " +
				"usually your session or working directory. The workspace is " +
				"<work_dir>/<workspace_id>/ and every file this server writes lands under it. " +
				"It is required and has no default, and the pair (work_dir, workspace_id) is " +
				"a workspace's whole address — this server keeps nothing across restarts.",
			"pcap_path may be anywhere you can read, and the capture is not copied. The only " +
				"refused locations are the credential and agent-control places under your home " +
				"(~/.ssh, ~/.aws and the rest of the list gem-agent and lagent use), wherever a " +
				"link directly inside one of those directories points, and any .env file except " +
				"its templates — found under any spelling: another case, a link, the path as " +
				"given or resolved — and refused whether or not a file is there, with the same " +
				"answer either way.",
			"The capture is mounted read-only into a network-less container and is never " +
				"copied or modified. Deleting a workspace never deletes the capture.",
			"Workspaces live on disk, so list_workspaces finds ones from earlier sessions.",
		},
		"suggested_flow": []string{
			"1. create_workspace(pcap_path, work_dir)",
			"2. describe_workspace — free; check packet_count, the time range, and truncated",
			"3. protocol_hierarchy — what protocols are in here",
			"4. list_conversations — who talked to whom, and the stream indices",
			"5. query_packets — narrow down with a display filter",
			"6. follow_stream — the actual bytes of one conversation, by stream index",
			"7. extract_objects — recover the files a capture carried",
		},
		"async": []string{
			"create_workspace, protocol_hierarchy, list_conversations, query_packets and " +
				"extract_objects accept async: true. They return a job_id immediately; " +
				"poll check_job. follow_stream does not: it touches one stream.",
			"Use it when the capture is large — a full pass takes minutes and a synchronous " +
				"call would hit your request timeout. describe_workspace reports packet_count " +
				"and file_size, which is what to decide on.",
			"Arguments are still validated before the job is created, so a mistake fails " +
				"immediately rather than as a failed job.",
			"A finished job returns exactly what the synchronous call would have returned.",
		},
		"result_contract": map[string]any{
			"shape": "Every result-returning tool answers with the same keys, whether or not " +
				"the bounds bit. Branch on `truncated`, never on which keys happen to be present.",
			"matched": "The number of packets the filter selected, always reported. Compare it " +
				"with `returned`: if matched is far larger, narrow the filter rather than " +
				"raising the limit. matched == 0 means the filter genuinely found nothing.",
			"bounds": "Rows come back in the response, bounded by `limit` (rows) and by a byte " +
				"budget. What the bounds leave out is reported as `truncated` + `omitted_rows`, " +
				"with a `note` naming the bound that stopped it. Nothing is written to a file " +
				"this server chose: it cannot know your context window, and a runtime that " +
				"needs a large response on disk already puts it there.",
			"max_bytes":         maxBytes,
			"default_row_limit": defaultRowLimit,
			"getting_more":      "Narrow the filter, ask for fewer fields, or raise limit if your context can hold it. matched stays exact either way.",
			"timestamps":        "Epoch seconds plus a UTC ISO-8601 rendering. Never local time.",
		},
		"extracted_objects": map[string]any{
			"shape": "extract_objects answers with a manifest, not the result_contract shape: " +
				"`objects` for what was recovered and `skipped` for what was not. Read both — " +
				"an empty `objects` with a populated `skipped` is a successful call.",
			"skipped": "Each entry carries source_name, bytes and a reason. Over-size and " +
				"over-budget objects are dropped deliberately; an object that could not be " +
				"read is usually the host's antivirus quarantining a sample mid-write, which " +
				"makes the skip itself a finding rather than a fault. A per-object failure " +
				"never fails the call.",
			"bytes": "Objects are stored as <sha256>.bin, mode 0600, no executable bit, and " +
				"never returned inline. The hash alone usually pivots to threat intelligence.",
		},
		"errors": map[string]any{
			"invalid_display_filter": "tshark's own message is in details.tshark_message, usually " +
				"with the expression and the column it objected to. Fix and retry.",
			"invalid_arguments":   "For a bad field name, details.invalid_fields lists exactly which ones.",
			"workspace_not_found": "Check work_dir; list_workspaces shows what is there.",
			"pcap_unreadable":     "The path does not resolve or cannot be read.",
			"path_not_allowed": "The capture resolves into a location no tool argument may " +
				"point at — a credential or agent-control directory. There is no operator " +
				"allowlist to widen; move or copy the capture somewhere ordinary.",
			"work_dir_required": "No work_dir argument, and your runtime attached no hint. " +
				"Pass the absolute path of a directory you can read back.",
			"work_dir_invalid":      "Not absolute, started with ~, or contained `..`.",
			"work_dir_not_found":    "The directory is not there, or is not a directory. It is yours, so this is a typo — this server does not create it.",
			"work_dir_not_writable": "This server cannot write there.",
			"work_dir_denied":       "A system location, your home directory itself, a credential or agent-control location (or where a link directly inside one points), one of this server's own config directories (~/.config/pcap-analyzer-mcp, or the directory holding the config file in use) — under any spelling — or the home directory cannot be determined, for work_dir and for the workspace directory <work_dir>/<workspace_id> it would use. details.reason says which: system_dir, home_dir, sensitive_path, server_dir, home_unknown, unconfigured, unresolvable_path.",
			"container_failed":      "podman could not run. `pcap-analyzer-mcp doctor` diagnoses this.",
			"payload_unavailable_truncated_capture": "The capture has no payload to extract. " +
				"This is a property of the evidence; retrying will not change it. Note that a " +
				"snaplen small enough to cut the transport header also empties " +
				"list_conversations, because the stream index lives there; query_packets " +
				"still reports addresses and ports.",
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
