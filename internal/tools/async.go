package tools

import (
	"context"
	"encoding/json"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/job"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/mcpserver"
)

// asyncField is the shared schema fragment for the async option. Only the
// tools that read the whole capture offer it (ADR-0006).
const asyncField = `"async": {"type": "boolean", "description": "Run in the background and return a job_id immediately. Use for large captures: a full pass takes minutes and would otherwise hit your request timeout. Poll with check_job."}`

// dispatch runs work synchronously, or hands it to the job manager when the
// caller asked for async.
//
// Everything that can be checked up front — arguments, the workspace, the
// output directory — has already been checked by the time this is reached, so
// an async call still fails immediately on a mistake instead of returning a
// job id that is doomed (ADR-0006).
func (d *Deps) dispatch(ctx context.Context, async bool, tool string, work job.RunFunc) (any, error) {
	if !async {
		return work(ctx, func(job.Progress) {})
	}
	// The job outlives this request, so it must not inherit the request's
	// context — that is cancelled the moment the job id is returned.
	id, err := d.Jobs.Submit(d.ServerCtx, tool, work)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"job_id":    id,
		"state":     job.StateQueued,
		"tool":      tool,
		"poll_with": "check_job",
		"note": "Running in the background. Call check_job with this job_id; " +
			"the finished result is identical to the synchronous one.",
	}, nil
}

// --- check_job --------------------------------------------------------------

type checkJobArgs struct {
	JobID string `json:"job_id"`
}

func (d *Deps) checkJob() registration {
	return registration{
		desc: mcpserver.Tool{
			Name: "check_job",
			Description: "Progress and result of a background analysis started with async. " +
				"While it runs you get a phase and the row count so far; when it finishes " +
				"you get exactly the result the synchronous call would have returned. " +
				"job_not_found means the server restarted — just re-run the original tool.",
			InputSchema: json.RawMessage(`{
  "type": "object",
  "properties": {
    "job_id": {"type": "string", "description": "From the tool call that started the job."}
  },
  "required": ["job_id"],
  "additionalProperties": false
}`),
		},
		handler: func(_ context.Context, raw json.RawMessage) (any, error) {
			var a checkJobArgs
			if err := decode(raw, &a); err != nil {
				return nil, err
			}
			st, err := d.Jobs.Get(a.JobID)
			if err != nil {
				return nil, err
			}
			return st, nil
		},
	}
}
