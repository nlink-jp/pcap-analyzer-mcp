package tools

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/job"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/toolerr"
)

// Only the tools that read the whole capture take async (ADR-0006); offering
// it on a cached lookup would be noise.
func TestAsyncIsOfferedExactlyWhereItShouldBe(t *testing.T) {
	want := map[string]bool{
		"create_workspace":   true,
		"protocol_hierarchy": true,
		"list_conversations": true,
		"query_packets":      true,
	}
	for _, r := range newDeps(&fakeRunner{}).all() {
		var schema struct {
			Properties map[string]any `json:"properties"`
		}
		if err := json.Unmarshal(r.desc.InputSchema, &schema); err != nil {
			t.Fatal(err)
		}
		_, has := schema.Properties["async"]
		if has != want[r.desc.Name] {
			t.Errorf("%s: async offered = %v, want %v", r.desc.Name, has, want[r.desc.Name])
		}
	}
}

// An async call must still fail immediately on a bad argument. Returning a job
// id for work that cannot possibly succeed wastes a poll cycle and hides the
// mistake.
func TestAsyncStillValidatesSynchronously(t *testing.T) {
	d := newDeps(&fakeRunner{})
	_, err := call(t, d, "query_packets", map[string]any{
		"workspace_id":  "absent-00000000",
		"workspace_dir": t.TempDir(),
		"async":         true,
	})
	if !errors.Is(err, toolerr.New(toolerr.CodeWorkspaceNotFound, "")) {
		t.Fatalf("want workspace_not_found up front, got %v", err)
	}
}

func TestAsyncFormatValidationIsSynchronous(t *testing.T) {
	d := newDeps(&fakeRunner{})
	_, err := call(t, d, "query_packets", map[string]any{
		"workspace_id": "x-00000000", "workspace_dir": t.TempDir(),
		"format": "parquet", "async": true,
	})
	if !errors.Is(err, toolerr.New(toolerr.CodeInvalidArguments, "")) {
		t.Errorf("want invalid_arguments before any job is created, got %v", err)
	}
}

// dispatch runs inline when async is false, and the caller sees the work's own
// return value rather than a job envelope.
func TestDispatchSynchronousPath(t *testing.T) {
	d := newDeps(&fakeRunner{})
	out, err := d.dispatch(context.Background(), false, "x",
		func(_ context.Context, _ func(job.Progress)) (any, error) { return "direct", nil })
	if err != nil {
		t.Fatal(err)
	}
	if out != "direct" {
		t.Errorf("got %v", out)
	}
}

func TestDispatchAsyncReturnsAPollableEnvelope(t *testing.T) {
	d := newDeps(&fakeRunner{})
	done := make(chan struct{})

	out, err := d.dispatch(context.Background(), true, "query_packets",
		func(_ context.Context, _ func(job.Progress)) (any, error) {
			close(done)
			return map[string]string{"answer": "42"}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	env := out.(map[string]any)
	id, _ := env["job_id"].(string)
	if !strings.HasPrefix(id, "job_") {
		t.Fatalf("job_id = %v", env["job_id"])
	}
	if env["poll_with"] != "check_job" {
		t.Errorf("the envelope must say how to poll: %v", env)
	}

	<-done
	st := pollUntilDone(t, d, id)
	res, _ := st.Result.(map[string]string)
	if res["answer"] != "42" {
		t.Errorf("the finished result must be what the sync call would have returned: %v", st.Result)
	}
}

// The work must survive the request that started it: it runs under the server
// context, not the request's, which is cancelled as soon as the id is returned.
func TestJobOutlivesTheRequestContext(t *testing.T) {
	d := newDeps(&fakeRunner{})
	reqCtx, cancel := context.WithCancel(context.Background())

	started := make(chan struct{})
	out, err := d.dispatch(reqCtx, true, "x",
		func(runCtx context.Context, _ func(job.Progress)) (any, error) {
			close(started)
			<-time.After(30 * time.Millisecond)
			// If the request context had been inherited, this would be done.
			if runCtx.Err() != nil {
				return nil, errors.New("job inherited the request context")
			}
			return "survived", nil
		})
	if err != nil {
		t.Fatal(err)
	}
	<-started
	cancel() // the request returns and its context is cancelled

	id := out.(map[string]any)["job_id"].(string)
	st := pollUntilDone(t, d, id)
	if st.State != job.StateDone {
		t.Fatalf("state = %s, error = %+v", st.State, st.Error)
	}
	if st.Result != "survived" {
		t.Errorf("Result = %v", st.Result)
	}
}

func TestCheckJobUnknownID(t *testing.T) {
	d := newDeps(&fakeRunner{})
	_, err := call(t, d, "check_job", map[string]any{"job_id": "job_nope"})
	if !errors.Is(err, toolerr.New(toolerr.CodeJobNotFound, "")) {
		t.Errorf("want job_not_found, got %v", err)
	}
}

func pollUntilDone(t *testing.T, d *Deps, id string) job.Status {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		st, err := d.Jobs.Get(id)
		if err != nil {
			t.Fatal(err)
		}
		if st.State == job.StateDone || st.State == job.StateFailed {
			return st
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("job did not finish")
	return job.Status{}
}
