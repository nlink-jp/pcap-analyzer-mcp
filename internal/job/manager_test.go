package job

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/toolerr"
)

func waitFor(t *testing.T, m *Manager, id string, want string) Status {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		st, err := m.Get(id)
		if err != nil {
			t.Fatal(err)
		}
		if st.State == want {
			return st
		}
		time.Sleep(2 * time.Millisecond)
	}
	st, _ := m.Get(id)
	t.Fatalf("job never reached %q (stuck in %q)", want, st.State)
	return Status{}
}

func TestSubmitReturnsImmediatelyAndCompletes(t *testing.T) {
	m := NewManager(2)
	release := make(chan struct{})

	id := m.Submit(context.Background(), "query_packets",
		func(context.Context, func(Progress)) (any, error) {
			<-release
			return map[string]string{"ok": "yes"}, nil
		})

	if id == "" || !strings.HasPrefix(id, "job_") {
		t.Fatalf("job id = %q", id)
	}
	st, err := m.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if st.State == StateDone {
		t.Error("Submit must not block until the work finishes")
	}
	if st.Tool != "query_packets" {
		t.Errorf("Tool = %q", st.Tool)
	}

	close(release)
	done := waitFor(t, m, id, StateDone)
	res, _ := done.Result.(map[string]string)
	if res["ok"] != "yes" {
		t.Errorf("Result = %v", done.Result)
	}
	if done.FinishedAt == "" {
		t.Error("a finished job should report when it finished")
	}
}

// A structured failure must reach the agent with its code intact, so the same
// branching works whether the tool ran synchronously or as a job.
func TestFailedJobKeepsTheStructuredCode(t *testing.T) {
	m := NewManager(1)
	id := m.Submit(context.Background(), "query_packets",
		func(context.Context, func(Progress)) (any, error) {
			return nil, toolerr.New(toolerr.CodeInvalidDisplayFilter, "bad filter")
		})

	st := waitFor(t, m, id, StateFailed)
	if st.Error == nil || st.Error.Code != toolerr.CodeInvalidDisplayFilter {
		t.Fatalf("Error = %+v", st.Error)
	}
}

func TestPlainErrorGetsTheFallbackCode(t *testing.T) {
	m := NewManager(1)
	id := m.Submit(context.Background(), "x",
		func(context.Context, func(Progress)) (any, error) {
			return nil, errors.New("disk exploded")
		})

	st := waitFor(t, m, id, StateFailed)
	if st.Error == nil || st.Error.Code != toolerr.CodeAnalysisFailed {
		t.Fatalf("Error = %+v", st.Error)
	}
}

func TestProgressIsVisibleWhileRunning(t *testing.T) {
	m := NewManager(1)
	reported := make(chan struct{})
	release := make(chan struct{})

	id := m.Submit(context.Background(), "x",
		func(_ context.Context, report func(Progress)) (any, error) {
			report(Progress{Phase: "reading", Rows: 40000})
			close(reported)
			<-release
			return "done", nil
		})

	<-reported
	st, err := m.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if st.Progress.Rows != 40000 || st.Progress.Phase != "reading" {
		t.Errorf("Progress = %+v", st.Progress)
	}
	close(release)
	waitFor(t, m, id, StateDone)
}

// Each job is one podman container, so the cap is what keeps a burst of
// requests from saturating the host.
func TestConcurrencyIsCapped(t *testing.T) {
	m := NewManager(2)
	var running, peak int32
	var mu sync.Mutex
	release := make(chan struct{})

	var ids []string
	for i := 0; i < 6; i++ {
		ids = append(ids, m.Submit(context.Background(), "x",
			func(context.Context, func(Progress)) (any, error) {
				n := atomic.AddInt32(&running, 1)
				mu.Lock()
				if n > peak {
					peak = n
				}
				mu.Unlock()
				<-release
				atomic.AddInt32(&running, -1)
				return nil, nil
			}))
	}

	// Give the goroutines time to pile up against the cap.
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	got := peak
	mu.Unlock()
	if got > 2 {
		t.Errorf("%d jobs ran at once with a cap of 2", got)
	}

	close(release)
	for _, id := range ids {
		waitFor(t, m, id, StateDone)
	}
}

// A job waiting for a slot is queued, not running — the distinction tells the
// agent its work has not started rather than that it is slow.
func TestQueuedStateIsVisible(t *testing.T) {
	m := NewManager(1)
	release := make(chan struct{})

	first := m.Submit(context.Background(), "x",
		func(context.Context, func(Progress)) (any, error) {
			<-release
			return nil, nil
		})
	waitFor(t, m, first, StateRunning)

	second := m.Submit(context.Background(), "x",
		func(context.Context, func(Progress)) (any, error) { return nil, nil })

	st, err := m.Get(second)
	if err != nil {
		t.Fatal(err)
	}
	if st.State != StateQueued {
		t.Errorf("second job state = %q, want queued", st.State)
	}

	close(release)
	waitFor(t, m, second, StateDone)
}

// The recovery instruction matters more than the error itself: re-running is
// always safe because the capture is read-only.
func TestUnknownJobExplainsRecovery(t *testing.T) {
	m := NewManager(1)
	_, err := m.Get("job_deadbeef")
	if !errors.Is(err, toolerr.New(toolerr.CodeJobNotFound, "")) {
		t.Fatalf("want job_not_found, got %v", err)
	}
	if !strings.Contains(err.Error(), "Re-run the original tool") {
		t.Errorf("the error should say how to recover: %v", err)
	}
}

// A job submitted under an already-cancelled context must not sit queued
// forever.
func TestShutdownBeforeStart(t *testing.T) {
	m := NewManager(1)
	blocker := make(chan struct{})
	defer close(blocker)

	// Occupy the only slot.
	m.Submit(context.Background(), "x", func(context.Context, func(Progress)) (any, error) {
		<-blocker
		return nil, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	id := m.Submit(ctx, "x", func(context.Context, func(Progress)) (any, error) {
		t.Error("this job should never have started")
		return nil, nil
	})
	cancel()

	st := waitFor(t, m, id, StateFailed)
	if st.Error == nil || !strings.Contains(st.Error.Message, "shut down") {
		t.Errorf("Error = %+v", st.Error)
	}
}

func TestFinishedJobsAreEvicted(t *testing.T) {
	m := NewManager(4)
	var ids []string
	for i := 0; i < maxFinishedJobs+10; i++ {
		id := m.Submit(context.Background(), "x",
			func(context.Context, func(Progress)) (any, error) { return nil, nil })
		ids = append(ids, id)
		waitFor(t, m, id, StateDone)
	}
	// Submitting one more triggers eviction of the oldest finished jobs.
	last := m.Submit(context.Background(), "x",
		func(context.Context, func(Progress)) (any, error) { return nil, nil })
	waitFor(t, m, last, StateDone)

	if _, err := m.Get(ids[0]); err == nil {
		t.Error("the oldest finished job should have been evicted")
	}
	if _, err := m.Get(last); err != nil {
		t.Errorf("the newest job must survive: %v", err)
	}
}

func TestTimestampsAreUTC(t *testing.T) {
	m := NewManager(1)
	id := m.Submit(context.Background(), "x",
		func(context.Context, func(Progress)) (any, error) { return nil, nil })
	st := waitFor(t, m, id, StateDone)

	for _, ts := range []string{st.StartedAt, st.FinishedAt} {
		if !strings.HasSuffix(ts, "Z") {
			t.Errorf("timestamp %q is not UTC", ts)
		}
	}
}
