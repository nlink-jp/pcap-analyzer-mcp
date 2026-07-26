// Package job runs long analyses in the background and tracks them in memory.
//
// Jobs are deliberately not persisted. After a server restart check_job reports
// job_not_found, and the recovery is simply to call the tool again: every
// analysis reads the same read-only capture and is therefore idempotent.
package job

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/toolerr"
)

// Job states.
const (
	StateQueued  = "queued"
	StateRunning = "running"
	StateDone    = "done"
	StateFailed  = "failed"
)

// maxFinishedJobs bounds the finished-job history kept in memory.
const maxFinishedJobs = 32

// Progress is a coarse view of how far an analysis has advanced.
//
// There is no percentage here on purpose. tshark does not report how far
// through a capture it is, and a fabricated percentage would be worse than
// none: an agent that believes a number will wait on it. The phase and the row
// count are both things actually known.
type Progress struct {
	Phase string `json:"phase"`          // queued | reading | counting | done
	Rows  int    `json:"rows"`           // rows produced so far
	Note  string `json:"note,omitempty"` // free-text detail, when useful
}

// Status is the check_job view of a job.
type Status struct {
	JobID      string         `json:"job_id"`
	Tool       string         `json:"tool"`
	State      string         `json:"state"`
	Progress   Progress       `json:"progress"`
	Result     any            `json:"result,omitempty"`
	Error      *toolerr.Error `json:"error,omitempty"`
	StartedAt  string         `json:"started_at"`
	FinishedAt string         `json:"finished_at,omitempty"`
}

// RunFunc performs the work, reporting progress through report.
type RunFunc func(ctx context.Context, report func(Progress)) (any, error)

type jobState struct {
	id   string
	tool string

	mu         sync.Mutex
	state      string
	progress   Progress
	result     any
	err        *toolerr.Error
	startedAt  time.Time
	finishedAt time.Time
}

// Manager owns the in-memory job table and bounds how many analyses run at once.
type Manager struct {
	mu   sync.Mutex
	jobs map[string]*jobState

	// slots caps concurrent runs. Each job is one `podman run`, and letting
	// them multiply without limit would saturate the host — the cost of the
	// ephemeral-container model (ADR-0002).
	slots chan struct{}
}

// NewManager creates a job manager allowing maxConcurrent simultaneous runs.
func NewManager(maxConcurrent int) *Manager {
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	return &Manager{
		jobs:  make(map[string]*jobState),
		slots: make(chan struct{}, maxConcurrent),
	}
}

// Submit starts run in the background and returns a job id immediately.
//
// ctx must be the server-lifetime context, not the request context: the
// request's context is cancelled the moment the job id is returned, which
// would kill the work before it began (ADR-0006).
func (m *Manager) Submit(ctx context.Context, tool string, run RunFunc) string {
	id := "job_" + randomHex(8)
	js := &jobState{
		id:        id,
		tool:      tool,
		state:     StateQueued,
		progress:  Progress{Phase: StateQueued},
		startedAt: time.Now(),
	}

	m.mu.Lock()
	m.jobs[id] = js
	m.evictLocked()
	m.mu.Unlock()

	go func() {
		// Waiting for a slot happens inside the goroutine so Submit never
		// blocks the caller; the job simply stays "queued" until one frees.
		select {
		case m.slots <- struct{}{}:
		case <-ctx.Done():
			js.finish(nil, toolerr.New(toolerr.CodeAnalysisFailed, "server shut down before the job started"))
			return
		}
		defer func() { <-m.slots }()

		js.begin()
		res, err := run(ctx, js.report)
		js.finish(res, err)
	}()
	return id
}

func (js *jobState) begin() {
	js.mu.Lock()
	defer js.mu.Unlock()
	if js.state == StateQueued {
		js.state = StateRunning
		js.progress.Phase = "reading"
		js.startedAt = time.Now()
	}
}

func (js *jobState) report(p Progress) {
	js.mu.Lock()
	defer js.mu.Unlock()
	if js.state == StateRunning {
		js.progress = p
	}
}

func (js *jobState) finish(res any, err error) {
	js.mu.Lock()
	defer js.mu.Unlock()
	if js.state == StateDone || js.state == StateFailed {
		return
	}
	js.finishedAt = time.Now()
	if err != nil {
		js.state = StateFailed
		var te *toolerr.Error
		if errors.As(err, &te) {
			js.err = te
		} else {
			js.err = toolerr.New(toolerr.CodeAnalysisFailed, err.Error())
		}
		return
	}
	js.state = StateDone
	js.result = res
	js.progress.Phase = "done"
}

// Get returns the status of a job, or a job_not_found error carrying the
// recovery instruction.
func (m *Manager) Get(jobID string) (Status, error) {
	m.mu.Lock()
	js, ok := m.jobs[jobID]
	m.mu.Unlock()
	if !ok {
		return Status{}, toolerr.Newf(toolerr.CodeJobNotFound,
			"no job %q — jobs are in memory and do not survive a server restart. "+
				"Re-run the original tool: it reads the same read-only capture, so the "+
				"result is the same.", jobID)
	}

	js.mu.Lock()
	defer js.mu.Unlock()
	st := Status{
		JobID:     js.id,
		Tool:      js.tool,
		State:     js.state,
		Progress:  js.progress,
		Result:    js.result,
		Error:     js.err,
		StartedAt: js.startedAt.UTC().Format(time.RFC3339),
	}
	if !js.finishedAt.IsZero() {
		st.FinishedAt = js.finishedAt.UTC().Format(time.RFC3339)
	}
	return st, nil
}

// evictLocked drops the oldest finished jobs beyond maxFinishedJobs.
// Caller holds m.mu.
func (m *Manager) evictLocked() {
	type fin struct {
		id string
		at time.Time
	}
	var finished []fin
	for id, js := range m.jobs {
		js.mu.Lock()
		if js.state == StateDone || js.state == StateFailed {
			finished = append(finished, fin{id, js.finishedAt})
		}
		js.mu.Unlock()
	}
	if len(finished) <= maxFinishedJobs {
		return
	}
	sort.Slice(finished, func(i, j int) bool { return finished[i].at.Before(finished[j].at) })
	for _, f := range finished[:len(finished)-maxFinishedJobs] {
		delete(m.jobs, f.id)
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is unrecoverable in practice; a time-based
		// fallback keeps ids unique enough for an in-memory table.
		return hex.EncodeToString([]byte(time.Now().Format("150405.000000000")))[:2*n]
	}
	return hex.EncodeToString(b)
}
