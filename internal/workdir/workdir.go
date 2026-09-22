// Package workdir resolves the directory one MCP call writes into — the
// caller's work directory, not this server's — and says which paths a call
// may never name.
//
// The value is per session and per calling runtime, so the server cannot know
// it; only the caller can. Of the channels a runtime could use, the per-call
// argument is the only one all four of our callers have: MCP roots come back
// empty from Codex and carry only the project directory from Claude Code, and
// Codex strips the environment before spawning a server, so a `${...}`
// expansion in a registration entry never arrives. The `_meta` key is the
// second channel, for the runtimes we write ourselves: they can set it on
// every tools/call without knowing any tool's schema.
//
// There is deliberately no third. A server-chosen default is readable by the
// caller only by coincidence, and when it is not, the call still succeeds and
// returns a path to a file the caller cannot open.
//
// The judgement itself — which directories may be a work directory, which
// paths are credential or agent-control locations, compared by file identity
// and by folded name — is nlink-jp/pathguard's, and there is no copy of it
// here. This package is the adapter: it takes the request's `_meta` from the
// context and carries the module's errors onto toolerr.
//
// Organization ADR-021; project ADR-0008, ADR-0010.
package workdir

import (
	"context"
	"errors"

	"github.com/nlink-jp/pathguard"
	pgwd "github.com/nlink-jp/pathguard/workdir"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/mcpserver"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/toolerr"
)

// MetaKey is the request-level `_meta` key a runtime sets on every tools/call
// to name the session work directory.
const MetaKey = pgwd.MetaKey

// requiredHint is this server's sentence for work_dir_required: why the
// directory has to be one the caller can read back.
const requiredHint = "Results come back as paths, and a path you cannot open is worth nothing."

// Resolver resolves and validates work directories. Only NewResolver builds a
// working one; the zero Resolver refuses every call.
type Resolver struct {
	r pgwd.Resolver
}

// NewResolver builds the resolver. serverDirs are this server's own config
// and state directories, which may never be a work directory; an empty one
// refuses every call rather than protecting nothing.
func NewResolver(serverDirs ...string) Resolver {
	var protected []pathguard.Place
	for _, d := range serverDirs {
		protected = append(protected, pathguard.ServerDir(d, ""))
	}
	return Resolver{r: pgwd.NewResolver(pgwd.Options{
		Protected:    protected,
		RequiredHint: requiredHint,
	})}
}

// Resolve returns the validated work directory for one call: the tool's
// work_dir argument, else the runtime hint in the request's `_meta`, else an
// error. The returned path is absolute and symlink-resolved.
func (r Resolver) Resolve(ctx context.Context, arg string) (string, error) {
	dir, err := r.r.Resolve(arg, mcpserver.RequestMeta(ctx))
	return dir, toolErr(err)
}

// Validate applies the closed list of checks and returns the resolved path.
func (r Resolver) Validate(dir string) (string, error) {
	resolved, err := r.r.Validate(dir)
	return resolved, toolErr(err)
}

// Sensitive reports why a path may not be read on a caller's say-so, or ""
// when it may be. Callers own the error code, since what an unreadable path
// means differs per tool. Pass every spelling you have — as the caller gave
// it, and symlink-resolved. An unknown home directory refuses.
func Sensitive(paths ...string) string { return pgwd.Sensitive(paths...) }

// CheckBeneath reports why dir — <work_dir>/<workspace_id>, the directory a
// call actually uses, which may not exist yet — may not be used, as a
// work_dir_denied toolerr, or nil. The workspace manager calls it before it
// creates, mounts or deletes a workspace.
func (r Resolver) CheckBeneath(dir string) error { return toolErr(r.r.CheckBeneath(dir)) }

// toolErr carries a pathguard refusal onto toolerr with the same code,
// message and details; any other error passes through.
func toolErr(err error) error {
	if err == nil {
		return nil
	}
	var e *pgwd.Error
	if !errors.As(err, &e) {
		return err
	}
	te := toolerr.New(e.Code, e.Message)
	if e.Details != nil {
		te = te.WithDetails(e.Details)
	}
	return te
}
