// Package workdir resolves the directory one MCP call writes into — the
// caller's work directory, not this server's — and holds the blacklist of
// locations a caller may never point a tool at.
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
// Organization ADR-021; project ADR-0008.
package workdir

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/mcpserver"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/toolerr"
)

// MetaKey is the request-level `_meta` key a runtime sets on every tools/call
// to name the session work directory.
const MetaKey = "jp.nlink/work_dir"

// Access mode bits for syscall.Access. Creating a workspace under the work
// directory needs both: write to add an entry, execute to traverse it.
const (
	wOK = 0x02
	xOK = 0x01
)

// deniedTrees are locations a work directory may never be, together with
// everything under them: this server would be writing there on behalf of a
// model that named them, with the operator's privileges. Paths are in resolved
// form (/etc and /var are symlinks on darwin).
var deniedTrees = []string{
	"/bin",
	"/sbin",
	"/usr",
	"/System",
	"/Library",
	"/Applications",
	"/private/etc",
}

// deniedExact are denied as the work directory itself but not as ancestors.
// /private/var holds the per-user temporary directory (/var/folders/...),
// which is a legitimate place for a caller to work in.
var deniedExact = []string{
	"/",
	"/private/var",
}

// sensitiveHomeTrees are the input blacklist: locations that hold credentials
// or steer an agent, which no tool argument may point at however the caller
// asks (ADR-0008 §4). They are relative to the home directory.
//
// This list is a floor, not a boundary. The next secret file is not on it.
// Bounding what this process may touch at all is a sandboxing MCP proxy's job.
// It lives in code rather than config on purpose: a knob here would recreate
// the hand-maintained model of the calling runtimes that ADR-0008 removed.
var sensitiveHomeTrees = []string{
	".ssh",
	".aws",
	".gnupg",
	".config/gcloud",
	".config/gem-agent",
	".config/lagent",
	".claude",
	".codex",
	"Library/Keychains",
}

// Resolver resolves and validates work directories. The zero value is usable;
// Denied adds server-specific trees to the built-in list.
type Resolver struct {
	// Denied are extra absolute paths (and their subtrees) this server
	// refuses to treat as a work directory — its own data directory,
	// typically.
	Denied []string
}

// Resolve returns the validated work directory for one call: the tool's
// work_dir argument, else the runtime hint in the request's `_meta`, else an
// error. The returned path is absolute and symlink-resolved.
func (r Resolver) Resolve(ctx context.Context, arg string) (string, error) {
	dir := strings.TrimSpace(arg)
	if dir == "" {
		hint, err := metaHint(ctx)
		if err != nil {
			return "", err
		}
		dir = hint
	}
	if dir == "" {
		return "", toolerr.New(toolerr.CodeWorkDirRequired,
			"work_dir is required: pass the absolute path of a directory you can read back "+
				"(your session or working directory). Results come back as paths, and a path you cannot open is worth nothing.")
	}
	return r.Validate(dir)
}

// Validate applies the closed list of checks and returns the resolved path.
func (r Resolver) Validate(dir string) (string, error) {
	if strings.HasPrefix(dir, "~") {
		return "", toolerr.Newf(toolerr.CodeWorkDirInvalid,
			"work_dir %q starts with ~: nothing expands it on this path — pass the absolute path", dir)
	}
	if !filepath.IsAbs(dir) {
		return "", toolerr.Newf(toolerr.CodeWorkDirInvalid,
			"work_dir %q must be an absolute path", dir)
	}
	if hasParentSegment(dir) {
		return "", toolerr.Newf(toolerr.CodeWorkDirInvalid,
			"work_dir %q contains a .. segment; pass the path you mean", dir)
	}

	resolved, err := filepath.EvalSymlinks(filepath.Clean(dir))
	if err != nil {
		return "", toolerr.Newf(toolerr.CodeWorkDirNotFound,
			"work_dir %q does not exist — it is your directory, so this is a typo, not something to create here", dir)
	}
	fi, err := os.Stat(resolved)
	if err != nil {
		return "", toolerr.Newf(toolerr.CodeWorkDirNotFound, "work_dir %q: %v", dir, err)
	}
	if !fi.IsDir() {
		return "", toolerr.Newf(toolerr.CodeWorkDirNotFound, "work_dir %q is not a directory", dir)
	}

	if why := r.denied(dir, resolved); why != "" {
		return "", toolerr.Newf(toolerr.CodeWorkDirDenied, "work_dir %q is refused: %s", dir, why).
			WithDetails(map[string]any{"work_dir": dir, "resolved": resolved})
	}
	if err := syscall.Access(resolved, wOK|xOK); err != nil {
		return "", toolerr.Newf(toolerr.CodeWorkDirNotWritable,
			"work_dir %q is not writable by this server", dir)
	}
	return resolved, nil
}

// Sensitive reports why a path may not be read on a caller's say-so, or ""
// when it may be. Callers own the error code, since what an unreadable path
// means differs per tool.
//
// Pass every form of the path you have — as the caller gave it, and its
// symlink-resolved form. Both are needed, and measurement is why: on this
// machine ~/.ssh is itself a symlink into a cloud-sync folder, so a resolved
// path no longer looks like ~/.ssh and a resolve-then-compare check walks
// straight past the list. Comparing only the unresolved path has the opposite
// hole — a link planted in an ordinary directory would step through it. Each
// form of the path is checked against each form of every entry.
func Sensitive(paths ...string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return sensitiveIn(home, paths)
}

// sensitiveIn is Sensitive with the home directory injected, so the rule can
// be tested against a constructed home — including one where a blacklisted
// directory is a symlink, which is the case that was missed.
func sensitiveIn(home string, paths []string) string {
	forms := pathForms(paths)
	for _, p := range forms {
		if base := filepath.Base(p); base == ".env" || strings.HasPrefix(base, ".env.") {
			return "a .env file holds credentials"
		}
	}
	for _, rel := range sensitiveHomeTrees {
		for _, entry := range pathForms([]string{filepath.Join(home, rel)}) {
			for _, p := range forms {
				if within(p, entry) {
					return "~/" + rel + " holds credentials or agent control files"
				}
			}
		}
	}
	return ""
}

// pathForms expands paths into every spelling worth comparing: absolute and
// cleaned, plus the symlink-resolved form when it differs.
func pathForms(paths []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, p := range paths {
		if p == "" {
			continue
		}
		if abs, err := filepath.Abs(p); err == nil {
			add(filepath.Clean(abs))
		} else {
			add(filepath.Clean(p))
		}
		if resolved, err := filepath.EvalSymlinks(p); err == nil {
			if abs, aerr := filepath.Abs(resolved); aerr == nil {
				add(filepath.Clean(abs))
			}
		}
	}
	return out
}

// denied reports why the path may not be a work directory, or "". It takes the
// path as given and resolved, for the reason Sensitive documents.
func (r Resolver) denied(raw, resolved string) string {
	home, err := os.UserHomeDir()
	if err == nil {
		if h, herr := filepath.EvalSymlinks(home); herr == nil {
			home = h
		}
		if resolved == home {
			return "it is the home directory itself; pass a directory inside it"
		}
	}
	for _, d := range deniedExact {
		if resolved == d {
			return "it is a system directory"
		}
	}
	for _, d := range deniedTrees {
		if within(resolved, d) {
			return "it is inside the system directory " + d
		}
	}
	if why := Sensitive(raw, resolved); why != "" {
		return why
	}
	for _, d := range r.Denied {
		if d == "" {
			continue
		}
		if e, err := filepath.EvalSymlinks(d); err == nil {
			d = e
		}
		if within(resolved, filepath.Clean(d)) {
			return "it is inside this server's own directory " + d
		}
	}
	return ""
}

// within reports whether path is root or lies under it.
func within(path, root string) bool {
	if path == root {
		return true
	}
	return strings.HasPrefix(path, strings.TrimSuffix(root, string(filepath.Separator))+string(filepath.Separator))
}

// hasParentSegment reports whether the path has a ".." component.
func hasParentSegment(p string) bool {
	for _, seg := range strings.Split(filepath.ToSlash(p), "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

// metaHint reads the work directory a runtime attached to the request. A
// present but non-string value is an error rather than a silent miss: a
// runtime that sets the key wrongly should hear about it once, not have every
// call fall through to "work_dir is required".
func metaHint(ctx context.Context) (string, error) {
	raw, ok := mcpserver.RequestMeta(ctx)[MetaKey]
	if !ok {
		return "", nil
	}
	var dir string
	if err := json.Unmarshal(raw, &dir); err != nil {
		return "", toolerr.Newf(toolerr.CodeWorkDirInvalid, "request _meta[%q] is not a string", MetaKey)
	}
	return strings.TrimSpace(dir), nil
}
