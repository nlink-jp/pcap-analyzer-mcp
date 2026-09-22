package workspace

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/toolerr"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/workdir"
)

// workspaceIDPattern constrains an id to characters that are safe both as a
// path segment and as part of a container name.
var workspaceIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// ValidateWorkspaceID checks the syntax of an agent-supplied workspace id.
func ValidateWorkspaceID(id string) error {
	if id == "" {
		return toolerr.New(toolerr.CodeMissingArgument, "workspace_id is required")
	}
	if !workspaceIDPattern.MatchString(id) {
		return toolerr.Newf(toolerr.CodeInvalidWorkspaceID,
			"workspace_id must match %s", workspaceIDPattern.String()).
			WithDetails(map[string]any{"workspace_id": id})
	}
	return nil
}

// WorkspacePath joins root and id, then verifies the result is still directly
// under root.
//
// ValidateWorkspaceID already rejects separators and dots, so this is the
// second of two independent checks: if the pattern is ever loosened, the
// containment check still holds.
func WorkspacePath(root, id string) (string, error) {
	if err := ValidateWorkspaceID(id); err != nil {
		return "", err
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", toolerr.Newf(toolerr.CodeInvalidArguments, "work_dir: %v", err)
	}
	joined := filepath.Join(absRoot, id)
	if filepath.Dir(joined) != filepath.Clean(absRoot) {
		return "", toolerr.Newf(toolerr.CodeInvalidWorkspaceID,
			"workspace_id escapes work_dir").
			WithDetails(map[string]any{"workspace_id": id})
	}
	return joined, nil
}

// ResolveInput resolves a capture path the caller named (following symlinks)
// and refuses it only if it lands in a blacklisted location.
//
// There is no operator allowlist (ADR-0008 §4). The one that existed could not
// express what it was for — prefix matching has no per-repository granularity,
// so covering a work root meant listing the home directory, which admits the
// files the list was there to keep out. What remains is a fixed blacklist of
// credential and agent-control locations, and it is a floor, not a boundary:
// bounding what this process may touch at all is a sandboxing proxy's job.
//
// The path is placed first (workdir.Where: every link followed, a dangling
// one by its target), so a symlink planted anywhere cannot point into a
// blacklisted directory (the check ADR-0004 asked for, kept), and it is judged
// there, as given and as placed, before anything asks whether it exists: a
// capture that exists and one that does not get the same answer, message and
// details included, so no answer tells the caller which secrets exist.
// Existence is then asked of the place, not re-walked from the spelling.
func ResolveInput(path string) (string, error) {
	if path == "" {
		return "", toolerr.New(toolerr.CodeMissingArgument, "pcap_path is required")
	}
	where := workdir.Where(path)
	if err := refused(path, where); err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(where)
	if err != nil {
		return "", toolerr.Newf(toolerr.CodePcapUnreadable, "%v", err).
			WithDetails(map[string]any{"pcap_path": path})
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", toolerr.Newf(toolerr.CodePcapUnreadable, "%v", err)
	}
	// It resolved somewhere other than it was placed: it changed in between.
	// Judge where it now leads.
	if resolved != where {
		if err := refused(path, resolved); err != nil {
			return "", err
		}
	}
	return resolved, nil
}

// refused is the floor on a capture path, as given and at its place. Both
// spellings go to the check: a blacklisted directory may itself be a symlink
// (see workdir.Sensitive), so the placed form alone is not enough, and the
// given form alone would miss a planted link.
func refused(path, where string) error {
	if why := workdir.Sensitive(path, where); why != "" {
		return toolerr.Newf(toolerr.CodePathNotAllowed,
			"%s is refused: %s", path, why).
			WithDetails(map[string]any{"pcap_path": path, "resolved": where})
	}
	return nil
}

// DeriveWorkspaceID builds a stable, readable id for a capture.
//
// The basename makes it recognisable in a directory listing; the path digest
// keeps two captures with the same name in different directories apart, and
// makes re-creating a workspace for the same file land on the same id.
func DeriveWorkspaceID(resolvedPath string) string {
	sum := sha256.Sum256([]byte(resolvedPath))
	suffix := hex.EncodeToString(sum[:4])

	base := filepath.Base(resolvedPath)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	base = sanitizeIDPart(base)
	if base == "" {
		base = "capture"
	}
	// 64 is the id limit; reserve the digest and its separator.
	if max := 64 - len(suffix) - 1; len(base) > max {
		base = base[:max]
	}
	return base + "-" + suffix
}

// sanitizeIDPart maps anything outside the id alphabet to '-' and collapses
// runs, so a capture named "2026-07-26 攻撃 (1).pcapng" still yields a usable id.
func sanitizeIDPart(s string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

// EvidenceMount is the fixed container-side path of the capture.
//
// A single-file bind mount, not the parent directory: measurement showed
// virtiofs handles it on macOS and that siblings then stay invisible. It also
// means the host basename never becomes part of a container path, so no name
// can influence an argv.
const EvidenceMount = "/evidence/capture"

// WorkMount is the container-side path of the workspace's writable area.
const WorkMount = "/work"
