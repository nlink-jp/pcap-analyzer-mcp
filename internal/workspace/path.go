package workspace

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/toolerr"
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
		return "", toolerr.Newf(toolerr.CodeInvalidArguments, "workspace_dir: %v", err)
	}
	joined := filepath.Join(absRoot, id)
	if filepath.Dir(joined) != filepath.Clean(absRoot) {
		return "", toolerr.Newf(toolerr.CodeInvalidWorkspaceID,
			"workspace_id escapes workspace_dir").
			WithDetails(map[string]any{"workspace_id": id})
	}
	return joined, nil
}

// ResolveAndCheck resolves path (following symlinks) and verifies it falls
// under one of allowedPaths.
//
// An empty allowedPaths means unrestricted (ADR-0004): the list is a guardrail
// an operator opts into, not a sandbox boundary. Resolution happens first so a
// symlink cannot point out of an allowed directory.
func ResolveAndCheck(path string, allowedPaths []string) (string, error) {
	if path == "" {
		return "", toolerr.New(toolerr.CodeMissingArgument, "pcap_path is required")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", toolerr.Newf(toolerr.CodePcapUnreadable, "%v", err).
			WithDetails(map[string]any{"pcap_path": path})
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", toolerr.Newf(toolerr.CodePcapUnreadable, "%v", err)
	}
	if len(allowedPaths) == 0 {
		return resolved, nil
	}
	for _, allowed := range allowedPaths {
		// An allowed_paths entry may itself be a symlink; resolve it too, or a
		// legitimate path would be rejected for a spurious mismatch.
		base, err := filepath.EvalSymlinks(allowed)
		if err != nil {
			base = allowed
		}
		if base, err = filepath.Abs(base); err != nil {
			continue
		}
		if resolved == base || strings.HasPrefix(resolved, base+string(filepath.Separator)) {
			return resolved, nil
		}
	}
	return "", toolerr.Newf(toolerr.CodePathNotAllowed,
		"%s is outside allowed_paths", path).
		WithDetails(map[string]any{
			"pcap_path":     path,
			"resolved":      resolved,
			"allowed_paths": allowedPaths,
		})
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
