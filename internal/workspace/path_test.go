package workspace

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/toolerr"
)

func TestValidateWorkspaceID(t *testing.T) {
	valid := []string{"a", "capture-1a2b3c4d", "under_score", strings.Repeat("x", 64)}
	for _, id := range valid {
		if err := ValidateWorkspaceID(id); err != nil {
			t.Errorf("ValidateWorkspaceID(%q) rejected a valid id: %v", id, err)
		}
	}

	invalid := map[string]string{
		"empty":     "",
		"too long":  strings.Repeat("x", 65),
		"slash":     "a/b",
		"parent":    "..",
		"dot":       "a.b",
		"backslash": `a\b`,
		"space":     "a b",
		"null byte": "a\x00b",
	}
	for name, id := range invalid {
		if err := ValidateWorkspaceID(id); err == nil {
			t.Errorf("ValidateWorkspaceID accepted %s (%q)", name, id)
		}
	}
}

// The containment check is the second of two defences. Even if the pattern
// were loosened, a joined path outside the root must still be refused.
func TestWorkspacePathRejectsEscapes(t *testing.T) {
	root := t.TempDir()
	for _, id := range []string{"..", "../sibling", "a/b", "/abs"} {
		if _, err := WorkspacePath(root, id); err == nil {
			t.Errorf("WorkspacePath accepted %q", id)
		}
	}
}

func TestWorkspacePathJoinsUnderRoot(t *testing.T) {
	root := t.TempDir()
	got, err := WorkspacePath(root, "cap-abcd1234")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(root, "cap-abcd1234"); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestResolveAndCheckUnrestrictedByDefault(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.pcap")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ResolveAndCheck(p, nil)
	if err != nil {
		t.Fatalf("empty allowed_paths must mean unrestricted: %v", err)
	}
	if !strings.HasSuffix(got, "c.pcap") {
		t.Errorf("got %q", got)
	}
}

func TestResolveAndCheckRejectsOutsideAllowed(t *testing.T) {
	allowed := t.TempDir()
	other := t.TempDir()
	p := filepath.Join(other, "c.pcap")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := ResolveAndCheck(p, []string{allowed})
	if err == nil {
		t.Fatal("want rejection")
	}
	if !errors.Is(err, toolerr.New(toolerr.CodePathNotAllowed, "")) {
		t.Errorf("want path_not_allowed, got %v", err)
	}
}

// A symlink inside an allowed directory pointing outside it must not smuggle
// the target in. Resolution happens before the containment check for exactly
// this case.
func TestResolveAndCheckFollowsSymlinksBeforeChecking(t *testing.T) {
	allowed := t.TempDir()
	secret := t.TempDir()

	target := filepath.Join(secret, "elsewhere.pcap")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(allowed, "innocent.pcap")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if _, err := ResolveAndCheck(link, []string{allowed}); err == nil {
		t.Error("a symlink out of an allowed directory must be rejected")
	}
}

// The converse: an allowed_paths entry that is itself a symlink (common on
// macOS, where /tmp is a link to /private/tmp) must still match.
func TestResolveAndCheckResolvesAllowedEntries(t *testing.T) {
	real := t.TempDir()
	linkDir := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, linkDir); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	p := filepath.Join(real, "c.pcap")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := ResolveAndCheck(p, []string{linkDir}); err != nil {
		t.Errorf("a symlinked allowed_paths entry should still match: %v", err)
	}
}

// A prefix match on the raw string would let /data-evil pass for /data.
func TestResolveAndCheckRequiresPathBoundary(t *testing.T) {
	base := t.TempDir()
	allowed := filepath.Join(base, "data")
	sibling := filepath.Join(base, "data-evil")
	for _, d := range []string{allowed, sibling} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	p := filepath.Join(sibling, "c.pcap")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := ResolveAndCheck(p, []string{allowed}); err == nil {
		t.Error("/data must not admit /data-evil")
	}
}

func TestResolveAndCheckMissingFile(t *testing.T) {
	_, err := ResolveAndCheck(filepath.Join(t.TempDir(), "absent.pcap"), nil)
	if !errors.Is(err, toolerr.New(toolerr.CodePcapUnreadable, "")) {
		t.Errorf("want pcap_unreadable, got %v", err)
	}
}

func TestDeriveWorkspaceIDIsStableAndValid(t *testing.T) {
	a := DeriveWorkspaceID("/captures/incident.pcapng")
	b := DeriveWorkspaceID("/captures/incident.pcapng")
	if a != b {
		t.Errorf("same path must yield the same id: %q vs %q", a, b)
	}
	if err := ValidateWorkspaceID(a); err != nil {
		t.Errorf("derived id %q is not valid: %v", a, err)
	}
	if !strings.HasPrefix(a, "incident-") {
		t.Errorf("id should stay recognisable, got %q", a)
	}
}

// Same filename in two directories must not collide — that is what the path
// digest is for.
func TestDeriveWorkspaceIDDistinguishesDirectories(t *testing.T) {
	a := DeriveWorkspaceID("/a/capture.pcap")
	b := DeriveWorkspaceID("/b/capture.pcap")
	if a == b {
		t.Errorf("ids collided across directories: %q", a)
	}
}

func TestDeriveWorkspaceIDHandlesAwkwardNames(t *testing.T) {
	for _, path := range []string{
		"/x/2026-07-26 攻撃 (1).pcapng",
		"/x/....pcap",
		"/x/" + strings.Repeat("verylongname", 20) + ".pcap",
		"/x/.pcap",
	} {
		id := DeriveWorkspaceID(path)
		if err := ValidateWorkspaceID(id); err != nil {
			t.Errorf("DeriveWorkspaceID(%q) = %q, which is invalid: %v", path, id, err)
		}
	}
}
