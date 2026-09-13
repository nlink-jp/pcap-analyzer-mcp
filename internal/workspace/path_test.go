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

func TestResolveInputTakesAnyReadablePath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.pcap")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ResolveInput(p)
	if err != nil {
		t.Fatalf("an ordinary capture path must be accepted: %v", err)
	}
	if !strings.HasSuffix(got, "c.pcap") {
		t.Errorf("got %q", got)
	}
}

// The blacklist is the whole of the input guard now (ADR-0008 §4). It is a
// floor, not a boundary — but the floor has to hold.
func TestResolveInputRefusesCredentialLocations(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home directory: %v", err)
	}
	p := filepath.Join(home, ".ssh", "id_rsa")
	if _, err := os.Stat(p); err != nil {
		t.Skipf("no %s on this host: %v", p, err)
	}
	_, err = ResolveInput(p)
	if err == nil {
		t.Fatal("a path under ~/.ssh must be refused")
	}
	if !errors.Is(err, toolerr.New(toolerr.CodePathNotAllowed, "")) {
		t.Errorf("want path_not_allowed, got %v", err)
	}
}

// Resolution happens before the blacklist check, so a link planted in an
// ordinary directory cannot smuggle a blacklisted target in.
func TestResolveInputFollowsSymlinksBeforeChecking(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home directory: %v", err)
	}
	target := filepath.Join(home, ".ssh")
	if _, err := os.Stat(target); err != nil {
		t.Skipf("no %s on this host: %v", target, err)
	}
	link := filepath.Join(t.TempDir(), "innocent.pcap")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := ResolveInput(link); err == nil {
		t.Error("a symlink into a blacklisted directory must be rejected")
	}
}

func TestResolveInputRejectsMissingPath(t *testing.T) {
	_, err := ResolveInput(filepath.Join(t.TempDir(), "absent.pcap"))
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
