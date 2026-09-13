package workdir

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/mcpserver"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/toolerr"
)

func code(t *testing.T, err error) string {
	t.Helper()
	var te *toolerr.Error
	if !errors.As(err, &te) {
		t.Fatalf("error %v is not a structured tool error", err)
	}
	return te.Code
}

func metaCtx(t *testing.T, value any) context.Context {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return mcpserver.WithRequestMeta(context.Background(),
		map[string]json.RawMessage{MetaKey: raw})
}

// TestResolveArgumentWins: the argument is the caller's own statement of where
// it can read files back; a runtime hint is a default beneath it.
func TestResolveArgumentWins(t *testing.T) {
	arg := t.TempDir()
	hint := t.TempDir()
	got, err := Resolver{}.Resolve(metaCtx(t, hint), arg)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != resolve(t, arg) {
		t.Errorf("Resolve = %q, want %q", got, arg)
	}
}

func TestResolveFallsBackToRequestMeta(t *testing.T) {
	hint := t.TempDir()
	got, err := Resolver{}.Resolve(metaCtx(t, hint), "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != resolve(t, hint) {
		t.Errorf("Resolve = %q, want %q", got, hint)
	}
}

// TestResolveWithoutEitherChannelIsAnError pins the whole point of the
// contract: there is no server-owned default to fall through to, because a
// destination the caller cannot read back turns a successful call into a path
// to nothing.
func TestResolveWithoutEitherChannelIsAnError(t *testing.T) {
	_, err := Resolver{}.Resolve(context.Background(), "")
	if got := code(t, err); got != toolerr.CodeWorkDirRequired {
		t.Errorf("code = %q, want %q", got, toolerr.CodeWorkDirRequired)
	}
	if !strings.Contains(err.Error(), "read back") {
		t.Errorf("message does not say what to pass: %v", err)
	}
}

func TestResolveRejectsNonStringMeta(t *testing.T) {
	_, err := Resolver{}.Resolve(metaCtx(t, 42), "")
	if got := code(t, err); got != toolerr.CodeWorkDirInvalid {
		t.Errorf("code = %q, want %q", got, toolerr.CodeWorkDirInvalid)
	}
}

func TestValidate(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a-file")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		in   string
		want string
	}{
		{"tilde", "~/work", toolerr.CodeWorkDirInvalid},
		{"relative", "work/dir", toolerr.CodeWorkDirInvalid},
		{"parent segment", dir + "/../elsewhere", toolerr.CodeWorkDirInvalid},
		{"missing", filepath.Join(dir, "not-there"), toolerr.CodeWorkDirNotFound},
		{"a file", file, toolerr.CodeWorkDirNotFound},
		{"system tree", "/usr/bin", toolerr.CodeWorkDirDenied},
		{"filesystem root", "/", toolerr.CodeWorkDirDenied},
		{"home itself", home, toolerr.CodeWorkDirDenied},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Resolver{}.Validate(c.in)
			if err == nil {
				t.Fatalf("Validate(%q) succeeded", c.in)
			}
			if got := code(t, err); got != c.want {
				t.Errorf("code = %q, want %q", got, c.want)
			}
		})
	}
}

// TestValidateAcceptsATemporaryDirectory guards against an over-broad deny
// list: on darwin a per-user temporary directory resolves under /private/var,
// and Codex names exactly that as a place it can write.
func TestValidateAcceptsATemporaryDirectory(t *testing.T) {
	dir := t.TempDir()
	got, err := Resolver{}.Validate(dir)
	if err != nil {
		t.Fatalf("Validate(%q): %v", dir, err)
	}
	if got != resolve(t, dir) {
		t.Errorf("Validate = %q, want the symlink-resolved %q", got, resolve(t, dir))
	}
}

func TestValidateRefusesServerOwnedDirectories(t *testing.T) {
	own := t.TempDir()
	inside := filepath.Join(own, "workspaces")
	if err := os.Mkdir(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	r := Resolver{Denied: []string{own}}
	for _, dir := range []string{own, inside} {
		if _, err := r.Validate(dir); code(t, err) != toolerr.CodeWorkDirDenied {
			t.Errorf("Validate(%q) = %v, want work_dir_denied", dir, err)
		}
	}
	// A sibling of the denied tree is not denied by prefix alone.
	sibling := own + "-elsewhere"
	if err := os.Mkdir(sibling, 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sibling)
	if _, err := r.Validate(sibling); err != nil {
		t.Errorf("Validate(%q) = %v, want accepted", sibling, err)
	}
}

func TestValidateRejectsUnwritableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write anywhere")
	}
	dir := filepath.Join(t.TempDir(), "read-only")
	if err := os.Mkdir(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	if _, err := (Resolver{}).Validate(dir); code(t, err) != toolerr.CodeWorkDirNotWritable {
		t.Errorf("Validate(%q) = %v, want work_dir_not_writable", dir, err)
	}
}

// resolve mirrors what Validate returns for a good path, so assertions do not
// have to care that /var and /tmp are symlinks on darwin.
func resolve(t *testing.T, dir string) string {
	t.Helper()
	got, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// TestSensitiveNamesTheCredentialLocations covers the input blacklist, which
// this server is the first to need: pcap_path is an absolute host path, so the
// floor has to hold here or it holds nowhere.
func TestSensitiveNamesTheCredentialLocations(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home directory: %v", err)
	}
	if h, herr := filepath.EvalSymlinks(home); herr == nil {
		home = h
	}
	for _, rel := range []string{".ssh", ".ssh/id_rsa", ".aws/credentials", ".gnupg", ".config/gcloud/x", ".claude/settings.json", ".codex/auth.json", "Library/Keychains/login.keychain-db"} {
		if why := Sensitive(filepath.Join(home, rel)); why == "" {
			t.Errorf("Sensitive(~/%s) = \"\", want a reason", rel)
		}
	}
	for _, p := range []string{filepath.Join(home, "Downloads", "capture.pcapng"), "/private/tmp/x.pcap"} {
		if why := Sensitive(p); why != "" {
			t.Errorf("Sensitive(%q) = %q, want it accepted", p, why)
		}
	}
}

func TestSensitiveCatchesDotEnvAnywhere(t *testing.T) {
	for _, p := range []string{"/srv/app/.env", "/srv/app/.env.production"} {
		if why := Sensitive(p); why == "" {
			t.Errorf("Sensitive(%q) = \"\", want a reason", p)
		}
	}
	if why := Sensitive("/srv/app/environment.csv"); why != "" {
		t.Errorf("a file merely starting with 'env' must be accepted, got %q", why)
	}
}

// A sibling directory must not be admitted by prefix alone: /data-evil is not
// inside /data. The allowlist this replaced had the same property and a test
// for it; the property moved, so the test moves with it.
func TestWithinDoesNotAdmitSiblings(t *testing.T) {
	if within("/data-evil/c.pcap", "/data") {
		t.Error("/data must not admit /data-evil")
	}
	if !within("/data/c.pcap", "/data") || !within("/data", "/data") {
		t.Error("/data must admit itself and its children")
	}
}

// TestSensitiveWhenTheBlacklistedTreeIsItselfASymlink is the case that was
// missed until the server was driven for real: on this machine ~/.ssh is a
// symlink into a cloud-sync folder, so resolving the path first made it stop
// looking like ~/.ssh and the check passed a private key straight through.
func TestSensitiveWhenTheBlacklistedTreeIsItselfASymlink(t *testing.T) {
	home := t.TempDir()
	real := filepath.Join(t.TempDir(), "synced-ssh")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(home, ".ssh")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	key := filepath.Join(real, "id_rsa")
	if err := os.WriteFile(key, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Named through the link, and named at its real location: both refused.
	viaLink := filepath.Join(home, ".ssh", "id_rsa")
	if why := sensitiveIn(home, []string{viaLink}); why == "" {
		t.Error("a key named through the ~/.ssh symlink must be refused")
	}
	if why := sensitiveIn(home, []string{key}); why == "" {
		t.Error("a key named at the symlink's target must be refused")
	}
	// And the other direction still holds: a link planted elsewhere that
	// points into the tree is refused too.
	planted := filepath.Join(t.TempDir(), "innocent.pcap")
	if err := os.Symlink(key, planted); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if why := sensitiveIn(home, []string{planted}); why == "" {
		t.Error("a planted link into the blacklisted tree must be refused")
	}
}
