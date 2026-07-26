package tools

import (
	"os"
	"strings"
	"testing"
)

func lsNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// Without a ceiling, `length: 100000000` returns 100MB inline. The schema
// cannot express the bound, so the handler has to.
func TestFollowWindowIsClamped(t *testing.T) {
	d := newDeps(&fakeRunner{})
	if d.Cfg.Payload.FollowMaxWindowBytes <= 0 {
		t.Fatal("no window ceiling configured")
	}
	if d.Cfg.Payload.FollowMaxWindowBytes < d.Cfg.Payload.FollowInlineMaxBytes {
		t.Error("the ceiling must not be below the default window")
	}
	if d.Cfg.Payload.FollowMaxReassemblyBytes < d.Cfg.Payload.FollowMaxWindowBytes {
		t.Error("a window larger than the reassembly budget could never be filled")
	}
}

// One manifest per protocol. Extracting smb after http must not overwrite the
// http record — losing the earlier extraction silently would be worse than
// failing.
func TestManifestIsPerProtocol(t *testing.T) {
	dir := t.TempDir()
	for _, proto := range []string{"http", "smb"} {
		if err := writeManifest(dir, "manifest-"+proto+".json", nil); err != nil {
			t.Fatal(err)
		}
	}
	names := lsNames(t, dir)
	if len(names) != 2 {
		t.Fatalf("got %v, want one manifest per protocol", names)
	}
	for _, want := range []string{"manifest-http.json", "manifest-smb.json"} {
		if !strings.Contains(strings.Join(names, " "), want) {
			t.Errorf("missing %s in %v", want, names)
		}
	}
}
