package tools

import (
	"os"
	"path/filepath"
	"testing"
)

// describe_workspace's `outputs` is how an agent finds what was extracted. It
// stopped reporting anything when ADR-0009 removed the spilled query results:
// the listing read one level of out/ and skipped directories, and the only
// product left — extracted objects — lives in out/objects/.
func TestListOutputsFindsExtractedObjects(t *testing.T) {
	out := t.TempDir()
	objects := filepath.Join(out, "objects")
	staging := filepath.Join(objects, "_raw")
	for _, d := range []string{objects, staging} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	obj := filepath.Join(objects, "deadbeef.bin")
	manifest := filepath.Join(objects, "manifest-http.json")
	for _, f := range []string{obj, manifest} {
		if err := os.WriteFile(f, []byte("xy"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The staging directory is tshark's, deleted on the way out; it must never
	// appear as a product.
	if err := os.WriteFile(filepath.Join(staging, "raw-1"), []byte("raw"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := listOutputs(out)
	if err != nil {
		t.Fatalf("listOutputs: %v", err)
	}
	paths := make([]string, 0, len(got))
	for _, e := range got {
		paths = append(paths, e["path"].(string))
		if e["bytes"].(int64) != 2 {
			t.Errorf("%v: bytes = %v, want 2", e["path"], e["bytes"])
		}
	}
	want := []string{obj, manifest}
	if len(paths) != len(want) {
		t.Fatalf("outputs = %v, want exactly %v", paths, want)
	}
	for i := range want {
		if paths[i] != want[i] {
			t.Errorf("outputs[%d] = %q, want %q", i, paths[i], want[i])
		}
	}
}

func TestListOutputsEmptyWorkspace(t *testing.T) {
	got, err := listOutputs(t.TempDir())
	if err != nil {
		t.Fatalf("listOutputs: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("outputs = %v, want none", got)
	}
}
