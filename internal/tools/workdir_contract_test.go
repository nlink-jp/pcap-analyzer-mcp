package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/mcpserver"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/toolerr"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/workdir"
)

// The work-directory contract (organization ADR-021, project ADR-0008) is a
// rule about every tool, not about one of them. Stated only in prose it gets
// re-decided by whoever adds the next tool, so it is pinned here.

// everyTool is the floor under every per-tool loop: with an empty list, each
// contract would pass without having examined anything.
func everyTool(t *testing.T, d *Deps) []registration {
	t.Helper()
	all := d.all()
	if len(all) == 0 {
		t.Fatal("no tools are registered, so every per-tool contract would pass without examining one")
	}
	return all
}

func TestNoToolSchemaCarriesARetiredWorkDirName(t *testing.T) {
	d := newDeps(&fakeRunner{})
	for _, r := range everyTool(t, d) {
		for _, old := range retiredWorkDirNames {
			if strings.Contains(string(r.desc.InputSchema), `"`+old+`"`) {
				t.Errorf("tool %q declares %q; the name is work_dir", r.desc.Name, old)
			}
		}
	}
}

// An optional work directory is an invitation to fall back to a server-owned
// default, which is the failure the contract removes.
func TestWorkDirIsRequiredWhereverItIsDeclared(t *testing.T) {
	d := newDeps(&fakeRunner{})
	for _, r := range everyTool(t, d) {
		var schema struct {
			Required   []string                   `json:"required"`
			Properties map[string]json.RawMessage `json:"properties"`
		}
		if err := json.Unmarshal(r.desc.InputSchema, &schema); err != nil {
			t.Fatalf("%s: input schema is not valid JSON: %v", r.desc.Name, err)
		}
		_, declares := schema.Properties["work_dir"]
		if _, addresses := schema.Properties["workspace_id"]; addresses && !declares {
			t.Errorf("tool %q takes a workspace_id but never says which work_dir it lives in", r.desc.Name)
		}
		if !declares {
			continue
		}
		if !contains(schema.Required, "work_dir") {
			t.Errorf("tool %q declares work_dir but does not require it", r.desc.Name)
		}
	}
}

// The rename is ours, so a caller working from an older manual recovers in one
// turn rather than re-reading the schema to guess what "unknown field" meant.
func TestARetiredSpellingNamesTheNewOne(t *testing.T) {
	d := newDeps(&fakeRunner{})
	for _, old := range retiredWorkDirNames {
		_, err := call(t, d, "list_workspaces", map[string]any{old: t.TempDir()})
		if !errors.Is(err, toolerr.New(toolerr.CodeWorkDirRequired, "")) {
			t.Errorf("%s: err = %v, want work_dir_required", old, err)
		}
		if err != nil && !strings.Contains(err.Error(), "work_dir") {
			t.Errorf("%s: error does not name the new argument: %v", old, err)
		}
	}
}

// The second channel: our own runtimes set it on every tools/call, so the
// model does not have to carry an argument it cannot get wrong.
func TestWorkDirComesFromRequestMeta(t *testing.T) {
	d := newDeps(&fakeRunner{})
	dir := t.TempDir()
	hint, err := json.Marshal(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := mcpserver.WithRequestMeta(context.Background(),
		map[string]json.RawMessage{workdir.MetaKey: hint})

	args, err := json.Marshal(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	out, err := find(t, d, "list_workspaces").handler(ctx, args)
	if err != nil {
		t.Fatalf("list_workspaces with only a _meta work dir: %v", err)
	}
	m, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("result is %T", out)
	}
	if m["count"] != 0 {
		t.Errorf("count = %v, want 0 for an empty work dir", m["count"])
	}
}

// A work directory that cannot be written to, or is not there, fails before
// anything is attempted — with a code that says which.
func TestWorkDirValidationCodes(t *testing.T) {
	d := newDeps(&fakeRunner{})
	cases := map[string]string{
		"~/captures":      toolerr.CodeWorkDirInvalid,
		"relative/dir":    toolerr.CodeWorkDirInvalid,
		"/usr/bin":        toolerr.CodeWorkDirDenied,
		"/nope/not/there": toolerr.CodeWorkDirNotFound,
	}
	for dir, want := range cases {
		_, err := call(t, d, "list_workspaces", map[string]any{"work_dir": dir})
		if !errors.Is(err, toolerr.New(want, "")) {
			t.Errorf("work_dir %q: got %v, want %s", dir, err, want)
		}
	}
}

func contains(haystack []string, want string) bool {
	for _, s := range haystack {
		if s == want {
			return true
		}
	}
	return false
}

// A schema test catches a renamed argument; it does not catch a sentence. The
// prose the model reads — tool descriptions, the usage manual, the container
// manifest — drifts silently because nothing compiles it, and after ADR-0009
// withdrew file-mediated results the help text still promised JSONL in the
// workspace. This is what compiles the prose.
func TestModelFacingProseNamesNoWithdrawnMechanism(t *testing.T) {
	withdrawn := []string{"JSONL", "result_file", "results file", "sample_rows", "inline_max_bytes"}
	d := newDeps(&fakeRunner{})
	texts := map[string]string{}
	for _, r := range everyTool(t, d) {
		texts["tool "+r.desc.Name+" description"] = r.desc.Description
		texts["tool "+r.desc.Name+" schema"] = string(r.desc.InputSchema)
	}
	texts["usage manual"] = fmt.Sprint(usageDoc(65536, 500))
	for _, old := range retiredWorkDirNames {
		withdrawn = append(withdrawn, old)
	}
	for where, text := range texts {
		for _, term := range withdrawn {
			if strings.Contains(text, term) {
				t.Errorf("%s still names %q: analysis results come back in the response "+
					"(ADR-0009), and the work directory argument is work_dir", where, term)
			}
		}
	}
}

// TestEveryRequiredNameIsDeclared is the regression for a tool list that a
// strict client refuses outright. Vertex AI validates `required` against
// `properties` and answers a whole tools/list with
// "schema at top-level requires unspecified property 'work_dir'" — one bad
// schema and the session cannot start at all (2026-09-14, gem-agent).
//
// The existing contract test checks the other direction (declared => required)
// and is blind to this one; JSON Schema itself permits it, so nothing else
// catches it either.
func TestEveryRequiredNameIsDeclared(t *testing.T) {
	d := newDeps(&fakeRunner{})
	for _, tool := range everyTool(t, d) {
		var schema struct {
			Properties map[string]json.RawMessage `json:"properties"`
			Required   []string                   `json:"required"`
		}
		if err := json.Unmarshal(tool.desc.InputSchema, &schema); err != nil {
			t.Fatalf("%s: input schema is not valid JSON: %v", tool.desc.Name, err)
		}
		for _, name := range schema.Required {
			if _, ok := schema.Properties[name]; !ok {
				t.Errorf("tool %q requires %q but does not declare it in properties: "+
					"a strict client refuses the whole tool list", tool.desc.Name, name)
			}
		}
	}
}
