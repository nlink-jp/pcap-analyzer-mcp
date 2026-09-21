package tools

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The initialize `instructions` string is the first thing a client's model
// reads about this server — before any tool list — and prose drifts silently
// because nothing compiles it. These tests hold each of its claims to the
// registered tools rather than to a copy of their names.

// identifierPattern matches the snake_case words the instructions use for tool
// and argument names. Every tool this server registers has an underscore in
// its name, so none can be mentioned without matching.
var identifierPattern = regexp.MustCompile(`[a-z][a-z0-9]*(?:_[a-z0-9]+)+`)

// schemaProperties returns the argument names a tool's input schema declares.
func schemaProperties(t *testing.T, r registration) map[string]json.RawMessage {
	t.Helper()
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(r.desc.InputSchema, &schema); err != nil {
		t.Fatalf("%s: input schema is not valid JSON: %v", r.desc.Name, err)
	}
	return schema.Properties
}

// A model that reads only this will otherwise omit an argument nine tools
// require, or invent a default the server refuses to supply.
func TestInstructionsNameTheWorkDirContract(t *testing.T) {
	for _, want := range []string{
		"work_dir",
		"absolute",
		"no default",
		"<work_dir>/<workspace_id>/",
		toolsWithoutWorkDir + " requires work_dir",
	} {
		if !strings.Contains(Instructions, want) {
			t.Errorf("the initialize instructions do not say %q", want)
		}
	}
	for _, old := range retiredWorkDirNames {
		if strings.Contains(Instructions, old) {
			t.Errorf("the initialize instructions name %q; the name is work_dir", old)
		}
	}
}

// A tool the instructions name but the server does not register sends the
// model looking for something that is not there. Argument names are allowed
// too, but only ones some registered tool actually declares.
func TestInstructionsNameOnlyRegisteredTools(t *testing.T) {
	d := newDeps(&fakeRunner{})
	registered := map[string]bool{}
	declared := map[string]bool{}
	for _, r := range everyTool(t, d) {
		registered[r.desc.Name] = true
		for name := range schemaProperties(t, r) {
			declared[name] = true
		}
	}

	namedTools := 0
	for _, word := range identifierPattern.FindAllString(Instructions, -1) {
		switch {
		case registered[word]:
			namedTools++
		case declared[word]:
		default:
			t.Errorf("the initialize instructions name %q, which is neither a registered "+
				"tool nor an argument any registered tool declares", word)
		}
	}
	if namedTools == 0 {
		t.Fatal("the instructions name no registered tool, so this test examined nothing")
	}
}

// The exception list is the claim a model acts on first: which calls need
// work_dir. It has to match the schemas in both directions — a new tool
// without work_dir must be listed, and a listed tool that gains work_dir must
// come off.
func TestInstructionsExemptExactlyTheToolsWithoutWorkDir(t *testing.T) {
	d := newDeps(&fakeRunner{})
	registered := map[string]bool{}
	var want []string
	for _, r := range everyTool(t, d) {
		registered[r.desc.Name] = true
		if _, ok := schemaProperties(t, r)["work_dir"]; !ok {
			want = append(want, r.desc.Name)
		}
	}

	var got []string
	for _, word := range identifierPattern.FindAllString(toolsWithoutWorkDir, -1) {
		if !registered[word] {
			t.Errorf("toolsWithoutWorkDir names %q, which is not a registered tool", word)
			continue
		}
		got = append(got, word)
	}

	sort.Strings(want)
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("the instructions say every tool except %v requires work_dir, "+
			"but the tools whose schema declares no work_dir are %v", got, want)
	}
}

// get_usage is how a client finds the manual, and check_job is the only way to
// collect an async result; a model that never hears what either is for cannot
// use them.
//
// The exception list names both tools too, so it is taken out first: being
// listed as needing no work_dir says nothing about what a tool is for, and
// with it left in, deleting either pointer would still pass.
func TestInstructionsPointAtGetUsageAndCheckJob(t *testing.T) {
	rest := strings.Replace(Instructions, toolsWithoutWorkDir, "", 1)
	if !strings.Contains(rest, "get_usage") {
		t.Error("the initialize instructions do not point at get_usage, which is how a client finds the manual")
	}
	for _, sentence := range strings.Split(rest, ". ") {
		if strings.Contains(sentence, "async") && strings.Contains(sentence, "job_id") &&
			strings.Contains(sentence, "check_job") {
			return
		}
	}
	t.Error("no sentence of the initialize instructions ties async to the job_id it returns " +
		"and to check_job, the tool that collects the result")
}
