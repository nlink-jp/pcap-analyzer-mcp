package toolerr_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/toolerr"
)

func TestErrorString(t *testing.T) {
	e := toolerr.New(toolerr.CodePathNotAllowed, "outside allowed_paths")
	if got := e.Error(); got != "path_not_allowed: outside allowed_paths" {
		t.Errorf("got %q", got)
	}
}

func TestErrorStringWithoutMessage(t *testing.T) {
	if got := toolerr.New(toolerr.CodeJobNotFound, "").Error(); got != "job_not_found" {
		t.Errorf("got %q, want bare code", got)
	}
}

func TestErrorIsByCode(t *testing.T) {
	sentinel := toolerr.New(toolerr.CodePathNotAllowed, "")
	actual := toolerr.Newf(toolerr.CodePathNotAllowed, "blocked: %s", "/etc/shadow")
	if !errors.Is(actual, sentinel) {
		t.Errorf("errors.Is should match by Code")
	}
	other := toolerr.New(toolerr.CodeInvalidDisplayFilter, "")
	if errors.Is(actual, other) {
		t.Errorf("errors.Is should not match a different Code")
	}
}

func TestErrorWrappedIs(t *testing.T) {
	inner := toolerr.New(toolerr.CodeTsharkFailed, "exit 2")
	wrapped := fmt.Errorf("podman run: %w", inner)
	if !errors.Is(wrapped, toolerr.New(toolerr.CodeTsharkFailed, "")) {
		t.Errorf("errors.Is should walk the wrapper chain")
	}
}

func TestErrorJSONMarshal(t *testing.T) {
	e := toolerr.New(toolerr.CodeInvalidDisplayFilter, "syntax error").WithDetails(map[string]any{
		"position":         14,
		"candidate_fields": []string{"tcp.flags.syn", "tcp.flags.reset"},
	})
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		`"code":"invalid_display_filter"`,
		`"message":"syntax error"`,
		`"position":14`,
		`tcp.flags.syn`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("marshaled error missing %q: %s", want, s)
		}
	}
}

func TestWithDetailsDoesNotMutate(t *testing.T) {
	e := toolerr.New(toolerr.CodePathNotAllowed, "x")
	_ = e.WithDetails(map[string]any{"k": "v"})
	if e.Details != nil {
		t.Errorf("WithDetails should not mutate receiver")
	}
}

// The codes are a client-facing contract: renaming one breaks agents that
// branch on it. Pin the wire strings so a rename cannot happen silently.
func TestCodeWireValues(t *testing.T) {
	// A slice, not a map: two constants colliding on the same value must
	// show up as a failure rather than silently deduplicating.
	cases := []struct{ name, got, want string }{
		{"CodeInvalidArguments", toolerr.CodeInvalidArguments, "invalid_arguments"},
		{"CodeMissingArgument", toolerr.CodeMissingArgument, "missing_argument"},
		{"CodeInvalidWorkspaceID", toolerr.CodeInvalidWorkspaceID, "invalid_workspace_id"},
		{"CodeWorkspaceNotFound", toolerr.CodeWorkspaceNotFound, "workspace_not_found"},
		{"CodePathNotAllowed", toolerr.CodePathNotAllowed, "path_not_allowed"},
		{"CodePcapUnreadable", toolerr.CodePcapUnreadable, "pcap_unreadable"},
		{"CodeInvalidDisplayFilter", toolerr.CodeInvalidDisplayFilter, "invalid_display_filter"},
		{"CodeContainerFailed", toolerr.CodeContainerFailed, "container_failed"},
		{"CodeTsharkFailed", toolerr.CodeTsharkFailed, "tshark_failed"},
		{"CodeJobNotFound", toolerr.CodeJobNotFound, "job_not_found"},
		{"CodePayloadUnavailableTruncatedCapture", toolerr.CodePayloadUnavailableTruncatedCapture, "payload_unavailable_truncated_capture"},
		{"CodeObjectTooLarge", toolerr.CodeObjectTooLarge, "object_too_large"},
	}
	seen := make(map[string]string, len(cases))
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
		if prev, dup := seen[c.got]; dup {
			t.Errorf("%s and %s share the wire value %q", prev, c.name, c.got)
		}
		seen[c.got] = c.name
	}
}
