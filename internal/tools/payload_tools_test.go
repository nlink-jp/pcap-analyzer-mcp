package tools

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/toolerr"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/tshark"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/workspace"
)

func truncatedWorkspace() *workspace.Workspace {
	limit := int64(40)
	return &workspace.Workspace{
		ID: "trunc-00000000",
		Meta: &workspace.Meta{
			Info: workspace.CaptureInfo{
				Truncated:          true,
				SnaplenHeader:      "(not set)",
				SnaplenInferredMax: &limit,
			},
		},
	}
}

// A truncated capture has no payload at all. Saying so before running anything
// is what stops an agent reading an empty result as a transient failure and
// retrying forever.
func TestPayloadToolsRefuseATruncatedCaptureUpFront(t *testing.T) {
	err := requirePayload(truncatedWorkspace())
	if !errors.Is(err, toolerr.New(toolerr.CodePayloadUnavailableTruncatedCapture, "")) {
		t.Fatalf("want payload_unavailable_truncated_capture, got %v", err)
	}
	var te *toolerr.Error
	errors.As(err, &te)
	if te.Details["snaplen_inferred_max"] != int64(40) {
		t.Errorf("the evidence for the verdict should travel with it: %v", te.Details)
	}
	guidance, _ := te.Details["guidance"].(string)
	if !strings.Contains(guidance, "still work") {
		t.Errorf("the agent should be told what it can still do: %q", guidance)
	}
}

func TestRequirePayloadAllowsAnIntactCapture(t *testing.T) {
	ws := &workspace.Workspace{Meta: &workspace.Meta{Info: workspace.CaptureInfo{Truncated: false}}}
	if err := requirePayload(ws); err != nil {
		t.Errorf("an intact capture must be allowed: %v", err)
	}
}

func TestFollowStreamArgumentValidation(t *testing.T) {
	d := newDeps(&fakeRunner{})
	base := map[string]any{"workspace_id": "x-00000000", "workspace_dir": t.TempDir()}

	if _, err := call(t, d, "follow_stream", base); !errors.Is(err, toolerr.New(toolerr.CodeMissingArgument, "")) {
		t.Errorf("stream is required: %v", err)
	}
	for name, args := range map[string]map[string]any{
		"negative stream": {"stream": -1},
		"bad protocol":    {"stream": 0, "protocol": "sctp"},
		"negative offset": {"stream": 0, "offset": -1},
		"negative length": {"stream": 0, "length": -5},
	} {
		merged := map[string]any{}
		for k, v := range base {
			merged[k] = v
		}
		for k, v := range args {
			merged[k] = v
		}
		if _, err := call(t, d, "follow_stream", merged); err == nil {
			t.Errorf("%s should be rejected", name)
		}
	}
}

func TestExtractObjectsProtocolValidation(t *testing.T) {
	d := newDeps(&fakeRunner{})
	base := map[string]any{"workspace_id": "x-00000000", "workspace_dir": t.TempDir()}

	if _, err := call(t, d, "extract_objects", base); !errors.Is(err, toolerr.New(toolerr.CodeMissingArgument, "")) {
		t.Errorf("protocol is required: %v", err)
	}

	bad := map[string]any{"workspace_id": "x-00000000", "workspace_dir": t.TempDir(), "protocol": "gopher"}
	_, err := call(t, d, "extract_objects", bad)
	if !errors.Is(err, toolerr.New(toolerr.CodeInvalidArguments, "")) {
		t.Fatalf("want invalid_arguments, got %v", err)
	}
	var te *toolerr.Error
	errors.As(err, &te)
	if _, ok := te.Details["supported"]; !ok {
		t.Error("the error should list what is supported so the agent can retry correctly")
	}
}

// --- follow response shaping ------------------------------------------------

// Verbatim from `tshark -q -z follow,tcp,raw,0` in the analysis image. The
// leading tab on the second payload line is the only direction marker there
// is.
const followRaw = "\n" +
	"===================================================================\n" +
	"Follow: tcp,raw\n" +
	"Filter: tcp.stream eq 0\n" +
	"Node 0: 10.2.2.2:80\n" +
	"Node 1: 10.1.1.1:1234\n" +
	"48545450\n" +
	"\t47455420\n" +
	"===================================================================\n"

func TestParseFollowSplitsByIndentation(t *testing.T) {
	f, err := tshark.ParseFollow("tcp", 0, followRaw)
	if err != nil {
		t.Fatal(err)
	}
	if f.NodeA != "10.2.2.2:80" || f.NodeB != "10.1.1.1:1234" {
		t.Fatalf("nodes = %q / %q", f.NodeA, f.NodeB)
	}
	if len(f.Chunks) != 2 {
		t.Fatalf("got %d chunks", len(f.Chunks))
	}
	if f.Chunks[0].From != "10.2.2.2:80" {
		t.Errorf("an unindented line comes from Node 0, got %q", f.Chunks[0].From)
	}
	if f.Chunks[1].From != "10.1.1.1:1234" {
		t.Errorf("an indented line comes from Node 1, got %q", f.Chunks[1].From)
	}
	if string(f.Chunks[0].Data) != "HTTP" || string(f.Chunks[1].Data) != "GET " {
		t.Errorf("hex not decoded: %q / %q", f.Chunks[0].Data, f.Chunks[1].Data)
	}
}

// Each direction is its own byte stream, so one offset into their
// concatenation would be meaningless. They window independently.
func TestFollowWindowsEachDirectionSeparately(t *testing.T) {
	f, err := tshark.ParseFollow("tcp", 0, followRaw)
	if err != nil {
		t.Fatal(err)
	}
	out := buildFollowResponse("ws", f, 1, 2)
	dirs := out["directions"].([]followWindow)
	if len(dirs) != 2 {
		t.Fatalf("got %d directions", len(dirs))
	}
	for _, d := range dirs {
		if d.Offset != 1 || d.Bytes != 2 {
			t.Errorf("%s→%s window = offset %d, %d bytes", d.From, d.To, d.Offset, d.Bytes)
		}
		if d.TotalBytes != 4 {
			t.Errorf("TotalBytes = %d, want the whole direction", d.TotalBytes)
		}
		if !d.MoreAfter {
			t.Error("MoreAfter should say there is more to page through")
		}
	}
}

// Reassembled content must arrive wrapped, whatever the caller does with it.
func TestFollowContentIsWrappedAsUntrusted(t *testing.T) {
	f, err := tshark.ParseFollow("tcp", 0, followRaw)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(buildFollowResponse("ws", f, 0, 100))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "untrusted-payload") {
		t.Errorf("stream content escaped its framing: %s", s)
	}
	if !strings.Contains(s, "not instructions") {
		t.Errorf("the framing text is missing: %s", s)
	}
}

// Binary bytes must be visible as escapes rather than silently dropped or
// replaced — an analyst reading a hex escape knows what they are looking at.
func TestRenderBytesEscapesNonPrinting(t *testing.T) {
	got := renderBytes([]byte{'A', 0x00, 0x1b, '\n', 0xff, 'B'})
	if got != `A\x00\x1b`+"\n"+`\xffB` {
		t.Errorf("got %q", got)
	}
	if !hasNonPrinting([]byte{0x00}) {
		t.Error("hasNonPrinting should flag a NUL")
	}
	if hasNonPrinting([]byte("plain text\r\n\t")) {
		t.Error("ordinary text with whitespace is printing")
	}
}

func TestFollowOffsetBeyondTheEndIsEmptyNotAnError(t *testing.T) {
	f, err := tshark.ParseFollow("tcp", 0, followRaw)
	if err != nil {
		t.Fatal(err)
	}
	dirs := buildFollowResponse("ws", f, 9999, 10)["directions"].([]followWindow)
	for _, d := range dirs {
		if d.Bytes != 0 {
			t.Errorf("past the end should yield nothing, got %d bytes", d.Bytes)
		}
		if d.MoreAfter {
			t.Error("there is nothing after the end")
		}
	}
}
