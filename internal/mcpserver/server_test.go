package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/toolerr"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/transport"
)

func newTestServer(t *testing.T, input string) (*Server, *bytes.Buffer) {
	t.Helper()
	out := &bytes.Buffer{}
	tr := transport.NewStdioTransport(bytes.NewBufferString(input), out)
	return New("pcap-analyzer-mcp", "test", tr, slog.New(slog.NewTextHandler(io.Discard, nil))), out
}

// TestBasicRoundTrip drives the server with a canned sequence of stdio
// messages and checks that initialize / notifications/initialized / tools/list
// / tools/call round-trip correctly. bytes.Buffer reads EOF after exhaustion,
// which causes Serve to return cleanly.
func TestBasicRoundTrip(t *testing.T) {
	srv, out := newTestServer(t, strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"hello"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"missing","arguments":{}}}`,
	}, "\n")+"\n")

	srv.RegisterTool(Tool{
		Name:        "echo",
		Description: "Echo the input msg",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"msg":{"type":"string"}},"required":["msg"]}`),
	}, func(_ context.Context, args json.RawMessage) (any, error) {
		var in struct {
			Msg string `json:"msg"`
		}
		_ = json.Unmarshal(args, &in)
		return map[string]string{"echoed": in.Msg}, nil
	})

	if err := srv.Serve(context.Background()); err != nil {
		t.Fatalf("serve returned error: %v", err)
	}

	lines := splitLines(out.String())

	// Notifications get no response, so we expect 4 responses for IDs 1,2,3,4.
	if got, want := len(lines), 4; got != want {
		t.Fatalf("got %d response lines, want %d\nout:\n%s", got, want, out.String())
	}

	if !strings.Contains(lines[0], `"protocolVersion":"2024-11-05"`) {
		t.Errorf("initialize response missing protocolVersion: %s", lines[0])
	}
	if !strings.Contains(lines[0], `"name":"pcap-analyzer-mcp"`) {
		t.Errorf("initialize response missing server name: %s", lines[0])
	}
	if !strings.Contains(lines[1], `"name":"echo"`) {
		t.Errorf("tools/list response missing echo: %s", lines[1])
	}
	if !strings.Contains(lines[2], `hello`) {
		t.Errorf("tools/call echo did not echo hello: %s", lines[2])
	}
	if strings.Contains(lines[2], `"isError":true`) {
		t.Errorf("tools/call echo unexpectedly flagged isError: %s", lines[2])
	}
	if !strings.Contains(lines[3], `"error"`) || !strings.Contains(lines[3], `unknown tool`) {
		t.Errorf("unknown tool call did not return a JSON-RPC error: %s", lines[3])
	}
}

// TestParseError checks that malformed JSON gets a parse-error response with id=null.
func TestParseError(t *testing.T) {
	srv, out := newTestServer(t, "not-json\n")
	if err := srv.Serve(context.Background()); err != nil {
		t.Fatalf("serve: %v", err)
	}
	if !strings.Contains(out.String(), `"code":-32700`) {
		t.Errorf("expected parse-error code -32700; got: %s", out.String())
	}
	if !strings.Contains(out.String(), `"id":null`) {
		t.Errorf("expected id:null on parse error; got: %s", out.String())
	}
}

func TestWrongJSONRPCVersion(t *testing.T) {
	srv, out := newTestServer(t, `{"jsonrpc":"1.0","id":1,"method":"tools/list"}`+"\n")
	if err := srv.Serve(context.Background()); err != nil {
		t.Fatalf("serve: %v", err)
	}
	if !strings.Contains(out.String(), `"code":-32600`) {
		t.Errorf("expected invalid-request code -32600; got: %s", out.String())
	}
}

func TestToolsListEmptyIsArrayNotNull(t *testing.T) {
	srv, out := newTestServer(t, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n")
	if err := srv.Serve(context.Background()); err != nil {
		t.Fatalf("serve: %v", err)
	}
	if !strings.Contains(out.String(), `"tools":[]`) {
		t.Errorf("empty tool list must serialize as [] not null; got: %s", out.String())
	}
}

// A *toolerr.Error must reach the client as structured JSON so the agent can
// branch on the code, not as a flattened English sentence.
func TestStructuredToolErrorSurfacesCodeAndDetails(t *testing.T) {
	srv, out := newTestServer(t,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"boom","arguments":{}}}`+"\n")

	srv.RegisterTool(Tool{Name: "boom", InputSchema: json.RawMessage(`{"type":"object"}`)},
		func(_ context.Context, _ json.RawMessage) (any, error) {
			return nil, toolerr.New(toolerr.CodeInvalidDisplayFilter, "syntax error").
				WithDetails(map[string]any{"position": 14})
		})

	if err := srv.Serve(context.Background()); err != nil {
		t.Fatalf("serve: %v", err)
	}
	isError, te := decodeToolError(t, out.String())
	if !isError {
		t.Errorf("tool error must set isError: %s", out.String())
	}
	if te.Code != toolerr.CodeInvalidDisplayFilter {
		t.Errorf("code = %q, want %q", te.Code, toolerr.CodeInvalidDisplayFilter)
	}
	if te.Message != "syntax error" {
		t.Errorf("message = %q", te.Message)
	}
	if got, ok := te.Details["position"].(float64); !ok || got != 14 {
		t.Errorf("details.position = %v, want 14", te.Details["position"])
	}
}

// A toolerr wrapped by fmt.Errorf must still be recognised: handlers add
// context as they unwind, and losing the code at the boundary would strip the
// agent's ability to self-correct.
func TestWrappedToolErrorStillStructured(t *testing.T) {
	srv, out := newTestServer(t,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"boom","arguments":{}}}`+"\n")

	srv.RegisterTool(Tool{Name: "boom", InputSchema: json.RawMessage(`{"type":"object"}`)},
		func(_ context.Context, _ json.RawMessage) (any, error) {
			inner := toolerr.New(toolerr.CodeTsharkFailed, "exit 2")
			return nil, fmt.Errorf("podman run: %w", inner)
		})

	if err := srv.Serve(context.Background()); err != nil {
		t.Fatalf("serve: %v", err)
	}
	isError, te := decodeToolError(t, out.String())
	if !isError {
		t.Errorf("wrapped tool error must set isError: %s", out.String())
	}
	if te.Code != toolerr.CodeTsharkFailed {
		t.Errorf("the code must survive fmt.Errorf wrapping: got %q", te.Code)
	}
}

// decodeToolError unpacks the two layers a structured tool error travels
// through — the JSON-RPC response, then the JSON document carried inside the
// text content block — so assertions can be made on real values instead of
// substring-matching escaped JSON.
func decodeToolError(t *testing.T, response string) (isError bool, te toolerr.Error) {
	t.Helper()

	var resp struct {
		Result struct {
			Content []ContentBlock `json:"content"`
			IsError bool           `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(response)), &resp); err != nil {
		t.Fatalf("decode response: %v\nraw: %s", err, response)
	}
	if len(resp.Result.Content) != 1 {
		t.Fatalf("expected exactly one content block, got %d", len(resp.Result.Content))
	}
	if err := json.Unmarshal([]byte(resp.Result.Content[0].Text), &te); err != nil {
		t.Fatalf("content block is not a structured tool error: %v\ntext: %s",
			err, resp.Result.Content[0].Text)
	}
	return resp.Result.IsError, te
}

// A handler returning a non-toolerr error still produces a well-formed tool
// error rather than a protocol-level failure.
func TestPlainErrorBecomesToolError(t *testing.T) {
	srv, out := newTestServer(t,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"boom","arguments":{}}}`+"\n")

	srv.RegisterTool(Tool{Name: "boom", InputSchema: json.RawMessage(`{"type":"object"}`)},
		func(_ context.Context, _ json.RawMessage) (any, error) {
			return nil, errors.New("something went wrong")
		})

	if err := srv.Serve(context.Background()); err != nil {
		t.Fatalf("serve: %v", err)
	}
	s := out.String()
	if strings.Contains(s, `"error"`) {
		t.Errorf("a tool failure must not become a JSON-RPC error: %s", s)
	}
	if !strings.Contains(s, `"isError":true`) || !strings.Contains(s, "something went wrong") {
		t.Errorf("plain error not surfaced as a tool error: %s", s)
	}
}

func TestUnknownMethod(t *testing.T) {
	srv, out := newTestServer(t, `{"jsonrpc":"2.0","id":1,"method":"resources/list"}`+"\n")
	if err := srv.Serve(context.Background()); err != nil {
		t.Fatalf("serve: %v", err)
	}
	if !strings.Contains(out.String(), `"code":-32601`) {
		t.Errorf("expected method-not-found -32601; got: %s", out.String())
	}
}

func TestNotificationProducesNoResponse(t *testing.T) {
	srv, out := newTestServer(t, `{"jsonrpc":"2.0","method":"notifications/initialized"}`+"\n")
	if err := srv.Serve(context.Background()); err != nil {
		t.Fatalf("serve: %v", err)
	}
	if out.String() != "" {
		t.Errorf("a notification must produce no response; got: %s", out.String())
	}
}

// The content block type must be unable to carry inline bytes (ADR-0007).
// If someone adds a Data/MimeType field back, this fails.
func TestContentBlockCarriesTextOnly(t *testing.T) {
	b, err := json.Marshal(ContentBlock{Type: "text", Text: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(b), `{"type":"text","text":"x"}`; got != want {
		t.Errorf("ContentBlock JSON = %s, want %s (no byte-carrying fields)", got, want)
	}
}

func splitLines(s string) []string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
