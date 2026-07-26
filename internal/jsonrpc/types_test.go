package jsonrpc_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/jsonrpc"
)

func TestIsNotification(t *testing.T) {
	var req jsonrpc.Request
	if err := json.Unmarshal([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`), &req); err != nil {
		t.Fatal(err)
	}
	if !req.IsNotification() {
		t.Error("a request without an id is a notification")
	}

	var withID jsonrpc.Request
	if err := json.Unmarshal([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`), &withID); err != nil {
		t.Fatal(err)
	}
	if withID.IsNotification() {
		t.Error("a request with an id is not a notification")
	}
}

// The spec allows string ids as well as numbers, and echoing the id back
// verbatim is the only way to stay correct for both.
func TestIDIsEchoedVerbatim(t *testing.T) {
	for _, raw := range []string{`1`, `"abc"`} {
		var req jsonrpc.Request
		if err := json.Unmarshal([]byte(`{"jsonrpc":"2.0","id":`+raw+`,"method":"tools/list"}`), &req); err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(jsonrpc.Response{JSONRPC: "2.0", ID: req.ID})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), `"id":`+raw) {
			t.Errorf("id %s not echoed verbatim: %s", raw, b)
		}
	}
}

// A response with no id must serialize as "id":null, not omit the field —
// that is what a parse error looks like on the wire.
func TestNilIDSerializesAsNull(t *testing.T) {
	b, err := json.Marshal(jsonrpc.Response{
		JSONRPC: "2.0",
		Error:   &jsonrpc.Error{Code: jsonrpc.CodeParseError, Message: "parse error"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"id":null`) {
		t.Errorf("expected id:null; got %s", b)
	}
}

func TestResultAndErrorAreMutuallyOmitted(t *testing.T) {
	b, err := json.Marshal(jsonrpc.Response{JSONRPC: "2.0", Result: json.RawMessage(`{"ok":true}`)})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"error"`) {
		t.Errorf("a success response must not carry an error key: %s", b)
	}
}
