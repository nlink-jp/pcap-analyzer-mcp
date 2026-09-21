package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/config"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/tools"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/transport"
)

// The layer this test observes is the wiring: newServer, which serve's RunE
// calls to build the server it runs. That the instructions text is right is
// internal/tools' business, and that SetInstructions reaches the initialize
// result is internal/mcpserver's; neither notices a served binary that never
// calls SetInstructions, which is the defect caught here.
func TestServedServerSendsTheInstructions(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(config.EnvConfigPath, "")

	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n")
	var out bytes.Buffer
	srv := newServer(context.Background(), config.Default(), nil, "",
		transport.NewStdioTransport(in, &out), nil)
	if err := srv.Serve(context.Background()); err != nil {
		t.Fatalf("serve: %v", err)
	}

	var resp struct {
		Result struct {
			Instructions string `json:"instructions"`
		} `json:"result"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &resp); err != nil {
		t.Fatalf("decode initialize response: %v\nraw: %s", err, out.String())
	}
	if resp.Result.Instructions != tools.Instructions {
		t.Errorf("the served server's initialize instructions are %q, want tools.Instructions",
			resp.Result.Instructions)
	}
}
