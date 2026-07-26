//go:build e2e

// Package e2e drives the built binary as a real MCP client would: over stdio,
// speaking JSON-RPC, against real podman and the real analysis image.
//
// The unit tests exercise the pieces against recorded output. This exercises
// the thing an agent actually talks to, which is where the defects that
// mattered have turned up.
package e2e

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"testing"
	"time"
)

// Client is a minimal MCP client over a subprocess's stdio.
type Client struct {
	cmd    *exec.Cmd
	in     io.WriteCloser
	out    *bufio.Reader
	nextID int
	t      *testing.T
}

// Start launches the server binary and completes the initialize handshake.
func Start(t *testing.T, binary string, args ...string) *Client {
	t.Helper()

	cmd := exec.Command(binary, append([]string{"serve"}, args...)...)
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	// Diagnostics go to stderr; keeping them off the protocol channel is the
	// property being relied on here.
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", binary, err)
	}

	c := &Client{cmd: cmd, in: in, out: bufio.NewReaderSize(out, 1<<20), t: t}
	t.Cleanup(c.Close)

	if _, err := c.request("initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "e2e", "version": "1"},
	}); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	c.notify("notifications/initialized")
	return c
}

// Close shuts the server down.
func (c *Client) Close() {
	_ = c.in.Close()
	done := make(chan struct{})
	go func() { _ = c.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = c.cmd.Process.Kill()
	}
}

// ToolNames returns the registered tool names.
func (c *Client) ToolNames() []string {
	c.t.Helper()
	raw, err := c.request("tools/list", nil)
	if err != nil {
		c.t.Fatalf("tools/list: %v", err)
	}
	var res struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		c.t.Fatal(err)
	}
	names := make([]string, 0, len(res.Tools))
	for _, t := range res.Tools {
		names = append(names, t.Name)
	}
	return names
}

// Call invokes a tool and decodes the JSON payload of its single text block.
// isError reports the MCP-level isError flag; a tool error is not a test
// failure, since several scenarios assert on one.
func (c *Client) Call(tool string, args map[string]any) (payload map[string]any, isError bool) {
	c.t.Helper()

	raw, err := c.request("tools/call", map[string]any{"name": tool, "arguments": args})
	if err != nil {
		c.t.Fatalf("%s: %v", tool, err)
	}
	var res struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		c.t.Fatalf("%s: decode result: %v", tool, err)
	}
	if len(res.Content) != 1 || res.Content[0].Type != "text" {
		c.t.Fatalf("%s: expected one text block, got %+v", tool, res.Content)
	}
	if err := json.Unmarshal([]byte(res.Content[0].Text), &payload); err != nil {
		c.t.Fatalf("%s: payload is not a JSON object: %v\n%s", tool, err, res.Content[0].Text)
	}
	return payload, res.IsError
}

// MustCall fails the test if the tool returned an error.
func (c *Client) MustCall(tool string, args map[string]any) map[string]any {
	c.t.Helper()
	p, isErr := c.Call(tool, args)
	if isErr {
		c.t.Fatalf("%s failed: %v", tool, p)
	}
	return p
}

// PollJob polls check_job until the job settles.
func (c *Client) PollJob(jobID string, timeout time.Duration) map[string]any {
	c.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st := c.MustCall("check_job", map[string]any{"job_id": jobID})
		switch st["state"] {
		case "done", "failed":
			return st
		}
		time.Sleep(50 * time.Millisecond)
	}
	c.t.Fatalf("job %s did not finish within %s", jobID, timeout)
	return nil
}

func (c *Client) request(method string, params any) (json.RawMessage, error) {
	c.nextID++
	id := c.nextID
	msg := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		msg["params"] = params
	}
	if err := c.write(msg); err != nil {
		return nil, err
	}

	line, err := c.out.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("read response to %s: %w", method, err)
	}
	var resp struct {
		ID     int             `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, fmt.Errorf("decode response to %s: %w\n%s", method, err, line)
	}
	if resp.ID != id {
		return nil, fmt.Errorf("response id %d does not match request %d", resp.ID, id)
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("jsonrpc error %d: %s", resp.Error.Code, resp.Error.Message)
	}
	return resp.Result, nil
}

func (c *Client) notify(method string) {
	_ = c.write(map[string]any{"jsonrpc": "2.0", "method": method})
}

func (c *Client) write(msg any) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if _, err := c.in.Write(append(b, '\n')); err != nil {
		return err
	}
	return nil
}
