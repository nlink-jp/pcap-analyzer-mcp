// Package mcpserver implements the MCP stdio server: protocol handling for
// initialize / notifications/initialized / tools/list / tools/call.
//
// Tool implementations live in internal/tools; the server only routes to them
// via the RegisterTool API.
package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/jsonrpc"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/transport"
)

// ProtocolVersion is the MCP protocol version this server advertises.
const ProtocolVersion = "2024-11-05"

// Tool is a single MCP tool descriptor returned by tools/list.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// ToolHandler is invoked when tools/call is received for a registered tool.
// The return value is JSON-serialized into a single text content block.
// Returning an error produces a result with isError=true per MCP convention.
type ToolHandler func(ctx context.Context, args json.RawMessage) (any, error)

// Server is the MCP stdio server.
type Server struct {
	name      string
	version   string
	tools     []Tool
	handlers  map[string]ToolHandler
	transport *transport.StdioTransport
	logger    *slog.Logger
}

// New creates a server bound to the given transport.
func New(name, version string, t *transport.StdioTransport, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Server{
		name:      name,
		version:   version,
		transport: t,
		handlers:  make(map[string]ToolHandler),
		logger:    logger,
	}
}

// RegisterTool registers a tool descriptor and its handler.
// Must be called before Serve.
func (s *Server) RegisterTool(t Tool, h ToolHandler) {
	s.tools = append(s.tools, t)
	s.handlers[t.Name] = h
}

// Serve reads requests in a loop until ctx is canceled or stdin returns EOF.
func (s *Server) Serve(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line, err := s.transport.ReadMessage()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := s.handle(ctx, line); err != nil {
			// handle() always either replies or (for notifications)
			// intentionally stays silent, so an error here means the write
			// itself failed; log and continue.
			s.logger.Warn("handle write failed", "err", err)
		}
	}
}

func (s *Server) handle(ctx context.Context, line []byte) error {
	var req jsonrpc.Request
	if err := json.Unmarshal(line, &req); err != nil {
		return s.writeError(nil, jsonrpc.CodeParseError, "parse error: "+err.Error())
	}
	if req.JSONRPC != "2.0" {
		return s.writeError(req.ID, jsonrpc.CodeInvalidRequest, "invalid jsonrpc version: "+req.JSONRPC)
	}

	// Notifications (no ID) do not produce a response per JSON-RPC spec.
	if req.IsNotification() {
		// Accept and discard: e.g. notifications/initialized.
		return nil
	}

	switch req.Method {
	case "initialize":
		return s.handleInitialize(req)
	case "tools/list":
		return s.handleToolsList(req)
	case "tools/call":
		return s.handleToolsCall(ctx, req)
	default:
		return s.writeError(req.ID, jsonrpc.CodeMethodNotFound, "method not found: "+req.Method)
	}
}

func (s *Server) writeResult(id *json.RawMessage, result any) error {
	rb, err := json.Marshal(result)
	if err != nil {
		return s.writeError(id, jsonrpc.CodeInternalError, "marshal result: "+err.Error())
	}
	return s.transport.WriteMessage(jsonrpc.Response{
		JSONRPC: "2.0",
		ID:      id,
		Result:  rb,
	})
}

func (s *Server) writeError(id *json.RawMessage, code int, msg string) error {
	return s.transport.WriteMessage(jsonrpc.Response{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &jsonrpc.Error{Code: code, Message: msg},
	})
}
