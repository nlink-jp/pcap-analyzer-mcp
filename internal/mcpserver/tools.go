package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime/debug"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/jsonrpc"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/toolerr"
)

type toolsListResult struct {
	Tools []Tool `json:"tools"`
}

func (s *Server) handleToolsList(req jsonrpc.Request) error {
	// Always return a non-nil slice so the JSON has [] not null.
	tools := s.tools
	if tools == nil {
		tools = []Tool{}
	}
	return s.writeResult(req.ID, toolsListResult{Tools: tools})
}

type toolsCallParams struct {
	Name      string                     `json:"name"`
	Arguments json.RawMessage            `json:"arguments"`
	Meta      map[string]json.RawMessage `json:"_meta"`
}

// metaCtxKey carries the request's `_meta` object to tool handlers.
type metaCtxKey struct{}

// RequestMeta returns the `_meta` object of the tools/call being handled, or
// nil. It is how a calling runtime hands this server per-session facts — the
// work directory above all — without every tool declaring them in its schema
// (ADR-0008 §2). Values are raw JSON: this layer does not know what any key
// means.
func RequestMeta(ctx context.Context) map[string]json.RawMessage {
	m, _ := ctx.Value(metaCtxKey{}).(map[string]json.RawMessage)
	return m
}

// WithRequestMeta attaches a `_meta` object to ctx. Exported for tests and for
// hosts that drive tool handlers without the stdio transport.
func WithRequestMeta(ctx context.Context, meta map[string]json.RawMessage) context.Context {
	return context.WithValue(ctx, metaCtxKey{}, meta)
}

// ContentBlock is one block in the tools/call result.content array.
//
// Text is the only content kind this server emits. The MCP spec also defines
// image content (base64 `data` + `mimeType`), and data-toolbox-mcp uses it —
// but here every result is either a JSON summary or a path into the
// workspace. Bytes lifted out of a capture are never returned inline
// (ADR-0007), so the fields that would carry them are deliberately absent:
// the restriction is enforced by the type, not by reviewer vigilance.
type ContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type toolsCallResult struct {
	Content []ContentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}

func (s *Server) handleToolsCall(ctx context.Context, req jsonrpc.Request) error {
	var p toolsCallParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return s.writeError(req.ID, jsonrpc.CodeInvalidParams, "invalid params: "+err.Error())
	}
	h, ok := s.handlers[p.Name]
	if !ok {
		return s.writeError(req.ID, jsonrpc.CodeMethodNotFound, "unknown tool: "+p.Name)
	}
	if len(p.Meta) > 0 {
		ctx = WithRequestMeta(ctx, p.Meta)
	}
	out, err := s.invoke(ctx, h, p.Arguments)
	if err != nil {
		return s.writeToolError(req, err)
	}
	body, err := json.Marshal(out)
	if err != nil {
		return s.writeError(req.ID, jsonrpc.CodeInternalError, fmt.Sprintf("marshal tool result: %v", err))
	}
	return s.writeResult(req.ID, toolsCallResult{
		Content: []ContentBlock{{Type: "text", Text: string(body)}},
	})
}

// invoke calls a handler with a recover barrier.
//
// Handlers parse bytes derived from a hostile capture. A panic in one would
// otherwise take the whole server down and drop every queued job with it, so
// it is converted into a failed call instead.
func (s *Server) invoke(ctx context.Context, h ToolHandler, args json.RawMessage) (out any, err error) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("tool handler panicked", "panic", r, "stack", string(debug.Stack()))
			err = toolerr.Newf(toolerr.CodeInternalError,
				"the server hit a bug handling this call: %v", r)
		}
	}()
	return h(ctx, args)
}

// writeToolError emits a tool error per MCP convention: a result with
// isError=true and a single text content block. If err is (or wraps) a
// *toolerr.Error, the content carries the structured {code, message, details}
// JSON so LLM clients can branch on the code. Otherwise the plain Error()
// string is used.
func (s *Server) writeToolError(req jsonrpc.Request, err error) error {
	var te *toolerr.Error
	if errors.As(err, &te) {
		body, marshalErr := json.Marshal(te)
		if marshalErr == nil {
			return s.writeResult(req.ID, toolsCallResult{
				IsError: true,
				Content: []ContentBlock{{Type: "text", Text: string(body)}},
			})
		}
		// Fall through to plain text on marshal failure.
	}
	return s.writeResult(req.ID, toolsCallResult{
		IsError: true,
		Content: []ContentBlock{{Type: "text", Text: err.Error()}},
	})
}
