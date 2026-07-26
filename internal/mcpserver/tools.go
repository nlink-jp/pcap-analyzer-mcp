package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

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
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
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
	out, err := h(ctx, p.Arguments)
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
