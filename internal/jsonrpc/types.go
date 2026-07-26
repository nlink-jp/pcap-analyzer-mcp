// Package jsonrpc defines JSON-RPC 2.0 message types used over the MCP stdio channel.
//
// Spec: https://www.jsonrpc.org/specification
package jsonrpc

import "encoding/json"

// Request is a JSON-RPC 2.0 request or notification.
// A notification has no ID (IsNotification reports true).
type Request struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Method  string           `json:"method"`
	Params  json.RawMessage  `json:"params,omitempty"`
}

// IsNotification reports whether the request is a notification (no response expected).
func (r *Request) IsNotification() bool {
	return r.ID == nil
}

// Response is a JSON-RPC 2.0 response.
// Exactly one of Result or Error must be set.
type Response struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id"`
	Result  json.RawMessage  `json:"result,omitempty"`
	Error   *Error           `json:"error,omitempty"`
}

// Error is a JSON-RPC 2.0 error payload.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}
