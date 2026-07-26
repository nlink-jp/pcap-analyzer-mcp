// Package transport provides the stdio JSON-RPC transport used by the MCP server.
//
// Each JSON-RPC message is one line (newline-terminated). The buffer is sized
// to 1MB per line, following the pattern in nlink-jp/mcp-guardian.
package transport

import (
	"bufio"
	"encoding/json"
	"io"
	"sync"
)

// MaxLineSize is the maximum size of a single JSON-RPC message line.
const MaxLineSize = 1024 * 1024 // 1MB

// StdioTransport reads newline-delimited JSON messages from an io.Reader
// and writes them to an io.Writer.
type StdioTransport struct {
	scanner *bufio.Scanner
	out     io.Writer
	mu      sync.Mutex
}

// NewStdioTransport wires a transport around the given Reader/Writer.
func NewStdioTransport(in io.Reader, out io.Writer) *StdioTransport {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, MaxLineSize), MaxLineSize)
	return &StdioTransport{scanner: scanner, out: out}
}

// ReadMessage returns the next line from stdin, or io.EOF when stdin is closed.
// The returned slice is owned by the caller (a fresh copy).
func (t *StdioTransport) ReadMessage() ([]byte, error) {
	if t.scanner.Scan() {
		src := t.scanner.Bytes()
		line := make([]byte, len(src))
		copy(line, src)
		return line, nil
	}
	if err := t.scanner.Err(); err != nil {
		return nil, err
	}
	return nil, io.EOF
}

// WriteMessage encodes msg as JSON and writes it as a single newline-terminated line.
// Writes are serialized; safe to call from multiple goroutines.
func (t *StdioTransport) WriteMessage(msg any) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	enc := json.NewEncoder(t.out)
	enc.SetEscapeHTML(false)
	return enc.Encode(msg)
}
