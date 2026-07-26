package transport

import (
	"bytes"
	"io"
	"strings"
	"sync"
	"testing"
)

func TestReadMessageReturnsLines(t *testing.T) {
	tr := NewStdioTransport(strings.NewReader("first\nsecond\n"), io.Discard)

	for _, want := range []string{"first", "second"} {
		got, err := tr.ReadMessage()
		if err != nil {
			t.Fatalf("ReadMessage: %v", err)
		}
		if string(got) != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
	if _, err := tr.ReadMessage(); err != io.EOF {
		t.Errorf("exhausted reader should yield io.EOF, got %v", err)
	}
}

// The scanner reuses its internal buffer, so a message handed to the caller
// must be a copy — otherwise the next Scan silently rewrites data the caller
// is still holding.
func TestReadMessageReturnsIndependentCopy(t *testing.T) {
	tr := NewStdioTransport(strings.NewReader("aaaa\nbbbb\n"), io.Discard)

	first, err := tr.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.ReadMessage(); err != nil {
		t.Fatal(err)
	}
	if string(first) != "aaaa" {
		t.Errorf("first message was clobbered by the second read: %q", first)
	}
}

// MCP payloads are routinely far larger than bufio's 64KB default, which is
// why the buffer is resized at construction.
func TestReadMessageHandlesLargeLine(t *testing.T) {
	large := strings.Repeat("x", 512*1024)
	tr := NewStdioTransport(strings.NewReader(large+"\n"), io.Discard)

	got, err := tr.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage on a %d byte line: %v", len(large), err)
	}
	if len(got) != len(large) {
		t.Errorf("got %d bytes, want %d", len(got), len(large))
	}
}

func TestWriteMessageEmitsOneJSONLine(t *testing.T) {
	var out bytes.Buffer
	tr := NewStdioTransport(strings.NewReader(""), &out)

	if err := tr.WriteMessage(map[string]string{"k": "v"}); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), "{\"k\":\"v\"}\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// HTML escaping would mangle display filters, which are full of & and <.
func TestWriteMessageDoesNotEscapeHTML(t *testing.T) {
	var out bytes.Buffer
	tr := NewStdioTransport(strings.NewReader(""), &out)

	if err := tr.WriteMessage(map[string]string{"filter": "tcp.port==80 && ip.len<100"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "&& ip.len<100") {
		t.Errorf("display filter operators were escaped: %s", out.String())
	}
}

// Async jobs complete on their own goroutines, so writes race unless
// serialized.
func TestWriteMessageIsSerialized(t *testing.T) {
	var out bytes.Buffer
	tr := NewStdioTransport(strings.NewReader(""), &out)

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			_ = tr.WriteMessage(map[string]int{"i": i})
		}(i)
	}
	wg.Wait()

	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != n {
		t.Fatalf("got %d lines, want %d (interleaved writes)", len(lines), n)
	}
	for _, l := range lines {
		if !strings.HasPrefix(l, `{"i":`) || !strings.HasSuffix(l, `}`) {
			t.Errorf("torn line: %q", l)
		}
	}
}
