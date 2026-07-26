package tshark

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// maxFollowLineBytes bounds one hex line. tshark emits a contiguous run of
// bytes as a single line, so this also bounds a single chunk.
const maxFollowLineBytes = 64 * 1024 * 1024

// FollowArgs builds the argv that reassembles one stream.
//
// The `raw` mode is used rather than `ascii`: it emits hex, which survives
// binary content unchanged and leaves the decision about how to present the
// bytes here rather than inside tshark's formatter.
func FollowArgs(protocol string, stream int64) []string {
	return []string{
		"tshark", "-r", Capture, "-q",
		"-z", fmt.Sprintf("follow,%s,raw,%d", protocol, stream),
	}
}

// FollowChunk is one contiguous run of bytes in one direction.
type FollowChunk struct {
	// From and To are the endpoints, so a caller never has to work out which
	// side "client" meant.
	From string `json:"from"`
	To   string `json:"to"`
	// Offset is this chunk's position within its direction's byte stream.
	Offset int    `json:"offset"`
	Bytes  int    `json:"bytes"`
	Data   []byte `json:"-"`
}

// FollowResult is a reassembled stream, split by direction.
type FollowResult struct {
	Protocol string        `json:"protocol"`
	Stream   int64         `json:"stream"`
	NodeA    string        `json:"node_a"`
	NodeB    string        `json:"node_b"`
	Chunks   []FollowChunk `json:"chunks"`
	// TotalBytes is the whole reassembled stream, before any windowing.
	TotalBytes int `json:"total_bytes"`
}

// ParseFollow parses `-z follow,<proto>,raw,<n>` output held in memory.
//
// Prefer ParseFollowStream for real captures: a single stream can be a
// multi-gigabyte transfer, and its hex rendering is twice that again.
func ParseFollow(protocol string, stream int64, out string) (*FollowResult, error) {
	res, _, err := ParseFollowStream(protocol, stream, strings.NewReader(out), 0)
	return res, err
}

// ParseFollowStream parses `-z follow,<proto>,raw,<n>` output as it arrives,
// accumulating at most budget decoded bytes.
//
// The budget is what keeps a large transfer from being pulled into memory
// whole — the threat ADR-0007 names but that a buffered read would not
// actually address, since the windowing happens after the bytes have already
// landed. A budget of 0 means unbounded and is only for tests.
//
// The format is a banner, two Node lines, then one hex line per contiguous run
// of bytes. Direction is carried by indentation and nothing else: a line with
// a leading tab came from Node 1, an unindented line from Node 0.
func ParseFollowStream(protocol string, stream int64, r io.Reader, budget int) (*FollowResult, bool, error) {
	res := &FollowResult{Protocol: protocol, Stream: stream}
	offsets := map[string]int{}
	truncated := false

	sc := bufio.NewScanner(r)
	// A single contiguous run is one line of hex, so lines are long.
	sc.Buffer(make([]byte, 0, 64*1024), maxFollowLineBytes)

	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "" || strings.HasPrefix(trimmed, "="):
			continue
		case strings.HasPrefix(trimmed, "Follow:"), strings.HasPrefix(trimmed, "Filter:"):
			continue
		case strings.HasPrefix(trimmed, "Node 0:"):
			res.NodeA = strings.TrimSpace(strings.TrimPrefix(trimmed, "Node 0:"))
			continue
		case strings.HasPrefix(trimmed, "Node 1:"):
			res.NodeB = strings.TrimSpace(strings.TrimPrefix(trimmed, "Node 1:"))
			continue
		}

		fromB := strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "    ")
		data, err := hex.DecodeString(trimmed)
		if err != nil {
			// Not a hex payload line; tshark occasionally emits notes here.
			continue
		}

		if budget > 0 && res.TotalBytes+len(data) > budget {
			// Keep the part that fits so a window near the budget still has
			// data, then stop reading rather than growing without limit.
			if keep := budget - res.TotalBytes; keep > 0 {
				data = data[:keep]
			} else {
				truncated = true
				break
			}
			truncated = true
		}

		from, to := res.NodeA, res.NodeB
		if fromB {
			from, to = res.NodeB, res.NodeA
		}
		res.Chunks = append(res.Chunks, FollowChunk{
			From:   from,
			To:     to,
			Offset: offsets[from],
			Bytes:  len(data),
			Data:   data,
		})
		offsets[from] += len(data)
		res.TotalBytes += len(data)

		if truncated {
			break
		}
	}
	if err := sc.Err(); err != nil {
		return nil, truncated, fmt.Errorf("read follow output: %w", err)
	}
	return res, truncated, nil
}

// StreamFromRow extracts a stream index from a field row, for callers that
// found the stream via query_packets rather than list_conversations.
func StreamFromRow(row Row, transport string) (int64, bool) {
	raw, ok := row[transport+".stream"]
	if !ok || raw == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	return n, err == nil
}

// ExportObjectsArgs builds the argv that writes protocol objects into dir.
func ExportObjectsArgs(protocol, dir string) []string {
	return []string{
		"tshark", "-r", Capture, "-q",
		"--export-objects", protocol + "," + dir,
	}
}
