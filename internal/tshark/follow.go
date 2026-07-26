package tshark

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

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

// ParseFollow parses `-z follow,<proto>,raw,<n>` output.
//
// The format is a banner, two Node lines, then one hex line per contiguous
// run of bytes. Direction is carried by indentation and nothing else: a line
// with a leading tab came from Node 1, an unindented line from Node 0.
func ParseFollow(protocol string, stream int64, out string) (*FollowResult, error) {
	res := &FollowResult{Protocol: protocol, Stream: stream}
	offsets := map[string]int{}

	for _, line := range strings.Split(out, "\n") {
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
	}
	return res, nil
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
