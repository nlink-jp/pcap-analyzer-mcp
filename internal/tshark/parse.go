package tshark

import (
	"encoding/csv"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// Row is one packet's selected fields.
type Row map[string]string

// ParseFields reads `-T fields` CSV output and calls fn for each row.
//
// Streaming rather than returning a slice: a full pass over a large capture
// produces more rows than belong in memory, and the caller (internal/output)
// decides when to stop.
//
// fn returning false stops the read; that is the normal way a row limit is
// applied, since tshark itself cannot limit by filter matches.
func ParseFields(r io.Reader, fn func(Row) bool) error {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true

	header, err := cr.Read()
	if err == io.EOF {
		// No header means no packets matched, which is an answer, not a fault.
		return nil
	}
	if err != nil {
		return fmt.Errorf("read field header: %w", err)
	}

	for {
		rec, err := cr.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read field row: %w", err)
		}
		row := make(Row, len(header))
		for i, name := range header {
			if i < len(rec) {
				row[name] = rec[i]
			}
		}
		if !fn(row) {
			return nil
		}
	}
}

// ProtocolNode is one entry in the protocol hierarchy tree.
type ProtocolNode struct {
	Protocol string         `json:"protocol"`
	Frames   int64          `json:"frames"`
	Bytes    int64          `json:"bytes"`
	Children []ProtocolNode `json:"children,omitempty"`
}

// ParseProtocolHierarchy parses `-z io,phs` output.
//
// The format is an indented tree — two spaces per level — with
// "frames:N bytes:N" trailing each protocol name, wrapped in banner lines.
func ParseProtocolHierarchy(out string) ([]ProtocolNode, error) {
	// Built as a tree of pointers rather than by taking addresses into
	// growing slices: appending to a []ProtocolNode can reallocate it, which
	// would leave the parent pointers on the stack aimed at freed storage.
	type node struct {
		protocol      string
		frames, bytes int64
		children      []*node
	}
	type frame struct {
		node  *node
		depth int
	}
	var roots []*node
	var stack []frame

	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" ||
			strings.HasPrefix(strings.TrimSpace(line), "=") ||
			strings.HasPrefix(strings.TrimSpace(line), "Protocol Hierarchy") ||
			strings.HasPrefix(strings.TrimSpace(line), "Filter:") {
			continue
		}

		indent := len(line) - len(strings.TrimLeft(line, " "))
		depth := indent / 2

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		n := &node{protocol: fields[0]}
		for _, f := range fields[1:] {
			switch {
			case strings.HasPrefix(f, "frames:"):
				n.frames = parseInt64(strings.TrimPrefix(f, "frames:"))
			case strings.HasPrefix(f, "bytes:"):
				n.bytes = parseInt64(strings.TrimPrefix(f, "bytes:"))
			}
		}

		for len(stack) > 0 && stack[len(stack)-1].depth >= depth {
			stack = stack[:len(stack)-1]
		}
		if len(stack) == 0 {
			roots = append(roots, n)
		} else {
			parent := stack[len(stack)-1].node
			parent.children = append(parent.children, n)
		}
		stack = append(stack, frame{node: n, depth: depth})
	}

	var convert func(*node) ProtocolNode
	convert = func(n *node) ProtocolNode {
		out := ProtocolNode{Protocol: n.protocol, Frames: n.frames, Bytes: n.bytes}
		for _, c := range n.children {
			out.Children = append(out.Children, convert(c))
		}
		return out
	}
	result := make([]ProtocolNode, 0, len(roots))
	for _, r := range roots {
		result = append(result, convert(r))
	}
	return result, nil
}

// Conversation is one endpoint pair, keyed by the stream index that
// follow_stream needs.
type Conversation struct {
	Stream   int64  `json:"stream"`
	AAddress string `json:"a_address"`
	APort    string `json:"a_port"`
	BAddress string `json:"b_address"`
	BPort    string `json:"b_port"`

	FramesAToB int64 `json:"frames_a_to_b"`
	BytesAToB  int64 `json:"bytes_a_to_b"`
	FramesBToA int64 `json:"frames_b_to_a"`
	BytesBToA  int64 `json:"bytes_b_to_a"`
	Frames     int64 `json:"frames"`
	Bytes      int64 `json:"bytes"`

	StartEpoch float64 `json:"start_epoch"`
	EndEpoch   float64 `json:"end_epoch"`
}

// ConversationAggregator folds per-packet rows into conversations.
//
// "A" is whichever endpoint sent the first packet of the stream, matching how
// an analyst reads a conversation: the side that initiated it.
type ConversationAggregator struct {
	transport string
	byStream  map[int64]*Conversation
}

// NewConversationAggregator returns an aggregator for "tcp" or "udp".
func NewConversationAggregator(transport string) *ConversationAggregator {
	return &ConversationAggregator{
		transport: transport,
		byStream:  make(map[int64]*Conversation),
	}
}

// Add folds one packet row in.
func (a *ConversationAggregator) Add(row Row) {
	streamField := a.transport + ".stream"
	raw, ok := row[streamField]
	if !ok || raw == "" {
		return
	}
	stream, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return
	}

	src := firstNonEmpty(row["ip.src"], row["ipv6.src"])
	dst := firstNonEmpty(row["ip.dst"], row["ipv6.dst"])
	sport := row[a.transport+".srcport"]
	dport := row[a.transport+".dstport"]
	size := parseInt64(row["frame.len"])
	ts := parseFloat64(row["frame.time_epoch"])

	c, seen := a.byStream[stream]
	if !seen {
		c = &Conversation{
			Stream:     stream,
			AAddress:   src,
			APort:      sport,
			BAddress:   dst,
			BPort:      dport,
			StartEpoch: ts,
			EndEpoch:   ts,
		}
		a.byStream[stream] = c
	}

	if src == c.AAddress && sport == c.APort {
		c.FramesAToB++
		c.BytesAToB += size
	} else {
		c.FramesBToA++
		c.BytesBToA += size
	}
	c.Frames++
	c.Bytes += size
	if ts < c.StartEpoch {
		c.StartEpoch = ts
	}
	if ts > c.EndEpoch {
		c.EndEpoch = ts
	}
}

// Result returns the conversations, sorted and optionally capped.
//
// sortBy is "bytes" (the default, which makes the head of the list the top
// talkers), "frames", "start", or "stream".
func (a *ConversationAggregator) Result(sortBy string, topN int) []Conversation {
	out := make([]Conversation, 0, len(a.byStream))
	for _, c := range a.byStream {
		out = append(out, *c)
	}

	less := func(i, j int) bool { return out[i].Bytes > out[j].Bytes }
	switch sortBy {
	case "frames":
		less = func(i, j int) bool { return out[i].Frames > out[j].Frames }
	case "start":
		less = func(i, j int) bool { return out[i].StartEpoch < out[j].StartEpoch }
	case "stream":
		less = func(i, j int) bool { return out[i].Stream < out[j].Stream }
	}
	// Break ties on the stream index so the order is stable across runs.
	sort.SliceStable(out, func(i, j int) bool {
		if less(i, j) {
			return true
		}
		if less(j, i) {
			return false
		}
		return out[i].Stream < out[j].Stream
	})

	if topN > 0 && len(out) > topN {
		out = out[:topN]
	}
	return out
}

// Len reports how many distinct conversations have been seen.
func (a *ConversationAggregator) Len() int { return len(a.byStream) }

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func parseInt64(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}

func parseFloat64(s string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return f
}
