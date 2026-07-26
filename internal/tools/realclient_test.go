package tools

import (
	"strings"
	"testing"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/tshark"
)

// Found by using the server from a real MCP client: on a capture whose snaplen
// cut the transport header, list_conversations returned [] with no
// explanation. There were two TCP conversations; an agent reading that
// concludes there were none.
func TestAggregatorDistinguishesNoPacketsFromNoStreamIndex(t *testing.T) {
	empty := tshark.NewConversationAggregator("tcp", 0)
	if empty.Seen() != 0 || empty.WithoutStream() != 0 {
		t.Errorf("nothing added: seen=%d withoutStream=%d", empty.Seen(), empty.WithoutStream())
	}

	// What a 40-byte snaplen produces: addresses survive, the stream index
	// does not.
	cut := tshark.NewConversationAggregator("tcp", 0)
	for i := 0; i < 4; i++ {
		cut.Add(tshark.Row{"ip.src": "10.0.0.10", "ip.dst": "203.0.113.66",
			"tcp.dstport": "80", "tcp.stream": "", "frame.len": "140"})
	}
	if len(cut.Result("bytes", 0)) != 0 {
		t.Fatal("no stream index means no conversations can be built")
	}
	if cut.Seen() != 4 || cut.WithoutStream() != 4 {
		t.Errorf("seen=%d withoutStream=%d; both are needed to tell this from an empty capture",
			cut.Seen(), cut.WithoutStream())
	}
}

// get_usage drifted from the code: extract_objects gained async but the text
// still listed four tools, and the suggested flow stopped before the payload
// tools existed at all.
func TestUsageMatchesTheToolsThatExist(t *testing.T) {
	doc := usageDoc(65536, 10000)

	async := strings.Join(toStrings(t, doc["async"]), " ")
	for _, tool := range []string{
		"create_workspace", "protocol_hierarchy", "list_conversations",
		"query_packets", "extract_objects",
	} {
		if !strings.Contains(async, tool) {
			t.Errorf("async guidance omits %s, which accepts async", tool)
		}
	}
	if !strings.Contains(async, "follow_stream does not") {
		t.Error("the one tool that does not take async should be named")
	}

	flow := strings.Join(toStrings(t, doc["suggested_flow"]), " ")
	for _, tool := range []string{"follow_stream", "extract_objects"} {
		if !strings.Contains(flow, tool) {
			t.Errorf("an agent following suggested_flow would never discover %s", tool)
		}
	}
}

func toStrings(t *testing.T, v any) []string {
	t.Helper()
	items, ok := v.([]string)
	if !ok {
		t.Fatalf("expected []string, got %T", v)
	}
	return items
}
