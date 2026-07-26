package tshark

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/toolerr"
)

// --- argv -------------------------------------------------------------------

func TestQueryArgsShape(t *testing.T) {
	got := strings.Join(QueryArgs("tcp.port == 80", []string{"ip.src", "ip.dst"}), " ")
	for _, want := range []string{
		"tshark -r " + Capture,
		"-Y tcp.port == 80",
		"-T fields",
		"-E header=y", "-E separator=,", "-E quote=d", "-E occurrence=f",
		"-e ip.src", "-e ip.dst",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("argv missing %q: %s", want, got)
		}
	}
}

func TestQueryArgsOmitsEmptyFilter(t *testing.T) {
	if strings.Contains(strings.Join(QueryArgs("", []string{"ip.src"}), " "), "-Y") {
		t.Error("an empty filter must not produce a -Y flag")
	}
}

// The count pass is parsed by the same reader as a query, so it needs the same
// header row. Without one the first packet would be eaten as column names and
// every count would be short by one.
func TestCountArgsEmitsAHeader(t *testing.T) {
	got := strings.Join(CountArgs("tcp"), " ")
	if !strings.Contains(got, "-E header=y") {
		t.Errorf("count pass must emit a header row: %s", got)
	}
	if !strings.Contains(got, "-e frame.number") {
		t.Errorf("count pass should ask for the cheapest field: %s", got)
	}
}

// list_conversations is the entry point to follow_stream, so the stream index
// must be among the fields collected.
func TestConversationFieldsCarryTheStreamIndex(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		fields := ConversationFields(transport)
		want := transport + ".stream"
		found := false
		for _, f := range fields {
			if f == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s conversation fields lack %s: %v", transport, want, fields)
		}
	}
}

func TestConversationArgsScopesTheFilter(t *testing.T) {
	got := strings.Join(ConversationArgs("tcp", "ip.addr == 10.0.0.1"), " ")
	if !strings.Contains(got, "-Y (tcp) && (ip.addr == 10.0.0.1)") {
		t.Errorf("the caller's filter must be ANDed with the transport, not replace it: %s", got)
	}
}

// --- field parsing ----------------------------------------------------------

const fieldsCSV = `frame.number,ip.src,_ws.col.Info
"1","10.1.1.1","GET / HTTP/1.1 "
"2","10.1.1.1","GET /a,b HTTP/1.1"
`

func TestParseFields(t *testing.T) {
	var rows []Row
	if err := ParseFields(strings.NewReader(fieldsCSV), func(r Row) bool {
		rows = append(rows, r)
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	if rows[0]["frame.number"] != "1" || rows[0]["ip.src"] != "10.1.1.1" {
		t.Errorf("row 0 = %v", rows[0])
	}
	// Quoting is why the output style asks for it: a comma inside a value
	// must not become a column break.
	if rows[1]["_ws.col.Info"] != "GET /a,b HTTP/1.1" {
		t.Errorf("a quoted comma was split: %q", rows[1]["_ws.col.Info"])
	}
}

// No matches means tshark prints nothing at all, not even a header. That is an
// answer, not a parse failure.
func TestParseFieldsEmptyOutput(t *testing.T) {
	n := 0
	if err := ParseFields(strings.NewReader(""), func(Row) bool { n++; return true }); err != nil {
		t.Fatalf("empty output must not error: %v", err)
	}
	if n != 0 {
		t.Errorf("got %d rows", n)
	}
}

func TestParseFieldsStopsWhenCallbackSaysSo(t *testing.T) {
	n := 0
	if err := ParseFields(strings.NewReader(fieldsCSV), func(Row) bool {
		n++
		return false
	}); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("read %d rows after being told to stop at 1", n)
	}
}

// --- protocol hierarchy -----------------------------------------------------

// Verbatim from `tshark -q -z io,phs` in the analysis image.
const phsOutput = `
===================================================================
Protocol Hierarchy Statistics
Filter:

eth                                      frames:2 bytes:144
  ip                                     frames:2 bytes:144
    tcp                                  frames:2 bytes:144
      http                               frames:2 bytes:144
===================================================================
`

func TestParseProtocolHierarchy(t *testing.T) {
	tree, err := ParseProtocolHierarchy(phsOutput)
	if err != nil {
		t.Fatal(err)
	}
	if len(tree) != 1 || tree[0].Protocol != "eth" {
		t.Fatalf("roots = %+v", tree)
	}
	if tree[0].Frames != 2 || tree[0].Bytes != 144 {
		t.Errorf("eth counts = %d/%d", tree[0].Frames, tree[0].Bytes)
	}
	ip := tree[0].Children
	if len(ip) != 1 || ip[0].Protocol != "ip" {
		t.Fatalf("eth children = %+v", ip)
	}
	if len(ip[0].Children) != 1 || ip[0].Children[0].Protocol != "tcp" {
		t.Fatalf("ip children = %+v", ip[0].Children)
	}
	if len(ip[0].Children[0].Children) != 1 || ip[0].Children[0].Children[0].Protocol != "http" {
		t.Fatalf("tcp children = %+v", ip[0].Children[0].Children)
	}
}

// Siblings at the same depth must all survive. An earlier version built the
// tree by taking addresses into a growing slice, which silently dropped
// children once the slice reallocated.
func TestParseProtocolHierarchyKeepsSiblings(t *testing.T) {
	out := `
eth                     frames:10 bytes:1000
  ip                    frames:6 bytes:600
    tcp                 frames:4 bytes:400
    udp                 frames:2 bytes:200
  arp                   frames:4 bytes:400
`
	tree, err := ParseProtocolHierarchy(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(tree) != 1 {
		t.Fatalf("roots = %d", len(tree))
	}
	eth := tree[0]
	if len(eth.Children) != 2 {
		t.Fatalf("eth should have ip and arp, got %+v", eth.Children)
	}
	if eth.Children[0].Protocol != "ip" || eth.Children[1].Protocol != "arp" {
		t.Errorf("children = %+v", eth.Children)
	}
	if len(eth.Children[0].Children) != 2 {
		t.Errorf("ip should have tcp and udp, got %+v", eth.Children[0].Children)
	}
}

func TestParseProtocolHierarchyEmpty(t *testing.T) {
	tree, err := ParseProtocolHierarchy("===\nProtocol Hierarchy Statistics\nFilter: \n===\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(tree) != 0 {
		t.Errorf("got %+v", tree)
	}
}

// --- conversations ----------------------------------------------------------

func TestConversationAggregation(t *testing.T) {
	agg := NewConversationAggregator("tcp", 0)
	// Two packets out, one back, on the same stream.
	agg.Add(Row{"tcp.stream": "0", "ip.src": "10.0.0.1", "tcp.srcport": "1234",
		"ip.dst": "10.0.0.2", "tcp.dstport": "80", "frame.len": "100", "frame.time_epoch": "10"})
	agg.Add(Row{"tcp.stream": "0", "ip.src": "10.0.0.1", "tcp.srcport": "1234",
		"ip.dst": "10.0.0.2", "tcp.dstport": "80", "frame.len": "50", "frame.time_epoch": "11"})
	agg.Add(Row{"tcp.stream": "0", "ip.src": "10.0.0.2", "tcp.srcport": "80",
		"ip.dst": "10.0.0.1", "tcp.dstport": "1234", "frame.len": "500", "frame.time_epoch": "12"})

	got := agg.Result("bytes", 0)
	if len(got) != 1 {
		t.Fatalf("got %d conversations, want 1", len(got))
	}
	c := got[0]
	// "A" is whoever spoke first, which is how an analyst reads a conversation.
	if c.AAddress != "10.0.0.1" || c.APort != "1234" {
		t.Errorf("A endpoint = %s:%s, want the initiator", c.AAddress, c.APort)
	}
	if c.FramesAToB != 2 || c.BytesAToB != 150 {
		t.Errorf("A→B = %d frames / %d bytes", c.FramesAToB, c.BytesAToB)
	}
	if c.FramesBToA != 1 || c.BytesBToA != 500 {
		t.Errorf("B→A = %d frames / %d bytes", c.FramesBToA, c.BytesBToA)
	}
	if c.Frames != 3 || c.Bytes != 650 {
		t.Errorf("totals = %d / %d", c.Frames, c.Bytes)
	}
	if c.StartEpoch != 10 || c.EndEpoch != 12 {
		t.Errorf("span = %v..%v", c.StartEpoch, c.EndEpoch)
	}
}

func TestConversationAggregatorIgnoresRowsWithoutAStream(t *testing.T) {
	agg := NewConversationAggregator("tcp", 0)
	agg.Add(Row{"ip.src": "10.0.0.1"})            // e.g. an ARP frame
	agg.Add(Row{"tcp.stream": "", "ip.src": "x"}) // field present but empty
	if agg.Len() != 0 {
		t.Errorf("got %d conversations", agg.Len())
	}
}

func TestConversationAggregatorIPv6(t *testing.T) {
	agg := NewConversationAggregator("udp", 0)
	agg.Add(Row{"udp.stream": "3", "ipv6.src": "2001:db8::1", "udp.srcport": "53",
		"ipv6.dst": "2001:db8::2", "udp.dstport": "5353", "frame.len": "80"})
	got := agg.Result("bytes", 0)
	if len(got) != 1 || got[0].AAddress != "2001:db8::1" {
		t.Errorf("IPv6 addresses not picked up: %+v", got)
	}
}

func TestConversationSortAndTopN(t *testing.T) {
	agg := NewConversationAggregator("tcp", 0)
	for i, size := range []string{"100", "900", "500"} {
		agg.Add(Row{"tcp.stream": string(rune('0' + i)), "ip.src": "a", "tcp.srcport": "1",
			"ip.dst": "b", "tcp.dstport": "2", "frame.len": size, "frame.time_epoch": "1"})
	}
	top := agg.Result("bytes", 2)
	if len(top) != 2 {
		t.Fatalf("top_n ignored: %d", len(top))
	}
	if top[0].Bytes != 900 || top[1].Bytes != 500 {
		t.Errorf("not sorted by bytes descending: %+v", top)
	}
	if byStream := agg.Result("stream", 0); byStream[0].Stream != 0 {
		t.Errorf("sort_by=stream should start at 0, got %d", byStream[0].Stream)
	}
}

// --- error classification ---------------------------------------------------

// Verbatim from tshark 4.0.17.
const badFilterMsg = `tshark: Left side of "==" expression must be a field or function, not tcp.flags.zyn.
    tcp.flags.zyn == 1
    ^~~~~~~~~~~~~`

func TestClassifyFilterError(t *testing.T) {
	err := ClassifyError(2, badFilterMsg)
	if !errors.Is(err, toolerr.New(toolerr.CodeInvalidDisplayFilter, "")) {
		t.Fatalf("want invalid_display_filter, got %v", err)
	}
	var te *toolerr.Error
	errors.As(err, &te)

	if te.Details["expression"] != "tcp.flags.zyn == 1" {
		t.Errorf("expression = %v", te.Details["expression"])
	}
	if te.Details["column"] != 1 {
		t.Errorf("column = %v, want 1 (the caret sits under the first token)", te.Details["column"])
	}
	// tshark's own wording is the most useful thing here; it must survive.
	if msg, _ := te.Details["tshark_message"].(string); !strings.Contains(msg, "tcp.flags.zyn") {
		t.Errorf("tshark's message was lost: %v", te.Details["tshark_message"])
	}
}

func TestClassifyFilterErrorMidExpression(t *testing.T) {
	msg := "tshark: \"=\" was unexpected in this context.\n    tcp.port = 80\n             ^"
	err := ClassifyError(2, msg)
	var te *toolerr.Error
	if !errors.As(err, &te) {
		t.Fatal(err)
	}
	if te.Details["column"] != 10 {
		t.Errorf("column = %v, want 10 (position of '=' in \"tcp.port = 80\")", te.Details["column"])
	}
}

// Not every filter error carries a caret; the classification must still hold.
func TestClassifyFilterErrorWithoutCaret(t *testing.T) {
	err := ClassifyError(2, "tshark: Unexpected end of filter expression.")
	if !errors.Is(err, toolerr.New(toolerr.CodeInvalidDisplayFilter, "")) {
		t.Fatalf("got %v", err)
	}
	var te *toolerr.Error
	errors.As(err, &te)
	if _, ok := te.Details["column"]; ok {
		t.Error("no caret means no column should be claimed")
	}
}

func TestClassifyInvalidFields(t *testing.T) {
	err := ClassifyError(2, "tshark: Some fields aren't valid:\n\tnosuch.field\n\talso.bad")
	var te *toolerr.Error
	if !errors.As(err, &te) {
		t.Fatal(err)
	}
	if te.Code != toolerr.CodeInvalidArguments {
		t.Errorf("code = %s", te.Code)
	}
	fields, _ := te.Details["invalid_fields"].([]string)
	if len(fields) != 2 || fields[0] != "nosuch.field" || fields[1] != "also.bad" {
		t.Errorf("invalid_fields = %v", te.Details["invalid_fields"])
	}
}

// An unrelated failure must not be blamed on the agent's filter.
func TestClassifyUnknownFailure(t *testing.T) {
	err := ClassifyError(2, "tshark: The file \"/evidence/capture\" appears to be damaged.")
	if !errors.Is(err, toolerr.New(toolerr.CodeTsharkFailed, "")) {
		t.Fatalf("want tshark_failed, got %v", err)
	}
	var te *toolerr.Error
	errors.As(err, &te)
	if te.Details["exit_code"] != 2 {
		t.Errorf("exit code should reach the agent: %v", te.Details)
	}
}

// The aggregator map lives in the server process, outside the container's
// memory cgroup, and top_n is applied after aggregation — so neither bounds it.
func TestConversationAggregatorCapsDistinctStreams(t *testing.T) {
	agg := NewConversationAggregator("tcp", 2)
	for i := 0; i < 10; i++ {
		agg.Add(Row{
			"tcp.stream": strconv.Itoa(i), "ip.src": "a", "tcp.srcport": "1",
			"ip.dst": "b", "tcp.dstport": "2", "frame.len": "10", "frame.time_epoch": "1",
		})
	}
	if agg.Len() != 2 {
		t.Errorf("held %d streams with a cap of 2", agg.Len())
	}
	if agg.Dropped() != 8 {
		t.Errorf("Dropped = %d, want 8 — silence here would read as a complete list", agg.Dropped())
	}
}

// Packets belonging to streams already known keep counting after the cap is
// reached; only new streams are refused.
func TestConversationAggregatorKeepsCountingKnownStreams(t *testing.T) {
	agg := NewConversationAggregator("tcp", 1)
	row := func(stream string) Row {
		return Row{"tcp.stream": stream, "ip.src": "a", "tcp.srcport": "1",
			"ip.dst": "b", "tcp.dstport": "2", "frame.len": "10", "frame.time_epoch": "1"}
	}
	agg.Add(row("0"))
	agg.Add(row("1")) // refused
	agg.Add(row("0")) // still counted

	got := agg.Result("bytes", 0)
	if len(got) != 1 || got[0].Frames != 2 {
		t.Errorf("known stream stopped accumulating: %+v", got)
	}
}
