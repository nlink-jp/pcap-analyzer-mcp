// Package tshark builds tshark command lines and parses what comes back.
//
// Nothing here starts a container; the caller supplies the runner. Keeping
// argv construction and output parsing pure is what makes them testable
// against recorded output.
package tshark

// Capture is the fixed container-side path of the capture under analysis.
// The host filename never appears in an argv (ADR-0004).
const Capture = "/evidence/capture"

// fieldOutputStyle makes `-T fields` emit RFC 4180 CSV: a header row, comma
// separators, and double-quoted values. Quoting matters — display filters
// select fields whose values contain commas — and it lets encoding/csv do the
// parsing instead of hand-rolled splitting.
//
// `occurrence=f` keeps one value per field. A packet can carry a field more
// than once (nested IP headers, multiple HTTP headers); without this, one row
// would hold a comma-joined list and the column count would vary by packet.
var fieldOutputStyle = []string{
	"-E", "header=y",
	"-E", "separator=,",
	"-E", "quote=d",
	"-E", "occurrence=f",
}

// QueryArgs builds the argv for a field extraction.
//
// An empty filter is valid and means every packet.
func QueryArgs(filter string, fields []string) []string {
	args := []string{"tshark", "-r", Capture}
	if filter != "" {
		args = append(args, "-Y", filter)
	}
	args = append(args, "-T", "fields")
	args = append(args, fieldOutputStyle...)
	for _, f := range fields {
		args = append(args, "-e", f)
	}
	return args
}

// CountArgs builds the argv for the pass that counts filter matches.
//
// This runs only when a result was truncated (ADR-0005): the common path must
// not pay for a second traversal. frame.number is the cheapest field to ask
// for, and the count is the number of rows.
//
// It shares QueryArgs' output style rather than emitting bare values, because
// the same parser reads both. Without the header row that parser would treat
// the first packet as column names and undercount by one.
func CountArgs(filter string) []string {
	return QueryArgs(filter, []string{"frame.number"})
}

// HierarchyArgs builds the argv for protocol hierarchy statistics.
func HierarchyArgs(filter string) []string {
	args := []string{"tshark", "-r", Capture}
	if filter != "" {
		args = append(args, "-Y", filter)
	}
	return append(args, "-q", "-z", "io,phs")
}

// ConversationFields lists the fields aggregated into a conversation view.
//
// `-z conv,tcp` is deliberately not used: measurement against tshark 4.0.17
// confirmed its output carries no stream index, and its row order does not
// even follow stream order. Since list_conversations is the entry point to
// follow_stream, the index has to be real, so conversations are aggregated
// here from per-packet fields instead.
func ConversationFields(transport string) []string {
	common := []string{"ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "frame.len", "frame.time_epoch"}
	switch transport {
	case "udp":
		return append([]string{"udp.stream", "udp.srcport", "udp.dstport"}, common...)
	default:
		return append([]string{"tcp.stream", "tcp.srcport", "tcp.dstport"}, common...)
	}
}

// ConversationArgs builds the argv behind list_conversations.
func ConversationArgs(transport, filter string) []string {
	scoped := transport
	if filter != "" {
		scoped = "(" + transport + ") && (" + filter + ")"
	}
	return QueryArgs(scoped, ConversationFields(transport))
}

// VersionArgs reports the tshark build actually in use.
func VersionArgs() []string { return []string{"tshark", "--version"} }
