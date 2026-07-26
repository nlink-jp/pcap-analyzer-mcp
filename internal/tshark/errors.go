package tshark

import (
	"strings"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/toolerr"
)

// ClassifyError turns a non-zero tshark exit into a structured tool error.
//
// tshark's own diagnostics are unusually good — a bad display filter comes
// back with the expression echoed and a caret under the offending token — so
// the hint is built by forwarding that text rather than paraphrasing it. An
// agent that sees exactly which token was rejected fixes the filter on its
// next call; one that only sees "invalid filter" tries the same thing again.
//
// tshark's message is forwarded whatever the classification, so a
// misclassified error still tells the agent what happened; only the code it
// can branch on changes.
func ClassifyError(exitCode int, stderr string) error {
	msg := strings.TrimSpace(stderr)

	if fields := invalidFields(msg); len(fields) > 0 {
		return toolerr.Newf(toolerr.CodeInvalidArguments,
			"tshark does not know these fields: %s", strings.Join(fields, ", ")).
			WithDetails(map[string]any{
				"invalid_fields": fields,
				"tshark_message": msg,
				"hint": "Field names come from Wireshark's dissectors, e.g. " +
					"ip.src, tcp.stream, http.request.uri, dns.qry.name.",
			})
	}

	if looksLikeFilterError(msg) {
		details := map[string]any{"tshark_message": msg}
		if expr, col, ok := caretPosition(msg); ok {
			details["expression"] = expr
			details["column"] = col
		}
		return toolerr.Newf(toolerr.CodeInvalidDisplayFilter,
			"tshark rejected the display filter").WithDetails(details)
	}

	return toolerr.Newf(toolerr.CodeTsharkFailed, "tshark exited %d", exitCode).
		WithDetails(map[string]any{
			"exit_code":      exitCode,
			"tshark_message": truncate(msg, 2000),
		})
}

// invalidFields extracts the names from tshark's
// "Some fields aren't valid:\n\tfoo.bar" report.
func invalidFields(msg string) []string {
	const marker = "Some fields aren't valid:"
	i := strings.Index(msg, marker)
	if i < 0 {
		return nil
	}
	var out []string
	for _, line := range strings.Split(msg[i+len(marker):], "\n") {
		if f := strings.TrimSpace(line); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// filterErrorMarkers are the phrasings tshark uses when a display filter does
// not parse. They are matched narrowly on purpose: a genuine read failure must
// not be reported back to the agent as its own syntax mistake.
var filterErrorMarkers = []string{
	"was unexpected in this context",
	"Unexpected end of filter expression",
	"expression must be a field or function",
	"is neither a field nor a protocol name",
	"Invalid display filter",
	"syntax error",
}

func looksLikeFilterError(msg string) bool {
	for _, m := range filterErrorMarkers {
		if strings.Contains(msg, m) {
			return true
		}
	}
	return false
}

// caretPosition finds the echoed expression and the 1-based column the caret
// points at.
//
// tshark indents the expression and the caret line identically, so the caret's
// offset in its own line is its offset in the expression once the shared
// indentation is removed.
func caretPosition(msg string) (expr string, column int, ok bool) {
	lines := strings.Split(msg, "\n")
	for i := 1; i < len(lines); i++ {
		caret := lines[i]
		if !isCaretLine(caret) {
			continue
		}
		exprRaw := lines[i-1]
		idx := strings.Index(caret, "^")
		indent := len(exprRaw) - len(strings.TrimLeft(exprRaw, " \t"))

		column = idx - indent + 1
		if column < 1 {
			column = 1
		}
		return strings.TrimSpace(exprRaw), column, true
	}
	return "", 0, false
}

func isCaretLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}
	for _, r := range trimmed {
		if r != '^' && r != '~' {
			return false
		}
	}
	return true
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
