package output

import (
	"encoding/json"
	"strings"
	"testing"
)

func row(k, v string) map[string]string { return map[string]string{k: v} }

func addAll(t *testing.T, w *Writer, n int, value string) int {
	t.Helper()
	added := 0
	for i := 0; i < n; i++ {
		ok, err := w.Add(row("v", value))
		if err != nil {
			t.Fatalf("Add: %v", err)
		}
		if !ok {
			break
		}
		added++
	}
	return added
}

func TestSmallResultComesBackWhole(t *testing.T) {
	w := NewWriter(Options{MaxBytes: 65536, RowLimit: 100})
	addAll(t, w, 3, "x")

	res, err := w.Finish("ws", "ip")
	if err != nil {
		t.Fatal(err)
	}
	if res.Truncated || res.Note != "" {
		t.Errorf("a result that fit must not report truncation: %+v", res)
	}
	if res.Returned != 3 || len(*res.Rows) != 3 {
		t.Errorf("returned %d rows", res.Returned)
	}
}

// The budget is bytes, not rows: in pcap work a hundred rows carrying a
// payload column outweigh ten thousand rows of addresses. That half of
// ADR-0005 survives the withdrawal of file mediation.
func TestByteBudgetStopsBeforeTheRowLimit(t *testing.T) {
	big := strings.Repeat("A", 400)
	w := NewWriter(Options{MaxBytes: 1000, RowLimit: 1000})
	added := addAll(t, w, 50, big)

	res, err := w.Finish("ws", "")
	if err != nil {
		t.Fatal(err)
	}
	if added >= 50 {
		t.Fatalf("the byte budget did not stop the read: added %d", added)
	}
	if !res.Truncated {
		t.Error("a result stopped by the budget must say so")
	}
	if !strings.Contains(res.Note, "byte budget") {
		t.Errorf("the note must name the cap that stopped it: %q", res.Note)
	}
	if res.Rows == nil || len(*res.Rows) != res.Returned {
		t.Error("the rows that did fit must still come back")
	}
	// And the response actually respects the budget it was given.
	body, err := json.Marshal(res.Rows)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > 1000+len(big) {
		t.Errorf("rows serialize to %d bytes, well past the 1000-byte budget", len(body))
	}
}

func TestRowLimitStopsTheRead(t *testing.T) {
	w := NewWriter(Options{MaxBytes: 1 << 20, RowLimit: 5})
	// Add returns "stop" on the call that stores the last row, so the loop
	// exits one iteration early; Returned is the count that matters.
	addAll(t, w, 20, "x")

	res, err := w.Finish("ws", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Returned != 5 || len(*res.Rows) != 5 {
		t.Errorf("returned=%d rows=%d, want 5", res.Returned, len(*res.Rows))
	}
	if !res.Truncated || !strings.Contains(res.Note, "row limit") {
		t.Errorf("a result stopped by the row limit must name it: %+v", res)
	}
}

// Nothing is written to disk any more: the response is the delivery.
func TestResultCarriesNoFileChannel(t *testing.T) {
	w := NewWriter(Options{MaxBytes: 100, RowLimit: 0})
	addAll(t, w, 100, strings.Repeat("B", 200))
	res, err := w.Finish("ws", "")
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{"result_file", "delivery", "sample", "result_bytes"} {
		if strings.Contains(string(body), gone) {
			t.Errorf("the result still carries %q: %s", gone, body)
		}
	}
}

func TestEmptyResultIsAnEmptyArray(t *testing.T) {
	w := NewWriter(Options{MaxBytes: 65536, RowLimit: 10})
	res, err := w.Finish("ws", "tcp.port == 9999")
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"rows":[]`) {
		t.Errorf("zero matches must serialize as an empty array: %s", body)
	}
}

// The shape is the same whether or not the caps bit: an agent reads the same
// keys every time and branches on `truncated`, not on which keys exist.
func TestShapeIsInvariant(t *testing.T) {
	keysOf := func(w *Writer) []string {
		res, err := w.Finish("ws", "ip")
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]json.RawMessage
		b, err := json.Marshal(res)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		out := make([]string, 0, len(m))
		for k := range m {
			if k == "note" || k == "omitted_rows" {
				continue // present only when something was dropped
			}
			out = append(out, k)
		}
		return out
	}

	small := NewWriter(Options{MaxBytes: 65536, RowLimit: 100})
	addAll(t, small, 2, "x")
	large := NewWriter(Options{MaxBytes: 200, RowLimit: 100})
	addAll(t, large, 50, strings.Repeat("C", 100))

	a, b := keysOf(small), keysOf(large)
	if len(a) != len(b) {
		t.Fatalf("key sets differ: %v vs %v", a, b)
	}
	seen := map[string]bool{}
	for _, k := range a {
		seen[k] = true
	}
	for _, k := range b {
		if !seen[k] {
			t.Errorf("key %q appears only in the capped result", k)
		}
	}
}

// matched is the exact total, and the gap between it and what came back is
// counted rather than left for the agent to work out.
func TestSetMatchedCountsWhatWasLeftOut(t *testing.T) {
	w := NewWriter(Options{MaxBytes: 1 << 20, RowLimit: 5})
	addAll(t, w, 20, "x")
	res, err := w.Finish("ws", "ip")
	if err != nil {
		t.Fatal(err)
	}
	SetMatched(&res, 4200)

	if res.Matched == nil || *res.Matched != 4200 {
		t.Fatalf("matched = %v, want the exact 4200", res.Matched)
	}
	if res.OmittedRows != 4195 {
		t.Errorf("omitted_rows = %d, want 4195", res.OmittedRows)
	}
	if !res.Truncated {
		t.Error("a result missing matched packets is truncated")
	}
}

func TestMatchedOmittedWhenUnknown(t *testing.T) {
	w := NewWriter(Options{MaxBytes: 65536, RowLimit: 10})
	addAll(t, w, 2, "x")
	res, err := w.Finish("ws", "ip")
	if err != nil {
		t.Fatal(err)
	}
	SetMatchedUnavailable(&res, "tshark did not report a count")

	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"matched"`) {
		t.Errorf("an unknown count must be absent, not zero: %s", b)
	}
	if !strings.Contains(string(b), "matched_unavailable_reason") {
		t.Errorf("a missing count must say why: %s", b)
	}
}
