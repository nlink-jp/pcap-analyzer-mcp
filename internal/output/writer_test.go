package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func row(i int) map[string]string {
	return map[string]string{"frame.number": fmt.Sprint(i), "ip.src": "10.0.0.1"}
}

func addAll(t *testing.T, w *Writer, n int) {
	t.Helper()
	for i := 1; i <= n; i++ {
		ok, err := w.Add(row(i))
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			return
		}
	}
}

func TestSmallResultStaysInline(t *testing.T) {
	w := NewWriter(t.TempDir(), "q1", nil, Options{InlineMaxBytes: 65536, RowLimit: 100, SampleRows: 5})
	addAll(t, w, 3)

	res, err := w.Finish("ws", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	if res.ResultFile != "" {
		t.Errorf("a small result must not touch disk, got %q", res.ResultFile)
	}
	if res.Delivery != "inline" {
		t.Errorf("Delivery = %q", res.Delivery)
	}
	if res.Rows == nil || len(*res.Rows) != 3 || res.Returned != 3 {
		t.Errorf("Rows=%v Returned=%d", res.Rows, res.Returned)
	}
	if res.Truncated {
		t.Error("nothing was dropped")
	}
}

// The threshold is bytes, so a handful of fat rows spills where many thin rows
// would not. That asymmetry is the entire point of counting bytes.
func TestByteThresholdNotRowCount(t *testing.T) {
	dir := t.TempDir()

	thin := NewWriter(dir, "thin", nil, Options{InlineMaxBytes: 512, RowLimit: 10000, SampleRows: 2})
	addAll(t, thin, 5)
	thinRes, err := thin.Finish("ws", "")
	if err != nil {
		t.Fatal(err)
	}
	if thinRes.ResultFile != "" {
		t.Errorf("5 small rows should stay inline, got %q", thinRes.ResultFile)
	}

	fat := NewWriter(dir, "fat", nil, Options{InlineMaxBytes: 512, RowLimit: 10000, SampleRows: 2})
	for i := 0; i < 5; i++ {
		if _, err := fat.Add(map[string]string{"payload": strings.Repeat("A", 400)}); err != nil {
			t.Fatal(err)
		}
	}
	fatRes, err := fat.Finish("ws", "")
	if err != nil {
		t.Fatal(err)
	}
	if fatRes.ResultFile == "" {
		t.Error("5 payload-carrying rows exceed the byte budget and must spill")
	}
	if fatRes.Returned != 5 {
		t.Errorf("Returned = %d, want 5", fatRes.Returned)
	}
}

// Rows buffered inline before the threshold was crossed must end up in the
// file too — losing them would silently drop the head of the result.
func TestSpillPreservesBufferedRows(t *testing.T) {
	w := NewWriter(t.TempDir(), "q", nil, Options{InlineMaxBytes: 120, RowLimit: 1000, SampleRows: 3})
	addAll(t, w, 20)

	res, err := w.Finish("ws", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.ResultFile == "" {
		t.Fatal("expected a spill")
	}

	f, err := os.Open(res.ResultFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if len(lines) != 20 {
		t.Fatalf("file holds %d rows, want all 20", len(lines))
	}
	var first map[string]string
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	if first["frame.number"] != "1" {
		t.Errorf("first row in the file is %v; the buffered head was lost", first)
	}
}

// A file-backed result still carries the leading rows, so the agent never
// needs an extra call just to see the shape of the data.
func TestFileResultCarriesSample(t *testing.T) {
	w := NewWriter(t.TempDir(), "q", nil, Options{InlineMaxBytes: 50, RowLimit: 1000, SampleRows: 3})
	addAll(t, w, 20)

	res, err := w.Finish("ws", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Sample == nil || len(*res.Sample) != 3 {
		t.Fatalf("Sample = %v, want 3 rows", res.Sample)
	}
	if res.Rows != nil {
		t.Error("a file-backed result must not also inline every row")
	}
	if res.Delivery != "file" {
		t.Errorf("Delivery = %q", res.Delivery)
	}
	if res.ResultBytes == 0 {
		t.Error("ResultBytes should report the file size")
	}
	if res.Format != "jsonl" {
		t.Errorf("Format = %q", res.Format)
	}
}

func TestRowLimitTruncates(t *testing.T) {
	w := NewWriter(t.TempDir(), "q", nil, Options{InlineMaxBytes: 1 << 20, RowLimit: 5, SampleRows: 2})
	addAll(t, w, 50)

	res, err := w.Finish("ws", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Returned != 5 {
		t.Errorf("Returned = %d, want 5", res.Returned)
	}
	if !res.Truncated {
		t.Error("hitting the row limit must set Truncated")
	}
}

// Add returning false is how the caller learns to stop draining tshark rather
// than reading a stream whose rows will be discarded.
func TestAddStopsAtLimit(t *testing.T) {
	w := NewWriter(t.TempDir(), "q", nil, Options{InlineMaxBytes: 1 << 20, RowLimit: 2})
	for i := 1; i <= 2; i++ {
		ok, err := w.Add(row(i))
		if err != nil || !ok {
			t.Fatalf("row %d: ok=%v err=%v", i, ok, err)
		}
	}
	ok, err := w.Add(row(3))
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("Add must report false once the limit is reached")
	}
}

// A row limit of zero means "give me everything", which cannot be an inline
// response.
func TestUnboundedAlwaysGoesToFile(t *testing.T) {
	w := NewWriter(t.TempDir(), "export", nil, Options{InlineMaxBytes: 1 << 20, RowLimit: 0, SampleRows: 2})
	addAll(t, w, 3)

	res, err := w.Finish("ws", "")
	if err != nil {
		t.Fatal(err)
	}
	if res.ResultFile == "" {
		t.Error("an unbounded export must be file-backed regardless of size")
	}
	if res.Truncated {
		t.Error("an unbounded export drops nothing")
	}
}

func TestEmptyResultIsAnEmptyArray(t *testing.T) {
	w := NewWriter(t.TempDir(), "q", nil, Options{InlineMaxBytes: 4096, RowLimit: 10})
	res, err := w.Finish("ws", "tcp.port == 9999")
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"rows":[]`) {
		t.Errorf("no matches must serialize as an empty array, got %s", b)
	}
}

// Inline and file-backed results must present the same keys for the fields
// they share, so the agent has nothing to branch on.
func TestShapeIsInvariant(t *testing.T) {
	dir := t.TempDir()

	small := NewWriter(dir, "small", nil, Options{InlineMaxBytes: 65536, RowLimit: 100, SampleRows: 2})
	addAll(t, small, 2)
	inline, err := small.Finish("ws", "tcp")
	if err != nil {
		t.Fatal(err)
	}

	big := NewWriter(dir, "big", nil, Options{InlineMaxBytes: 50, RowLimit: 100, SampleRows: 2})
	addAll(t, big, 40)
	spilled, err := big.Finish("ws", "tcp")
	if err != nil {
		t.Fatal(err)
	}

	for _, res := range []Result{inline, spilled} {
		var m map[string]any
		b, _ := json.Marshal(res)
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"workspace_id", "filter", "returned", "truncated", "delivery"} {
			if _, ok := m[key]; !ok {
				t.Errorf("%q missing from a result: %s", key, b)
			}
		}
	}
}

func TestCSVFormat(t *testing.T) {
	headers := []string{"frame.number", "ip.src"}
	w := NewWriter(t.TempDir(), "q", headers, Options{InlineMaxBytes: 10, RowLimit: 100, Format: "csv", SampleRows: 1})
	addAll(t, w, 3)

	res, err := w.Finish("ws", "")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Ext(res.ResultFile) != ".csv" {
		t.Errorf("ResultFile = %q, want a .csv", res.ResultFile)
	}
	b, err := os.ReadFile(res.ResultFile)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if lines[0] != "frame.number,ip.src" {
		t.Errorf("header = %q", lines[0])
	}
	if len(lines) != 4 {
		t.Errorf("got %d lines, want header + 3 rows: %q", len(lines), lines)
	}
}

func TestSetMatched(t *testing.T) {
	var res Result
	SetMatched(&res, 48213)
	if res.Matched == nil || *res.Matched != 48213 {
		t.Fatalf("Matched = %v", res.Matched)
	}

	var other Result
	SetMatchedUnavailable(&other, "count_timed_out")
	if other.Matched != nil {
		t.Error("Matched should stay absent")
	}
	if other.MatchedUnavailableReason != "count_timed_out" {
		t.Errorf("reason = %q", other.MatchedUnavailableReason)
	}
}

// Matched must be omitted rather than serialized as 0, which an agent would
// read as "no matches".
func TestMatchedOmittedWhenUnknown(t *testing.T) {
	b, err := json.Marshal(Result{WorkspaceID: "ws", Returned: 3})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"matched"`) {
		t.Errorf("an unknown match count must be omitted, not zero: %s", b)
	}
}
