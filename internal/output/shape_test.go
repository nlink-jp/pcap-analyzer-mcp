package output

import (
	"encoding/json"
	"testing"
)

// The contract promises the same keys every time. An empty filter used to make
// the key vanish, which is a shape change like any other — noticed when an
// unfiltered export came back without it.
func TestFilterIsEchoedEvenWhenEmpty(t *testing.T) {
	w := NewWriter(t.TempDir(), "q", nil, Options{InlineMaxBytes: 4096, RowLimit: 10})
	res, err := w.Finish("ws", "")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	b, _ := json.Marshal(res)
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["filter"]; !ok {
		t.Errorf("filter must be present even when empty: %s", b)
	}
}
