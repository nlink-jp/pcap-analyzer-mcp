package output

import (
	"encoding/csv"
	"encoding/json"
	"io"
)

// csvEncoder writes rows as CSV with a fixed column order.
//
// CSV exists for the handoff to data-toolbox-mcp / DuckDB; JSONL is the
// default because it survives streaming and partial reads better.
type csvEncoder struct {
	w             *csv.Writer
	headers       []string
	wroteHeader   bool
	headerFromRow bool
}

func newCSVEncoder(out io.Writer, headers []string) *csvEncoder {
	return &csvEncoder{w: csv.NewWriter(out), headers: headers}
}

func (e *csvEncoder) encode(row any) error {
	m, err := toStringMap(row)
	if err != nil {
		return err
	}
	if !e.wroteHeader {
		if len(e.headers) == 0 {
			// No declared column order: fall back to the row's own keys, sorted
			// for determinism by the caller that built them.
			e.headers = sortedKeys(m)
			e.headerFromRow = true
		}
		if err := e.w.Write(e.headers); err != nil {
			return err
		}
		e.wroteHeader = true
	}
	rec := make([]string, len(e.headers))
	for i, h := range e.headers {
		rec[i] = m[h]
	}
	return e.w.Write(rec)
}

func (e *csvEncoder) flush() { e.w.Flush() }

func toStringMap(row any) (map[string]string, error) {
	switch v := row.(type) {
	case map[string]string:
		return v, nil
	default:
		b, err := json.Marshal(row)
		if err != nil {
			return nil, err
		}
		var m map[string]string
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, err
		}
		return m, nil
	}
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// Insertion sort: these are tshark field lists, a handful of entries.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
