package workspace

import (
	"encoding/csv"
	"fmt"
	"strconv"
	"strings"
)

// capinfosFields is the exact set of infos requested from capinfos, and the
// reason the output is parseable at all.
//
// `-T -m -Q` produces a quoted, comma-separated table with a header row.
// `-M` is not used: it only affects the *long* report, and the long report is
// "Field name: value" prose with unit suffixes. The comment field (`-k`) is
// deliberately absent — capture comments contain literal newlines, which would
// break the record structure for no benefit.
//
// `-S` renders the start and end times as epoch seconds. Formatting the
// human-readable form in Go from that keeps timezones out of the parser
// entirely.
var capinfosFields = []string{
	"-T", "-m", "-Q", // quoted CSV table with a header row
	"-S",       // start/end as epoch seconds
	"-t",       // file type
	"-E",       // encapsulation
	"-l",       // packet size limit (+ the inferred min/max)
	"-c",       // packet count
	"-s",       // file size
	"-d",       // total packet bytes
	"-u",       // duration
	"-a", "-e", // start / end
	"-y", // average byte rate
	"-z", // average packet size
	"-H", // file hashes
	"-F", // capture hardware / OS / application
}

// CapinfosArgs returns the argv for capinfos against a container-side path.
func CapinfosArgs(containerPath string) []string {
	return append(append([]string{"capinfos"}, capinfosFields...), containerPath)
}

// CaptureInfo is the subset of capinfos output recorded in meta.json.
type CaptureInfo struct {
	Format        string `json:"format"`
	Encapsulation string `json:"encapsulation"`
	PacketCount   int64  `json:"packet_count"`
	FileSize      int64  `json:"file_size"`
	DataSize      int64  `json:"data_size"`

	FirstPacket Timestamp `json:"first_packet"`
	LastPacket  Timestamp `json:"last_packet"`
	DurationSec float64   `json:"duration_sec"`

	AvgPacketSize  float64 `json:"avg_packet_size"`
	AvgBytesPerSec float64 `json:"avg_bytes_per_sec"`

	// SnaplenHeader is what the file header declares, verbatim — often
	// "(not set)". It is context, not the truncation verdict.
	SnaplenHeader string `json:"snaplen_header"`
	// SnaplenInferredMin/Max are only present when capinfos observed at least
	// one packet whose captured length was shorter than its original length.
	SnaplenInferredMin *int64 `json:"snaplen_inferred_min,omitempty"`
	SnaplenInferredMax *int64 `json:"snaplen_inferred_max,omitempty"`

	// Truncated means packets in this capture are missing bytes, so payload
	// tools cannot succeed.
	//
	// It is derived from the inferred values, not from the header. capinfos
	// only infers a limit when it actually saw a packet whose captured length
	// was shorter than its original length, which is the question that matters.
	// The header is unreliable in both directions: a capture truncated with
	// `editcap -s 40` still reports "(not set)", and a header limit of 262144
	// means nothing was cut at all.
	Truncated bool `json:"truncated"`

	// SHA256 is capinfos' own digest of the file. The authoritative value in
	// meta.json is computed host-side; keeping this one gives two independent
	// computations to compare.
	SHA256 string `json:"capinfos_sha256,omitempty"`

	CaptureHardware string `json:"capture_hardware,omitempty"`
	CaptureOS       string `json:"capture_os,omitempty"`
	CaptureApp      string `json:"capture_app,omitempty"`
}

// ParseCapinfos parses one `capinfos -T -m -Q ...` record.
func ParseCapinfos(out []byte) (CaptureInfo, error) {
	r := csv.NewReader(strings.NewReader(string(out)))
	r.FieldsPerRecord = -1

	records, err := r.ReadAll()
	if err != nil {
		return CaptureInfo{}, fmt.Errorf("parse capinfos output: %w", err)
	}
	if len(records) < 2 {
		return CaptureInfo{}, fmt.Errorf("capinfos produced %d record(s), want a header and one row", len(records))
	}

	// Key by header name rather than by position: the column order follows the
	// order capinfos itself chooses, not the order the flags were given.
	header, row := records[0], records[1]
	col := make(map[string]string, len(header))
	for i, name := range header {
		if i < len(row) {
			col[name] = strings.TrimSpace(row[i])
		}
	}

	info := CaptureInfo{
		Format:          col["File type"],
		Encapsulation:   col["File encapsulation"],
		PacketCount:     parseInt(col["Number of packets"]),
		FileSize:        parseInt(col["File size (bytes)"]),
		DataSize:        parseInt(col["Data size (bytes)"]),
		DurationSec:     parseFloat(col["Capture duration (seconds)"]),
		AvgPacketSize:   parseFloat(col["Average packet size (bytes)"]),
		AvgBytesPerSec:  parseFloat(col["Data byte rate (bytes/sec)"]),
		SnaplenHeader:   col["Packet size limit"],
		SHA256:          col["SHA256"],
		CaptureHardware: col["Capture hardware"],
		CaptureOS:       col["Capture oper-sys"],
		CaptureApp:      col["Capture application"],
	}
	info.FirstPacket = NewTimestamp(parseFloat(col["Start time"]))
	info.LastPacket = NewTimestamp(parseFloat(col["End time"]))
	info.SnaplenInferredMin = parseOptionalInt(col["Packet size limit min (inferred)"])
	info.SnaplenInferredMax = parseOptionalInt(col["Packet size limit max (inferred)"])
	info.Truncated = info.SnaplenInferredMin != nil || info.SnaplenInferredMax != nil

	return info, nil
}

// parseOptionalInt returns nil for capinfos' "n/a" and "(not set)" markers.
func parseOptionalInt(s string) *int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return nil
	}
	return &n
}

func parseInt(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}

func parseFloat(s string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return f
}
