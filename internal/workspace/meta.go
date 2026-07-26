package workspace

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"
)

// MetaFile is the name of the per-workspace metadata cache.
const MetaFile = "meta.json"

// MetaSchemaVersion is bumped when meta.json's shape changes incompatibly.
// A workspace written by a newer server is refused rather than misread.
const MetaSchemaVersion = 1

// Timestamp carries both representations so no consumer has to guess a
// timezone. Locally formatted times are never produced.
type Timestamp struct {
	Epoch float64 `json:"epoch"`
	UTC   string  `json:"utc"`
}

// NewTimestamp builds a Timestamp from epoch seconds.
func NewTimestamp(epoch float64) Timestamp {
	sec, frac := math.Modf(epoch)
	return Timestamp{
		Epoch: epoch,
		UTC:   time.Unix(int64(sec), int64(frac*1e9)).UTC().Format(time.RFC3339Nano),
	}
}

// Capture identifies the evidence file a workspace is bound to.
type Capture struct {
	// HostPath is the symlink-resolved absolute path on the host.
	HostPath string `json:"host_path"`
	// Name is the basename, kept for display. The container always sees the
	// capture at a fixed path, so this never reaches an argv.
	Name string `json:"name"`
	// SHA256 is computed host-side and anchors the chain of custody.
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Runtime records what actually performed the analysis, so a later disagreement
// with the static manifest is visible instead of silent.
type Runtime struct {
	Image         string `json:"image"`
	ImageID       string `json:"image_id"`
	TsharkVersion string `json:"tshark_version"`
}

// Meta is the contents of meta.json.
type Meta struct {
	SchemaVersion int         `json:"schema_version"`
	WorkspaceID   string      `json:"workspace_id"`
	CreatedAt     Timestamp   `json:"created_at"`
	Capture       Capture     `json:"capture"`
	Info          CaptureInfo `json:"info"`
	Runtime       Runtime     `json:"runtime"`
}

// Write persists meta.json into the workspace directory.
func (m *Meta) Write(dir string) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal meta: %w", err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(filepath.Join(dir, MetaFile), b, 0o600); err != nil {
		return fmt.Errorf("write meta: %w", err)
	}
	return nil
}

// ReadMeta loads meta.json from a workspace directory.
func ReadMeta(dir string) (*Meta, error) {
	b, err := os.ReadFile(filepath.Join(dir, MetaFile))
	if err != nil {
		return nil, err
	}
	var m Meta
	dec := json.NewDecoder(bytes.NewReader(b))
	// Strict decode: a key we do not recognise means the file was written by a
	// different schema, and guessing at it would be worse than refusing.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", MetaFile, err)
	}
	if m.SchemaVersion > MetaSchemaVersion {
		return nil, fmt.Errorf("%s has schema version %d; this build understands up to %d",
			MetaFile, m.SchemaVersion, MetaSchemaVersion)
	}
	return &m, nil
}
