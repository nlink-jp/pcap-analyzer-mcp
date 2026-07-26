// Package config loads and validates pcap-analyzer-mcp's config.toml.
//
// The schema mirrors the sectioned-TOML convention used across the org.
// Defaults are chosen so that an absent config file is a valid configuration:
// every field below has a working default, and config.toml only ever narrows
// or overrides.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// EnvConfigPath overrides the config file location when set.
const EnvConfigPath = "PCAP_ANALYZER_MCP_CONFIG"

// Config is the whole configuration tree.
type Config struct {
	Container Container `toml:"container"`
	Workspace Workspace `toml:"workspace"`
	Output    Output    `toml:"output"`
	Payload   Payload   `toml:"payload"`
	Log       Log       `toml:"log"`
}

// Container describes the analysis image and its runtime restrictions.
type Container struct {
	// Image is digest-pinned so the tshark version is fixed regardless of
	// what is installed on the host (ADR-0003).
	Image  string `toml:"image"`
	Limits Limits `toml:"limits"`
}

// Limits are the per-run resource and isolation settings applied to every
// `podman run` (ADR-0002).
type Limits struct {
	CPU     string `toml:"cpu"`
	Memory  string `toml:"memory"`
	Network string `toml:"network"`
}

// Workspace controls where analysis state lives and which captures may be
// opened.
type Workspace struct {
	// AllowedPaths is a guardrail, not a sandbox boundary (ADR-0004).
	// Empty means unrestricted.
	AllowedPaths []string `toml:"allowed_paths"`
}

// Output implements the size half of the output contract (ADR-0005).
type Output struct {
	// InlineMaxBytes is the serialized-byte threshold above which a result
	// is written to the workspace instead of returned inline. Bytes, not
	// rows, because a payload column makes row counts meaningless here.
	InlineMaxBytes int `toml:"inline_max_bytes"`
	// DefaultRowLimit is the secondary guard.
	DefaultRowLimit int `toml:"default_row_limit"`
	// SampleRows is how many leading rows accompany a file-backed result so
	// the agent never needs a round trip just to learn the shape.
	SampleRows int `toml:"sample_rows"`
}

// Payload bounds the payload-returning tools (ADR-0007).
type Payload struct {
	FollowInlineMaxBytes  int   `toml:"follow_inline_max_bytes"`
	ExtractMaxObjectBytes int64 `toml:"extract_max_object_bytes"`
}

// Log configures diagnostics. Payload bytes are never written here
// (ADR-0007 item 3).
type Log struct {
	Level string `toml:"level"`
	File  string `toml:"file"`
}

// Default returns the configuration used when no config.toml is present.
func Default() Config {
	return Config{
		Container: Container{
			Image: "localhost/pcap-analyzer-runtime:latest",
			Limits: Limits{
				CPU:     "2",
				Memory:  "4g",
				Network: "none",
			},
		},
		Workspace: Workspace{
			AllowedPaths: nil,
		},
		Output: Output{
			InlineMaxBytes:  65536,
			DefaultRowLimit: 10000,
			SampleRows:      5,
		},
		Payload: Payload{
			FollowInlineMaxBytes:  8192,
			ExtractMaxObjectBytes: 100 << 20, // 100 MiB
		},
		Log: Log{
			Level: "info",
		},
	}
}

// Load reads config.toml from path, or from EnvConfigPath, or returns the
// defaults when neither is set. A path that is set but unreadable is an
// error: silently falling back to defaults would hide a typo in the one
// place the user tried to be explicit.
func Load(path string) (Config, error) {
	cfg := Default()

	if path == "" {
		path = os.Getenv(EnvConfigPath)
	}
	if path == "" {
		if err := cfg.Validate(); err != nil {
			return Config{}, err
		}
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}
	// Decoding onto the defaults means an absent key keeps its default
	// rather than becoming a zero value.
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}

	cfg.normalize()
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("config %s: %w", path, err)
	}
	return cfg, nil
}

// normalize applies boundary conversions once, so the rest of the program
// only ever sees canonical values.
func (c *Config) normalize() {
	for i, p := range c.Workspace.AllowedPaths {
		c.Workspace.AllowedPaths[i] = ExpandHome(p)
	}
	c.Log.File = ExpandHome(c.Log.File)
	c.Log.Level = strings.ToLower(strings.TrimSpace(c.Log.Level))
}

// Validate is the single validation path, shared by Load and by any
// programmatic override, so the two can never drift apart.
func (c *Config) Validate() error {
	if c.Container.Image == "" {
		return fmt.Errorf("container.image must not be empty")
	}
	switch c.Container.Limits.Network {
	case "none", "bridge":
	default:
		return fmt.Errorf("container.limits.network must be \"none\" or \"bridge\", got %q",
			c.Container.Limits.Network)
	}
	if c.Output.InlineMaxBytes <= 0 {
		return fmt.Errorf("output.inline_max_bytes must be positive, got %d", c.Output.InlineMaxBytes)
	}
	if c.Output.DefaultRowLimit <= 0 {
		return fmt.Errorf("output.default_row_limit must be positive, got %d", c.Output.DefaultRowLimit)
	}
	if c.Output.SampleRows < 0 {
		return fmt.Errorf("output.sample_rows must not be negative, got %d", c.Output.SampleRows)
	}
	if c.Payload.FollowInlineMaxBytes <= 0 {
		return fmt.Errorf("payload.follow_inline_max_bytes must be positive, got %d",
			c.Payload.FollowInlineMaxBytes)
	}
	if c.Payload.ExtractMaxObjectBytes <= 0 {
		return fmt.Errorf("payload.extract_max_object_bytes must be positive, got %d",
			c.Payload.ExtractMaxObjectBytes)
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log.level must be one of debug/info/warn/error, got %q", c.Log.Level)
	}
	for _, p := range c.Workspace.AllowedPaths {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("workspace.allowed_paths entries must be absolute, got %q", p)
		}
	}
	return nil
}

// ExpandHome resolves a leading ~ against the current user's home directory.
func ExpandHome(p string) string {
	if p == "" || p[0] != '~' {
		return p
	}
	if len(p) > 1 && p[1] != filepath.Separator {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	return filepath.Join(home, p[1:])
}
