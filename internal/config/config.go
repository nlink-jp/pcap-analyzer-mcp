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
	"time"

	"github.com/BurntSushi/toml"
)

// Duration is a time.Duration that decodes from a TOML string such as "30m".
type Duration struct{ time.Duration }

// UnmarshalText implements encoding.TextUnmarshaler for TOML decoding.
func (d *Duration) UnmarshalText(text []byte) error {
	parsed, err := time.ParseDuration(string(text))
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", text, err)
	}
	d.Duration = parsed
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (d Duration) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

// EnvConfigPath overrides the config file location when set.
const EnvConfigPath = "PCAP_ANALYZER_MCP_CONFIG"

// Config is the whole configuration tree.
type Config struct {
	Container Container `toml:"container"`
	Workspace Workspace `toml:"workspace"`
	Output    Output    `toml:"output"`
	Jobs      Jobs      `toml:"jobs"`
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

	// Timeout bounds a single container run in wall-clock time.
	//
	// Memory is capped by the cgroup, but CPU and wall time are not: a capture
	// crafted to drive a dissector into a pathological path — a recurring
	// class of Wireshark CVE, and this tool's stated adversary — would
	// otherwise run forever and, because the stdio server handles requests in
	// order, take the whole server with it.
	Timeout Duration `toml:"timeout"`
}

// Workspace is retained as a config section with no keys.
//
// It held allowed_paths, deleted in ADR-0008: an operator allowlist could not
// express what it was for, and a fixed blacklist in code replaced it. The
// section stays declared so a config that still carries the key is reported by
// name rather than as an unknown section.
type Workspace struct{}

// Output implements the size half of the output contract (ADR-0005, amended by
// ADR-0009).
type Output struct {
	// MaxBytes is the serialized-byte budget for the rows in one response.
	// Bytes, not rows, because a payload column makes row counts meaningless
	// here. Rows past the budget are left out of the response and counted;
	// they are no longer written to a file this server chose (ADR-0009).
	MaxBytes int `toml:"max_bytes"`
	// DefaultRowLimit is the other bound, applied to rows.
	DefaultRowLimit int `toml:"default_row_limit"`

	// MaxConversations bounds the distinct streams list_conversations holds
	// in memory. The container's memory cgroup does not cover this map, and
	// top_n is applied after aggregation, so neither protects against a
	// capture full of spoofed ports.
	MaxConversations int `toml:"max_conversations"`
}

// Jobs bounds background analyses (ADR-0006).
type Jobs struct {
	// MaxConcurrent caps simultaneous background runs. Each one is a
	// `podman run`; unbounded parallelism would saturate the host, which is
	// the cost of the ephemeral-container model (ADR-0002).
	MaxConcurrent int `toml:"max_concurrent"`
}

// Payload bounds the payload-returning tools (ADR-0007).
type Payload struct {
	// FollowInlineMaxBytes is the default window size for follow_stream.
	FollowInlineMaxBytes int `toml:"follow_inline_max_bytes"`
	// FollowMaxWindowBytes is the largest window a caller may ask for. Without
	// a ceiling, `length: 100000000` would return 100MB inline.
	FollowMaxWindowBytes int `toml:"follow_max_window_bytes"`
	// FollowMaxReassemblyBytes bounds how much of a stream is held in memory
	// while looking for the window. A single TCP stream can be a multi-gigabyte
	// transfer, and a ranged read is no protection if the whole thing has
	// already been read in to serve it (ADR-0007 threat 4).
	FollowMaxReassemblyBytes int `toml:"follow_max_reassembly_bytes"`

	// ExtractMaxObjectBytes bounds one object.
	ExtractMaxObjectBytes int64 `toml:"extract_max_object_bytes"`
	// ExtractMaxObjects and ExtractMaxTotalBytes bound the extraction as a
	// whole. A per-object cap does not stop a capture carrying a very large
	// number of small objects from filling the host workspace.
	ExtractMaxObjects    int   `toml:"extract_max_objects"`
	ExtractMaxTotalBytes int64 `toml:"extract_max_total_bytes"`
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
				Timeout: Duration{30 * time.Minute},
			},
		},
		Output: Output{
			MaxBytes:         65536,
			DefaultRowLimit:  10000,
			MaxConversations: 200000,
		},
		Jobs: Jobs{
			MaxConcurrent: 2,
		},
		Payload: Payload{
			FollowInlineMaxBytes:     8192,
			FollowMaxWindowBytes:     1 << 20,  // 1 MiB
			FollowMaxReassemblyBytes: 64 << 20, // 64 MiB
			ExtractMaxObjectBytes:    100 << 20,
			ExtractMaxObjects:        5000,
			ExtractMaxTotalBytes:     2 << 30, // 2 GiB
		},
		Log: Log{
			Level: "info",
		},
	}
}

// ConventionalDir is the per-server config directory the org uses,
// ~/.config/pcap-analyzer-mcp. Empty when the home directory cannot be
// determined.
//
// Both the search below and the work-directory denial in cmd are this one
// expression, so the directory that gets read and the directory that gets
// refused cannot drift apart.
func ConventionalDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".config", "pcap-analyzer-mcp")
}

// DefaultPath is the config file consulted when neither --config nor
// EnvConfigPath names one. Empty when there is no home directory to put it in.
func DefaultPath() string {
	dir := ConventionalDir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "config.toml")
}

// ResolvePath reports the config file this invocation reads: the explicit
// path, else EnvConfigPath, else DefaultPath when a file is actually there,
// else "" — meaning no file and the built-in defaults.
//
// The default location is only returned when it exists, because an absent
// default is not a mistake — an absent config file is a valid configuration
// here. An explicit path is returned whether or not it exists, so that Load
// can fail on it: a path someone typed and got wrong must not read as "use the
// defaults".
//
// Load calls this, and so does the wiring that denies the server's own config
// directory as a work directory (organization ADR-021 §4). One expression, so
// the denial cannot come to disagree with what is actually being read.
//
// The current working directory is deliberately not searched, unlike some
// sibling servers. This process is spawned by an agent runtime that chooses
// its own cwd, so a ./config.toml candidate would make the configuration
// depend on who started the server — pin: TestResolvePathIgnoresTheWorkingDirectory.
func ResolvePath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if fromEnv := os.Getenv(EnvConfigPath); fromEnv != "" {
		return fromEnv
	}
	def := DefaultPath()
	if def == "" {
		return ""
	}
	// A directory named config.toml is not a config file; reporting it would
	// turn a mistake in the filesystem into an unreadable-file error further
	// away from its cause.
	if st, err := os.Stat(def); err != nil || st.IsDir() {
		return ""
	}
	return def
}

// Load reads the config file ResolvePath names — the explicit path, the one
// EnvConfigPath points at, or ~/.config/pcap-analyzer-mcp/config.toml when it
// exists — and returns the built-in defaults when there is none.
//
// A path that was *asked for* but is unreadable is an error: silently falling
// back to defaults would hide a typo in the one place the user tried to be
// explicit. The default location is different — it is consulted, not demanded,
// and its absence is a valid configuration.
func Load(path string) (Config, error) {
	cfg := Default()

	path = ResolvePath(path)
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
	md, err := toml.Decode(string(data), &cfg)
	if err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := rejectUnknownKeys(path, md.Undecoded()); err != nil {
		return Config{}, err
	}

	cfg.normalize()
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("config %s: %w", path, err)
	}
	return cfg, nil
}

// removedKeys names keys this server used to honour, so a config still
// carrying one is told what happened instead of being told it is unknown.
var removedKeys = map[string]string{
	"output.inline_max_bytes": "removed in ADR-0009: results are no longer written to a file above a threshold. " +
		"Use max_bytes, which caps the rows a response carries (what it leaves out is counted, and matched stays exact).",
	"output.sample_rows": "removed in ADR-0009: there is no file-backed result to sample any more — every row that fits comes back in the response.",
	"workspace.allowed_paths": "removed in ADR-0008: the capture path is no longer " +
		"checked against an operator allowlist, only against a fixed blacklist of " +
		"credential locations. Delete the key (and the [workspace] section if it is " +
		"now empty).",
}

// rejectUnknownKeys turns a key this server does not read into a startup
// failure. Silence here is the worse outcome by a distance: an operator who
// wrote a guard and had it ignored would believe it was in force, and the one
// key that has actually been removed is exactly such a guard.
func rejectUnknownKeys(path string, undecoded []toml.Key) error {
	if len(undecoded) == 0 {
		return nil
	}
	var msgs []string
	for _, k := range undecoded {
		name := k.String()
		if why, ok := removedKeys[name]; ok {
			msgs = append(msgs, fmt.Sprintf("%s: %s", name, why))
			continue
		}
		msgs = append(msgs, fmt.Sprintf("%s: not a setting this server reads", name))
	}
	return fmt.Errorf("config %s: %s", path, strings.Join(msgs, "; "))
}

// normalize applies boundary conversions once, so the rest of the program
// only ever sees canonical values.
func (c *Config) normalize() {
	c.Log.File = ExpandHome(c.Log.File)
	c.Log.Level = strings.ToLower(strings.TrimSpace(c.Log.Level))
}

// Validate is the single validation path, shared by Load and by any
// programmatic override, so the two can never drift apart.
func (c *Config) Validate() error {
	if c.Container.Image == "" {
		return fmt.Errorf("container.image must not be empty")
	}
	if c.Container.Limits.CPU == "" {
		return fmt.Errorf("container.limits.cpu must not be empty; an empty value silently drops the --cpus flag")
	}
	if c.Container.Limits.Memory == "" {
		return fmt.Errorf("container.limits.memory must not be empty; an empty value silently drops the --memory flag")
	}
	if c.Container.Limits.Timeout.Duration <= 0 {
		return fmt.Errorf("container.limits.timeout must be positive, got %s", c.Container.Limits.Timeout)
	}
	switch c.Container.Limits.Network {
	case "none", "bridge":
	default:
		return fmt.Errorf("container.limits.network must be \"none\" or \"bridge\", got %q",
			c.Container.Limits.Network)
	}
	if c.Output.MaxBytes <= 0 {
		return fmt.Errorf("output.max_bytes must be positive, got %d", c.Output.MaxBytes)
	}
	if c.Output.DefaultRowLimit <= 0 {
		return fmt.Errorf("output.default_row_limit must be positive, got %d", c.Output.DefaultRowLimit)
	}
	if c.Output.MaxConversations <= 0 {
		return fmt.Errorf("output.max_conversations must be positive, got %d", c.Output.MaxConversations)
	}
	if c.Jobs.MaxConcurrent <= 0 {
		return fmt.Errorf("jobs.max_concurrent must be positive, got %d", c.Jobs.MaxConcurrent)
	}
	if c.Payload.FollowInlineMaxBytes <= 0 {
		return fmt.Errorf("payload.follow_inline_max_bytes must be positive, got %d",
			c.Payload.FollowInlineMaxBytes)
	}
	if c.Payload.FollowMaxWindowBytes < c.Payload.FollowInlineMaxBytes {
		return fmt.Errorf("payload.follow_max_window_bytes (%d) must be at least follow_inline_max_bytes (%d)",
			c.Payload.FollowMaxWindowBytes, c.Payload.FollowInlineMaxBytes)
	}
	if c.Payload.FollowMaxReassemblyBytes < c.Payload.FollowMaxWindowBytes {
		return fmt.Errorf("payload.follow_max_reassembly_bytes (%d) must be at least follow_max_window_bytes (%d)",
			c.Payload.FollowMaxReassemblyBytes, c.Payload.FollowMaxWindowBytes)
	}
	if c.Payload.ExtractMaxObjectBytes <= 0 {
		return fmt.Errorf("payload.extract_max_object_bytes must be positive, got %d",
			c.Payload.ExtractMaxObjectBytes)
	}
	if c.Payload.ExtractMaxObjects <= 0 {
		return fmt.Errorf("payload.extract_max_objects must be positive, got %d", c.Payload.ExtractMaxObjects)
	}
	if c.Payload.ExtractMaxTotalBytes <= 0 {
		return fmt.Errorf("payload.extract_max_total_bytes must be positive, got %d", c.Payload.ExtractMaxTotalBytes)
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log.level must be one of debug/info/warn/error, got %q", c.Log.Level)
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
