package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadNoPathReturnsDefaults(t *testing.T) {
	// HOME is pointed at an empty directory this test owns. Without it the
	// default search would read the developer's own config.toml and the
	// assertions below would pass or fail by accident — which is what happened
	// the moment the search started working.
	t.Setenv("HOME", t.TempDir())
	t.Setenv(EnvConfigPath, "")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\"): %v", err)
	}
	if cfg.Output.MaxBytes != 65536 {
		t.Errorf("max_bytes: got %d, want 65536", cfg.Output.MaxBytes)
	}
	if cfg.Container.Limits.Network != "none" {
		t.Errorf("network: got %q, want \"none\"", cfg.Container.Limits.Network)
	}
}

func TestLoadAbsentKeysKeepDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	// Only one key is set; everything else must retain its default rather
	// than collapsing to a zero value.
	if err := os.WriteFile(path, []byte("[output]\nmax_bytes = 1024\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Output.MaxBytes != 1024 {
		t.Errorf("max_bytes: got %d, want 1024", cfg.Output.MaxBytes)
	}
	if cfg.Output.DefaultRowLimit != 10000 {
		t.Errorf("default_row_limit should keep its default, got %d", cfg.Output.DefaultRowLimit)
	}
	if cfg.Payload.FollowInlineMaxBytes != 8192 {
		t.Errorf("follow_max_bytes should keep its default, got %d",
			cfg.Payload.FollowInlineMaxBytes)
	}
}

func TestLoadMissingFileIsAnError(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "absent.toml")); err == nil {
		t.Error("an explicitly named but unreadable config must be an error, not a silent default")
	}
}

func TestLoadUsesEnvConfigPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "env.toml")
	if err := os.WriteFile(path, []byte("[log]\nlevel = \"debug\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvConfigPath, path)

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("log.level: got %q, want \"debug\"", cfg.Log.Level)
	}
}

func TestValidateRejectsBadValues(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"empty image", func(c *Config) { c.Container.Image = "" }},
		{"unknown network", func(c *Config) { c.Container.Limits.Network = "host" }},
		{"zero max_bytes", func(c *Config) { c.Output.MaxBytes = 0 }},
		{"negative row limit", func(c *Config) { c.Output.DefaultRowLimit = -1 }},
		{"zero follow cap", func(c *Config) { c.Payload.FollowInlineMaxBytes = 0 }},
		{"zero object cap", func(c *Config) { c.Payload.ExtractMaxObjectBytes = 0 }},
		{"unknown log level", func(c *Config) { c.Log.Level = "trace" }},
		{"zero job concurrency", func(c *Config) { c.Jobs.MaxConcurrent = 0 }},
		{"window smaller than default", func(c *Config) { c.Payload.FollowMaxWindowBytes = 1 }},
		{"reassembly smaller than window", func(c *Config) { c.Payload.FollowMaxReassemblyBytes = 1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Default()
			tt.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Errorf("Validate() accepted an invalid config (%s)", tt.name)
			}
		})
	}
}

func TestValidateAcceptsDefaults(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Errorf("the defaults must be a valid configuration: %v", err)
	}
}

// ExpandHome still has users (log.file); the allowed_paths one is gone with
// the key (ADR-0008).
func TestExpandHomeLeavesOtherPathsAlone(t *testing.T) {
	for _, p := range []string{"", "/abs/path", "relative/path", "~user/dir"} {
		if got := ExpandHome(p); got != p {
			t.Errorf("ExpandHome(%q) = %q, want unchanged", p, got)
		}
	}
}

// A key this server does not read must stop it, not be ignored. The operator
// wrote it meaning something; silence would let them believe it took effect.
func TestLoadRejectsUnknownKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("[output]\ninlin_max_bytes = 1024\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("an unknown key must fail the load")
	}
	if !strings.Contains(err.Error(), "inlin_max_bytes") {
		t.Errorf("the error must name the key, got %v", err)
	}
}

// The one key that was actually removed gets told what happened to it, since
// it was a guard and its silent disappearance is the worst outcome (ADR-0008).
func TestLoadNamesTheRemovedAllowedPathsKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("[workspace]\nallowed_paths = [\"/tmp\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("a config still carrying allowed_paths must fail the load")
	}
	for _, want := range []string{"workspace.allowed_paths", "ADR-0008"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got %v", want, err)
		}
	}
}

// --- the default location -----------------------------------------------
// The --config flag promised "the standard locations" while the loader
// consulted only the explicit path and PCAP_ANALYZER_MCP_CONFIG, so a
// config.toml in ~/.config/pcap-analyzer-mcp was read by nobody and reported
// by nothing. These pin the search that closed that gap.

// homeWith points HOME at a directory this test owns and writes body to the
// conventional config path inside it, returning that path.
func homeWith(t *testing.T, body string) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(EnvConfigPath, "")
	dir := filepath.Join(home, ".config", "pcap-analyzer-mcp")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestResolvePathFindsTheConventionalFile(t *testing.T) {
	path := homeWith(t, "[log]\nlevel = \"debug\"\n")
	if got := ResolvePath(""); got != path {
		t.Errorf("ResolvePath(\"\") = %q, want %q", got, path)
	}
}

// The file has to take effect, not merely be found: the defect was a file that
// existed and changed nothing.
func TestLoadAppliesTheConventionalFile(t *testing.T) {
	homeWith(t, "[log]\nlevel = \"debug\"\n")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("log.level: got %q, want \"debug\" from ~/.config/pcap-analyzer-mcp/config.toml", cfg.Log.Level)
	}
}

func TestResolvePathIgnoresAnAbsentDefault(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(EnvConfigPath, "")
	if got := ResolvePath(""); got != "" {
		t.Errorf("ResolvePath(\"\") = %q, want \"\" — an absent default file is a valid configuration", got)
	}
}

// Precedence, stated as three assertions rather than trusted from the code:
// explicit over everything, env over the default.
func TestExplicitPathBeatsEnvAndDefault(t *testing.T) {
	homeWith(t, "[log]\nlevel = \"debug\"\n")
	env := filepath.Join(t.TempDir(), "env.toml")
	if err := os.WriteFile(env, []byte("[log]\nlevel = \"warn\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvConfigPath, env)
	explicit := filepath.Join(t.TempDir(), "explicit.toml")
	if err := os.WriteFile(explicit, []byte("[log]\nlevel = \"error\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ResolvePath(explicit); got != explicit {
		t.Errorf("ResolvePath(explicit) = %q, want %q", got, explicit)
	}
	cfg, err := Load(explicit)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Log.Level != "error" {
		t.Errorf("log.level: got %q, want \"error\"", cfg.Log.Level)
	}
}

func TestEnvBeatsTheDefault(t *testing.T) {
	homeWith(t, "[log]\nlevel = \"debug\"\n")
	env := filepath.Join(t.TempDir(), "env.toml")
	if err := os.WriteFile(env, []byte("[log]\nlevel = \"warn\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvConfigPath, env)
	if got := ResolvePath(""); got != env {
		t.Errorf("ResolvePath(\"\") = %q, want the env path %q", got, env)
	}
}

// A broken file in the conventional location is read, so it is an error. The
// alternative — falling back to defaults — would hide a config the operator
// believes is in force.
func TestLoadReportsAParseErrorInTheConventionalFile(t *testing.T) {
	homeWith(t, "[log]\nlevel = \n")
	if _, err := Load(""); err == nil {
		t.Error("a malformed config.toml in the default location must be an error")
	}
}

// A directory named config.toml is a mistake in the filesystem; reading it
// would surface as an unreadable-file error far from its cause.
func TestResolvePathIgnoresADirectoryNamedConfigToml(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(EnvConfigPath, "")
	if err := os.MkdirAll(filepath.Join(home, ".config", "pcap-analyzer-mcp", "config.toml"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := ResolvePath(""); got != "" {
		t.Errorf("ResolvePath(\"\") = %q, want \"\" for a directory", got)
	}
}

// Pins the deliberate difference from some sibling servers: the working
// directory is NOT searched. This process is spawned by an agent runtime that
// chooses its own cwd, so a ./config.toml candidate would make the
// configuration depend on who started the server. Not parallel: it changes a
// process-wide setting.
func TestResolvePathIgnoresTheWorkingDirectory(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(EnvConfigPath, "")

	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, "config.toml"), []byte("[log]\nlevel = \"debug\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(old); err != nil {
			t.Fatal(err)
		}
	})

	if got := ResolvePath(""); got != "" {
		t.Errorf("ResolvePath(\"\") = %q — the working directory must not be searched", got)
	}
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Log.Level != Default().Log.Level {
		t.Errorf("log.level: got %q, want the default %q", cfg.Log.Level, Default().Log.Level)
	}
}
