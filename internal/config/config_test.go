package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadNoPathReturnsDefaults(t *testing.T) {
	t.Setenv(EnvConfigPath, "")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\"): %v", err)
	}
	if cfg.Output.InlineMaxBytes != 65536 {
		t.Errorf("inline_max_bytes: got %d, want 65536", cfg.Output.InlineMaxBytes)
	}
	if cfg.Container.Limits.Network != "none" {
		t.Errorf("network: got %q, want \"none\"", cfg.Container.Limits.Network)
	}
	if len(cfg.Workspace.AllowedPaths) != 0 {
		t.Errorf("allowed_paths should default to unrestricted, got %v", cfg.Workspace.AllowedPaths)
	}
}

func TestLoadAbsentKeysKeepDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	// Only one key is set; everything else must retain its default rather
	// than collapsing to a zero value.
	if err := os.WriteFile(path, []byte("[output]\ninline_max_bytes = 1024\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Output.InlineMaxBytes != 1024 {
		t.Errorf("inline_max_bytes: got %d, want 1024", cfg.Output.InlineMaxBytes)
	}
	if cfg.Output.DefaultRowLimit != 10000 {
		t.Errorf("default_row_limit should keep its default, got %d", cfg.Output.DefaultRowLimit)
	}
	if cfg.Payload.FollowInlineMaxBytes != 8192 {
		t.Errorf("follow_inline_max_bytes should keep its default, got %d",
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
		{"zero inline_max_bytes", func(c *Config) { c.Output.InlineMaxBytes = 0 }},
		{"negative row limit", func(c *Config) { c.Output.DefaultRowLimit = -1 }},
		{"zero follow cap", func(c *Config) { c.Payload.FollowInlineMaxBytes = 0 }},
		{"zero object cap", func(c *Config) { c.Payload.ExtractMaxObjectBytes = 0 }},
		{"unknown log level", func(c *Config) { c.Log.Level = "trace" }},
		{"zero job concurrency", func(c *Config) { c.Jobs.MaxConcurrent = 0 }},
		{"window smaller than default", func(c *Config) { c.Payload.FollowMaxWindowBytes = 1 }},
		{"reassembly smaller than window", func(c *Config) { c.Payload.FollowMaxReassemblyBytes = 1 }},
		{"relative allowed path", func(c *Config) { c.Workspace.AllowedPaths = []string{"captures"} }},
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

func TestNormalizeExpandsHomeInAllowedPaths(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory in this environment")
	}
	cfg := Default()
	cfg.Workspace.AllowedPaths = []string{"~/captures"}
	cfg.normalize()

	want := filepath.Join(home, "captures")
	if cfg.Workspace.AllowedPaths[0] != want {
		t.Errorf("allowed_paths[0]: got %q, want %q", cfg.Workspace.AllowedPaths[0], want)
	}
}

func TestExpandHomeLeavesOtherPathsAlone(t *testing.T) {
	for _, p := range []string{"", "/abs/path", "relative/path", "~user/dir"} {
		if got := ExpandHome(p); got != p {
			t.Errorf("ExpandHome(%q) = %q, want unchanged", p, got)
		}
	}
}
