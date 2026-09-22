package cmd

import (
	"context"
	"path/filepath"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/config"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/job"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/tools"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/workdir"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/workspace"
)

// newToolDeps assembles what every tool shares. It is the only place
// tools.Deps is built, which is what makes the work-directory resolver below
// impossible for a tool added later to forget: no tool constructs a Resolver
// of its own, all twelve read Deps.WorkDir.
//
// serverCtx outlives any single request; background analyses run under it
// (ADR-0006). cfgPath is the --config value as given, needed because the
// directory holding the config file in use is one of the directories denied
// as a work directory.
func newToolDeps(serverCtx context.Context, cfg config.Config, pc tools.ContainerRunner, cfgPath string) *tools.Deps {
	return &tools.Deps{
		Cfg:       cfg,
		Podman:    pc,
		Workspace: workspace.NewManager(cfg, pc),
		Jobs:      job.NewManager(cfg.Jobs.MaxConcurrent),
		WorkDir:   workDirResolver(cfgPath),
		ServerCtx: serverCtx,
	}
}

// workDirResolver builds the per-call work-directory resolver, denying this
// server's own directories.
//
// A work directory is the caller's, not ours (organization ADR-021 §4: "not a
// system location … and not the server's own config or state directory" →
// `work_dir_denied`). Without the denial a caller could name our config
// directory as its work directory and have the server create workspaces there,
// mount captures from it into a container and write extracted objects beside
// the file that sets this server's own limits — on a model's say-so.
func workDirResolver(cfgPath string) workdir.Resolver {
	return workdir.NewResolver(serverOwnedDirs(cfgPath)...)
}

// serverOwnedDirs lists this server's own config and state directories.
//
// There is no state directory: workspaces live under the caller's `work_dir`
// (ADR-0008), captures are mounted read-only and never copied, and results
// come back in the response rather than in a file this server chose. What is
// left is configuration, in two forms:
//
//   - the conventional per-server directory `~/.config/pcap-analyzer-mcp`,
//     which is where this server's config.toml belongs — it is searched by
//     config.ResolvePath and named here whether or not a file is in it,
//     since a workspace put there would collide with a config file added
//     later;
//   - the directory holding the config file actually in use, when `--config`
//     or `PCAP_ANALYZER_MCP_CONFIG` names one. An operator who points that at
//     a directory shared with other work — `--config ./config.toml` in a
//     project tree — is refused that directory as a work directory, loudly
//     and by name. Giving the config file a directory of its own is the fix;
//     a workspace built inside the server's own configuration is the outcome
//     this row exists to prevent.
//
// The log file's directory is deliberately not here. It is operator-chosen and
// routinely somewhere broad (`/tmp`, `~/Library/Logs`); denying a tree that
// wide would refuse work directories callers legitimately use, which is a
// worse outcome than the one it would prevent.
//
// The conventional directory is passed on even when empty (no home): an empty
// one refuses every call rather than protecting nothing.
func serverOwnedDirs(cfgPath string) []string {
	dirs := []string{configDir()}
	if p := config.ResolvePath(cfgPath); p != "" {
		if abs, err := filepath.Abs(p); err == nil {
			dirs = append(dirs, filepath.Dir(abs))
		}
	}
	return dirs
}

// configDir is the conventional directory for this server's own config.toml.
// Empty when the home directory cannot be determined.
//
// Delegated rather than repeated: the loader searches this directory, so a
// second copy of the expression here could come to deny a directory other than
// the one being read.
func configDir() string { return config.ConventionalDir() }
