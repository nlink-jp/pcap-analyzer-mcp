// Package logging sets up the server's logger.
//
// Two things matter here. stdout belongs to the MCP protocol, so diagnostics
// must never go there; and payload must never reach a log file at all, which
// is enforced upstream by payload.Untrusted redacting itself rather than by
// anything in this package.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/config"
)

// keptGenerations is how many previous logs are retained when rotating.
const keptGenerations = 5

// New returns a logger for the given configuration, plus a closer for the log
// file if one was opened.
//
// With no log.file configured, diagnostics go to stderr — never stdout, which
// carries the JSON-RPC stream and would be corrupted by a stray line.
func New(cfg config.Log) (*slog.Logger, io.Closer, error) {
	opts := &slog.HandlerOptions{Level: level(cfg.Level)}

	if cfg.File == "" {
		return slog.New(slog.NewTextHandler(os.Stderr, opts)), nil, nil
	}

	if err := os.MkdirAll(filepath.Dir(cfg.File), 0o700); err != nil {
		return nil, nil, fmt.Errorf("create log directory: %w", err)
	}
	if err := rotate(cfg.File); err != nil {
		return nil, nil, err
	}
	f, err := os.OpenFile(cfg.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open log file: %w", err)
	}
	return slog.New(slog.NewTextHandler(f, opts)), f, nil
}

// rotate shifts existing logs down one generation at startup.
//
// Rotating on start rather than by size keeps one server run in one file,
// which is what you want when reconstructing what a session did.
func rotate(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}
	oldest := fmt.Sprintf("%s.%d", path, keptGenerations)
	_ = os.Remove(oldest)

	for i := keptGenerations - 1; i >= 1; i-- {
		from := fmt.Sprintf("%s.%d", path, i)
		if _, err := os.Stat(from); err != nil {
			continue
		}
		if err := os.Rename(from, fmt.Sprintf("%s.%d", path, i+1)); err != nil {
			return fmt.Errorf("rotate log: %w", err)
		}
	}
	if err := os.Rename(path, path+".1"); err != nil {
		return fmt.Errorf("rotate log: %w", err)
	}
	return nil
}

func level(name string) slog.Level {
	switch name {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
