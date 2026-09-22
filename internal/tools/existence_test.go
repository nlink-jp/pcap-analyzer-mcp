package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nlink-jp/pcap-analyzer-mcp/internal/config"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/job"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/toolerr"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/workdir"
	"github.com/nlink-jp/pcap-analyzer-mcp/internal/workspace"
)

// Whether a capture exists is never the difference between two answers to
// create_workspace. Each case names one path twice — once while a file is
// there and once after it is removed — and the whole answer (code, message,
// details) must be the same both times, and a refusal. Otherwise "unreadable"
// against "refused" tells the caller which secrets exist (knowledge:
// security.md, "Compare places by identity, not by name").
//
// The layer observed is the tool call, the answer a caller receives; the home
// directory is a temporary one, so no real credential directory is touched,
// and the container runner is a fake.
func TestExistenceIsNotRevealed(t *testing.T) {
	base := realDir(t, t.TempDir())
	home := filepath.Join(base, "home")
	t.Setenv("HOME", home)
	dot := filepath.Join(home, "dotfiles", "config")
	sync := filepath.Join(base, "sync")
	other := filepath.Join(base, "other")
	work := filepath.Join(base, "work")
	for _, d := range []string{
		filepath.Join(dot, "gcloud"), filepath.Join(home, ".aws"), filepath.Join(home, ".docker"),
		filepath.Join(home, ".ssh"), sync, other, work,
	} {
		mkdirAll(t, d)
	}
	symlink(t, dot, filepath.Join(home, ".config"))
	symlink(t, filepath.Join(sync, "ssh_config"), filepath.Join(home, ".ssh", "config"))
	symlink(t, filepath.Join(home, ".aws", "planted.pcap"), filepath.Join(other, "lnk_file.pcap"))
	symlink(t, filepath.Join(home, ".aws"), filepath.Join(other, "lnk_dir"))

	d := depsIn(t, filepath.Join(base, "server"))
	answer := func(p string) string {
		_, err := call(t, d, "create_workspace", map[string]any{"pcap_path": p, "work_dir": work})
		return errAnswer(err)
	}
	for _, c := range []struct{ name, arg, leaf string }{
		{"in a credential directory", filepath.Join(home, ".aws", "c.pcap"), filepath.Join(home, ".aws", "c.pcap")},
		{"through a dotfiles-linked ~/.config", filepath.Join(home, ".config", "gcloud", "c.pcap"), filepath.Join(dot, "gcloud", "c.pcap")},
		{"a credential file", filepath.Join(home, ".docker", "config.json"), filepath.Join(home, ".docker", "config.json")},
		{"a planted link to a credential file", filepath.Join(other, "lnk_file.pcap"), filepath.Join(home, ".aws", "planted.pcap")},
		{"through a planted link to a credential directory", filepath.Join(other, "lnk_dir", "via.pcap"), filepath.Join(home, ".aws", "via.pcap")},
		{"where a link in ~/.ssh leads", filepath.Join(sync, "ssh_config"), filepath.Join(sync, "ssh_config")},
		{"a .env file", filepath.Join(other, ".env"), filepath.Join(other, ".env")},
	} {
		t.Run(c.name, func(t *testing.T) {
			writeFileAt(t, c.leaf)
			e := answer(c.arg)
			if err := os.Remove(c.leaf); err != nil {
				t.Fatal(err)
			}
			m := answer(c.arg)
			if !strings.HasPrefix(e, toolerr.CodePathNotAllowed+" ") {
				t.Errorf("existing: %s\n  want path_not_allowed", e)
			}
			if e != m {
				t.Errorf("the answer tells them apart\n  existing: %s\n  missing:  %s", e, m)
			}
		})
	}
	// The control: an ordinary missing capture is still reported unreadable.
	if a := answer(filepath.Join(other, "typo.pcap")); !strings.HasPrefix(a, toolerr.CodePcapUnreadable+" ") {
		t.Errorf("an ordinary missing capture: %s", a)
	}
}

// A planted link whose target climbs with .. past a component that is a
// directory, a file or missing gets one answer in all three cases: existence
// is asked at the place, not re-walked from the spelling. A chain of links
// that does not end is refused and named as the caller gave it.
func TestPlacementCorners(t *testing.T) {
	base := realDir(t, t.TempDir())
	home := filepath.Join(base, "home")
	t.Setenv("HOME", home)
	other := filepath.Join(base, "other")
	plant := filepath.Join(base, "plant")
	work := filepath.Join(base, "work")
	for _, dir := range []string{filepath.Join(home, ".aws"), filepath.Join(other, "probe_d"), plant, work} {
		mkdirAll(t, dir)
	}
	writeFileAt(t, filepath.Join(other, "probe_f"))
	d := depsIn(t, filepath.Join(base, "server"))
	answer := func(p string) string {
		_, err := call(t, d, "create_workspace", map[string]any{"pcap_path": p, "work_dir": work})
		return errAnswer(err)
	}
	for _, target := range []string{filepath.Join(home, ".aws", "c.pcap"), filepath.Join(plant, "none.pcap")} {
		if strings.Contains(target, ".aws") {
			writeFileAt(t, target)
		}
		rel, err := filepath.Rel(other, target)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]string{}
		for _, k := range []string{"d", "f", "m"} {
			// Written as a string: filepath.Join would clean the ".." away.
			link := filepath.Join(other, "probe_"+k) + string(filepath.Separator) + ".." + string(filepath.Separator) + rel
			at := filepath.Join(plant, "L_"+k+"_"+filepath.Base(target))
			symlink(t, link, at)
			got[k] = strings.ReplaceAll(answer(at), "L_"+k+"_", "L_?_")
		}
		if got["d"] != got["f"] || got["d"] != got["m"] {
			t.Errorf("a link climbing past a directory / a file / nothing to %s:\n  %s\n  %s\n  %s", target, got["d"], got["f"], got["m"])
		}
	}

	symlink(t, "loopB", filepath.Join(plant, "loopA"))
	symlink(t, "loopA", filepath.Join(plant, "loopB"))
	loop := filepath.Join(plant, "loopA")
	if a := answer(loop); !strings.HasPrefix(a, toolerr.CodePathNotAllowed+" ") || !strings.Contains(a, loop+" is refused") {
		t.Errorf("a loop: %s; want path_not_allowed naming %s", a, loop)
	}
}

// depsIn is newDeps with this server's own directory at server, and a fake
// runner behind the workspace manager: a path the floor let through by
// mistake reaches the fake, never a container.
func depsIn(t *testing.T, server string) *Deps {
	t.Helper()
	cfg := config.Default()
	r := &fakeRunner{}
	resolver := workdir.NewResolver(server)
	return &Deps{
		Cfg:       cfg,
		Podman:    r,
		WorkDir:   resolver,
		Workspace: workspace.NewManager(cfg, r, resolver.CheckBeneath),
		Jobs:      job.NewManager(cfg.Jobs.MaxConcurrent),
		ServerCtx: context.Background(),
	}
}

func errAnswer(err error) string {
	if err == nil {
		return "accepted"
	}
	var te *toolerr.Error
	if !errors.As(err, &te) {
		return "untyped: " + err.Error()
	}
	d, _ := json.Marshal(te.Details)
	return fmt.Sprintf("%s | %s | %s", te.Code, te.Message, d)
}

func realDir(t *testing.T, d string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(d)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func mkdirAll(t *testing.T, d string) {
	t.Helper()
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
}

func symlink(t *testing.T, target, at string) {
	t.Helper()
	if err := os.Symlink(target, at); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
}

func writeFileAt(t *testing.T, p string) {
	t.Helper()
	mkdirAll(t, filepath.Dir(p))
	if err := os.WriteFile(p, []byte("not really a capture"), 0o600); err != nil {
		t.Fatal(err)
	}
}
