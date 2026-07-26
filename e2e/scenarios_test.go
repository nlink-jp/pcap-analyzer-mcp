//go:build e2e

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The scenarios below are the graded walkthrough from samples/README.md, run
// automatically:
//
//	make build && make runtime-image
//	go test -tags e2e ./e2e/
//
// They need real podman and the real analysis image, which is why they sit
// behind a build tag.

func setup(t *testing.T) (client *Client, samples, workspaceDir string) {
	t.Helper()

	binary, err := filepath.Abs("../dist/pcap-analyzer-mcp")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(binary); err != nil {
		t.Skipf("binary not built; run `make build` (%v)", err)
	}
	if _, err := exec.LookPath("podman"); err != nil {
		t.Skip("podman not on PATH")
	}

	samples, err = filepath.Abs("../samples")
	if err != nil {
		t.Fatal(err)
	}

	// Podman Machine can only reach its virtiofs shares, and Go's default
	// TMPDIR on macOS is not one of them.
	workspaceDir, err = os.MkdirTemp("/private/tmp", "pcap-e2e-")
	if err != nil {
		workspaceDir = t.TempDir()
	} else {
		t.Cleanup(func() { os.RemoveAll(workspaceDir) })
	}

	return Start(t, binary), samples, workspaceDir
}

func TestStage1_Handshake(t *testing.T) {
	c, _, _ := setup(t)

	names := c.ToolNames()
	if len(names) != 12 {
		t.Errorf("registered %d tools, want 12: %v", len(names), names)
	}
	for _, want := range []string{
		"get_usage", "create_workspace", "describe_workspace", "list_workspaces",
		"delete_workspace", "describe_runtime", "protocol_hierarchy",
		"list_conversations", "query_packets", "follow_stream", "extract_objects",
		"check_job",
	} {
		if !strings.Contains(strings.Join(names, " "), want) {
			t.Errorf("missing tool %q", want)
		}
	}
}

func TestStage2_OpenAndDescribe(t *testing.T) {
	c, samples, ws := setup(t)

	created := c.MustCall("create_workspace", map[string]any{
		"pcap_path": filepath.Join(samples, "mixed.pcapng"), "workspace_dir": ws,
	})
	id, _ := created["workspace_id"].(string)
	if id == "" {
		t.Fatalf("no workspace_id: %v", created)
	}

	// describe_workspace must answer from cache without a container, so it
	// should be markedly faster than the create that populated it.
	start := time.Now()
	d := c.MustCall("describe_workspace", map[string]any{"workspace_id": id, "workspace_dir": ws})
	elapsed := time.Since(start)
	t.Logf("describe_workspace took %s", elapsed)
	if elapsed > 2*time.Second {
		t.Errorf("describe_workspace took %s; it should be a file read, not a container start", elapsed)
	}

	info := d["info"].(map[string]any)
	if info["packet_count"].(float64) != 4 {
		t.Errorf("packet_count = %v, want 4", info["packet_count"])
	}
	if d["truncated"] != false {
		t.Errorf("mixed.pcapng is not truncated: %v", d["truncated"])
	}
	capture := d["capture"].(map[string]any)
	if len(capture["sha256"].(string)) != 64 {
		t.Errorf("sha256 = %v", capture["sha256"])
	}
}

func TestStage3_SurveyTheCapture(t *testing.T) {
	c, samples, ws := setup(t)
	id := openSample(t, c, samples, ws, "mixed.pcapng")

	h := c.MustCall("protocol_hierarchy", map[string]any{"workspace_id": id, "workspace_dir": ws})
	tree, _ := h["hierarchy"].([]any)
	if len(tree) == 0 {
		t.Fatalf("empty hierarchy: %v", h)
	}
	if tree[0].(map[string]any)["protocol"] != "eth" {
		t.Errorf("root = %v", tree[0])
	}

	conv := c.MustCall("list_conversations", map[string]any{"workspace_id": id, "workspace_dir": ws})
	if conv["total"].(float64) != 2 {
		t.Errorf("total conversations = %v, want 2", conv["total"])
	}
	// The stream index is what makes follow_stream reachable at all.
	first := conv["conversations"].([]any)[0].(map[string]any)
	if _, ok := first["stream"]; !ok {
		t.Errorf("conversation has no stream index: %v", first)
	}
	if conv["untrusted"] == nil {
		t.Error("results carrying wire-derived values must be framed")
	}
}

func TestStage4_QueryAndNarrow(t *testing.T) {
	c, samples, ws := setup(t)
	id := openSample(t, c, samples, ws, "mixed.pcapng")

	all := c.MustCall("query_packets", map[string]any{
		"workspace_id": id, "workspace_dir": ws, "filter": "tcp",
	})
	if all["matched"].(float64) != 4 {
		t.Errorf("matched = %v, want 4", all["matched"])
	}
	if all["delivery"] != "inline" {
		t.Errorf("a 4-row result should come back inline, got %v", all["delivery"])
	}

	// matched must reflect the filter, not the returned rows: that is what
	// tells an agent whether to narrow further.
	limited := c.MustCall("query_packets", map[string]any{
		"workspace_id": id, "workspace_dir": ws, "filter": "tcp", "limit": 1,
	})
	if limited["returned"].(float64) != 1 {
		t.Errorf("returned = %v", limited["returned"])
	}
	if limited["matched"].(float64) != 4 {
		t.Errorf("matched = %v, want the full 4 even though 1 row came back", limited["matched"])
	}
	if limited["truncated"] != true {
		t.Error("a limited result must say it was truncated")
	}

	// A filter that matches nothing is an answer, not a failure.
	none := c.MustCall("query_packets", map[string]any{
		"workspace_id": id, "workspace_dir": ws, "filter": "tcp.port == 9999",
	})
	if none["matched"].(float64) != 0 {
		t.Errorf("matched = %v, want 0", none["matched"])
	}
	if none["rows"] == nil {
		t.Error("zero matches must still present rows as an empty array")
	}
}

// tshark's own diagnostic is the thing that lets an agent fix its filter, so
// it has to survive the trip.
func TestStage5_BadFilterExplainsItself(t *testing.T) {
	c, samples, ws := setup(t)
	id := openSample(t, c, samples, ws, "mixed.pcapng")

	p, isErr := c.Call("query_packets", map[string]any{
		"workspace_id": id, "workspace_dir": ws, "filter": "tcp.flags.zyn == 1",
	})
	if !isErr {
		t.Fatalf("a bad filter must be an error: %v", p)
	}
	if p["code"] != "invalid_display_filter" {
		t.Errorf("code = %v", p["code"])
	}
	details := p["details"].(map[string]any)
	msg, _ := details["tshark_message"].(string)
	if !strings.Contains(msg, "tcp.flags.zyn") {
		t.Errorf("tshark's message did not survive: %v", details)
	}
	if _, ok := details["column"]; !ok {
		t.Errorf("the caret position should reach the agent: %v", details)
	}
}

func TestStage6_PayloadIsFramed(t *testing.T) {
	c, samples, ws := setup(t)
	id := openSample(t, c, samples, ws, "suspicious-download.pcapng")

	f := c.MustCall("follow_stream", map[string]any{
		"workspace_id": id, "workspace_dir": ws, "stream": 0,
	})
	dirs := f["directions"].([]any)
	if len(dirs) != 2 {
		t.Fatalf("got %d directions", len(dirs))
	}

	var found bool
	for _, d := range dirs {
		content := d.(map[string]any)["content"].(string)
		if !strings.Contains(content, "not instructions") {
			t.Error("stream content arrived without its framing")
		}
		if !strings.Contains(content, "untrusted-payload") {
			t.Error("stream content arrived without delimiters")
		}
		if strings.Contains(content, "IGNORE ALL PREVIOUS") {
			found = true
			// The framing has to precede the payload; behind it, it is useless.
			if strings.Index(content, "not instructions") > strings.Index(content, "IGNORE ALL") {
				t.Error("the framing came after the payload it describes")
			}
		}
	}
	if !found {
		t.Error("the sample's injection attempt was not returned at all")
	}
}

func TestStage7_ObjectsAreDefanged(t *testing.T) {
	c, samples, ws := setup(t)
	id := openSample(t, c, samples, ws, "suspicious-download.pcapng")

	out := c.MustCall("extract_objects", map[string]any{
		"workspace_id": id, "workspace_dir": ws, "protocol": "http",
	})
	if out["count"].(float64) < 1 {
		t.Fatalf("no objects extracted: %v", out)
	}
	objects := out["manifest"].(map[string]any)["objects"].([]any)
	obj := objects[0].(map[string]any)

	stored := obj["stored_as"].(string)
	sha := obj["sha256"].(string)
	if filepath.Base(stored) != sha+".bin" {
		t.Errorf("stored as %q, want <sha256>.bin", filepath.Base(stored))
	}

	info, err := os.Stat(stored)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600", perm)
	}
	// The name tshark chose comes off the wire. It is reported plainly and
	// framed once at the manifest level — per-name framing cost ~250 bytes of
	// identical preamble around a ~20-byte string.
	manifest := out["manifest"].(map[string]any)
	framing, _ := manifest["untrusted"].(string)
	if !strings.Contains(framing, "chosen by whoever produced the traffic") {
		t.Errorf("the manifest does not frame the names: %q", framing)
	}
	src, _ := obj["source_name"].(string)
	if src == "" || strings.Contains(src, "untrusted-payload") {
		t.Errorf("source_name should be the plain name, got %q", src)
	}
}

// A truncated capture has no payload. Being told so up front is what stops an
// agent reading the empty result as a transient failure.
func TestStage8_TruncatedCaptureRefusesPayloadTools(t *testing.T) {
	c, samples, ws := setup(t)
	id := openSample(t, c, samples, ws, "truncated.pcapng")

	d := c.MustCall("describe_workspace", map[string]any{"workspace_id": id, "workspace_dir": ws})
	if d["truncated"] != true {
		t.Fatalf("truncated.pcapng must be detected as truncated: %v", d["info"])
	}
	if _, ok := d["payload_note"]; !ok {
		t.Error("a truncated capture should carry an explanation")
	}

	for _, tool := range []string{"follow_stream", "extract_objects"} {
		args := map[string]any{"workspace_id": id, "workspace_dir": ws}
		if tool == "follow_stream" {
			args["stream"] = 0
		} else {
			args["protocol"] = "http"
		}
		p, isErr := c.Call(tool, args)
		if !isErr {
			t.Errorf("%s should refuse a truncated capture: %v", tool, p)
			continue
		}
		if p["code"] != "payload_unavailable_truncated_capture" {
			t.Errorf("%s: code = %v", tool, p["code"])
		}
	}

	// Metadata tools must still work — that is the point of saying which.
	q := c.MustCall("query_packets", map[string]any{"workspace_id": id, "workspace_dir": ws})
	if q["matched"].(float64) != 4 {
		t.Errorf("metadata tools should still work on a truncated capture: %v", q)
	}
}

func TestStage9_AsyncRoundTrip(t *testing.T) {
	c, samples, ws := setup(t)
	id := openSample(t, c, samples, ws, "mixed.pcapng")

	env := c.MustCall("query_packets", map[string]any{
		"workspace_id": id, "workspace_dir": ws, "filter": "tcp", "async": true,
	})
	jobID, _ := env["job_id"].(string)
	if jobID == "" {
		t.Fatalf("no job_id: %v", env)
	}

	st := c.PollJob(jobID, 60*time.Second)
	if st["state"] != "done" {
		t.Fatalf("job %s: %v", st["state"], st["error"])
	}
	// The finished result must be what the synchronous call would have given.
	res := st["result"].(map[string]any)
	if res["matched"].(float64) != 4 {
		t.Errorf("async result differs from the sync one: %v", res)
	}

	// An unknown job id explains the recovery rather than just failing.
	p, isErr := c.Call("check_job", map[string]any{"job_id": "job_0000000000000000"})
	if !isErr || p["code"] != "job_not_found" {
		t.Errorf("unknown job: %v", p)
	}
}

func TestStage10_WorkspaceLifecycle(t *testing.T) {
	c, samples, ws := setup(t)
	pcap := filepath.Join(samples, "web-session.pcapng")
	id := openSample(t, c, samples, ws, "web-session.pcapng")

	list := c.MustCall("list_workspaces", map[string]any{"workspace_dir": ws})
	if list["count"].(float64) != 1 {
		t.Errorf("count = %v", list["count"])
	}

	preview := c.MustCall("delete_workspace", map[string]any{
		"workspace_id": id, "workspace_dir": ws, "dry_run": true,
	})
	if preview["dry_run"] != true {
		t.Errorf("dry_run not honoured: %v", preview)
	}
	if _, err := os.Stat(filepath.Join(ws, id)); err != nil {
		t.Error("dry_run must not remove anything")
	}

	c.MustCall("delete_workspace", map[string]any{"workspace_id": id, "workspace_dir": ws})
	if _, err := os.Stat(filepath.Join(ws, id)); !os.IsNotExist(err) {
		t.Error("workspace should be gone")
	}
	// Deleting a workspace must never touch the evidence.
	if _, err := os.Stat(pcap); err != nil {
		t.Errorf("the capture was affected by workspace deletion: %v", err)
	}
}

func TestStage11_RuntimeDisclosure(t *testing.T) {
	c, _, _ := setup(t)

	r := c.MustCall("describe_runtime", nil)
	m := r["manifest"].(map[string]any)
	if m["tshark_version"] == "" {
		t.Error("no tshark version disclosed")
	}
	protos := m["export_object_protocols"].([]any)
	if len(protos) != 6 {
		t.Errorf("export protocols = %v, want the six tshark supports", protos)
	}
	if r["local_image_id"] == nil {
		t.Error("the locally installed image should be reported alongside the manifest")
	}

	usage := c.MustCall("get_usage", nil)
	if usage["result_contract"] == nil || usage["errors"] == nil {
		t.Errorf("get_usage should describe the contract and the error codes: %v", usage)
	}
}

func openSample(t *testing.T, c *Client, samples, ws, name string) string {
	t.Helper()
	created := c.MustCall("create_workspace", map[string]any{
		"pcap_path": filepath.Join(samples, name), "workspace_dir": ws,
	})
	id, _ := created["workspace_id"].(string)
	if id == "" {
		t.Fatalf("create_workspace(%s) returned no id: %v", name, created)
	}
	return id
}
