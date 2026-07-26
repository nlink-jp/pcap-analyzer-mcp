package payload

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Measured against real malware: the host's antivirus quarantines a sample
// while tshark is writing it, the read fails with EPERM, and the extraction
// used to abort — 2 of 3 objects detected returned nothing at all, not even
// the benign one. What is recoverable must survive.
func TestUnreadableObjectIsSkippedNotFatal(t *testing.T) {
	raw, store := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(raw, "benign.txt"), "harmless")
	quarantined := filepath.Join(raw, "invoice.doc")
	writeFile(t, quarantined, "MZ...")
	if err := os.Chmod(quarantined, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(quarantined, 0o600) })
	if f, err := os.Open(quarantined); err == nil {
		f.Close()
		t.Skip("running with rights that ignore file permissions")
	}

	m, err := Defang("http", raw, store, Limits{})
	if err != nil {
		t.Fatalf("one unreadable object must not fail the extraction: %v", err)
	}
	if len(m.Objects) != 1 || m.Objects[0].Bytes != 8 {
		t.Fatalf("the readable object should still come back: %+v", m.Objects)
	}
	if len(m.Skipped) != 1 {
		t.Fatalf("the unreadable one must be reported, not silently dropped: %+v", m.Skipped)
	}
	if m.Skipped[0].SourceName != "invoice.doc" {
		t.Errorf("skipped name = %q", m.Skipped[0].SourceName)
	}
	// The reason has to point at the likely cause; a bare errno leaves the
	// caller guessing between a bug and their own antivirus.
	if !strings.Contains(m.Skipped[0].Reason, "antivirus") {
		t.Errorf("reason should name the likely cause: %q", m.Skipped[0].Reason)
	}
	if !strings.Contains(m.Skipped[0].Reason, "true positive") {
		t.Errorf("reason should say the detection is correct, not a fault: %q", m.Skipped[0].Reason)
	}
}
