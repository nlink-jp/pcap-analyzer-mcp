package runtime

import (
	"strings"
	"testing"
)

// The manifest answers describe_runtime without starting a container, which
// only works if it stays in step with the Dockerfile. These tests are the
// thing keeping the two honest.
func TestManifestMatchesDockerfile(t *testing.T) {
	if !strings.Contains(Dockerfile, "FROM "+BaseImage+"@"+BaseImageDigest) {
		t.Errorf("BaseImageDigest %s does not appear in the Dockerfile FROM line", BaseImageDigest)
	}
}

// A tag would let the base image move underneath us, and with it the tshark
// version — which is the entire reason the analysis runs in a container.
func TestDockerfilePinsByDigest(t *testing.T) {
	for _, line := range strings.Split(Dockerfile, "\n") {
		if !strings.HasPrefix(line, "FROM ") {
			continue
		}
		if !strings.Contains(line, "@sha256:") {
			t.Errorf("FROM line is not digest-pinned: %s", line)
		}
	}
}

// ADR-0003: the image must not be able to capture. Three independent
// properties enforce that, and losing any one of them silently would be bad.
func TestDockerfileCannotCapture(t *testing.T) {
	checks := []struct {
		want, why string
	}{
		{"wireshark-common/install-setuid boolean false", "setuid dumpcap must be declined at install time"},
		{"rm -f /usr/bin/dumpcap", "the dumpcap binary must be deleted, not merely de-privileged"},
		{"USER 1000:1000", "the image must not run as root"},
	}
	for _, c := range checks {
		if !strings.Contains(Dockerfile, c.want) {
			t.Errorf("%s (missing %q)", c.why, c.want)
		}
	}
}

// tshark writes scratch files during object export and reassembly. /evidence
// is read-only, so TMPDIR has to point at the writable mount.
func TestDockerfileKeepsTempOnTheWritableMount(t *testing.T) {
	if !strings.Contains(Dockerfile, "ENV TMPDIR=/work/tmp") {
		t.Error("TMPDIR must live under /work; /evidence is mounted read-only")
	}
}

// Installing tshark pulls in wireshark-common, which is where capinfos,
// editcap, mergecap and text2pcap come from. The manifest advertises them, so
// nothing may be claimed that the install does not provide.
func TestManifestToolsAreAllFromTshark(t *testing.T) {
	if !strings.Contains(Dockerfile, "apt-get install -y --no-install-recommends tshark") {
		t.Fatal("the Dockerfile no longer installs tshark the way the manifest assumes")
	}
	m := Default()
	want := map[string]bool{
		"tshark": true, "capinfos": true, "editcap": true,
		"mergecap": true, "text2pcap": true,
	}
	if len(m.Tools) != len(want) {
		t.Errorf("Tools = %v; update this test if the package set changed", m.Tools)
	}
	for _, tool := range m.Tools {
		if !want[tool] {
			t.Errorf("manifest advertises %q, which the tshark package does not provide", tool)
		}
	}
}

// Verified against tshark 4.0.17 with `tshark --export-objects help`. If the
// base digest moves, re-run that command before changing this list.
func TestManifestExportObjectProtocols(t *testing.T) {
	got := Default().ExportObjectProtocols
	want := []string{"dicom", "ftp-data", "http", "imf", "smb", "tftp"}

	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("protocol[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestManifestDescribesBothMounts(t *testing.T) {
	m := Default()
	ev, ok := m.Mounts["/evidence"]
	if !ok {
		t.Fatal("manifest must describe /evidence")
	}
	if !strings.Contains(ev, "read-only") {
		t.Errorf("/evidence must be described as read-only, got %q", ev)
	}
	if _, ok := m.Mounts["/work"]; !ok {
		t.Fatal("manifest must describe /work")
	}
}
