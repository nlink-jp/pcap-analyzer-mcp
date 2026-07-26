package workspace

import (
	"strings"
	"testing"
)

// Captured verbatim from `capinfos -T -m -Q -S -t -E -l -c -s -d -u -a -e -y -z -H -F`
// running tshark 4.0.17 inside the analysis image.
const realCapinfosOutput = `"File name","File type","File encapsulation","File time precision","Packet size limit","Packet size limit min (inferred)","Packet size limit max (inferred)","Number of packets","File size (bytes)","Data size (bytes)","Capture duration (seconds)","Start time","End time","Data byte rate (bytes/sec)","Average packet size (bytes)","SHA256","RIPEMD160","SHA1","Capture hardware","Capture oper-sys","Capture application"
"/evidence/capture","pcapng","ether","nanoseconds","(not set)","n/a","n/a","2","504","144","0.000000000","1785043399.000001000","1785043399.000001000","0.00","72.00","a5c2bc7615d4e2534c5a5e09f3fbc5630a08b1651a40bc4d97a7cd7b7b6b470b","a88c4d820b2430cfcf8ce85fc4dc6b47f262853d","0f6b1d6efdf70e5d7fb417732913cb370448eacf","","Linux 6.15.10-200.fc42.aarch64","Mergecap (Wireshark) 4.0.17"
`

func TestParseCapinfosRealOutput(t *testing.T) {
	info, err := ParseCapinfos([]byte(realCapinfosOutput))
	if err != nil {
		t.Fatal(err)
	}
	if info.Format != "pcapng" {
		t.Errorf("Format = %q", info.Format)
	}
	if info.Encapsulation != "ether" {
		t.Errorf("Encapsulation = %q", info.Encapsulation)
	}
	if info.PacketCount != 2 {
		t.Errorf("PacketCount = %d", info.PacketCount)
	}
	if info.FileSize != 504 || info.DataSize != 144 {
		t.Errorf("sizes = %d/%d", info.FileSize, info.DataSize)
	}
	if info.AvgPacketSize != 72 {
		t.Errorf("AvgPacketSize = %v", info.AvgPacketSize)
	}
	if info.SHA256 != "a5c2bc7615d4e2534c5a5e09f3fbc5630a08b1651a40bc4d97a7cd7b7b6b470b" {
		t.Errorf("SHA256 = %q", info.SHA256)
	}
	if info.CaptureOS == "" || !strings.HasPrefix(info.CaptureApp, "Mergecap") {
		t.Errorf("capture provenance not picked up: %q / %q", info.CaptureOS, info.CaptureApp)
	}
}

// `-S` gives epoch seconds; the UTC rendering is produced in Go so no timezone
// ever has to be inferred from the text.
func TestParseCapinfosTimestamps(t *testing.T) {
	info, err := ParseCapinfos([]byte(realCapinfosOutput))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.FirstPacket.Epoch; got < 1785043398 || got > 1785043400 {
		t.Errorf("FirstPacket.Epoch = %v", got)
	}
	if !strings.HasPrefix(info.FirstPacket.UTC, "2026-07-26T05:23:19") {
		t.Errorf("FirstPacket.UTC = %q, want a UTC rendering", info.FirstPacket.UTC)
	}
	if !strings.HasSuffix(info.FirstPacket.UTC, "Z") {
		t.Errorf("timestamps must be UTC, got %q", info.FirstPacket.UTC)
	}
}

// An untruncated capture reports "n/a" for the inferred limits, and that — not
// the header — is what decides the verdict.
func TestParseCapinfosNotTruncated(t *testing.T) {
	info, err := ParseCapinfos([]byte(realCapinfosOutput))
	if err != nil {
		t.Fatal(err)
	}
	if info.Truncated {
		t.Error("a capture with no inferred limit is not truncated")
	}
	if info.SnaplenInferredMin != nil || info.SnaplenInferredMax != nil {
		t.Error(`"n/a" must decode to nil, not 0`)
	}
	if info.SnaplenHeader != "(not set)" {
		t.Errorf("SnaplenHeader = %q; the raw header value is kept as context", info.SnaplenHeader)
	}
}

// Verbatim from the same image after `editcap -s 40`. The header still says
// "(not set)" while the packets are in fact cut — the case that makes
// header-based truncation detection wrong.
const truncatedCapinfosOutput = `"File name","Packet size limit","Packet size limit min (inferred)","Packet size limit max (inferred)","Number of packets"
"/evidence/capture","(not set)","40","40","2"
`

func TestParseCapinfosTruncatedDespiteUnsetHeader(t *testing.T) {
	info, err := ParseCapinfos([]byte(truncatedCapinfosOutput))
	if err != nil {
		t.Fatal(err)
	}
	if !info.Truncated {
		t.Fatal("inferred limits present means the packets were cut")
	}
	if info.SnaplenHeader != "(not set)" {
		t.Errorf("SnaplenHeader = %q", info.SnaplenHeader)
	}
	if info.SnaplenInferredMin == nil || *info.SnaplenInferredMin != 40 {
		t.Errorf("SnaplenInferredMin = %v, want 40", info.SnaplenInferredMin)
	}
	if info.SnaplenInferredMax == nil || *info.SnaplenInferredMax != 40 {
		t.Errorf("SnaplenInferredMax = %v, want 40", info.SnaplenInferredMax)
	}
}

// Columns are keyed by header name, so capinfos reordering them (or adding
// one) must not shift the values.
func TestParseCapinfosIsOrderIndependent(t *testing.T) {
	reordered := `"Number of packets","File type","New Column We Do Not Know","File encapsulation"
"7","pcap","junk","ether"
`
	info, err := ParseCapinfos([]byte(reordered))
	if err != nil {
		t.Fatal(err)
	}
	if info.PacketCount != 7 || info.Format != "pcap" || info.Encapsulation != "ether" {
		t.Errorf("positional decoding leaked through: %+v", info)
	}
}

func TestParseCapinfosRejectsUnusableOutput(t *testing.T) {
	for name, in := range map[string]string{
		"empty":       "",
		"header only": `"File type"` + "\n",
	} {
		if _, err := ParseCapinfos([]byte(in)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

// The comment field is excluded on purpose; assert it stays excluded, because
// capture comments contain literal newlines that would break the record.
func TestCapinfosArgsExcludeTheCommentField(t *testing.T) {
	args := CapinfosArgs("/evidence/capture")
	for _, a := range args {
		if a == "-k" {
			t.Error("-k (capture comment) must not be requested: comments contain newlines")
		}
	}
	if args[0] != "capinfos" || args[len(args)-1] != "/evidence/capture" {
		t.Errorf("unexpected argv shape: %v", args)
	}
	joined := strings.Join(args, " ")
	for _, required := range []string{"-T", "-m", "-Q", "-S", "-l", "-H"} {
		if !strings.Contains(joined, required) {
			t.Errorf("argv missing %s: %s", required, joined)
		}
	}
}
