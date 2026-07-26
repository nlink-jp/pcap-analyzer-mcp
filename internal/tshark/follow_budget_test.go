package tshark

import (
	"strings"
	"testing"
)

// A ranged read is no protection if the whole transfer has already been pulled
// into memory to serve it. The budget is what actually bounds it.
func TestParseFollowStreamRespectsTheBudget(t *testing.T) {
	// 100 bytes per direction, hex-encoded.
	big := strings.Repeat("41", 100)
	out := "Node 0: a:1\nNode 1: b:2\n" + big + "\n\t" + big + "\n"

	res, truncated, err := ParseFollowStream("tcp", 0, strings.NewReader(out), 150)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated {
		t.Error("exceeding the budget must be reported")
	}
	if res.TotalBytes > 150 {
		t.Errorf("read %d bytes with a budget of 150", res.TotalBytes)
	}
	if res.TotalBytes != 150 {
		t.Errorf("the budget should be filled, got %d", res.TotalBytes)
	}
}

func TestParseFollowStreamUnderBudget(t *testing.T) {
	out := "Node 0: a:1\nNode 1: b:2\n" + strings.Repeat("41", 10) + "\n"
	res, truncated, err := ParseFollowStream("tcp", 0, strings.NewReader(out), 1000)
	if err != nil {
		t.Fatal(err)
	}
	if truncated {
		t.Error("a stream inside the budget is not truncated")
	}
	if res.TotalBytes != 10 {
		t.Errorf("TotalBytes = %d", res.TotalBytes)
	}
}
