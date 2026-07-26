package runtime

// DefaultImageTag is the tag `build-runtime` produces. It is local-only: the
// image is never pushed to a registry (ADR-0003).
const DefaultImageTag = "localhost/pcap-analyzer-runtime:latest"

// BaseImage is the human-readable base image reference.
const BaseImage = "debian:12-slim"

// BaseImageDigest pins the base image. It must match the FROM line in
// Dockerfile; TestManifestMatchesDockerfile enforces that.
//
// Changing this digest changes the tshark build, and with it TsharkVersion and
// possibly ExportObjectProtocols. Re-verify both against a freshly built image
// whenever you touch it.
const BaseImageDigest = "sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818"

// TsharkVersion is the tshark shipped by the pinned base image.
const TsharkVersion = "4.0.17"

// Manifest is the static description of the analysis runtime, returned by
// describe_runtime.
//
// It is static by design: it states what the image is *supposed* to contain,
// and answers describe_runtime without paying for a container start. What a
// given analysis actually ran against is recorded per workspace at
// create_workspace time, so a stale local image surfaces as a disagreement
// between the two rather than as a silently wrong answer.
type Manifest struct {
	BaseImage       string   `json:"base_image"`
	BaseImageDigest string   `json:"base_image_digest"`
	TsharkVersion   string   `json:"tshark_version"`
	Tools           []string `json:"tools"`

	// ExportObjectProtocols is what `tshark --export-objects` accepts in this
	// image, taken from the pinned build rather than from documentation.
	ExportObjectProtocols []string `json:"export_object_protocols"`

	// Mounts describes the two bind mounts every analysis container gets.
	Mounts map[string]string `json:"mounts"`

	// Notes are addressed to the agent reading describe_runtime.
	Notes []string `json:"notes"`
}

// Default is the manifest for the image this binary knows how to build.
func Default() Manifest {
	return Manifest{
		BaseImage:       BaseImage,
		BaseImageDigest: BaseImageDigest,
		TsharkVersion:   TsharkVersion,
		Tools:           []string{"tshark", "capinfos", "editcap", "mergecap", "text2pcap"},
		ExportObjectProtocols: []string{
			"dicom", "ftp-data", "http", "imf", "smb", "tftp",
		},
		Mounts: map[string]string{
			"/evidence": "read-only. The directory holding the capture. Never written to, never copied.",
			"/work":     "read-write. The workspace: query output, extracted objects, tshark scratch.",
		},
		Notes: []string{
			"This image cannot capture traffic. It runs with no network, as a " +
				"non-root user, with all capabilities dropped, and the dumpcap " +
				"binary is deleted at build time.",
			"Objects written under /work/out/objects/ come from the capture and " +
				"are untrusted. They are stored as <sha256>.bin, never executable, " +
				"and their bytes are never returned inline — pivot on the hash.",
			"Results are files under /work, not inline bytes. Large output is " +
				"JSONL so it can be read incrementally or loaded straight into DuckDB.",
		},
	}
}
