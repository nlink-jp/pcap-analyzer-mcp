// Package runtime embeds the analysis container's Dockerfile into the binary
// so `build-runtime` can build the image without shipping loose files
// (ADR-0003).
package runtime

import _ "embed"

// Dockerfile is the source of the tshark analysis image.
//
//go:embed Dockerfile
var Dockerfile string
