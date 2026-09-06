#!/usr/bin/env bash
# test-linux.sh — run this repository's Go test suite on Linux.
#
# The development host is macOS/arm64, so every GOOS=linux branch compiles
# but never executes. This runs the suite inside a Linux container so those
# branches are actually exercised before a linux/* binary is published.
#
#   scripts/test-linux.sh                 # linux/arm64 (native speed)
#   ARCH=amd64 scripts/test-linux.sh      # linux/amd64 via qemu-user
#   scripts/test-linux.sh -run TestFoo    # extra args go to `go test`
#
# Env:
#   GO_IMAGE  container image (default: golang:1.26)
#   ARCH      arm64 (default) | amd64
#
# Three container-side defaults are wrong for this job, and each one fails
# silently — the suite goes green (or red) for reasons that have nothing to
# do with Linux. They are pinned below; do not drop them:
#
#   --platform      A locally cached amd64 image is picked up without an
#                   error, and the whole suite then runs under qemu. That
#                   surfaces as `qemu: uncaught target signal 11`, which
#                   reads like a real crash and is not one.
#   --userns        As root, DAC checks are bypassed: a test that chmods a
#                   path to 0500 and expects the write to fail will see it
#                   succeed. keep-id runs as the invoking user instead.
#   GOTOOLCHAIN     The image pins GOTOOLCHAIN=local, so a repo whose go.mod
#                   asks for a newer Go than the image fails to build rather
#                   than fetching the toolchain.
#
# amd64 runs under QEMU user-mode emulation inside the container VM. It does
# not depend on Apple's Rosetta, which Apple is retiring after macOS 27. It
# is also not proof that the binary works on a real amd64 host.

set -euo pipefail

GO_IMAGE="${GO_IMAGE:-golang:1.26}"
ARCH="${ARCH:-arm64}"

CONTAINER="$(command -v podman 2>/dev/null || command -v docker 2>/dev/null || true)"
if [ -z "$CONTAINER" ]; then
	echo "test-linux: podman or docker is required (brew install podman)." >&2
	exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The Go caches must not live on the virtiofs bind mount — it is slow, and
# unix sockets do not traverse it. Named volumes are shared across every
# nlink-jp repo, so the second run onward is warm. `:U` hands them to the
# container user, which keep-id has already changed away from root.
exec "$CONTAINER" run --rm \
	--platform "linux/$ARCH" \
	--userns=keep-id \
	-v "$repo_root:/src:z" \
	-w /src \
	-v nlink-gocache-u:/gocache:U \
	-v nlink-gomod-u:/gomod:U \
	-e HOME=/tmp/h \
	-e GOCACHE=/gocache \
	-e GOMODCACHE=/gomod \
	-e GOTOOLCHAIN=auto \
	-e GOFLAGS=-buildvcs=false \
	"$GO_IMAGE" \
	go test "$@" ./...
