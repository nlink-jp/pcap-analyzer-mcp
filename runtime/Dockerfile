# Analysis runtime for pcap-analyzer-mcp (ADR-0003).
#
# Lean by design: tshark and nothing else. No Python, no DuckDB — SQL over an
# exported packet table is data-toolbox-mcp's job, so exports leave as
# JSONL/CSV rather than parquet.
#
# TODO(Track C): replace the tag with a digest pin (debian:12-slim@sha256:...)
# once the image is first built, and record it in internal/runtime/manifest.go.
# Pinning the version is the entire point of running tshark in a container.
FROM debian:12-slim

# The wireshark-common package asks, via debconf, whether non-superusers
# should be able to capture packets. Answer it non-interactively and say no:
# this image only ever reads capture files, so setuid dumpcap would be pure
# attack surface. Installing tshark also brings capinfos, editcap, mergecap
# and text2pcap along, which is where capture metadata and split-capture
# merging come from.
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" \
      | debconf-set-selections \
 && DEBIAN_FRONTEND=noninteractive apt-get update \
 && apt-get install -y --no-install-recommends tshark \
 && rm -rf /var/lib/apt/lists/*

# tshark warns loudly when run as root, and there is no reason to be root
# here: /evidence is read-only and /work is owned by the invoking user via
# --userns=keep-id.
RUN useradd -m -u 1000 pcap
USER 1000:1000

# Keep temporary files on the writable mount. /evidence is read-only, and
# object export and reassembly both need scratch space.
ENV TMPDIR=/work/tmp
WORKDIR /work

# Containers are started per call with an explicit command (ADR-0002); this
# is only a safe default for an interactive `podman run`.
CMD ["tshark", "--version"]
