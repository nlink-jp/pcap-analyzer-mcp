# Analysis runtime for pcap-analyzer-mcp (ADR-0003).
#
# Lean by design: tshark and nothing else. No Python, no DuckDB — SQL over an
# exported packet table is data-toolbox-mcp's job, so exports leave as
# JSONL/CSV rather than parquet.
#
# Pinned by digest, not by tag: `debian:12-slim` moves, and a moving base
# means the tshark version moves with it. Pinning the version is the entire
# point of running tshark in a container. internal/runtime/manifest.go carries
# the same digest and a drift test keeps the two in step.
FROM debian:12-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

# The wireshark-common package asks, via debconf, whether non-superusers
# should be able to capture packets. Answer it non-interactively and say no:
# this image only ever reads capture files, so setuid dumpcap would be pure
# attack surface. Installing tshark also brings capinfos, editcap, mergecap
# and text2pcap along, which is where capture metadata and split-capture
# merging come from.
#
# The debconf answer leaves dumpcap installed, just without its setuid bit, so
# delete the binary outright: nothing here ever captures, and a capture tool
# that cannot be invoked is better than one that merely lacks privileges.
# tshark -r does not use dumpcap.
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" \
      | debconf-set-selections \
 && DEBIAN_FRONTEND=noninteractive apt-get update \
 && apt-get install -y --no-install-recommends tshark \
 && rm -f /usr/bin/dumpcap \
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
