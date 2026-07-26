# ADR-0003: Lean tshark-only image with a digest pin

- Status: Accepted
- Date: 2026-07-26
- Driver: magi
- Revisions: 2026-07-26 — Decision and Consequences amended after the Track C build (dumpcap removal, measured size, resolved digest)
- Generalises to: none

---

## Context

Delegating analysis to tshark inside a container (ADR-0001 / ADR-0002) requires deciding what goes into the runtime image.

The first motivation is **pinning the tshark version**. Field names under `-T fields` / `-T ek`, `-z` statistic formats, and the protocols supported by `--export-objects` all change between tshark versions. Depending on the host's installed tshark means output varies per machine and parsers break.

The second motivation is **isolation**. Wireshark dissectors have historically been a source of vulnerabilities, and analyzing an attacker-controlled pcap is itself risky.

Two image compositions were considered:

- **A. Lean (tshark only)** — results leave as JSONL / CSV, SQL aggregation is delegated to data-toolbox-mcp
- **B. Combined (tshark + Python + DuckDB)** — tshark → tabular → SQL all inside one container

B removes handoff friction but duplicates functionality that data-toolbox-mcp already owns.

## Decision

**Adopt A (lean). The image contains tshark and its dependencies only — no Python, DuckDB, or pyarrow.**

```dockerfile
FROM debian:12-slim@sha256:7b140f37...    # digest pin (real value in runtime/Dockerfile)

# wireshark-common asks via debconf whether non-superusers may capture packets.
# Make it non-interactive and explicitly disable setuid dumpcap (we never
# capture). The debconf answer alone leaves the dumpcap binary in place, just
# without its setuid bit, so delete it outright. tshark -r does not use it.
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" \
      | debconf-set-selections \
 && DEBIAN_FRONTEND=noninteractive apt-get update \
 && apt-get install -y --no-install-recommends tshark \
 && rm -f /usr/bin/dumpcap \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 pcap
USER 1000:1000
ENV TMPDIR=/work/tmp
WORKDIR /work
```

- **The base image is pinned by digest.** No dependency on a moving tag like `debian:12-slim`
- **The image digest and tshark version used are recorded in the workspace metadata** (ADR-0004). Being able to answer "which tshark version produced this result" matters as provenance and when a dissector-specific interpretation difference is suspected
- The Dockerfile is embedded with `go:embed` and built locally via the `build-runtime` subcommand. No registry push (same policy as data-toolbox-mcp ADR-0005)
- `describe_runtime` discloses the image digest, tshark version, and supported export-object protocols, with a drift test against the Dockerfile

Export formats are **JSONL / CSV**.

## Consequences

**Positive:**

- **Measured image size of 274MB** (versus data-toolbox-mcp's 882MB). The original 150–250MB estimate was low, but the size and the `build-runtime` time are both acceptable
- **`capinfos` / `editcap` / `mergecap` / `text2pcap` come along automatically (verified).** Because `tshark` depends on `wireshark-common`, both metadata retrieval (`capinfos`) and split-capture merging (`mergecap`) work with no extra installs. A useful side effect: `text2pcap` can synthesize test fixtures
- **Deleting the dumpcap binary and running non-root produces an image with no capture capability.** Live capture being out of scope is guaranteed by construction, not by policy
- **`tshark --export-objects` supports six protocols** (`dicom` / `ftp-data` / `http` / `imf` / `smb` / `tftp`). The RFP assumed four; `ftp-data` and `dicom` turned up on measurement
- No functional overlap with data-toolbox-mcp; the split of responsibility stays clean

**Negative:**

- **parquet cannot be written.** There is no parquet writer in the container, and adding one on the Go side would defeat the lean goal. Exports are limited to JSONL / CSV. data-toolbox-mcp's `load_data` reads both through DuckDB so the handoff works, but it is less efficient than parquet at scale
- **SQL aggregation requires a second server (data-toolbox-mcp).** Users configure two MCP servers. Furthermore, data-toolbox's `load_data` physically copies host files into `/work/_upload/`, so handing over a huge export triggers a copy. In practice, exports should be filtered down first
- A digest pin does not pick up tshark security updates automatically. Image updates become an explicit task — accepted as the cost of version pinning
- Debian's tshark version lags upstream Wireshark. Needing the newest dissectors would require a separate decision

## See also

- ADR-0001: Choose tshark as the analysis backend
- ADR-0002: Ephemeral per-call containers
- Ported from: data-toolbox-mcp ADR-0005 (local build + `go:embed` Dockerfile)
