# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2026-07-26

### Fixed

- **A single unreadable object no longer sinks `extract_objects`.** Over-size
  objects were already recorded in `skipped` and the extraction carried on, but
  an object that could not be read aborted the call. On a host with antivirus
  running that is the normal case, not the edge case: the AV quarantines a
  sample mid-write, and a capture where 2 of 3 objects were detected returned
  nothing at all — not even the benign one. Unreadable objects are now skipped
  with a reason naming the likely cause, and the recoverable ones come back.
  Reported in the field notes contributed by @magifd2

### Changed

- `get_usage` now describes the `extract_objects` manifest, including what a
  populated `skipped` list means. An empty `objects` with entries in `skipped`
  is a successful call, and worth reading as a finding

## [0.1.1] - 2026-07-26

### Fixed

- **`--version` now works.** Only the `version` subcommand did. Every other
  tool in the org answers the flag, and the shared homebrew formula template
  tests for it — so the tap's test block would have failed on install. Found
  by wiring up tap distribution

## [0.1.0] - 2026-07-26

First release. An MCP server that lets an agent analyse pcap / pcapng captures
through a version-pinned tshark running in a container.

### Added

- **Twelve MCP tools** over stdio: `get_usage`, `create_workspace`,
  `describe_workspace`, `list_workspaces`, `delete_workspace`,
  `describe_runtime`, `protocol_hierarchy`, `list_conversations`,
  `query_packets`, `follow_stream`, `extract_objects`, `check_job`
- **CLI**: `serve`, `build-runtime`, `doctor`, `version`
- **A digest-pinned analysis image** (`debian:12-slim` + tshark 4.0.17, 274MB),
  built locally by `build-runtime` from a Dockerfile embedded in the binary.
  Pinning the version is why the container exists: `-T fields` names and `-z`
  formats drift between tshark releases
- **The capture is mounted read-only as a single file and never copied.** The
  original stays byte-identical, siblings in its directory stay invisible, and
  the host filename never becomes a container path or an argv
- **A workspace is a directory plus a metadata file.** No long-lived container,
  no in-memory registry — so workspaces survive a restart and
  `describe_workspace` answers in milliseconds from a cache
- **One result contract for every tool** (ADR-0005): the size threshold is
  serialized bytes rather than rows, `matched` always reports what the filter
  hit so "too broad" is distinguishable from "nothing there", large results go
  to the workspace as JSONL or CSV with a leading `sample`, and the response
  shape does not change between the two
- **`async: true` with `check_job`** for the tools that read a whole capture,
  bounded by a concurrency cap. Progress carries a phase and a row count, never
  a percentage — tshark does not report how far through a capture it is, and an
  invented number is worse than none
- **tshark's own diagnostics are forwarded**, not paraphrased. A bad display
  filter comes back with the expression and the column tshark objected to,
  which is what lets a caller fix it rather than retry it
- **`samples/`** — four synthetic captures, a generator that builds them with
  the image's own Wireshark tools, and an eleven-stage graded walkthrough
- **Documentation**: RFP, ADR-0001–0007, architecture, and client setup, in
  English and Japanese

### Security

This server exists to analyse hostile captures, so adversarial input is the
normal case rather than the exception.

- **The analysis container cannot capture traffic.** No network, non-root, all
  capabilities dropped, and the `dumpcap` binary deleted at build time — the
  scope boundary is enforced by construction, not by policy
- **Content read out of a capture is framed as untrusted, framing first.** Free-
  text blobs (reassembled streams) get nonce-tagged delimiters; field values and
  object names get one statement at the head of the result, since JSON escaping
  already makes their structure unforgeable
- **Payload cannot reach the log.** It lives in a type that redacts itself in
  formatting, errors and `slog`; the single explicit accessor is greppable
- **Extracted objects are defanged**: stored as `<sha256>.bin`, mode 0600, never
  returned inline. tshark writes attacker-derived filenames — on the bundled
  sample, one carrying a URL-encoded slash
- **A truncated capture is refused before anything runs**, with the inferred
  snaplen as evidence and a note on which tools still work
- Container runs are bounded by a wall-clock timeout; panics are recovered at
  the request and job boundaries; and host-side memory and disk are bounded
  independently of the container's cgroup, which does not cover them

### Known limitations

- One capture per workspace; ring-buffer split captures are not yet merged
- Live capture, IDS-style detection, pcap editing and parquet output are all out
  of scope
- Requests are handled in order, so a long synchronous call blocks the rest —
  use `async` for large captures
- `dropped_packets` is not reported: `capinfos` does not expose pcapng ISB drop
  counts
