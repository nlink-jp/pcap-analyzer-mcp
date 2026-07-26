# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Phase 1 (Planning): RFP in `docs/{en,ja}/`
- Phase 0 (Design): ADR-0001 through ADR-0007, `architecture`, `phase1-plan`
- Phase 2 (Scaffolding): repository structure, `Makefile`, `config.example.toml`,
  and the `serve` / `build-runtime` / `doctor` / `version` subcommand skeletons
- `internal/config`: config.toml loading with a single validation path
- Phase 1 Track B: MCP stdio protocol layer — `internal/transport`,
  `internal/jsonrpc`, `internal/mcpserver`, `internal/toolerr`
- Phase 1 Track C: the tshark analysis image (`runtime/`, digest-pinned,
  274MB), `internal/podman`, a working `build-runtime` (with `--force`) and
  `doctor`, and the static `describe_runtime` manifest with a Dockerfile
  drift test
- Phase 1 Track D: `internal/workspace` — workspace creation and listing,
  `meta.json`, capinfos parsing, host-side SHA-256, path validation, and
  `podman.RunOnce`; plus integration tests that drive the real image
- Phase 1 Track E: the read-only edition — `internal/tshark` (argv, field/CSV
  parsing, protocol hierarchy, conversation aggregation, error classification),
  `internal/output` (the ADR-0005 contract), `internal/tools` (nine tools), and
  a wired-up `serve`
- Phase 1 Track F: `internal/job` — background execution with `async: true` on
  the four whole-capture tools, a `check_job` tool, and a `[jobs]
  max_concurrent` cap on simultaneous container runs
- Phase 1 Track G: `follow_stream` and `extract_objects`, with the four
  safety mechanisms of ADR-0007 — `payload.Untrusted` (self-redacting in logs,
  errors and formatting; framing emitted ahead of the content), object defang
  to `<sha256>.bin` at mode 0600, and ranged reads windowed per direction

### Added (Phase 2)

- `samples/` — four synthetic captures, a generator that builds them with the
  analysis image's own Wireshark tools, and an eleven-stage graded walkthrough
- `e2e/` — a dummy MCP client that drives the built binary over stdio through
  those same eleven stages against real podman
- `internal/logging` — `[log] file` is now honoured, rotating five generations
  on startup and written 0600. It was configurable but ignored before
- `docs/{en,ja}/reference/client-setup.md`

### Fixed (real-client validation)

Found by driving the server from an actual MCP client rather than a harness.

- **`list_conversations` returned an empty list on a truncated capture with no
  explanation.** A snaplen small enough to cut the TCP header removes the stream
  index the tool aggregates on, so a capture with two conversations reported
  none — and the truncation guidance had explicitly promised this tool still
  worked. It now reports how many packets lacked an index and why
- **`extract_objects` wrapped every `source_name` individually**: ~250 bytes of
  identical framing around a ~20-byte filename, which for a hundred objects is
  25KB of the same sentence. Names are now framed once at the manifest level —
  the byte-budget reasoning ADR-0007 already applies to field values
- `get_usage` had drifted from the code: its async list omitted
  `extract_objects`, and `suggested_flow` stopped before the payload tools, so
  an agent following it would never discover them
- A finished job reported `progress.rows: 0` alongside a result containing rows
- The aggregator's doc claimed "A" is the initiator. It is whichever endpoint
  appears first, which differs on a capture that starts mid-stream

### Security

Findings from an independent review of the whole tree.

- **Container runs now have a wall-clock timeout** (`[container.limits] timeout`,
  default 30m) and the server context is signal-aware. Previously nothing bounded
  a run: `rootCmd.Execute()` supplies `context.Background()`, so `cmd.Context()`
  never cancelled, and a capture that drove a dissector into a pathological loop
  would hang the server indefinitely — requests are handled in order, so one
  input file took everything with it
- **Panics are recovered** at the request boundary and, more importantly, inside
  the background-job goroutine, where Go would otherwise terminate the process
  and drop every queued job
- **`query_packets` and `list_conversations` results now carry an `untrusted`
  statement** ahead of the rows. Field values such as `_ws.col.Info` are text off
  the wire and were returned unframed while `follow_stream` carefully wrapped the
  same class of data. ADR-0007 and CLAUDE.md disagreed on this; ADR-0007 now sets
  out three tiers explicitly
- **`list_conversations` bounds distinct streams** (`[output] max_conversations`)
  and reports what it dropped. The aggregation map lives in the server process,
  outside the container's memory cgroup, and `top_n` applies after aggregation
- **`extract_objects` bounds object count and total bytes**
  (`[payload] extract_max_objects`, `extract_max_total_bytes`), not just per-object size
- An oversized stdio frame no longer ends the session, live jobs are capped,
  `cpu`/`memory` are validated as non-empty (an empty value silently dropped the
  flag), and a negative `limit` is rejected

### Fixed

- `follow_stream` no longer buffers a whole stream before windowing it; parsing
  is streamed and bounded by `[payload] follow_max_reassembly_bytes`
- `follow_stream` clamps `length` to `[payload] follow_max_window_bytes`; it was
  previously unbounded
- `extract_objects` writes `manifest-<protocol>.json`, so extracting a second
  protocol no longer overwrites the first manifest

### Changed

- Release archives are 4 platforms, not 5: darwin ships arm64 only per
  CONVENTIONS.md §Release Archive Standard (effective 2026-07-12)
- The analysis image deletes `/usr/bin/dumpcap` rather than only declining its
  setuid bit (ADR-0003 amended)
- The capture is bind-mounted as a single file at the fixed container path
  `/evidence/capture`, not as its parent directory (ADR-0004 amended). Siblings
  are no longer exposed, and the host filename never reaches an argv
- Results carry an explicit `delivery` field ("inline" or "file") instead of
  leaving the agent to infer the channel from which keys are present
  (ADR-0005 amended)
- Docs corrected against the built image: `--export-objects` supports six
  protocols (not four), `capinfos` metadata is read via `-T -m -Q`
  (not `-M`), truncation must be judged from the inferred snaplen as well as
  the file header, and `dropped_packets` is dropped from v1 because `capinfos`
  does not report pcapng ISB drop counts
