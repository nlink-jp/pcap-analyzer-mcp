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
