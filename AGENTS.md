# AGENTS.md — pcap-analyzer-mcp

Navigation hints for AI agents (Claude Code, Cursor, etc.) working inside this project.

## What this project is

An MCP server (stdio, single Go binary) that analyses pcap / pcapng captures on
behalf of an LLM agent. A version-pinned tshark runs inside a rootless,
network-less container; the capture is mounted **read-only and never copied**.
Results come back inline when small and as JSONL files in the workspace when
large.

**Status: Phase 2 (Scaffolding) complete. No business logic yet** — `serve`,
`build-runtime`, and `doctor` are skeletons that report which Phase 1 track
will implement them.

## Build / test

- `make build` — never `go build` directly (writes to `dist/`, injects the version)
- `make test` — all Go unit tests
- `make runtime-image` — builds the tshark container image (wraps `pcap-analyzer-mcp build-runtime`)
- `make build-all` — cross-compile darwin/arm64 + linux/{amd64,arm64} + windows/amd64
- `make help` — list targets

darwin is **arm64 only** (no amd64, no universal) per CONVENTIONS.md
§Release Archive Standard.

## Project structure

| Path | Role | Phase 1 track |
|------|------|---------------|
| `main.go` | Entry point, delegates to `cmd.Execute()` | A ✅ |
| `cmd/` | cobra subcommands (root / serve / build-runtime / doctor / version) | A ✅ |
| `internal/config/` | config.toml loading, single `Validate()` path | A ✅ |
| `runtime/Dockerfile` | Source for the tshark image, embedded via `go:embed` | C |
| `internal/transport/` | MCP stdio JSON-RPC framing | B |
| `internal/jsonrpc/` | JSON-RPC 2.0 types | B |
| `internal/mcpserver/` | MCP protocol (initialize, tools/list, tools/call) | B |
| `internal/toolerr/` | Structured `{code, message, details}` tool errors | B |
| `internal/workspace/` | Workspace creation, `meta.json`, per-call `podman run` | D |
| `internal/tshark/` | tshark argument assembly and output parsing | E |
| `internal/output/` | The output contract: byte threshold, `matched`, `sample`, JSONL | E |
| `internal/job/` | Async jobs + `check_job` | F |
| `internal/payload/` | Nonce XML isolation, defang | G |
| `internal/tools/` | The 11 tool handlers | E, G |
| `testdata/gen/` | gopacket fixture generators (synthetic captures only) | H |
| `e2e/` | Dummy MCP client harness (build tag `e2e`) | H |
| `docs/{en,ja}/` | RFP, ADR-0001–0007, architecture, phase1-plan | Phase 0/1 ✅ |

## ADR cheat sheet

- **ADR-0001**: tshark is the backend. Display filters pass through from the agent verbatim. Zeek is deferred, and adopting it would mean *new tools*, not a backend swap.
- **ADR-0002**: Containers are **ephemeral, one per `podman run --rm` per call**. No persistent container, no `podman exec`, no orphan scanning. tshark is stateless, so there is nothing to persist.
- **ADR-0003**: Lean image — `debian:12-slim` (digest-pinned) + `tshark` only. No DuckDB, no Python, therefore **no parquet**; exports are JSONL / CSV. setuid dumpcap is disabled, so the image cannot capture.
- **ADR-0004**: **1 pcap : 1 workspace.** The capture's parent directory is mounted `ro` at `/evidence` and never copied. `workspace_dir` is an argument, not config. `allowed_paths` is a guardrail (default: unrestricted), not a sandbox boundary.
- **ADR-0005**: Output contract — threshold in **bytes not rows**, response shape identical inline vs. file, `matched` always returned, `sample` attached for file results, large output is **JSONL not a JSON array**.
- **ADR-0006**: Async for heavy tools only (`create_workspace`, `protocol_hierarchy`, `list_conversations`, `query_packets`, `extract_objects`). Validation stays synchronous. Jobs are in-memory; `job_not_found` means "just re-run it".
- **ADR-0007**: Payload safety, all four in the same commit as the payload code — nonce XML isolation with the framing **first**, defang to `<sha256>.bin` mode 0600, payload never logged, ranged reads via `offset`/`length`.

## Tool surface (11 + get_usage)

`get_usage` · `create_workspace` · `describe_workspace` · `list_workspaces` ·
`delete_workspace` · `describe_runtime` · `protocol_hierarchy` ·
`list_conversations` · `query_packets` · `follow_stream` · `extract_objects` ·
`check_job`

`describe_workspace` is the free one — it reads the `capinfos` cache and starts
no container. Expect it to be the most-called tool.

## Gotchas

- **`-z conv,tcp` does not carry `tcp.stream`.** `list_conversations` is the entry point to `follow_stream`, so it must be built from `-T fields -e tcp.stream ...` with server-side aggregation. Confirm against real output (phase1-plan §5 Q5-1).
- **Truncated captures.** A capture taken with a small snaplen has no payload. Surface `snaplen` / `truncated` from `describe_workspace` and return `payload_unavailable_truncated_capture` *before* running a payload tool, or the agent will read the empty result as a transient failure and retry forever.
- **`dropped_packets` changes conclusions.** "No SYN" means something entirely different when the capture engine dropped packets. Disclose it when pcapng ISB records it.
- **`capinfos -M`** for machine-readable output. Do not parse the human-formatted form with thousands separators and unit suffixes.
- **Debian's `tshark` package prompts via debconf** about setuid dumpcap. Non-interactive install plus `debconf-set-selections` setting it to false.
- **tshark warns when run as root.** The image runs as `USER 1000`.
- **macOS virtiofs.** Captures outside `/Users`, `/private/tmp`, `/var/folders` cannot be mounted. `doctor` checks this.
- **Podman Machine memory.** 4GB default is not enough for a full pass over a large capture; 8GB recommended.
- Time values are returned as **epoch plus UTC ISO-8601**, never local-formatted.

## Conventions (organization-wide)

https://github.com/nlink-jp/.github/blob/main/CONVENTIONS.md — tests are
mandatory, docs move with behaviour (README.md **and** README.ja.md in the same
commit), commits are small and typed.
