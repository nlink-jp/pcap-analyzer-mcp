# AGENTS.md — pcap-analyzer-mcp

Navigation hints for AI agents (Claude Code, Cursor, etc.) working inside this project.

## What this project is

An MCP server (stdio, single Go binary) that analyses pcap / pcapng captures on
behalf of an LLM agent. A version-pinned tshark runs inside a rootless,
network-less container; the capture is mounted **read-only and never copied**.
Results come back inline when small and as JSONL files in the workspace when
large.

**Status: Phase 1 complete (Tracks A–G).** All twelve tools are implemented and
driven end to end against real podman, payload extraction included. What
remains before a release is the Track G security review and Phase 2 (real-client
validation, samples, client-setup docs).

## Build / test

- `make build` — never `go build` directly (writes to `dist/`, injects the version)
- `make test` — all Go unit tests
- `go test -tags integration ./internal/workspace/` — drives real podman and the analysis image (needs `make runtime-image` first)
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
| `runtime/` | tshark image Dockerfile + `go:embed` + the static `describe_runtime` manifest | C ✅ |
| `internal/podman/` | podman CLI wrapper (build / inspect / machine / mount probe) | C ✅ |
| `internal/transport/` | MCP stdio JSON-RPC framing | B ✅ |
| `internal/jsonrpc/` | JSON-RPC 2.0 types | B ✅ |
| `internal/mcpserver/` | MCP protocol (initialize, tools/list, tools/call) | B ✅ |
| `internal/toolerr/` | Structured `{code, message, details}` tool errors | B ✅ |
| `internal/workspace/` | Workspace creation, `meta.json`, capinfos parsing, path validation | D ✅ |
| `internal/tshark/` | tshark argument assembly and output parsing | E ✅ |
| `internal/output/` | The output contract: byte threshold, `matched`, `sample`, JSONL | E ✅ |
| `internal/job/` | Async jobs + `check_job`, with a concurrency cap | F ✅ |
| `internal/payload/` | Untrusted (self-redacting), nonce framing, object defang | G ✅ |
| `internal/tools/` | All twelve tool handlers | E ✅, G ✅ |
| `testdata/gen/` | gopacket fixture generators (synthetic captures only) | H |
| `e2e/` | Dummy MCP client harness (build tag `e2e`) | H |
| `docs/{en,ja}/` | RFP, ADR-0001–0007, architecture, phase1-plan | Phase 0/1 ✅ |

## ADR cheat sheet

- **ADR-0001**: tshark is the backend. Display filters pass through from the agent verbatim. Zeek is deferred, and adopting it would mean *new tools*, not a backend swap.
- **ADR-0002**: Containers are **ephemeral, one per `podman run --rm` per call**. No persistent container, no `podman exec`, no orphan scanning. tshark is stateless, so there is nothing to persist.
- **ADR-0003**: Lean image — `debian:12-slim` (digest-pinned) + `tshark` only, 274MB. No DuckDB, no Python, therefore **no parquet**; exports are JSONL / CSV. The dumpcap binary is deleted, so the image cannot capture.
- **ADR-0004**: **1 pcap : 1 workspace.** The capture file itself is mounted `ro` at the fixed path `/evidence/capture` and never copied. `workspace_dir` is an argument, not config. `allowed_paths` is a guardrail (default: unrestricted), not a sandbox boundary.
- **ADR-0005**: Output contract — threshold in **bytes not rows**, response shape identical inline vs. file, `matched` always returned, `sample` attached for file results, large output is **JSONL not a JSON array**.
- **ADR-0006**: Async for heavy tools only (`create_workspace`, `protocol_hierarchy`, `list_conversations`, `query_packets`, `extract_objects`). Validation stays synchronous. Jobs are in-memory; `job_not_found` means "just re-run it".
- **ADR-0007**: Payload safety, all four in the same commit as the payload code — nonce XML isolation with the framing **first**, defang to `<sha256>.bin` mode 0600, payload never logged, ranged reads via `offset`/`length`.

## Tool surface (12)

`get_usage` · `create_workspace` · `describe_workspace` · `list_workspaces` ·
`delete_workspace` · `describe_runtime` · `protocol_hierarchy` ·
`list_conversations` · `query_packets` · `follow_stream` · `extract_objects` ·
`check_job`

`describe_workspace` is the free one — it reads the `capinfos` cache and starts
no container. Expect it to be the most-called tool.

## Gotchas

- **`-z conv,tcp` does not carry `tcp.stream`** — confirmed against tshark 4.0.17. Its row order does not even match stream order, so there is no way to recover the index from it. `list_conversations` is the entry point to `follow_stream`, so build it from `-T fields -e tcp.stream ...` with server-side aggregation.
- **Truncated captures.** A capture taken with a small snaplen has no payload. `truncated` comes from capinfos' *inferred* limits, never the file header — `editcap -s 40` leaves the header at `(not set)`. Surface it from `describe_workspace` and return `payload_unavailable_truncated_capture` *before* running a payload tool, or the agent will read the empty result as a transient failure and retry forever.
- **`capinfos -T -m -Q` with selected fields**, not `-M` — `-M` only affects long reports. `-Q` quotes values so `encoding/csv` reads them. Never select `-k` (comment): it contains newlines. And `capinfos` does **not** report pcapng ISB drop counts, so `dropped_packets` is out of v1.
- **Debian's `tshark` package prompts via debconf** about setuid dumpcap. Non-interactive install plus `debconf-set-selections` setting it to false — and note that this leaves the dumpcap binary in place, which is why the Dockerfile deletes it.
- **tshark warns when run as root.** The image runs as `USER 1000`.
- **macOS virtiofs.** Captures outside the machine's shares cannot be mounted. `podman machine inspect` does not expose the share list, so `doctor` finds out by attempting a real read-only mount.
- **Podman Machine memory.** 4GB default is not enough for a full pass over a large capture; 8GB recommended.
- Time values are returned as **epoch plus UTC ISO-8601**, never local-formatted.
- **`CountArgs` must emit a header row.** The same reader parses queries and the count pass; without `-E header=y` the first packet is eaten as column names and every `matched` is one short. There is a regression test.
- **A row limit kills the container on purpose.** `StreamResult.Stopped` says so — treat a non-zero exit as tshark's fault only when `Stopped` is false, or every limited query reports a container failure.
- **`rows` is a pointer.** An empty inline result must serialize as `[]`; under `omitempty` a plain slice vanishes and becomes indistinguishable from a file-backed result. `delivery` states the channel outright.
- **Background jobs must not inherit the request context.** It is cancelled the moment the job id is returned; `Deps.ServerCtx` is what they run under.
- **Payload must stay inside `payload.Untrusted`.** It redacts in `String`/`LogValue`, so nothing leaks through a log line or an error. `Reveal()` is the only way out — grep for it to audit every such site.
- **Never store an object under a name from the wire.** tshark writes `object1.text%2fplain` at 0644; `payload.Defang` renames to `<sha256>.bin` at 0600.
- **A ranged read is not a memory bound.** `follow_stream` streams tshark's output under `follow_max_reassembly_bytes`; buffering first and windowing after would let a multi-gigabyte stream through anyway.
- **stdout is the protocol channel.** All logging goes to stderr; a stray `fmt.Println` corrupts the JSON-RPC stream.

## Conventions (organization-wide)

https://github.com/nlink-jp/.github/blob/main/CONVENTIONS.md — tests are
mandatory, docs move with behaviour (README.md **and** README.ja.md in the same
commit), commits are small and typed.
