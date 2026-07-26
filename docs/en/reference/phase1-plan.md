# Phase 1 Development Plan: pcap-analyzer-mcp

> Date: 2026-07-26
> Status: Draft

---

## 1. Goals (Phase 1 completion criteria)

- The four subcommands `serve` / `build-runtime` / `doctor` / `version` work
- 12 entries (11 work tools + `get_usage`) are exposed over MCP stdio and all respond per spec
- The analysis image builds locally, and `describe_runtime` discloses its digest and tshark version
- The output contract (ADR-0005) is uniformly honored by every tool
- The four payload safety mechanisms (ADR-0007) are implemented
- Unit / integration / E2E tests are all green
- `make build` emits to `dist/` (`feedback_make_build`)

## 2. Work breakdown (by track)

### Track A: Repository scaffold + subcommand skeleton

- Structure per the CONVENTIONS.md templates, verified with `check-org.sh`
- `main.go` + `cmd/`, `Makefile` (version from `git describe`, `feedback_makefile_version`)
- `.gitignore` containing only `dist/` (`feedback_gitignore_binary_pattern`) plus `.claude/`
- `LICENSE` (MIT) / `AGENTS.md` (never copied from another project)
- `internal/config` (sectioned TOML, `config.example.toml`)
- Skeletons for the four subcommands

### Track B: MCP stdio framework

Ported from data-toolbox-mcp (`feedback_data_toolbox_mcp_skeleton`).

- `internal/transport/stdio.go`, `internal/jsonrpc/{types.go,codes.go}`
- `internal/mcpserver/{server.go,tools.go,initialize.go}`
- `internal/toolerr/toolerr.go` — sentinel codes replaced for this project (architecture §5.1)

### Track C: Runtime container image + build-runtime + doctor

- `runtime/Dockerfile` (ADR-0003) + `runtime/embed.go`
- Non-interactive debconf and disabled setuid dumpcap, non-root, `TMPDIR=/work/tmp`
- Base image digest pin
- The `build-runtime` subcommand
- `doctor`: podman presence / machine state (macOS) / image presence / config parse / **virtiofs shared-path check**
- `internal/runtime/manifest.go` plus a drift test against the Dockerfile

### Track D: Workspace layer

- `internal/workspace`: `Create` / `List` / `Delete` / `Load`
- `meta.json` schema, reading and writing
- SHA-256 computation (host-side)
- Port `podman.go` and add **`RunOnce`** (single-shot `--rm` execution); add `--cap-drop=ALL` to `RunOpts`
- Path validation (`ResolveAndCheck` equivalent + `workspace_id` syntax + re-verification of the joined path)

### Track E: Read-only tools + output contract

- `internal/tshark`: argument assembly and output parsing
- `internal/output`: a writer that accumulates while counting bytes and switches to a file past the threshold; attaches `matched` / `truncated` / `sample`
- Tools: `get_usage` / `create_workspace` / `describe_workspace` / `list_workspaces` / `delete_workspace` / `describe_runtime` / `protocol_hierarchy` / `list_conversations` / `query_packets`
- **At the end of this track the project reaches a usable minimum as a read-only edition without payload support**

### Track F: Async jobs

- Port video-studio-mcp's `internal/job` (ADR-0006)
- Add the `async` argument to the five target tools, plus `check_job`
- Cap on concurrent jobs
- Guarantee that validation stays synchronous

### Track G: Payload tools + safety mechanisms

- `internal/payload`: nonce generation, XML wrapping, escaping nonce collisions inside payload
- `follow_stream` (per-direction chunking, `offset` / `length`)
- `extract_objects` (rename to `<sha256>.bin`, mode 0600, `manifest.json`, remove `_raw`)
- The path that returns `payload_unavailable_truncated_capture` up front based on `meta.json.truncated`
- **A type structure that makes payload-bearing values impossible to pass to the logger**
- Review with virtual-reviewer / `/security-review` on completion

### Track H: Test harness + fixtures

- gopacket-based synthetic pcap generation scripts (`testdata/gen/`) with committed output
  - Basic TCP/UDP/DNS flows
  - An HTTP flow (for `extract_objects`, with benign dummy files)
  - A truncated capture (small `snaplen`)
  - pcapng with SHB/ISB options
- Dummy MCP client E2E harness (`e2e/`, `-tags e2e`)

## 3. Dependencies between tracks

```
A ──┬── B ──┬── E ── F
    │       │
    ├── C ──┤
    │       │
    └── D ──┴── G
            │
            └── H (from E onward, in parallel with each track)
```

- A is a prerequisite for everything
- E waits on B / C / D
- G depends on D (workspace) and E (output contract)
- F depends on E and is independent of G
- H builds up in parallel once E is underway

## 4. Definition of Done per track

A track is complete when all of the following hold.

- Unit tests are green
- The relevant README.md / README.ja.md text is updated
- `make build` succeeds and emits to `dist/`
- Work is split into typed commits (`feedback_commit_discipline`)
- Nothing deviates from the decisions recorded in the ADRs (any deviation amends the ADR first)

## 5. Open questions

Unresolved as of Phase 0. To be settled empirically before or during the relevant track.

### Q5-1. Does `-z conv,tcp` really omit the stream index?

Making `list_conversations` the entry point to `follow_stream` requires `tcp.stream`. The design assumes it is absent and aggregates from `-T fields`, but this **must be confirmed against real output**. If present, the implementation simplifies. (Before Track E)

### Q5-2. virtiofs behavior for single-file bind mounts

Smaller blast radius than a parent-directory ro mount, but behavior across macOS Podman Machine is unverified. If it works, make single-file the default. (Track D)

### Q5-3. Full-pass duration for `create_workspace`

How long `capinfos` + SHA-256 take relative to pcap size. This is the basis for guidance to the agent on when `async` is needed. (Track D, measured on real pcaps)

### Q5-4. Concurrency cap for async jobs

How many parallel `podman run` processes are acceptable, balanced against macOS Podman Machine memory (4GB default, 8GB recommended). (Track F)

### Q5-5. How to enumerate `--export-objects` supported protocols

We want `describe_runtime` to disclose this dynamically. Confirm whether an equivalent of `tshark --export-objects help` is usable in the image's tshark. (Track C)

### Q5-6. Does `capinfos` report pcapng ISB drop counts?

Whether `dropped_packets` can be disclosed depends on this. If not, investigate obtaining it from tshark instead. (Track D)

## 6. Reference reuse map

| Source | Target | Changes |
|---|---|---|
| data-toolbox-mcp `internal/transport` | As is | Import path only |
| data-toolbox-mcp `internal/jsonrpc` | As is | Import path only |
| data-toolbox-mcp `internal/mcpserver` | Nearly as is | `RawResult` unnecessary (we never return bytes) |
| data-toolbox-mcp `internal/toolerr` | Structure reused | Sentinel codes fully replaced |
| data-toolbox-mcp `internal/workspace/podman.go` | Reused | `Run`/`Exec` → `RunOnce`, add `--cap-drop=ALL`. `Mount.ReadOnly` already exists and is used as is |
| data-toolbox-mcp `runtime/embed.go` + `build-runtime` | As is | Dockerfile replaced |
| data-toolbox-mcp `internal/logging` | As is | **Plus a type design that keeps payload out** |
| video-studio-mcp `internal/job` | As is | Job kinds replaced |
| json-to-table | — | Not used here (no rendering) |

## 7. Estimated effort (rough)

| Track | Size | Notes |
|---|---|---|
| A | Small | Mostly template application |
| B | Small | Nearly mechanical porting |
| C | Medium | debconf / setuid details need empirical work |
| D | Medium | Path validation and `meta.json` are the crux |
| E | **Large** | tshark output parsing and the output contract are the substance |
| F | Small–Medium | Porting plus concurrency control |
| G | **Large** | Safety mechanisms are the main work, review included |
| H | Medium | Synthesizing fixtures with gopacket takes effort |

E and G carry the weight. Because **a release decision can be made at the end of Track E**, a read-only edition can still land even if G proves difficult.

## See also

- ADR-0001 through ADR-0007
- `architecture.md`
- `pcap-analyzer-mcp-rfp.md`
