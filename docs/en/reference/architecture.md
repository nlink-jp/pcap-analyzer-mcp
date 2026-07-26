# Architecture: pcap-analyzer-mcp

> Date: 2026-07-26
> Status: Phase 0 (design)

The corresponding design decisions are recorded in ADR-0001 through ADR-0007. This document integrates them into a single operational model.

---

## 0. Binary layout — single binary + subcommands

Following `feedback_single_binary_subcommand`, one binary hosts four subcommands.

| Subcommand | Purpose |
|---|---|
| `serve` | Start the MCP stdio server (the normal mode of operation) |
| `build-runtime` | Build the analysis image locally from the `go:embed`ded Dockerfile |
| `doctor` | Check podman, the image, config, and virtiofs shared paths |
| `version` | Print the version derived from `git describe` |

## 1. Overview

```
┌─────────────────────┐
│    MCP client       │  Claude Code / Cowork / Claude Desktop
│     (the agent)     │
└──────────┬──────────┘
           │ stdio (JSON-RPC 2.0 / MCP 2024-11-05)
┌──────────▼──────────────────────────────────────────────┐
│  pcap-analyzer-mcp (Go, host process)                    │
│                                                          │
│  internal/transport   stdio read/write                   │
│  internal/jsonrpc     JSON-RPC 2.0                       │
│  internal/mcpserver   tool routing                       │
│  internal/toolerr     structured errors                  │
│  internal/job         async jobs (ADR-0006)              │
│  internal/workspace   ws creation, meta.json, podman     │
│  internal/tshark      argument assembly, output parsing  │
│  internal/output      output contract (ADR-0005)         │
│  internal/payload     isolation, defang (ADR-0007)       │
│  internal/tools       tool handlers                      │
└──────────┬───────────────────────────────────────────────┘
           │ exec: podman run --rm ...   (per call / ADR-0002)
┌──────────▼──────────────────────────────────────────────┐
│  Analysis container (debian:12-slim + tshark, digest pin)│
│    network=none / non-root / --cap-drop=ALL              │
│                                                          │
│    /evidence  ro  ← parent directory of the pcap         │
│    /work      rw  ← <workspace>/work                     │
└──────────────────────────────────────────────────────────┘
```

**All state lives on the host filesystem.** The container is disposable compute, and the server process holds no workspace state in memory either (apart from transient async job state).

## 2. Process boundaries (trust boundaries)

| Boundary | Content |
|---|---|
| Agent → server | Tool arguments. `workspace_id` syntax is validated; paths are symlink-resolved and checked against `allowed_paths` |
| Server → container | `podman run` arguments. Mounts are assembled by the server; there is no path by which the agent specifies an arbitrary mount |
| **pcap bytes → tshark** | **The most dangerous boundary.** Dissectors interpret attacker-controlled data. Contained by `network=none` / non-root / `--cap-drop=ALL` / read-only mount |
| **tshark output → agent** | **The second most dangerous boundary.** Payload is attacker-controlled text, isolated in nonce XML (ADR-0007) |

Because `/evidence` is read-only, **the original evidence cannot be modified** even if a dissector vulnerability is exploited. The only writable area is `/work`, confined within the workspace.

## 3. Data flow (happy path)

### 3.1 create_workspace(pcap_path, workspace_dir, async?)

1. Verify `workspace_dir` is writable; symlink-resolve `pcap_path` and check `allowed_paths`
2. Generate a `workspace_id` (pcap basename + short hash) and create `<workspace_dir>/<id>/work/{tmp,out,out/objects}`
3. Compute the pcap's **SHA-256** on the host
4. Run `podman run --rm -v <pcap parent>:/evidence:ro -v <ws>/work:/work <image> capinfos -T -m -Q <selected fields> /evidence/<name>`
5. Obtain `tshark --version` and the image digest
6. Write steps 3–5 into `<ws>/meta.json`
7. Return the `workspace_id` and a summary

### 3.2 describe_workspace(workspace_id)

Read `<ws>/meta.json`, scan `work/out/` for `outputs[]`, and return. **No container is started.**

### 3.3 query_packets(workspace_id, filter, fields, limit, format, async?)

1. Read `meta.json` for the pcap path and mount information
2. `podman run --rm ... tshark -r /evidence/<name> -Y <filter> -T fields -e <field>... -E header=y -E separator=/t`
3. Convert stdout line by line into JSON records, **counting bytes while accumulating**
4. Once `inline_max_bytes` is exceeded, switch to `work/out/<n>.jsonl` and stream from there
5. Only when `truncated`, run an extra counting pass (`-Y <filter> -T fields -e frame.number`) to obtain `matched`
6. Return in the unified shape of ADR-0005

### 3.4 protocol_hierarchy(workspace_id, async?)

Convert `tshark -r ... -q -z io,phs` output into a hierarchical JSON structure.

### 3.5 list_conversations(workspace_id, type, sort_by, top_n, async?)

Collect `-T fields -e tcp.stream -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e frame.len` and **aggregate server-side**. `-z conv,tcp` is not used because its output does not include `tcp.stream`, leaving no path into `follow_stream` (to be confirmed in Phase 1 Open Question Q5-1).

### 3.6 follow_stream(workspace_id, protocol, stream_index, offset, length)

1. Run `tshark -r ... -q -z follow,<proto>,raw,<index>`
2. Structure into per-direction chunks and window by `offset` / `length`
3. **Wrap in nonce-tagged XML** and return (ADR-0007)

### 3.7 extract_objects(workspace_id, protocol, async?)

1. Run `tshark -r ... --export-objects <proto>,/work/out/objects/_raw`
2. Compute SHA-256 for each emitted file and rename to `<sha256>.bin` (mode 0600)
3. Record the original name / Content-Type / URI / frame number in `manifest.json` (attacker-derived strings wrapped in nonce XML)
4. Remove `_raw`; return the manifest and paths only. **Bytes are never returned**

### 3.8 delete_workspace(workspace_id, dry_run?)

Delete the directory. With `dry_run`, return only the target paths and disk usage. No container stop is needed (ADR-0002).

## 4. State model

### 4.1 In-memory (inside the server process)

- **Async jobs only** (`internal/job`), in-memory and non-persistent, lost on restart
- No in-memory list or state of workspaces

### 4.2 On disk (persistent)

```
<workspace_dir>/<workspace_id>/
├── meta.json     # pcap path / sha256 / capinfos / tshark version / image digest
└── work/
    ├── tmp/            # tshark TMPDIR
    ├── out/            # query results (JSONL/CSV)
    └── out/objects/    # extracted objects (untrusted, 0600, <sha256>.bin)
```

### 4.3 In-memory ⇄ disk sync

**There are no synchronization points.** Dropping persistent containers in ADR-0002 means the class of problem described in `feedback_in_memory_disk_sync` cannot arise. `list_workspaces` is a directory scan; `describe_workspace` is a `meta.json` read.

## 5. Error & lifecycle

### 5.1 MCP protocol principles

Tool errors are returned as `isError: true` plus structured JSON (`{code, message, details}`) in the content, not as JSON-RPC errors (ported from data-toolbox-mcp `internal/toolerr`).

Proposed sentinel codes: `invalid_arguments` / `missing_argument` / `invalid_workspace_id` / `workspace_not_found` / `path_not_allowed` / `pcap_unreadable` / `invalid_display_filter` / `container_failed` / `tshark_failed` / `job_not_found` / `payload_unavailable_truncated_capture` / `object_too_large`

### 5.2 Self-repair hints

The `details` of `invalid_display_filter` carry the syntax error position reported by tshark plus candidate field names. Without this the agent repeats the same mistake (the same idea as data-toolbox v0.4.0's `CatalogException` hint).

`payload_unavailable_truncated_capture` is returned **before** running `follow_stream` / `extract_objects` when `truncated` is true in `meta.json`, so an empty result on a truncated capture is not mistaken for a transient failure.

### 5.3 Timeouts

Each `podman run` has its own timeout. For synchronous calls it is set below the client timeout; for async it follows the overall job timeout.

### 5.4 Container failure

`--rm` means failed containers do not linger. The exit code and stderr are surfaced in the `details` of `container_failed` / `tshark_failed` (`feedback_child_process_exit_status`).

### 5.5 MCP disconnection

Workspaces remain on disk. On the next connection they are discoverable via `list_workspaces` and work resumes through `describe_workspace`. In-flight async jobs continue under the server-lifetime context (ADR-0006).

## 6. Security model

### 6.1 Host file access

- `pcap_path` is checked against `allowed_paths` after symlink resolution (default empty = unrestricted, ADR-0004)
- `workspace_dir` is checked only for writability
- Mount targets are determined by the server; the agent cannot specify them

### 6.2 workspace_id validation

`^[a-zA-Z0-9_-]{1,64}$`. Path-traversal defense is applied twice: syntax validation, then re-verification that the joined path stays under `workspace_dir`.

### 6.3 Container runtime restrictions

`--network=none` / `--cap-drop=ALL` / non-root (`USER 1000`) / `--userns=keep-id` / `--cpus` / `--memory` / `--rm`. The dumpcap binary is deleted from the image, so it has no capture capability at all.

### 6.4 Payload handling

The four items of ADR-0007 (nonce XML isolation / defang / log exclusion / ranged reads). Payload-bearing types are structurally unable to reach the logging path.

### 6.5 Provenance

The SHA-256 / tshark version / image digest in `meta.json` anchor the chain of custody. The read-only mount keeps the original unmodified.

## 7. Testability

### 7.1 Unit tests

`internal/tshark` (argument assembly, output parsing), `internal/output` (byte threshold, shape), `internal/payload` (nonce generation, escaping, defang), `internal/workspace` (path validation). podman invocations are swapped out through the `runner` interface (reusing the seam from the source project).

### 7.2 Integration tests

Real podman plus the real image, under `-tags integration`.

### 7.3 Automated E2E harness

A dummy MCP client exercising every tool over stdio (`feedback_dummy_mcp_client_harness`), under `-tags e2e`.

### 7.4 pcap fixtures

**Synthesized with gopacket.** No third-party binaries in the repository; deterministic and small. The generation script is committed along with its output. HTTP flows are assembled so `extract_objects` can be tested too. **No live malware samples.**

A truncated-capture fixture (small `snaplen`) is included to exercise the `payload_unavailable_truncated_capture` path.

## 8. Out of scope (Phase 1)

- Live capture (impossible by construction, ADR-0003)
- IDS / signature detection (Suricata, Zeek scripts)
- pcap editing / anonymization
- parquet output (ADR-0003)
- HTTP / SSE transport (stdio only)
- `mergecap` joining of split captures (ADR-0004, to be added additively)
- Workspace TTL GC
- A Zeek second backend (ADR-0001)

## See also

- ADR-0001 through ADR-0007
- `pcap-analyzer-mcp-rfp.md`
- `phase1-plan.md`
