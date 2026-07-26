# ADR-0004: 1 pcap : 1 workspace with read-only mounts

- Status: Accepted
- Date: 2026-07-26
- Driver: magi
- Revisions: 2026-07-26 — the parent-directory read-only mount became a **single-file** read-only mount after Track D measurement
- Generalises to: none

---

## Context

We must decide how the target pcap and the analysis artifacts move between the agent and the MCP server. Three idioms already exist across the org.

| Idiom | Example | Direction |
|---|---|---|
| Per-call `workspace_root` | asn-lookup / abuse-lookup | File-mediated large results |
| `workspace_dir` + manifest | voice-studio-mcp / video-studio-mcp | Staging input material |
| `workspace_id` + `allowed_paths` + `/work` | data-toolbox-mcp | Bidirectional |

pcap differs from all of them: **the input is pre-existing and huge (GB scale), and the output is large too.**

data-toolbox-mcp's `load_data` **physically copies** a host file (after an `allowed_paths` check) into `/work/_upload/` before the container reads it (`internal/tools/load_data.go`). Reasonable for CSVs, unacceptable for GB-scale pcaps on two counts:

- Significant waste of disk and time
- **Duplicating original evidence** is poor IR practice

Additionally, hosting several pcaps in one workspace makes it ambiguous which capture an output file came from, which breaks provenance.

## Decision

### 1 pcap : 1 workspace

**A workspace corresponds one-to-one with a single capture.** `create_workspace(pcap_path, workspace_dir)` creates it, and every analysis tool afterwards takes a `workspace_id`.

On-disk layout:

```
<workspace_dir>/
└── <workspace_id>/
    ├── meta.json        # sha256 / capinfos results / tshark version / image digest
    └── work/            # mounted rw at container /work
        ├── tmp/         # tshark TMPDIR
        ├── out/         # query results (JSONL/CSV)
        └── out/objects/ # extract_objects output (untrusted)
```

`workspace_id` syntax is constrained to `^[a-zA-Z0-9_-]{1,64}$` (path-traversal defense, container-name safety).

### Read-only mount, no copying

**The capture file itself is mounted read-only at `/evidence/capture`.** It is never copied into the workspace.

```
-v <symlink-resolved pcap>:/evidence/capture:ro
-v <workspace>/work:/work
```

Because ADR-0002 starts a container per call, mounts can be decided per call. **There is no need to declare a fixed evidence root in config.**

**The original plan was a parent-directory mount**, because it was unclear whether a single-file bind mount survives macOS virtiofs. Track D measured it: it does, and siblings are then invisible to the container. A secondary benefit is that **the container-side path is fixed at `/evidence/capture`** — the host filename never appears in a container path or an argv, so a name like `--not-a-flag.pcap` cannot be read as an option.

### `workspace_dir` is supplied per call by the agent

Taken as a tool argument rather than from config: the agent knows where its writable area is, the config does not. Same idiom as `workspace_root` in asn-lookup / abuse-lookup.

### `allowed_paths` is a guardrail, not a sandbox boundary

`allowed_paths` remains, but its role changes. With ephemeral containers deciding mounts per call, it becomes a **policy check** (equivalent to `ResolveAndCheck`, evaluated after symlink resolution) rather than a mount constraint. The default is empty = unrestricted, because forcing a config edit before every Cowork session would be pure friction.

### Provenance

At `create_workspace` time, the following run once and are cached in `meta.json`:

- The input pcap's **SHA-256**
- The output of `capinfos -T -m -Q <selected fields>` (packet count / time range / snaplen / truncation verdict, etc.)
- The **tshark version and image digest** used

Afterwards `describe_workspace` only reads this JSON and never starts a container.

### Split captures

Ring-buffer captures (`cap_00001_*.pcap` …) form one logical capture across a set of files. **v1 accepts a single file only.** Later, `pcap_paths: []` can be added additively, merging into `<workspace>/work/merged.pcapng` with `mergecap` so the "1 workspace : 1 logical capture" rule still holds. Only that case incurs a copy, which is unavoidable for split captures.

## Consequences

**Positive:**

- **GB-scale pcaps are never copied.** No disk or time cost, and the original evidence stays intact
- The read-only mount means **the original cannot be modified** even if a dissector vulnerability is exploited
- One-to-one correspondence between workspace and evidence makes every output file's origin unambiguous. The SHA-256 in `meta.json` anchors the chain of custody
- `describe_workspace` needs no container, so the highest-frequency operation costs nothing
- No fixed paths in config, so environments like Cowork have no setup friction

**Negative:**

- **With `allowed_paths` defaulting to unrestricted, the server will open any readable file on the host as a pcap unless configured.** This is a deliberate tradeoff for single-user local use; a shared deployment must set it
- The 1:1 rule means comparing two captures requires the agent to create two workspaces and correlate the results itself
- v1 cannot handle split captures

## See also

- ADR-0002: Ephemeral per-call containers
- ADR-0005: Output contract
- ADR-0007: Payload safety (handling of `out/objects/`)
