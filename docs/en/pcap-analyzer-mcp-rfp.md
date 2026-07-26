# RFP: pcap-analyzer-mcp

> Generated: 2026-07-26
> Status: Draft

## 1. Problem Statement

Agents cannot work with pcap / pcapng files. Wrapping tshark thinly in an MCP server does not help: `tshark -V` produces hundreds of lines for a single packet, and `-T json` yields several MB for a thousand packets. The output burns through the context window before any analysis can happen.

`pcap-analyzer-mcp` is an MCP server that confines a version-pinned tshark inside a container, mounts the target capture read-only, and returns results under a single contract: **small results inline as JSON, large results as a JSONL file in the workspace**. This lets an agent progressively narrow down a GB-scale packet capture during security incident investigation and network troubleshooting.

The target user is the developer themselves, performing incident response and troubleshooting from Claude Code / Cowork.

## 2. Functional Specification

### Commands / API Surface

#### CLI subcommands (single binary)

| Subcommand | Purpose |
|---|---|
| `serve` | Start the MCP stdio server |
| `build-runtime` | Build the analysis container image locally (Dockerfile embedded via `go:embed`) |
| `doctor` | Health-check podman, the image, config, and virtiofs shared paths |
| `version` | Print version |

#### MCP tools (11)

| Tool | Purpose | Starts container | async |
|---|---|---|---|
| `get_usage` | Self-disclosure of the workspace model, output contract, and error-recovery table | No | — |
| `create_workspace` | Create a workspace for a pcap. Records sha256 / capinfos / tshark version / image digest | Yes | Yes |
| `describe_workspace` | Return cached capture metadata (**free**) | **No** | — |
| `list_workspaces` | Enumerate workspaces by scanning `workspace_dir` | No | — |
| `delete_workspace` | Delete a workspace (with `dry_run`) | No | — |
| `describe_runtime` | Static disclosure of image digest / tshark version / supported export-object protocols | No | — |
| `protocol_hierarchy` | Protocol hierarchy statistics (`-z io,phs`; full pass) | Yes | Yes |
| `list_conversations` | Conversation list including `tcp.stream` / `udp.stream` index. Sorting by bytes gives top talkers | Yes | Yes |
| `query_packets` | **The workhorse.** Display filter + field selection + limit + format | Yes | Yes |
| `follow_stream` | Reassembled stream content, with `offset` / `length` ranged reads | Yes | — |
| `extract_objects` | Export HTTP / SMB / IMF / TFTP / FTP-DATA / DICOM objects, defanged, plus a manifest | Yes | Yes |
| `check_job` | Progress and result of an async job | No | — |

(12 entries including `check_job`; 11 are actual work tools once `get_usage` is excluded.)

`describe_workspace` only reads a JSON cache of the `capinfos` run performed once at `create_workspace` time — it never starts a container. Metadata stays retrievable even for a workspace created in an earlier session, without recreating it.

### Input / Output

#### Input

- **The pcap is never copied.** The parent directory of the path passed to `create_workspace` is mounted **read-only** at `/evidence`. This avoids duplicating GB-scale files and preserves the integrity of the original evidence
- The writable area is `<workspace_dir>/<workspace_id>/work`, mounted rw at `/work`. tshark's `TMPDIR` points here as well
- **Strictly 1 pcap : 1 workspace.** Ring-buffer split captures will later be merged into one logical capture with `mergecap` so the rule still holds (v1 accepts a single file only)
- `workspace_dir` is **supplied by the agent on each call**, not by config. The agent knows where its writable area is; the config does not

#### Output contract

Every result-returning tool follows one shape. The shape does **not** change between inline and file delivery, so the agent never has to branch.

```json
{
  "workspace_id": "...",
  "filter": "tcp.flags.reset == 1",
  "matched": 48213,
  "returned": 200,
  "truncated": true,
  "rows": [ "... inline only ..." ],
  "result_file": "<workspace>/out/q3.jsonl",
  "result_bytes": 48231904,
  "sample": [ "... always attached, even for file output ..." ]
}
```

- **The threshold is serialized bytes, not row count** (default 65536). In pcap work, 100 rows carrying a payload column routinely exceed 10000 rows of plain fields, so row counts cannot control size
- **`matched` (total filter hits) is always returned.** Without it the agent cannot tell whether the filter narrowed things down or simply matched nothing
- **`sample` carries the first few rows even for file output**, so the agent never needs a second round trip just to learn the shape of the data
- **Large output is JSONL, never a single JSON array.** JSONL can be partially read with `head` / `grep` and is read natively by DuckDB's `read_json_auto`. A 500MB JSON array is unusable for everyone
- Output files are designed for **(a) input to the next tool** or **(b) partial reads**, not for the agent to read in full
- Timestamps are returned as **both epoch and UTC ISO-8601**; no locally formatted times

#### `describe_workspace` payload

```
pcap_path, sha256, file_size, format (pcap/pcapng), encapsulation
packet_count, first_packet, last_packet, duration_sec
avg_packet_size, max_packet_size, avg_bytes_per_sec
snaplen_header, snaplen_inferred_min, snaplen_inferred_max, truncated
capture_os, capture_app   (when recorded in the pcapng SHB)
tshark_version, image_digest
outputs[]                 (files generated so far)
```

Disclosing the snaplen fields and `truncated` is mandatory. The file-header snaplen alone is not enough — it can be unset while the packets are in fact truncated — so the decision also uses the inferred min/max values capinfos reports. A capture taken with `-s 96` has no payload, so `follow_stream` and `extract_objects` will come up empty. The agent must learn this **before** trying, otherwise it will read the failure as a transient error and retry pointlessly.

Whether "there is no SYN" means no traffic occurred or the capture engine dropped it also changes the conclusion, but disclosing the drop count is deferred (see §7).

### Configuration

`config.toml`, following the sectioned-TOML conventions used across the org:

```toml
[container]
image = "pcap-analyzer-runtime@sha256:..."   # digest pin

[container.limits]
cpu = "2"
memory = "4g"
network = "none"

[workspace]
allowed_paths = []          # empty = unrestricted (a guardrail, not a sandbox boundary)

[output]
inline_max_bytes = 65536
default_row_limit = 10000

[payload]
follow_inline_max_bytes = 8192
extract_max_object_bytes = 104857600

[log]
level = "info"              # payload bytes are never written to the log
```

`allowed_paths` is a policy check (equivalent to `ResolveAndCheck`), not a mount constraint. Because containers are ephemeral, mounts are decided per call, so there is no need to declare a fixed evidence root in config. Requiring a config edit before every Cowork session would be pure friction, so the default is unrestricted.

### External Dependencies

- **Podman** (rootless, daemonless) — the `podman` binary is exec'd as a child process
- **The analysis container image** — `debian:12-slim` (digest-pinned) + `tshark`. The dependency on `wireshark-common` brings `capinfos` / `editcap` / `mergecap` / `text2pcap` along automatically. Measured image size 274MB
- No external APIs, no credentials, no network access (`network = "none"`)

## 3. Design Decisions

### Language / framework

**Go**, matching the org's other MCP servers (data-toolbox-mcp, voice-studio-mcp, video-studio-mcp, the `*-lookup` family). Light dependencies, single-binary distribution.

### tshark as the backend

- **tshark**: display filters (`ip.addr == x && tcp.flags.syn == 1`) are the shared vocabulary of both human analysts and LLMs. Over 3000 dissectors. Installs from a single package
- **Zeek** (rejected): `conn.log` / `dns.log` / `http.log` are tabular from the start and closer to standard IR practice, but the dependency is much heavier. Deferred as a **possible second backend** behind the same tool surface

### Ephemeral per-call containers (no long-lived container)

data-toolbox-mcp keeps a persistent container per workspace because **DuckDB holds state inside the container**. Tables created by `load_data` vanish when the container dies, so `workspace_id` must be a live session.

**tshark is entirely stateless** — every invocation re-reads the pcap from the beginning, and there is no in-container state worth preserving. All state lives on the host filesystem (the read-only pcap and the read-write output directory). A persistent container buys nothing but saved startup latency, and that latency (roughly 0.3–1.0s per run under Podman on macOS) is noise against a tshark full pass measured in seconds to minutes.

Going ephemeral removes:

- The whole orphan-container label-scanning subsystem
- `Release` / container teardown
- `container_state` in `list_workspaces`
- **Workspaces disappearing on server restart** — a workspace becomes a host directory plus a metadata JSON, so surviving restarts is free and `list_workspaces` is a directory scan

It also lets mounts be chosen per call, which removes the need to declare a fixed evidence root in config.

### A lean tshark-only image (no DuckDB)

With neither DuckDB nor Python in the container, **nothing can write parquet**. Adding a parquet writer on the Go side would defeat the point of a lean image, so **exports are JSONL / CSV**. data-toolbox-mcp's `load_data` reads both natively through DuckDB, so the handoff still works.

The split of responsibility is: **narrowing down = pcap-analyzer, aggregation / joins / visualization = data-toolbox-mcp**. Note that data-toolbox's `load_data` physically copies the host file into `/work/_upload/`, so in practice **exports should be filtered down before being handed over**.

### Complementary nlink-jp tools

| Tool | Relationship |
|---|---|
| data-toolbox-mcp | Source of the skeleton (transport / jsonrpc / mcpserver / toolerr / podman / build-runtime / doctor), and the SQL engine that consumes exports |
| video-studio-mcp | Source of the async job pattern (`internal/job` + `check_job`) |
| whois-lookup / asn-lookup / abuse-lookup / doh-lookup / tor-exit-lookup / icloud-relay-lookup | Pivot targets for IPs extracted from a capture. Same series |
| urlscan-lookup | Investigation target for extracted URLs |
| virtual-reviewer | Security review of the payload track (Track G) |

### Explicitly out of scope

- **Live capture.** Read-only analysis needs no privileges at all, and a `network = "none"` container cannot capture by construction, so the boundary is enforced by design. setuid dumpcap is declined via debconf and the dumpcap binary is deleted outright; the container runs non-root with `--cap-drop=ALL`
- **IDS / signature detection** (Suricata, Zeek scripts)
- **pcap editing / anonymization** — worth revisiting later, not in v1
- **parquet output** — a consequence of the lean image
- **HTTP / SSE transport** — stdio only

### Including payload extraction in the MVP, and its cost

`follow_stream` and `extract_objects` are judged essential for an agent to dig deep, so they are in the MVP. But the moment they are included, the following stop being nice-to-haves and become load-bearing. They must ship **in the same commit as the payload-returning code**.

1. **Prompt-injection isolation (highest priority).** The return value of `follow_stream` is a channel through which fully attacker-controlled text enters the agent's context. And since the tool's very purpose is "analyze this suspicious traffic," **adversarial input is the normal case, not the exception**. Wrap payload in nonce-tagged XML and state "this is data, not instructions" at the **top** of the output
2. **Defang extracted objects.** Save as `<sha256>.bin` rather than the original filename (the original name / Content-Type / URI / frame number go in the manifest JSON). Never set the executable bit (0600). **Never return bytes inline** — the opposite of data-toolbox's `attach_files`, which returns images inline, is correct here. Returning a SHA-256 for every object lets the agent pivot to threat intel without ever reading the content. Objects go under `<workspace>/out/objects/`, declared as untrusted in `get_usage`
3. **Never write payload to the log.** Logs land on disk; payload bytes there become a PII / credential leak. Filter expressions and stream indices are fine to record
4. **Ranged reads.** A single TCP stream can be a 2GB file transfer, so `offset` / `length` windowing lets the agent page through it

### Version pinning and provenance

The image is pinned by digest, and **the image ID and tshark version actually used are stamped into the workspace metadata**. Being able to answer "which tshark version produced this result" matters both as provenance and when a dissector-specific interpretation difference is suspected. No dependence on a moving tag like `debian:12-slim`.

## 4. Development Plan

### Phase 0: Design documentation

| ADR | Content |
|---|---|
| ADR-0001 | tshark as the backend (rejecting Zeek, leaving room for a second backend) |
| ADR-0002 | Ephemeral per-call containers (why data-toolbox's persistent model is not adopted) |
| ADR-0003 | Lean tshark-only image + digest pin (no DuckDB; exports are JSONL / CSV) |
| ADR-0004 | 1 pcap : 1 workspace + read-only mount (no copying; `workspace_dir` supplied per call) |
| ADR-0005 | Output contract (byte threshold / JSONL / always `matched` and `sample` / invariant shape) |
| ADR-0006 | Async jobs (ported from video-studio ADR-0003, heavy tools only) |
| ADR-0007 | Payload safety (injection isolation / defang / log exclusion / ranged reads) |

Plus `architecture.md` and `phase1-plan.md`, in both docs/ja and docs/en.

### Phase 1: Core

| Track | Content |
|---|---|
| A | Scaffold + subcommands (`serve` / `build-runtime` / `doctor` / `version`) |
| B | Port the MCP stdio skeleton (`internal/{transport,jsonrpc,mcpserver,toolerr}`) |
| C | Runtime image (`go:embed` Dockerfile, setuid dumpcap disabled, non-root, digest pin) + `build-runtime` + `doctor` |
| D | Workspace layer (create / list / delete, sha256, capinfos cache, ro mount, ephemeral exec, `--cap-drop=ALL`) |
| E | Read-only tools (`describe_workspace` / `describe_runtime` / `protocol_hierarchy` / `list_conversations` / `query_packets`) + the output contract |
| F | Async jobs + `check_job` |
| G | Payload tools (`follow_stream` / `extract_objects`) + the four safety mechanisms |
| H | Dummy MCP client E2E harness + pcap fixtures |

**Test pcaps are synthesized with gopacket.** Wireshark's public sample captures carry licensing / attribution overhead, and third-party binaries should not live in the repository. gopacket fixtures are deterministic, small, and can assemble real HTTP flows, which covers `extract_objects` testing too. **No live malware samples in the repository.**

### Phase 2: Features

- **Real-client validation on Claude Code / Cowork**, following the method data-toolbox-mcp used with Claude Desktop (11 graded cases with a graded README)
- **Self-repair hints for invalid display filters.** When tshark rejects a filter, put the offending position and candidate field names into the error `details`. Same idea as data-toolbox v0.4.0's `CatalogException` hint; without it the agent repeats the same mistake
- `samples/` (synthetic pcaps) + graded README
- `docs/{en,ja}/reference/client-setup.md`
- Logging (rotate on startup, strict payload exclusion)

### Phase 3: Release

LICENSE (MIT) / README.md / README.ja.md / AGENTS.md / CHANGELOG.md → signing + notarization → 4-platform archives (darwin arm64 zip + linux amd64/arm64 tar.gz + windows amd64 zip) → `gh release create` → add as a cybersecurity-series submodule → update the org profile README → `check-org.sh` all green.

### Independently reviewable checkpoints

| Checkpoint | What is reviewed |
|---|---|
| End of Phase 0 | The design decisions themselves |
| End of Tracks A–D | The skeleton: containers start and workspaces can be created |
| **End of Track E** | **Already a usable minimum without payload support** (a read-only edition could ship first) |
| End of Track G | Security review (virtual-reviewer / `/security-review`) |

Because the work splits cleanly at Track E, a read-only edition can ship first even if payload extraction proves difficult.

## 5. Required API Scopes / Permissions

**None.**

No external service access, credentials, OAuth scopes, or IAM roles are required. The only permissions needed are local:

- Permission to execute the `podman` binary (rootless; no root required)
- **Read** permission on the target pcap
- Write permission on `workspace_dir`

The container runs with `network = "none"`, as non-root, with `--cap-drop=ALL`, and with setuid dumpcap disabled.

## 6. Series Placement

Series: **cybersecurity-series**

Reason:

- The primary use case is security incident investigation, matching the series definition (AI-augmented security tools: threat intel, IR, risk assessment)
- The series already hosts Go MCP servers (whois-lookup, abuse-lookup, doh-lookup, mac-lookup, tor-exit-lookup, icloud-relay-lookup, urlscan-lookup), so Go + MCP has precedent here
- IPs, domains, and URLs extracted from a capture pivot directly into those lookup tools. Co-locating them makes the combination natural
- util-series centers on pipe-friendly data-transformation CLIs and is not the right home for a domain-specific security analyzer

The name is `pcap-analyzer-mcp`. It is neither a `-studio` (composition) nor a `-lookup` (single-shot query) tool, which puts it in the same naming family as util-series' `mail-analyzer`.

## 7. External Platform Constraints

### MCP clients

- **Request timeouts** — a full pass over a 20GB pcap takes minutes and will routinely exceed the client timeout. Heavy tools (`create_workspace`, `protocol_hierarchy`, `list_conversations`, `query_packets`, `extract_objects`) avoid this with `async` + `check_job`
- **Response size** — every return value lands in the context window. The byte threshold in the output contract is the direct answer to this constraint
- **Client-side inputSchema validation** — Claude Desktop validates `enum` on the client side, so server-side checks may never be reached. Server-side validation is kept as defense in depth

### macOS + Podman Machine

- **virtiofs shared-path constraint** — the target pcap must live under a Podman Machine shared path (by default `/Users`, `/private/tmp`, `/var/folders`) to be mountable. Captures on external disks or directly under `/Volumes` cannot be passed through, so `doctor` checks for this
- **VM memory** — the 4GB default can be insufficient for a full pass over a large capture. 8GB recommended
- **Single-file bind mounts** — smaller blast radius than mounting the parent directory read-only, but the virtiofs behavior is unverified. Default to parent-directory ro; treat single-file mounts as a tightening to validate later

### tshark

- **Output differences across versions** — `-T fields` / `-T ek` field names and `-z` statistic formats drift between versions. This is the primary motivation for pinning the version inside a container
- **`-z conv,tcp` does not include the stream index** — the output carries only addresses, ports, frame counts, and byte counts, never `tcp.stream`. Reverse-mapping from the 4-tuple breaks down under port reuse. If `list_conversations` is to be the entry point to `follow_stream`, building it from `-T fields -e tcp.stream ...` with local aggregation is more robust (**to be confirmed against real output during implementation**)
- **Warning when run as root** — tshark warns when run as root, so non-root execution (`USER 1000`) is assumed
- **Debian debconf prompt** — `wireshark-common` asks interactively whether non-superusers may capture packets. Use `DEBIAN_FRONTEND=noninteractive` + `debconf-set-selections` to set setuid explicitly to false
- **Use `capinfos -T -m -Q` with selected fields** — `-M` only affects long reports, not the table form. `-Q` quotes the values so `encoding/csv` can read them. Do not select the comment field (`-k`); it can contain newlines

### Constraints of the evidence itself

- **Truncated captures** — a capture taken with `-s <n>` has no payload, so `follow_stream` / `extract_objects` cannot work. Disclosed up front via `snaplen` / `truncated` in `describe_workspace`
- **Capture drops** — whether "no packet" means "no traffic" or "we missed it" changes the conclusion, so this is worth disclosing, but measurement showed **`capinfos` does not report pcapng ISB drop counts** (tshark 4.0.17). v1 omits `dropped_packets`; an alternative route is left for Track D

---

## Discussion Log

### Origin

The discussion started from the proposal: "Wouldn't an MCP server offering a tshark-like packet-analysis toolset be useful for agents doing security incident and troubleshooting analysis? And to exchange data even under a strong sandbox like Cowork's, couldn't we use the `workspace_dir` approach from video-studio?"

### Initial framing

- Agreed that **tshark must not be exposed directly**, and that the real design work is mapping "the shapes of an analyst's questions" onto tools rather than wrapping tshark
- Catalogued the three existing workspace idioms in the org (per-call `workspace_root`; `workspace_dir` + manifest; `workspace_id` + `allowed_paths` + `/work`). Concluded that none alone suffices for pcap, where the input is pre-existing and huge and the output is also large
- Raised two concerns: tshark's dissectors have historically been a CVE farm, and pcap files are dense with PII and credentials
- Considered Zeek as a backend but chose tshark, prioritizing display filters as a shared vocabulary

### Decision 1: Containerization (proposed by the user)

"Build a data-toolbox-style analysis container, mount the directory containing the pcap read-only, and analyze with tshark inside the container. Pinning tshark at image build time removes any dependency on the locally installed version."

This was confirmed to solve three problems at once:

1. tshark version pinning (removing drift in `-T fields` / `-z` output formats)
2. Dissector CVE risk (isolated by `network=none` + non-root + cap-drop)
3. The live-capture question disappearing (a `network=none` container cannot capture by construction)

Reading the actual code revealed that data-toolbox's `internal/workspace/podman.go` **already implements a `ReadOnly` field on `Mount` with `:ro` suffixing** (unused by data-toolbox itself). It also revealed that `load_data` **physically copies the host file into `/work/_upload/`** — unacceptable for GB-scale pcaps and damaging to evidence integrity. The read-only mount is therefore not a straight port of the data-toolbox model but a derivative that fixes exactly that point.

### Decision 2: Interaction model (proposed by the user)

"Rather than standing up an analysis container and leaving it waiting: (1) create a workspace by specifying the pcap and `workspace_dir` (always one workspace per pcap), (2) analyze by specifying the workspace plus the query / filter, (3) return JSON inline when the result is small, or write a JSON file via `workspace_dir` when it is large. What to do with the output is left to the agent."

This prompted **withdrawing** the previously recommended "persistent container + `podman exec`". The reasoning: data-toolbox needs a persistent container because DuckDB holds state inside it, whereas tshark is entirely stateless and has nothing worth persisting. Going ephemeral eliminates orphan detection, teardown, and `container_state`, and makes workspaces survive server restarts for free. It also allows **per-call mounts**, which in turn removed the previously recommended "declare a fixed `evidence_root` in config".

The output contract was sharpened with:

- A threshold in **bytes, not rows** (100 rows with a payload column can exceed 10000 rows of plain fields)
- **JSONL** rather than a single JSON array for large output (partially readable; read directly by DuckDB)
- An **invariant response shape** across inline and file delivery
- **`matched` always returned**, and **`sample` with the first few rows** even for file output
- An observation that the **time axis** was orthogonal to size and still unaddressed, leading to async jobs (ported from video-studio ADR-0003)

The single gap in "1 pcap : 1 workspace" was identified as ring-buffer split captures; merging them into one logical capture with `mergecap` preserves the rule. v1 stays single-file, with `pcap_paths: []` as a later additive change.

### Decision 3: Lean image + payload extraction (proposed by the user)

"Make it a tshark-only image (no DuckDB and the like)" and "payload extraction is needed, since it lets the agent dig deeper."

The lean image makes **parquet output impossible**, so the earlier parquet proposal was withdrawn in favor of JSONL / CSV (DuckDB reads both, so the handoff still works). It was also confirmed that Debian's `tshark` package depends on `wireshark-common` and therefore ships `capinfos` / `editcap` / `mergecap` / `text2pcap` automatically.

Including payload extraction in the MVP shifts the security design from nice-to-have to load-bearing. In particular, **the return value of `follow_stream` is a channel through which fully attacker-controlled text enters the agent's context**, and since the tool exists precisely to analyze suspicious traffic, adversarial input is the normal case. Four requirements were made mandatory and same-commit: nonce-tagged XML wrapping placed at the top of the output, defanging of extracted objects, exclusion of payload from logs, and ranged reads.

### Decision 4: A metadata tool (proposed by the user)

"It might be good to have something that retrieves pcap metadata (packet counts, timing information)."

The original design folded this into the `create_workspace` return value, but forcing a workspace to be recreated just to see its metadata is wrong when the workspace may have been created in an earlier session. It became a standalone `describe_workspace`. Since `capinfos` runs once at `create_workspace` time and is cached, subsequent calls only read JSON and **never start a container** (effectively zero cost).

This observation exposed that the original `describe_capture` **conflated two operations with very different costs**. Decomposing it:

- Metadata (free) → the new `describe_workspace`
- Protocol hierarchy (full pass) → renamed `protocol_hierarchy`, so the name no longer sounds cheap while doing a full pass
- Top talkers → already covered by `list_conversations`

The tool count did not grow. Two fields were made mandatory in the metadata: `snaplen` / `truncated` (so the agent learns **before trying** that payload extraction will come up empty on a truncated capture) and `dropped_packets`. The latter was dropped from v1 during Track C, when measurement showed capinfos does not report ISB drop counts.

Separately, `export_table` was folded into `query_packets`, since it was really just "`query_packets` with an output destination and format" and the inline-versus-file switch is decided by size automatically anyway.
