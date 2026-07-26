# pcap-analyzer-mcp

[日本語](README.ja.md)

An MCP server that lets an AI agent analyse packet captures.

Agents cannot work with pcap files, and wrapping tshark thinly does not help:
`tshark -V` produces hundreds of lines for a single packet. `pcap-analyzer-mcp`
runs a **version-pinned tshark inside a container**, mounts the capture
**read-only**, and returns small results inline while writing large ones to the
workspace as JSONL — so an agent can narrow down a GB-scale capture step by
step instead of drowning in its first response.

> **Status: v0.1.0.** Twelve tools, driven end to end against a real container
> and validated from an MCP client. An independent security review has been
> through the tree. See [known limitations](CHANGELOG.md#known-limitations).

## Why a container

Pinning tshark at image build time solves three problems at once:

- **Reproducibility** — `-T fields` field names and `-z` statistic formats
  drift between tshark versions. The image fixes the version regardless of what
  is installed on the host, and every result records the tshark version and
  image digest that produced it.
- **Isolation** — Wireshark dissectors parse attacker-controlled data. The
  container runs with `--network=none`, as a non-root user, with all
  capabilities dropped.
- **No accidental capture** — the `dumpcap` binary is deleted from the image,
  which also has no network. Live capture is impossible by construction, not
  by policy.

The capture is **never copied**. Its directory is mounted read-only, so the
original stays byte-identical — cheap for GB-scale files, and correct for
evidence handling.

## Requirements

- [Podman](https://podman.io/) (rootless; no daemon)
- macOS: `podman machine start`, 8GB VM memory recommended. The capture must
  live under a shared path (`/Users`, `/private/tmp`, `/var/folders`).

## Install

```bash
git clone https://github.com/nlink-jp/pcap-analyzer-mcp.git
cd pcap-analyzer-mcp
make build              # → dist/pcap-analyzer-mcp
make runtime-image      # builds the tshark analysis image locally
```

## Usage

Register the binary as an MCP server in your client:

```json
{
  "mcpServers": {
    "pcap-analyzer": {
      "command": "/path/to/pcap-analyzer-mcp",
      "args": ["serve"]
    }
  }
}
```

A typical session: create a workspace for a capture, look at its metadata,
find the interesting conversations, then narrow down with a display filter.

```
create_workspace(pcap_path, workspace_dir)  →  workspace_id, sha256, summary
describe_workspace(workspace_id)            →  packet count, time range, snaplen
list_conversations(workspace_id)            →  who talked to whom (+ stream index)
query_packets(workspace_id, filter, fields) →  rows inline, or a JSONL file
follow_stream(workspace_id, ...)            →  the bytes on the wire
extract_objects(workspace_id, "http")       →  files, defanged, hashed
```

### Tools

| Tool | What it does |
|---|---|
| `get_usage` | Workspace model, output contract, error recovery |
| `create_workspace` | Open a capture. Records SHA-256, `capinfos`, tshark version |
| `describe_workspace` | Cached capture metadata — starts no container |
| `list_workspaces` | Enumerate workspaces under a `workspace_dir` |
| `delete_workspace` | Remove a workspace (`dry_run` available) |
| `describe_runtime` | Image digest, tshark version, supported object protocols |
| `protocol_hierarchy` | What protocols are in this capture |
| `list_conversations` | Endpoint pairs with byte counts and stream indices |
| `query_packets` | Display filter + field selection — the workhorse |
| `follow_stream` | Reassembled stream content, with ranged reads |
| `extract_objects` | Export HTTP / SMB / IMF / TFTP / FTP-DATA / DICOM objects |
| `check_job` | Progress and result of an async run |

Heavy tools accept `async: true` and return a `job_id`; poll with `check_job`.
A full pass over a large capture takes minutes and would otherwise hit the MCP
client's request timeout.

### Working with the output

Large results are written as **JSONL**, which is readable with `head` / `grep`
and loadable directly by DuckDB — including via
[data-toolbox-mcp](https://github.com/nlink-jp/data-toolbox-mcp), if you want
SQL over the packet table. Narrowing down is this tool's job; aggregation and
joins are that one's.

Every response reports `matched` (how many packets the filter hit) alongside
`returned`, so it is always clear whether a filter needs tightening.

## Handling untrusted captures

Captures under investigation are, by definition, attacker-influenced. Two
consequences worth knowing about:

- **Stream content is wrapped** in nonce-tagged markers declaring it as data
  rather than instructions. This is a mitigation, not a guarantee.
- **Extracted objects are defanged**: saved as `<sha256>.bin`, never
  executable, never returned as inline bytes. The SHA-256 in the manifest is
  usually all you need to pivot to threat intelligence — you rarely have to
  touch the file at all.

Payload never reaches the log file, at any log level.

## Configuration

Configuration is optional; every value has a working default. See
[`config.example.toml`](config.example.toml). Pass `--config <path>` or set
`PCAP_ANALYZER_MCP_CONFIG`.

## Documentation

- [RFP](docs/en/pcap-analyzer-mcp-rfp.md) — problem statement, scope, plan
- [Architecture](docs/en/reference/architecture.md) — trust boundaries, data flow, security model
- [ADRs](docs/en/adr/) — every design decision and its cost
- [Client setup](docs/en/reference/client-setup.md) — registering the server, and what to do when it misbehaves
- [Sample captures](samples/README.md) — four synthetic captures and a graded walkthrough
- [Phase 1 plan](docs/en/reference/phase1-plan.md) — tracks and open questions

## License

MIT
