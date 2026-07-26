# Client setup

> Date: 2026-07-26

## Prerequisites

```bash
make build            # → dist/pcap-analyzer-mcp
make runtime-image    # builds the tshark image locally (a few minutes, once)
./dist/pcap-analyzer-mcp doctor
```

`doctor` is the fastest way to find out whether this will work at all. Expect:

```
  [ok  ] config                 using defaults (no config file given)
  [ok  ] podman                 podman version 6.0.2
  [ok  ] podman machine         running
  [ok  ] analysis image         localhost/pcap-analyzer-runtime:latest (...), expecting tshark 4.0.17
  [ok  ] mount (default shares) /Users
  ...
```

## Registering the server

Use an absolute path — MCP clients do not resolve `~` or rely on your `PATH`.

### Claude Code

```bash
claude mcp add pcap-analyzer -- /absolute/path/to/dist/pcap-analyzer-mcp serve
```

### Claude Desktop

`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS:

```json
{
  "mcpServers": {
    "pcap-analyzer": {
      "command": "/absolute/path/to/dist/pcap-analyzer-mcp",
      "args": ["serve"]
    }
  }
}
```

### With a configuration file

```json
{
  "mcpServers": {
    "pcap-analyzer": {
      "command": "/absolute/path/to/dist/pcap-analyzer-mcp",
      "args": ["serve", "--config", "/absolute/path/to/config.toml"]
    }
  }
}
```

`PCAP_ANALYZER_MCP_CONFIG` works too. Configuration is optional: every value
has a working default, so start without one.

## Where captures and workspaces can live

On macOS podman runs inside a VM, and it can only reach paths the VM shares —
by default `/Users`, `/private/tmp`, and `/var/folders`. A capture on an
external disk or directly under `/Volumes` **cannot be analysed** until it is
copied somewhere reachable.

`doctor` does not guess at this. It attempts a real read-only mount and reports
what podman said, because `podman machine inspect` does not expose the share
list.

The same applies to `workspace_dir`. Somewhere under your home directory is the
straightforward choice:

```
~/pcap-workspaces/
```

## First run

Point the agent at a sample and ask it to open the capture:

```
Open samples/mixed.pcapng as a workspace under ~/pcap-workspaces and tell me
what protocols are in it.
```

The graded walkthrough in [`samples/README.md`](../../../samples/README.md)
covers every tool in eleven stages and says what each should produce.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `container_failed` on every call | podman is not running. macOS: `podman machine start` |
| `analysis image ... not built` | `make runtime-image` |
| A capture cannot be mounted | It is outside the VM's shared paths. Copy it under `/Users` or `/private/tmp`; `doctor` will confirm |
| A capture takes minutes and the client times out | Pass `async: true` and poll `check_job`. `describe_workspace` reports `packet_count` and `file_size`, which is what to decide on |
| `payload_unavailable_truncated_capture` | The capture was recorded with a small snaplen, so the payload bytes were never written. `query_packets`, `list_conversations` and `protocol_hierarchy` still work |
| `job_not_found` | The server restarted. Jobs live in memory; re-run the tool |
| A rebuild seems to have no effect | The client started the server process at registration time and still holds it. `make build` replaces the file on disk but not the running process — restart the MCP server (or the client) to pick it up |
| Results feel truncated | Compare `matched` with `returned`. If `matched` is much larger, narrow the filter rather than raising `limit` |
| A call hangs for a long time | Runs are bounded by `[container.limits] timeout` (default 30m). Requests are handled in order, so a long synchronous call blocks the rest — use `async` for large captures |

### Logs

By default diagnostics go to stderr, which most clients capture. Set a file to
keep them:

```toml
[log]
level = "debug"
file = "~/.local/state/pcap-analyzer-mcp/server.log"
```

The file rotates on startup, keeping five generations, and is written `0600`.
Packet payload never appears in it at any level.

Never log to stdout: that is the JSON-RPC channel, and a stray line corrupts
the protocol.

## Using it with data-toolbox-mcp

`query_packets` with `limit: 0` writes every matching packet to the workspace
as JSONL, which DuckDB reads natively. To run SQL over it, register
[data-toolbox-mcp](https://github.com/nlink-jp/data-toolbox-mcp) as well and
add your workspace directory to its `allowed_paths`.

Filter before exporting: data-toolbox's `load_data` copies the file it is
given, so handing it an unfiltered export of a large capture copies the lot.

## See also

- [Architecture](architecture.md) — trust boundaries, data flow, security model
- [ADRs](../adr/) — every design decision and its cost
