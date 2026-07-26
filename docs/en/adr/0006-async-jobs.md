# ADR-0006: Async jobs for heavy tools only

- Status: Accepted
- Date: 2026-07-26
- Driver: magi
- Generalises to: none

---

## Context

ADR-0005 solved the **size** problem. An orthogonal **time** axis remains.

- A tshark full pass over a 20GB pcap takes minutes
- `create_workspace`'s `capinfos` also walks the entire file to count packets
- MCP clients have request timeouts, and long synchronous responses get cut off

Leaving this synchronous produces the worst possible behavior on large captures: the agent cannot tell a timeout from work in progress, and retries the same heavy call, saturating the host.

video-studio-mcp already solved this in its ADR-0003 (in-memory non-persistent jobs via `internal/job`, a server-lifetime `JobCtx`, re-run on `job_not_found`). That implementation ports directly.

## Decision

**Port `internal/job` (video-studio-mcp ADR-0003) and give an `async: true` option to heavy tools only.**

| Tool | async | Reason |
|---|---|---|
| `create_workspace` | Yes | `capinfos` full pass + SHA-256 |
| `protocol_hierarchy` | Yes | `-z io,phs` full pass |
| `list_conversations` | Yes | Full packet walk + aggregation |
| `query_packets` | Yes | Full pass depending on the filter |
| `extract_objects` | Yes | Full packet walk + reassembly |
| `follow_stream` | No | Limited to one stream, relatively light |
| `describe_workspace` / `describe_runtime` / `list_workspaces` / `delete_workspace` / `get_usage` | No | No container, or metadata operations only |

Design points:

- **Validation stays synchronous.** Invalid arguments, missing workspaces, and path violations return errors immediately even with `async`. Only genuine runtime failures occur after the job starts
- The job's execution context is **the server-lifetime context, not the request context**, since the request context is canceled once the response returns
- Jobs are in-memory and non-persistent, lost on server restart. If `check_job` returns `job_not_found`, the agent simply re-runs the original tool (results are idempotent)
- **Job concurrency is capped** (addressing the Negative in ADR-0002). Unbounded parallel `podman run` would saturate the host
- `check_job` returns progress (the current phase) and, on completion, the same unified shape defined in ADR-0005

## Consequences

**Positive:**

- Large captures are no longer blocked by client timeouts
- The agent explicitly knows work is in progress, so pointless retries do not happen
- The implementation is a port from video-studio-mcp, so novel-design risk is low
- The concurrency cap solves the ephemeral-container resource problem in the same place

**Negative:**

- **The agent must decide whether to use `async`.** `get_usage` needs to give rough guidance, using `packet_count` / `file_size` from `describe_workspace` as the deciding inputs. An alternative — the server automatically switching to async above a threshold and returning a `job_id` — would make the response shape vary at runtime, so it is not adopted in v1
- Jobs are non-persistent, so long-running work does not survive a server restart and the heavy full pass must be redone
- Both synchronous and asynchronous paths need testing, increasing E2E combinations

## See also

- ADR-0002: Ephemeral per-call containers (concurrency cap)
- ADR-0005: Output contract (the size axis)
- Ported from: video-studio-mcp ADR-0003 (`internal/job`)
