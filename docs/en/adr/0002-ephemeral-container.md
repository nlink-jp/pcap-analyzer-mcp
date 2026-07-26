# ADR-0002: Use ephemeral per-call containers

- Status: Accepted
- Date: 2026-07-26
- Driver: magi
- Generalises to: candidate org ADR (`.github/adr/`) — generalizes as a criterion for "should this container be persistent?"

---

## Context

This project ports data-toolbox-mcp's container execution layer. The source keeps a **persistent container per workspace**, starts and reuses it idempotently via `Ensure(ctx, workspace_id)`, scans labels for orphan detection, and exposes `container_state` through `list_workspaces`.

On review, **the reason the source needs a persistent container does not exist here.**

data-toolbox-mcp persists because **DuckDB holds state inside the container**. Tables created by `load_data` are lost when the container dies, so `workspace_id` only means something if it maps to a live session.

**tshark, by contrast, is entirely stateless:**

- Every invocation re-reads the pcap from the start of the file
- There is no in-memory state to carry between calls
- Everything worth keeping (the pcap, the metadata cache, output files) lives on the host filesystem

So the only value a persistent container offers is saved startup latency. Under macOS + Podman Machine, `podman run --rm` costs roughly 0.3–1.0s, while a tshark full pass takes seconds to minutes. The saving is under a few percent.

## Decision

**A container is started per MCP tool call with `podman run --rm` and destroyed when the call completes.**

- No persistent containers, no `Ensure`-based reuse, no `podman exec`
- A workspace *is* **a host directory plus a metadata JSON**; the container is disposable compute running on top of it
- Mounts are decided per call (ADR-0004)
- Runtime restrictions are applied every time: `--network=none` / `--cap-drop=ALL` / `--userns=keep-id` / `--cpus` / `--memory`

From the source `internal/workspace/podman.go`, instead of `Run` / `Exec` we introduce **`RunOnce`**, specialized for single-shot execution. The `Mount` struct (which already implements a `ReadOnly` field with `:ro` suffixing) is reused as is. `RunOpts` gains a field for `--cap-drop=ALL`.

## Consequences

**Positive:**

- **The entire orphan-detection label-scanning subsystem disappears.** With `--rm`, containers do not linger unless the process dies abnormally
- **`Release` / teardown / container stopping in `delete_workspace` are all unnecessary**
- **`container_state` disappears from `list_workspaces`.** A workspace's state reduces to "does it exist on disk"
- **Workspaces surviving a server restart becomes free.** With no in-memory container references, the in-memory ⇄ disk synchronization problem cannot arise. `list_workspaces` is implemented as a directory scan
- **Mounts can be chosen per call**, which removed the need to declare a fixed evidence root in config (ADR-0004)
- A failed call cannot leave contaminated state for the next one

**Negative:**

- **Every call pays 0.3–1.0s of container startup.** A workload firing dozens of small `query_packets` calls will feel the accumulation. However, `describe_workspace` (cache read, no container) covers the highest-frequency operation — checking metadata — without that cost
- **A concurrency cap must be implemented locally.** Letting async jobs (ADR-0006) run unbounded would spawn dozens of concurrent `podman run` processes and saturate the host. Job concurrency is capped
- Argument assembly for `podman run` happens on every call, so mount logic lives in the hot path. Path-traversal defense is applied twice within that logic

## See also

- ADR-0004: 1 pcap : 1 workspace and read-only mounts
- ADR-0006: Async jobs
- Ported from: data-toolbox-mcp `internal/workspace/{manager.go,podman.go}`
