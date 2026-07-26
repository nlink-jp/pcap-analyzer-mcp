# ADR-0005: Output contract — byte threshold, JSONL, invariant shape

- Status: Accepted
- Date: 2026-07-26
- Driver: magi
- Revisions: 2026-07-26 — a `delivery` field was added during Track E
- Generalises to: candidate org ADR (`.github/adr/`) — applies to any MCP tool returning large results

---

## Context

What actually determines whether this project succeeds is not how well it drives tshark but **how it returns results**. `tshark -V` emits hundreds of lines per packet; `-T json` yields several MB per thousand packets. Every MCP return value lands in the agent's context, so returning results naively burns the context window and makes analysis impossible to continue.

data-toolbox-mcp caps `query_data` at a row limit (default 20000) and added `truncated` / `total` in v0.4.0. Two lessons carry over:

- Silently truncating at the limit makes the LLM believe it has the full set. `truncated` and `total` must be disclosed
- Paths for returning artifacts (the `host_work_dir` addition in v0.2.1, `attach_files` in v0.3.0) were retrofitted and surfaced as UX defects during real-client validation

A pcap-specific problem: **row counts cannot control output size.** 100 rows including a payload column routinely exceed 10000 rows of `ip.src,ip.dst`.

## Decision

Every result-returning tool follows one contract.

### 1. The threshold is serialized bytes

Whether a result is returned inline or written to a file is decided by **the byte size after JSON serialization** (`[output] inline_max_bytes`, default 65536). A row count (`default_row_limit`, default 10000) is kept as a secondary guard, but bytes are the primary control.

### 2. The shape does not change between inline and file

```json
{
  "workspace_id": "...",
  "filter": "tcp.flags.reset == 1",
  "matched": 48213,
  "returned": 200,
  "truncated": true,
  "delivery": "file",
  "rows": [ "... inline only ..." ],
  "result_file": "<workspace>/work/out/q3.jsonl",
  "result_bytes": 48231904,
  "sample": [ "... file output only, first few rows ..." ]
}
```

Shared fields always sit in the same place with the same meaning, so the agent never branches.

**`delivery` (`"inline"` / `"file"`) was added during Track E.** The original design let the agent infer the channel from which keys were present — `rows` for inline, `result_file` for a file. Implementation showed that **an inline result with zero matches has an empty `rows`, which `omitempty` drops, making it indistinguishable from a file-backed result.** `rows` became a pointer so an empty array survives, and an explicit field replaced the inference.

### 3. `matched` is always returned

`matched` is **the total number of packets matching the display filter**, returned independently of `returned` (the number of rows actually delivered). Without it, the agent cannot distinguish "the filter narrowed things down" from "nothing matched", and picks the wrong next move.

Implementation may require a second tshark pass. To avoid paying on the common path, **the extra counting pass runs only when the result is `truncated`** (the same reasoning as data-toolbox v0.4.0's `total`). If the extra pass times out, `matched_unavailable_reason` is returned.

### 4. `sample` is attached even for file output

The first few rows (default 5) are always included inline. Without this, the agent is forced into a round trip purely to learn the shape of the data.

### 5. Large output is JSONL, never a single JSON array

- Partially readable with `head` / `grep` / `tail`
- Read natively by DuckDB's `read_json_auto`
- Allows streaming writes, so the server never holds the whole result in memory

CSV is selectable via a `format` argument. parquet is not offered, as a consequence of ADR-0003.

### 6. Output files are not meant to be read in full

Output files are designed as **(a) input to the next tool (data-toolbox-mcp / DuckDB)** or **(b) targets for partial reads / grep**. The agent is not expected to read them whole. This assumption is stated explicitly in `get_usage`.

### 7. Timestamps as both epoch and UTC ISO-8601

No locally formatted times. Timezone confusion causes fatal errors in IR analysis.

## Consequences

**Positive:**

- Context exhaustion is prevented structurally. The agent always learns from `matched` and `truncated` that its filter is too loose, and self-corrects toward narrowing
- Identical shapes across inline and file delivery keep the agent-side code simple
- JSONL lets both server and agent handle large results in a streaming fashion
- `sample` removes one round trip whenever output goes to a file

**Negative:**

- **Obtaining `matched` may require an extra tshark pass.** Even limited to the truncated case, this is a non-trivial cost on huge captures. A timeout plus the `matched_unavailable_reason` fallback is required
- Deciding on post-serialization bytes could naively mean serializing first and then switching to file output. The implementation must count bytes incrementally while accumulating rows and switch to a file the moment the threshold is crossed, avoiding duplicated work
- Output files accumulate under `work/out/`. No automatic GC beyond `delete_workspace` in v1 (visibility only, via `outputs[]` in `describe_workspace`)

## See also

- ADR-0003: Why parquet is not offered
- ADR-0006: Async jobs (the "time" axis, orthogonal to size)
- Lessons ported from: data-toolbox-mcp ADR-0010 (`truncated` / `total`), ADR-0006 v0.2.1 amendment (artifact exchange)
