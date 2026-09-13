# ADR-0009: Withdraw file-mediated results; bound and count instead

- Status: Accepted
- Date: 2026-09-13
- Amends: [ADR-0005](0005-output-contract.md) (the output contract)

## Context

ADR-0005 settled four things: (1) the threshold is bytes, not rows; (2) the
response shape is identical inline or file-backed; (3) `matched` is always
returned; (4) large output is JSONL, not a JSON array. This record withdraws
**the file-mediated delivery that (2) and (4) presuppose**.

The organization decided on 2026-09-06 (owner's decision, bigquery-mcp RFP
Item 2, fleet-wide):

> A server writing anything above a threshold into a file it chose, and
> returning the path, is retired. A server cannot know the caller's context
> window, and a threshold, a destination and a read-back path per server means
> the whole fleet reimplements the same mechanism. Putting a large response on
> disk is the agent runtime's job (gem-agent ADR-0058 intake). What stays in a
> server is **an explicit cap and the count of what it dropped**.

This applies it here, in the same shape as splunk-mcp, which removed its spill
the same day.

## Decision

1. **`query_packets` returns rows in the response.** `result_file`, `sample`,
   `delivery` and `format` (jsonl/csv) are gone, and the CSV encoder with them.
2. **Two bounds**: `limit` (rows — the call argument plus config
   `default_row_limit`) and **`max_bytes`** (the byte budget in config, renamed
   from `inline_max_bytes` with a changed meaning). ADR-0005's "measure in
   bytes" judgement **stands**: a hundred rows carrying a payload column
   outweigh ten thousand rows of addresses, and that reason is untouched.
3. **What is left out is counted.** Beside `truncated`, the result carries
   `omitted_rows` (= `matched` − `returned`) and a `note` naming the bound that
   stopped it. `matched` stays **exact**, so a bounded answer is still an answer
   about the whole capture.
4. **Shape invariance (ADR-0005 (2)) is kept.** The keys do not change according
   to whether a bound bit; callers branch on `truncated`.
5. The removed config keys (`output.inline_max_bytes`, `output.sample_rows`)
   **fail the load by name** if a config still carries them. Ignoring them
   silently would delete a limit the operator believes they set.
6. **`work_dir` stays.** `extract_objects` produces files as its product, and the
   workspace (`meta.json`) needs a home. What was withdrawn is only the server
   deciding to turn *data* into a file — organization ADR-021's distinction
   between a server whose product is a file and one whose product is data.

## Consequences

- **Breaking.** `query_packets` loses its `format` argument, and results lose
  `result_file`, `sample` and `delivery`. `limit: 0` now means "bounded by the
  byte budget alone" rather than "export everything to a file".
- An investigation that needs everything narrows the filter, asks for fewer
  fields, or raises `limit` — and a runtime that spills large responses to disk
  covers the rest.
- `internal/output` loses `csv.go` and the file path entirely; it now only
  accumulates rows, stops at a bound, and reports what it left out.

## References

- Organization decision of 2026-09-06 (bigquery-mcp RFP Item 2); gem-agent
  ADR-0058 (the runtime-side intake)
- splunk-mcp's matching change the same day (`inline_row_threshold` → `max_rows`)
- [ADR-0005](0005-output-contract.md), [ADR-0004](0004-workspace-per-capture.md),
  organization ADR-021 (the work-directory contract — `work_dir` survives this
  change)
