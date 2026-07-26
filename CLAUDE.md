# CLAUDE.md — pcap-analyzer-mcp

Organization rules apply in full:
https://github.com/nlink-jp/.github/blob/main/CONVENTIONS.md

Read `AGENTS.md` first for the project map. This file only records the rules
that are specific to *this* project and easy to get wrong.

## Never

- **Never commit a real packet capture.** Test fixtures are synthesized with
  gopacket under `testdata/gen/`. Captures from real networks contain PII and
  credentials, and malware samples must never enter the repository.
- **Never log payload.** Display filters, stream indices, and object hashes may
  be logged. Reassembled stream content, extracted object contents, and
  anything derived from packet payload may not (ADR-0007). Payload-bearing
  types must be structurally unable to reach the logging path.
- **Never return payload bytes inline.** Extracted objects are returned as
  metadata plus a path. This is the opposite of data-toolbox-mcp's
  `attach_files`, and the difference is deliberate.
- **Never copy the capture.** It is mounted read-only; the original must stay
  byte-identical to what the user handed us (ADR-0004).
- **Never `go build` directly.** Use `make build` (writes to `dist/`).

## Always

- **Wrap attacker-derived text in nonce-tagged XML, with the framing at the
  top of the output** (ADR-0007). Everything read out of a capture is
  attacker-controlled: filenames, URIs, Host headers, stream content.
- **Honour the output contract in every result-returning tool** (ADR-0005):
  byte-based threshold, invariant response shape, `matched` always present,
  `sample` attached whenever the result went to a file, JSONL for large output.
- **Amend the ADR before deviating from it.** The ADRs are the source of truth
  for design decisions; code that disagrees with an ADR is a bug in one of them.

## Gotchas

- The container is **ephemeral, one per call** (ADR-0002). There is no
  long-lived container and no `podman exec`. Do not reintroduce `Ensure`.
- There is **no in-memory ⇄ disk synchronization** anywhere, and it should stay
  that way. Workspaces are a directory plus `meta.json`; `list_workspaces` is a
  directory scan.
- `describe_workspace` must **not** start a container. It reads the `capinfos`
  cache written at `create_workspace` time. It is the highest-frequency call.
- Check `meta.json`'s `truncated` before running payload tools. A capture taken
  with a small snaplen has no payload, and an empty result there is an answer,
  not a transient failure.
- macOS: the capture must live under a Podman Machine shared path
  (`/Users`, `/private/tmp`, `/var/folders`) or the read-only mount cannot be
  passed through virtiofs.
