# ADR-0008: Take the work directory as a per-call `work_dir`, and delete `allowed_paths`

- Status: Accepted — its implementation (the work-directory checks and the input blacklist) is
  replaced by [ADR-0010](0010-pathguard.md) (nlink-jp/pathguard)
- Date: 2026-09-13
- Amends: the `allowed_paths` clause of [ADR-0004](0004-workspace-per-capture.md)

## Context

This applies organization ADR-021 (the work-directory contract for file-mediated
MCP servers) to this server. The reference implementation is voice-scribe (its
ADR-0010); this is the fleet's second adopter and **the first one whose inputs are
routinely absolute host paths**, so the shape of the blacklist is settled here.

Two facts motivate it.

**1. The argument name is split across the fleet.** The same argument exists as
`workspace_root`, `workspaceRoot` and `workspace_dir`, so a model has to learn a
different name per server. This server spells it `workspace_dir`.

**2. `allowed_paths` makes this server unusable from Claude Code.** This machine's
config lists two agent state roots and `~/Downloads`; Claude Code stages files under
`/private/tmp/claude-<uid>/…`, so **a capture the agent has just staged is refused**.
ADR-0004 framed the list correctly — a guardrail, unrestricted by default, not a
sandbox boundary — but the mechanism cannot express what it was meant to: the
matcher is a resolved-path prefix test with no per-repository granularity. Covering
~105 repositories under one work root means listing `~/works`, or `~`, and `~`
admits `.ssh` and `.aws`, at which point the list means nothing. What an operator
can actually write is a short list of narrow non-project roots, and the refusal
above is the result.

Measurement of the four calling runtimes (Claude Code, ChatGPT Codex, gem-agent,
lagent) on 2026-09-13 also showed that MCP `roots` is unusable as a channel — Codex
declares no capability and returns an empty list, Claude Code returns the project
directory and never the scratchpad — and that Codex strips the environment before
spawning a server. **The per-call argument is the only channel all four have.**

## Decision

### 1. The argument is `work_dir`, still required by every tool

`workspace_dir` is renamed to `work_dir`, meaning **the absolute path of a directory
the caller can read back**. A workspace is `<work_dir>/<workspace_id>/`. It stays on
every call: the pair `(work_dir, workspace_id)` is a workspace's address, and the
server holds no state across restarts.

**Beware the collision**: `work_dir` (the caller's root) and `Workspace.WorkDir()`
(`<ws>/work`, the writable area mounted at `/work`) are **different levels**. Go
identifiers for the caller's root stay `root`; `WorkDir()` is not touched.

### 2. Resolution is argument → `_meta` → error

`params._meta["jp.nlink/work_dir"]` is the second channel, which our own runtimes
can set on every `tools/call` without knowing any schema. With neither,
`work_dir_required`. **There is no server-owned default.**

### 3. Validation is a closed list

Absolute, no `~`, no `..`, exists and is a directory, writable, not a system
location. Codes: `work_dir_invalid`, `work_dir_not_found`, `work_dir_not_writable`,
`work_dir_denied`. **The directory is not created** — the caller's own directory
always exists, so a path that is not there is a typo.

### 4. Delete `allowed_paths`; a blacklist becomes the floor for inputs

- `pcap_path` may be an absolute path outside `work_dir`. The capture is **mounted
  read-only and never copied** (ADR-0004), so forcing a multi-gigabyte capture to be
  staged would be the more harmful rule.
- What is refused is a fixed, **in-code** blacklist of credential and agent-control
  locations: `~/.ssh`, `~/.aws`, `~/.config/gcloud`, `~/.gnupg`,
  `~/Library/Keychains`, `~/.claude`, `~/.codex`, `~/.config/{gem-agent,lagent}`,
  and any `.env`. Symlinks are resolved first (ADR-0004's re-check is kept).
- The `workspace.allowed_paths` key is removed, and **a config still carrying it
  fails loudly** (unknown keys detected via BurntSushi's `Undecoded()`). Ignoring it
  silently would delete a guard the operator believes they wrote.
- **The check runs on both spellings: the path as given and its symlink-resolved
  form.** Measurement settled this: `~/.ssh/config` on this machine is a symlink to a
  file in a cloud-sync folder, so resolving first made the path stop looking like
  `~/.ssh` and walked straight past the list. Comparing only the unresolved form has
  the opposite hole — a link planted in an ordinary directory would step through it.
  Both forms of the path are checked against both forms of every entry, since an
  entry may itself be a symlink.
- The blacklist is a **floor, not a boundary**. When the same content also exists
  outside the list — the cloud-sync copy above, named directly — nothing stops it.
  Bounding what the process may touch at all belongs to a sandboxing MCP proxy,
  which is deliberately deferred.

### 5. Writes stay under `work_dir`

Already true (the workspace lives under the root; the capture is read-only). Stated
so it stays true.

### 6. Results echo where they went

Results that name a workspace carry the resolved absolute `work_dir`. A caller whose
runtime supplied the directory through `_meta` learns the destination from the
result and nowhere else.

## Consequences

- **Breaking.** A call sending `workspace_dir` is refused with a
  `work_dir_required` that names the replacement; a config carrying
  `allowed_paths` fails at startup.
- **Claude Code can use this server.** A capture staged in its scratchpad is
  accepted.
- **Server configuration stops naming runtimes.** Two runtime state roots leave the
  config, and a fifth calling runtime needs no change here.
- `doctor`'s mount check loses its `allowed_paths` branch and probes the
  conventional shares (`/Users`, `/private/tmp`, `/var/folders`) only.
- The operator loses the knob that narrowed *this server's* reach. The place it
  comes back is the future sandboxing proxy, where it applies to every server at
  once.

## References

- Organization ADR-021 (the work-directory contract) and voice-scribe ADR-0010 (the
  reference implementation)
- [ADR-0004](0004-workspace-per-capture.md) — 1 pcap : 1 workspace, read-only mount.
  This record replaces only its `allowed_paths` clause.
