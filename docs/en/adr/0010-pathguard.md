# ADR-0010: Leave path judgement to nlink-jp/pathguard — keep no copy

- Status: Accepted
- Date: 2026-09-22

## Context

Since ADR-0008, `work_dir` validation and the read blacklist (`workdir.Sensitive`) lived in
`internal/mcp/workdir`, a copy of voice-scribe's (the reference implementation of organization
ADR-021); seven other servers held the same copy. Every copy compared places **by name**. APFS is
case-insensitive by default, so `~/.SSH`, `.ENV` and `/USR/local` named the same places and passed
the checks. When the home directory could not be determined, `Sensitive` returned "" and passed
everything.

The organization moved this judgement into one module (`nlink-jp/pathguard`, lib-series). It compares
places by file identity and by names folded the way the disk folds them, and it catches a place that
does not exist yet through the identity of its parent. It holds one list, the same as gem-agent's and
lagent's.

## Decision

- Depend on `github.com/nlink-jp/pathguard` v0.1.0. No code from outside this organization comes
  with it.
- `internal/mcp/workdir` becomes a **thin adapter**. It keeps only:
  - taking the request's `_meta` from the context and passing it to `pathguard/workdir`'s `Resolve`,
  - moving that `*workdir.Error` onto `toolerr` with the same code, message and details,
  - `NewResolver(serverDirs...)` — passing this server's own config directories
    (`~/.config/pcap-analyzer-mcp` and the directory holding the config file in use) as protected places (`pathguard.ServerDir`), and its one
    sentence for `work_dir_required` as `RequiredHint`. An empty path refuses every call rather than
    protecting nothing (the config directory is undetermined only when the home directory is, and
    then pathguard refuses everything anyway),
  - `Sensitive` — `pathguard/workdir.Sensitive` (the Local policy), passed through.
- The call sites (`Resolve`, `Validate`, `Sensitive`) do not change. What changes is the one line that
  builds the resolver (`workDirResolver` in `cmd/tools_wiring.go`) and the tests that built it as a zero value.
- The tests of the judgement itself are in pathguard. What stays here are the adapter's tests (taking
  `_meta`, carrying the error across, the protected place, a zero value refusing) and the existing
  contract tests.

## Consequences

`create_workspace` and the `work_dir` check behave differently (the CHANGELOG says so):

- **Refused now**: the real places under your home from the runtimes' list (`~/.kube`,
  `~/.config/gh`, `~/.azure`, `~/.terraform.d`, `~/.gemini`, `~/.config/mcp-bridge`, `~/.netrc`,
  `~/.npmrc`, `~/.pypirc`, `~/.git-credentials`, `~/.vault-token`, `~/.docker/config.json`,
  `~/.claude.json`, `~/.bash_history`, `~/.zsh_history`); every spelling of any floor place — case
  variants, links, firmlinks; wherever a link directly inside one of those directories points (a
  `~/.ssh/config` that links into a sync folder protects the file it points at); when `$HOME` names
  another directory than the account's home, both; Linux `/etc` as a `work_dir`.
- **Accepted now**: `.env.example`, `.env.sample`, `.env.template`, `.env.dist` (templates, not
  secrets).
- **An unknown home refuses capture paths and every `work_dir`.** It used to pass everything.
- `work_dir_denied` carries `reason` in its `details`.
- One check costs about 2 ms (measured in pathguard) — nothing next to an analysis.

With no copy here, a fix to the judgement is a pathguard release and a one-line dependency update.

## Amendment (2026-09-22): judge the directory actually used

Only `work_dir` was checked, so `work_dir=~/.config` with `workspace_id=gh` reached `~/.config/gh` (a
workspace could be created there and its `work/` mounted into the container). The hole dates from
ADR-0008; image-forge's independent review found it. `workspace.NewManager(cfg, runner, check)` takes
the judgement as a required argument, and `Create` and `Load` (which `PreviewDelete` and `Delete`
go through) judge the workspace directory with `workdir.Resolver.CheckBeneath` (pathguard v0.2.0)
first; `newToolDeps` wires it. A Manager without one refuses every workspace. pathguard v0.2.0 also
refuses a path holding a NUL byte.

## Amendment (2026-09-22, v0.6.1): whether a file exists never changes the answer

`pcap_path` was resolved with `filepath.EvalSymlinks` before the floor judged it, so a file in a
credential location got `path_not_allowed` when it was there and `pcap_unreadable` when it was not —
the answer told the caller which secrets exist. A link climbing with `..` split three ways too: judged
beyond a directory, "not a directory" past a file, "no such file" past nothing. It is the class the
independent reviews of slack-mcp-extender and chrome-pilot-mcp found; here it was measured with the
home directory redirected to a temporary one (all 7 pairs got different answers).

- `ResolveInput` places the path first (`workdir.Where`, the last of pathguard's `Forms`: every link
  followed, a dangling one by its target — for a path that exists, what `EvalSymlinks` returns), judges
  it as given and as placed (`refused`), and only then asks existence of the place
  (`EvalSymlinks(where)`). When it resolves elsewhere than it was placed (it changed in between), it is
  judged again there.
- A refusal names the path only as given; `details` no longer carries `resolved`. The place differs
  when an entry on the way is a link (`~/.ssh/config` into a sync folder, a dotfiles-linked `~/.aws`),
  so a dangling link and no entry got different values, and the value said which entries exist and
  where they lead; for a loop it named a hop the caller never gave (the independent review of this
  change found it).
- A chain of links that does not end is `path_not_allowed` (pathguard's unresolvable), not
  `pcap_unreadable`.
- A path that does not resolve gets no branch of its own.
- `TestExistenceIsNotRevealed` (internal/tools) calls `create_workspace` with the same path while a
  file is there and after it is removed and compares the whole answer. `TestPlacementCorners` pins a
  link climbing with `..` and a loop. Five mutations (the old order, the floor removed, existence
  re-walked from the spelling, no placement, the place put back into the refusal) all fail by
  assertion; the credential entry that is a link and the credential directory that is a link are in
  the table.
- Two answers change besides the refusals. A relative `pcap_path` under a working directory reached
  through a link is now resolved all the way, as its absolute spelling always was, so its workspace id
  changes. A path with `..` after a file or a missing name is placed as pathguard places it (the `..`
  applied to what exists), so it is opened there rather than answered "not a directory" / "no such
  file" as the kernel would.
- Known limits in pathguard, recorded for its next release:
  - A `..` that climbs out through an entry of a credential directory — in the path, or in the target
    of a planted link — is judged where it leads, not where it passes, so the answer can still show
    whether that entry is a link and where its target lies: pathguard judges cleaned forms, not the
    directories a walk passes through.
  - The place is the last of pathguard's forms. When a chain of links comes back to a spelling already
    met, that is an earlier hop rather than the end; every hop has been judged, so nothing unjudged is
    opened, but a file reached that way can be reported missing or read from the earlier hop.
    pathguard does not expose the final place.
  - `work_dir` is validated by pathguard/workdir in the order organization ADR-022 §4 sets (not found
    before denied), so a `work_dir` naming a credential directory is answered by whether it exists.
  - A link target with a non-ASCII name spelled in another Unicode normalisation is found by identity
    only while it exists (pathguard does not normalise). A hard link made elsewhere is refused only when
    it is to a file that is itself a place on the floor (`~/.netrc`, `~/.docker/config.json`, …), and
    only while it exists; one to a file inside a credential directory (`~/.ssh/id_rsa`) or to a `.env`
    is not refused at all — a directory is compared by its own identity, not by its files'.
- The judgement and the read are two steps, and a link swapped in between them is followed: a
  check-to-use race, not closed here (closing it means judging what was opened, by its descriptor).

## References

- Organization ADR-021 (the work-dir contract of the file-mediated MCP servers)
- ADR-0008 (work-dir contract): the closed list of checks and the read blacklist — whose
  implementation this replaces
- nlink-jp/pathguard's RFP (`docs/en/pathguard-rfp.md`)
