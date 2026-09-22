# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **The Linux archives no longer carry macOS file metadata.** macOS `tar` wrote
  each bundled file's extended attributes (`com.apple.provenance`, and a Dropbox
  attribute where the tree is synced) into the `.tar.gz` twice: as AppleDouble
  `._` members, which GNU tar extracts as stray `._<name>` files beside the real
  ones, and as `LIBARCHIVE.xattr.*` / `SCHILY.xattr.*` pax headers, which it
  reports as unknown keywords. `make package` now archives with
  `COPYFILE_DISABLE=1 tar --no-xattrs`; each setting stops one of the two.
  Archives already published still carry them; the files themselves are
  unaffected.

### Internal

- `make verify-release` also judges each Linux archive: no AppleDouble or other
  macOS metadata members — listed with `--options 'tar:!mac-ext'`, because a
  plain macOS listing folds `._` members away — no extended attributes as pax
  headers, and exactly the canonical binary, `README.md` and `LICENSE`, compared
  in the C locale.
- The Linux-archive check in `make verify-release` reads each archive's pax
  headers with Python's `tarfile` instead of grepping the decompressed stream,
  which also matched file text that names the keywords (a bundled CHANGELOG,
  for one).

## [0.6.2] - 2026-09-22

### Fixed

- A path's place is nlink-jp/pathguard v0.3.0's `Where`, the end of its walk.
  It was the last of pathguard's forms, which is a middle hop when a chain of
  links comes back to a spelling it already passed.

## [0.6.1] - 2026-09-22

### Security

- **Whether a capture exists no longer changes the answer.** A `pcap_path` in
  a credential or agent-control location was refused when the file was there
  and answered `pcap_unreadable` when it was not, so the answer told the
  caller which secrets exist. The path is now judged at the place it leads to
  before anything looks for a file, and a refused place gets the same answer,
  message and details, either way (ADR-0010, amendment). A chain of links
  that does not end is now refused (`path_not_allowed`) rather than reported
  unreadable, and a link climbing with `..` past a file gets the same answer
  as one climbing past a directory.
- A refusal names the path only as given: `details.resolved` is gone. It
  named where the path leads, which differed when an entry on the way is a
  link, and so said which entries exist and where they lead.

### Changed

- A relative `pcap_path` under a working directory reached through a link is
  resolved all the way, as its absolute spelling always was, so it gets that
  spelling's workspace id; re-creating an earlier workspace for it makes a
  new one.
- A path with `..` after a file or a missing name is opened where pathguard
  places it (the `..` applied to what exists) rather than answered "not a
  directory" / "no such file".

## [0.6.0] - 2026-09-22

### Changed

- **Path judgement moved to [nlink-jp/pathguard](https://github.com/nlink-jp/pathguard)**
  (ADR-0010). `internal/workdir` is now an adapter onto it; the resolver is
  built with `workdir.NewResolver(serverOwnedDirs(cfgPath)...)`. Places are
  compared by file identity and by names folded the way the disk folds them,
  instead of by name.
- `create_workspace` now **refuses** a `pcap_path` in the real places under your
  home from the list gem-agent and lagent use — newly `~/.kube`, `~/.config/gh`,
  `~/.azure`, `~/.terraform.d`, `~/.gemini`, `~/.config/mcp-bridge`, `~/.netrc`,
  `~/.npmrc`, `~/.pypirc`, `~/.git-credentials`, `~/.vault-token`,
  `~/.docker/config.json`, `~/.claude.json`, `~/.bash_history`, `~/.zsh_history`
  — every spelling of any refused place (another case, a link, a firmlink), and
  wherever a link directly inside one of those directories points. When `$HOME`
  names another directory than the account's home, both are protected. Linux
  `/etc` is refused as a `work_dir`.
- `.env.example`, `.env.sample`, `.env.template` and `.env.dist` are now
  **accepted** (templates, not secrets).
- When the home directory cannot be determined, capture paths and every
  `work_dir` are **refused**; they used to pass unchecked.
- `work_dir_denied` carries `reason` in its `details`.

### Security

- **The workspace directory is judged, not only `work_dir`.** `work_dir=~/.config`
  with `workspace_id=gh` reached `~/.config/gh`, a credential directory: a
  workspace could be created there and its `work/` mounted into the container.
  `<work_dir>/<workspace_id>` is now refused with `work_dir_denied` wherever
  `work_dir` itself would be, in `create_workspace` and in every tool that loads
  or deletes a workspace. The hole was present since the work-directory contract
  (ADR-0008).
- A path holding a NUL byte is refused (pathguard v0.2.0).

## [0.5.0] - 2026-09-22

### Added

- **The server now sends MCP `instructions` at initialize**, as every other
  work-directory MCP server in the organization does. A client hands this text
  to its model before any tool list, so the work-directory contract no longer
  has to be discovered from the schemas: every tool except `get_usage`,
  `describe_runtime` and `check_job` requires `work_dir` (absolute, no
  default), the workspace is `<work_dir>/<workspace_id>/`, heavy tools take
  `async: true` and are collected with `check_job`, and `get_usage` holds the
  rest. Tests hold every tool it names to the registered tools, and its list of
  tools without `work_dir` to their schemas, in both directions.

### Fixed

- `get_usage` said "Every call names work_dir"; `get_usage`, `describe_runtime`
  and `check_job` take none. It now names the exceptions, from the same list the
  instructions use.

### Tests

- The per-tool contract tests fail when no tool is registered. They loop over
  the registered tools, and with an empty list every one of them passed without
  examining anything.

## [0.4.0] - 2026-09-21

### Fixed

- **`make verify-release` now fails closed.** Its last block chained unzip, the
  packaged binary's `--version` and `spctl` with `&&` and ended the whole chain
  in `|| true`, so a zip that did not unpack or a binary that did not run exited
  0 and the upload proceeded. Each step is now judged on its own, the packaged
  binary's `--version` must contain the tag being released, and only the
  informational `spctl` line may be ignored. Matches the org template
  (CONVENTIONS.md §Code Signing → Verifying a release).

### Changed

- **`~/.config/pcap-analyzer-mcp/config.toml` is now read.** The `--config`
  flag's help said the default was to "search the standard locations", but the
  loader consulted only the explicit path and `PCAP_ANALYZER_MCP_CONFIG` — so a
  config.toml in the conventional directory was silently ignored while the help
  promised it worked. Resolution is now: `--config`, else
  `PCAP_ANALYZER_MCP_CONFIG`, else `~/.config/pcap-analyzer-mcp/config.toml`
  when a file is there, else the built-in defaults. Every sibling MCP server in
  the fleet already searched that directory.

  **This is a behaviour change:** a config.toml sitting in that directory
  starts taking effect. If one is there and you had given up on it, read it
  before upgrading — its values now apply, and a malformed one is an error
  rather than a silent fallback, on the grounds that a config the operator
  believes is in force must not be ignored.

  The working directory is deliberately not searched, unlike some siblings that
  also look at `./config.toml`: this server is spawned by an agent runtime that
  chooses its own cwd, so that candidate would make the configuration depend on
  who started it. Pinned by a test.

## [0.3.0] - 2026-09-21

### Security

- **`work_dir` may no longer be one of this server's own config directories.**
  Organization ADR-021 §4 closes the work-directory checks with "not a system
  location … and not the server's own config or state directory" →
  `work_dir_denied`, and the resolver has carried a `Denied` list for exactly
  that — but nothing populated it here, so it ran as its zero value. A caller
  could name this server's config directory as its `work_dir` and have the
  server create workspaces there, mount captures from it into a container and
  write extracted objects beside the file that sets the server's own limits,
  on a model's say-so. Now refused, subdirectories included:
  `~/.config/pcap-analyzer-mcp`, and the directory holding the config file in
  use when `--config` or `PCAP_ANALYZER_MCP_CONFIG` names one — so an operator
  who keeps the config file in a directory they also work in should give it a
  directory of its own. The log file's directory is deliberately not denied:
  it is operator-chosen and routinely broad, and a tree that wide would refuse
  work directories callers legitimately use.
- The path in use comes from one new expression, `config.ResolvePath`, which
  `Load` now calls too, so the denial cannot come to disagree with what is
  actually being read.

## [0.2.2] - 2026-09-14

### Added

- `TestEveryRequiredNameIsDeclared` — a schema that lists a name in `required`
  without declaring it in `properties` makes a strict client refuse the whole
  tool list (Vertex AI: "schema at top-level requires unspecified property").
  data-toolbox-mcp shipped exactly that and broke a session outright; the
  existing contract test checked declared ⇒ required only, so the fleet is
  pinned in both directions now.

## [0.2.1] - 2026-09-13

### Fixed

- **`describe_workspace` reported no outputs at all.** The listing read one
  level of `<workspace>/out/` and skipped directories — which worked while the
  spilled query results sat there, and stopped working the moment 0.2.0 removed
  them (ADR-0009). The only product left, what `extract_objects` recovers,
  lives in `out/objects/`, one level down. The listing walks now, and skips
  tshark's staging directory.
- `--help` and the `describe_runtime` manifest still told the model that
  results are files under `/work`, written as JSONL when large. They say what
  the server does: results come back in the response under a row limit and a
  byte bound, and the workspace holds only extracted objects.
- The RFP's headline contract and two ADR index rows are annotated with the
  revisions that overtook them, instead of reading as current.
- **The reference docs still taught the removed file export**: the client-setup
  handoff told the reader to pass `limit: 0` to write JSONL and to add the work
  directory to data-toolbox's `allowed_paths` (a key that no longer loads), the
  tips said `limit: 0` exports everything as a file, and the workspace tree in
  the architecture document still showed `out/` holding query results. They
  describe what happens now, in both languages.

### Added

- `TestModelFacingProseNamesNoWithdrawnMechanism` and
  `TestManifestNamesNoWithdrawnMechanism` — the schema test already caught a
  renamed argument; these catch a sentence. Prose drifts silently because
  nothing compiles it.
- `make test` now also type-checks the `integration` and `e2e` suites, which
  `go test ./...` never builds.

## [0.2.0] - 2026-09-13

### Changed

- **Breaking: results are no longer written to a file by this server.**
  `query_packets` loses its `format` argument (jsonl/csv), and results lose
  `result_file`, `sample` and `delivery`. Rows come back in the response under
  two explicit bounds — `limit` and the byte budget — and what the bounds leave
  out is counted: `truncated`, `omitted_rows`, and a `note` naming the bound
  that stopped it. `matched` stays exact, so a bounded answer is still an answer
  about the whole capture. See
  [ADR-0009](docs/en/adr/0009-withdraw-file-mediated-results.md).
- **Breaking: `output.inline_max_bytes` is renamed to `output.max_bytes`** with
  a changed meaning (the budget for rows in a response, not the threshold for
  spilling to a file), and `output.sample_rows` is removed. A config still
  carrying either fails at startup with the reason named.
- `limit: 0` now means "bounded by the byte budget alone" rather than "export
  everything to a file".
- `work_dir` is unaffected: `extract_objects` produces files as its product, and
  the workspace still lives under the caller's directory.

### Changed

- **Breaking: `workspace_dir` is now `work_dir`, on every tool.** It means what
  the caller means by it — the absolute path of a directory the caller can read
  back — and the workspace is `<work_dir>/<workspace_id>/` as before. A call
  still sending `workspace_dir` (or `workspace_root` / `workspaceRoot`) is
  refused with `work_dir_required` naming the replacement. This is the
  organization's work-directory contract for file-mediated MCP servers; see
  [ADR-0008](docs/en/adr/0008-work-dir-contract.md).
- **Breaking: `workspace.allowed_paths` is deleted, and a config still carrying
  it fails at startup.** The list could not express what ADR-0004 wanted from
  it: prefix matching has no per-repository granularity, so covering a work root
  meant listing the home directory, which admits the files the list existed to
  keep out. In practice it named two agent runtimes' state directories by hand
  and refused a capture staged by a third. Unknown config keys are now rejected
  by name rather than ignored.
- `pcap_path` may now be any path you can read, except a fixed in-code blacklist
  of credential and agent-control locations (`~/.ssh`, `~/.aws`,
  `~/.config/gcloud`, `~/.gnupg`, `~/Library/Keychains`, `~/.claude`, `~/.codex`,
  `~/.config/{gem-agent,lagent}`, any `.env`). Symlinks are resolved first, so a
  link cannot smuggle a blacklisted target in. The blacklist is a floor, not a
  boundary — bounding what this process may touch at all is left to a future
  sandboxing proxy.
- A runtime may supply the work directory instead of the model: the server reads
  `_meta["jp.nlink/work_dir"]` from the `tools/call` request when the argument is
  absent. The argument always wins.
- Results that name a workspace now echo the resolved `work_dir`.
- `doctor` drops its `allowed_paths` branch and probes the conventional macOS
  shares (`/Users`, `/private/tmp`, `/var/folders`) only.

### Added

- Five error codes that say which part of the contract failed:
  `work_dir_required`, `work_dir_invalid`, `work_dir_not_found`,
  `work_dir_not_writable`, `work_dir_denied`. The work directory must already
  exist (the server does not create it), be writable, and not be a system
  location, the home directory itself, or a credential directory.

### Fixed

- **A job no longer starts while the server is shutting down.** A queued job
  waits on a `select` between "a slot freed" and "the context was cancelled";
  when both are ready Go picks uniformly at random, so shutdown started roughly
  half the jobs it should have abandoned — each one a fresh `podman run`
  (ADR-0002). The context is now re-checked after the slot is won and before
  the job begins.

## [0.1.2] - 2026-07-26

### Fixed

- **A single unreadable object no longer sinks `extract_objects`.** Over-size
  objects were already recorded in `skipped` and the extraction carried on, but
  an object that could not be read aborted the call. On a host with antivirus
  running that is the normal case, not the edge case: the AV quarantines a
  sample mid-write, and a capture where 2 of 3 objects were detected returned
  nothing at all — not even the benign one. Unreadable objects are now skipped
  with a reason naming the likely cause, and the recoverable ones come back.
  Reported in the field notes contributed by @magifd2

### Changed

- `get_usage` now describes the `extract_objects` manifest, including what a
  populated `skipped` list means. An empty `objects` with entries in `skipped`
  is a successful call, and worth reading as a finding

## [0.1.1] - 2026-07-26

### Fixed

- **`--version` now works.** Only the `version` subcommand did. Every other
  tool in the org answers the flag, and the shared homebrew formula template
  tests for it — so the tap's test block would have failed on install. Found
  by wiring up tap distribution

## [0.1.0] - 2026-07-26

First release. An MCP server that lets an agent analyse pcap / pcapng captures
through a version-pinned tshark running in a container.

### Added

- **Twelve MCP tools** over stdio: `get_usage`, `create_workspace`,
  `describe_workspace`, `list_workspaces`, `delete_workspace`,
  `describe_runtime`, `protocol_hierarchy`, `list_conversations`,
  `query_packets`, `follow_stream`, `extract_objects`, `check_job`
- **CLI**: `serve`, `build-runtime`, `doctor`, `version`
- **A digest-pinned analysis image** (`debian:12-slim` + tshark 4.0.17, 274MB),
  built locally by `build-runtime` from a Dockerfile embedded in the binary.
  Pinning the version is why the container exists: `-T fields` names and `-z`
  formats drift between tshark releases
- **The capture is mounted read-only as a single file and never copied.** The
  original stays byte-identical, siblings in its directory stay invisible, and
  the host filename never becomes a container path or an argv
- **A workspace is a directory plus a metadata file.** No long-lived container,
  no in-memory registry — so workspaces survive a restart and
  `describe_workspace` answers in milliseconds from a cache
- **One result contract for every tool** (ADR-0005): the size threshold is
  serialized bytes rather than rows, `matched` always reports what the filter
  hit so "too broad" is distinguishable from "nothing there", large results go
  to the workspace as JSONL or CSV with a leading `sample`, and the response
  shape does not change between the two
- **`async: true` with `check_job`** for the tools that read a whole capture,
  bounded by a concurrency cap. Progress carries a phase and a row count, never
  a percentage — tshark does not report how far through a capture it is, and an
  invented number is worse than none
- **tshark's own diagnostics are forwarded**, not paraphrased. A bad display
  filter comes back with the expression and the column tshark objected to,
  which is what lets a caller fix it rather than retry it
- **`samples/`** — four synthetic captures, a generator that builds them with
  the image's own Wireshark tools, and an eleven-stage graded walkthrough
- **Documentation**: RFP, ADR-0001–0007, architecture, and client setup, in
  English and Japanese

### Security

This server exists to analyse hostile captures, so adversarial input is the
normal case rather than the exception.

- **The analysis container cannot capture traffic.** No network, non-root, all
  capabilities dropped, and the `dumpcap` binary deleted at build time — the
  scope boundary is enforced by construction, not by policy
- **Content read out of a capture is framed as untrusted, framing first.** Free-
  text blobs (reassembled streams) get nonce-tagged delimiters; field values and
  object names get one statement at the head of the result, since JSON escaping
  already makes their structure unforgeable
- **Payload cannot reach the log.** It lives in a type that redacts itself in
  formatting, errors and `slog`; the single explicit accessor is greppable
- **Extracted objects are defanged**: stored as `<sha256>.bin`, mode 0600, never
  returned inline. tshark writes attacker-derived filenames — on the bundled
  sample, one carrying a URL-encoded slash
- **A truncated capture is refused before anything runs**, with the inferred
  snaplen as evidence and a note on which tools still work
- Container runs are bounded by a wall-clock timeout; panics are recovered at
  the request and job boundaries; and host-side memory and disk are bounded
  independently of the container's cgroup, which does not cover them

### Known limitations

- One capture per workspace; ring-buffer split captures are not yet merged
- Live capture, IDS-style detection, pcap editing and parquet output are all out
  of scope
- Requests are handled in order, so a long synchronous call blocks the rest —
  use `async` for large captures
- `dropped_packets` is not reported: `capinfos` does not expose pcapng ISB drop
  counts
