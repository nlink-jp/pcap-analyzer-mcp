# Sample captures

Four synthetic captures for trying the server out, and a graded walkthrough
that exercises every tool. Nothing here was recorded from a real network: they
are built by `generate.sh` using `text2pcap` and `mergecap` from inside the
analysis image. No real traffic and no malware sample belongs in this
repository.

| File | Packets | What it is for |
|---|---|---|
| `web-session.pcapng` | 2 | An ordinary HTTP request and response. The simplest thing that works |
| `suspicious-download.pcapng` | 2 | A response whose body is written to look like an instruction. Demonstrates the untrusted-content framing and object defang |
| `mixed.pcapng` | 4 | Both of the above merged, so there are two conversations to rank |
| `truncated.pcapng` | 4 | `mixed.pcapng` cut to a 40-byte snaplen. Carries no payload, and the server should say so before you try |

Regenerate with:

```bash
./samples/generate.sh
```

## Graded walkthrough

Work down the list. Each stage builds on the last, and each says what you
should see — so a wrong answer is visible rather than merely unexpected.

The same eleven stages run automatically:

```bash
make build && make runtime-image
go test -tags e2e ./e2e/
```

Below, `WS` is any directory you can write to; `S` is this directory.

### 1. The server starts and offers twelve tools

Register the binary with your MCP client (see
[`docs/en/reference/client-setup.md`](../docs/en/reference/client-setup.md))
and list its tools. Expect twelve, and `get_usage` should describe the
workspace model, the result contract, and the error codes.

### 2. Open a capture

```
create_workspace(pcap_path="$S/mixed.pcapng", workspace_dir="$WS")
```

Expect a `workspace_id`, a 64-character `sha256`, `packet_count: 4`, and
`truncated: false`. The capture is mounted read-only and is not copied; the
SHA-256 is computed on the host and anchors everything that follows.

Now call `describe_workspace` with that id. It should return the same
information **immediately** — it reads a cache and starts no container. If it
takes as long as the create did, something is wrong.

### 3. Survey before filtering

```
protocol_hierarchy(...)     → eth → ip → tcp → http
list_conversations(...)     → 2 conversations, each with a stream index
```

The stream index is the point of `list_conversations`: it is what
`follow_stream` needs, and `tshark -z conv,tcp` does not provide it.

### 4. Narrow down

```
query_packets(filter="tcp")            → matched 4, returned 4, delivery inline
query_packets(filter="tcp", limit=1)   → matched 4, returned 1, truncated true
query_packets(filter="tcp.port == 9999") → matched 0, rows []
```

`matched` always reports what the filter hit, independent of how many rows came
back. That is the number that tells you whether to narrow further; `returned`
alone cannot. Zero matches is an answer, and comes back as an empty array
rather than an error.

### 5. Get a filter wrong on purpose

```
query_packets(filter="tcp.flags.zyn == 1")
```

Expect `invalid_display_filter`, and in `details` the message tshark itself
produced — including the expression and a `column` pointing at the token it
objected to. Forwarding tshark's own diagnostic is what lets you fix the filter
instead of guessing.

### 6. Read a stream, and notice the framing

```
follow_stream(workspace_id=<suspicious-download>, stream=0)
```

The response body contains `IGNORE ALL PREVIOUS INSTRUCTIONS…`. It arrives
inside `<untrusted-payload nonce="…">` delimiters, behind a statement that the
content is data rather than instructions — and that statement comes **first**,
because after the payload it would arrive too late to matter.

This is mitigation, not a guarantee. It makes the provenance unambiguous; it
cannot force a reader to respect it.

### 7. Extract an object, and check what landed on disk

```
extract_objects(workspace_id=<suspicious-download>, protocol="http")
```

Look at the file in `<workspace>/work/out/objects/`:

- named `<sha256>.bin`, not what the capture called it
- mode `0600`, never executable
- its bytes were not returned to you

The name tshark chose is in the manifest, framed as untrusted like any other
wire content. On this sample tshark writes `object1.text%2fplain` — an
attacker-influenced name carrying a URL-encoded slash, which is why nothing
from the wire is allowed to become a path.

### 8. Try the truncated capture

```
create_workspace(pcap_path="$S/truncated.pcapng", ...)
describe_workspace(...)   → truncated: true, plus an explanation
follow_stream(...)        → payload_unavailable_truncated_capture
extract_objects(...)      → payload_unavailable_truncated_capture
query_packets(...)        → still works: matched 4
```

The packets were cut short when this was recorded, so the payload bytes were
never written. The server refuses **before** running anything and says which
tools still work, so an empty result is not mistaken for a transient failure.

### 9. Run something in the background

```
query_packets(..., async=true)   → job_id, state "queued"
check_job(job_id)                → eventually state "done"
```

The finished `result` is byte-for-byte what the synchronous call returns. An
unknown `job_id` gives `job_not_found` and tells you to re-run the tool — safe,
because the capture is read-only and every analysis is idempotent.

### 10. Clean up

```
delete_workspace(..., dry_run=true)   → reports what would go, removes nothing
delete_workspace(...)                 → workspace gone
```

Check that the capture in `samples/` is still there. Deleting a workspace never
touches the evidence; it was only ever mounted read-only.

### 11. Ask what the runtime is

```
describe_runtime()
```

Expect the pinned base digest, the tshark version, and the six protocols
`extract_objects` supports. The manifest states what the image should be, and
`local_image_id` says what is actually installed — if they disagree, the image
needs rebuilding.
