# Tips — how to actually run an investigation

> Date: 2026-07-26

Where [`samples/README.md`][samples] teaches the tools in eleven
graded steps against synthetic captures, this page covers **the shape of a real
investigation and the recipes that go with it**.

**Every filter below was verified against a real capture** (2026-07-26). The public
exercise captures used:

| Source | What it covered |
|---|---|
| Unit 42's "Using Wireshark: Exporting Objects from a pcap" — five exercise pcaps | HTTP / SMB / SMTP / FTP |
| [sbousseaden/PCAP-ATTACK](https://github.com/sbousseaden/PCAP-ATTACK) | Kerberos / DCERPC / DNS tunnelling / lateral movement |
| [chrissanders/packets](https://github.com/chrissanders/packets) (Practical Packet Analysis material) | DNS zone transfer / scanning / TCP anomalies |

Recipes that could not be confirmed are not listed.

## The shape of an investigation

| Step | Tool | Purpose |
|---|---|---|
| 1 | `describe_workspace` | Size and provenance. Starts no container, so it is effectively free |
| 2 | `protocol_hierarchy` | **What is in here. Look before writing a filter** |
| 3 | `list_conversations` | Who talked to whom, plus the stream index `follow_stream` needs |
| 4 | `query_packets` | Narrowing and fact extraction. This is where the work happens |
| 5 | `follow_stream` / `extract_objects` | Depth, and recovering files |

### Why step 2 is not optional

On an SMB capture, filtering on `smb2.filename` returned `matched: 0`.
`protocol_hierarchy` showed 604 `smb` frames against only 85 `smb2` frames — the
transfers were **SMB1**. Switching to `smb.file` hit immediately.

**The same concept has different field names across protocol generations.**
`matched: 0` can mean "wrong field name" rather than "not present". Reading the
hierarchy first gets it right on the first try.

## Recipes by protocol

### HTTP — what was downloaded

Start with the requests. This alone usually answers "what came from where".

```
query_packets(filter: "http.request",
              fields: ["frame.number", "ip.src", "ip.dst",
                       "http.host", "http.request.method", "http.request.uri"])
```

Then look at the responses for content types. `http.request_in` carries the request's
frame number, so the two sides line up.

```
query_packets(filter: "http.response",
              fields: ["frame.number", "http.response.code", "http.content_type",
                       "http.content_length", "http.request_in"])
```

`application/x-msdownload` or `application/msword` means an executable or document was
pulled down. Know that much before reaching for `extract_objects(protocol: "http")`.

For phishing, look at where the form went:

```
query_packets(filter: "http.request.method == \"POST\"",
              fields: ["http.host", "http.request.uri",
                       "urlencoded-form.key", "urlencoded-form.value"])
```

### SMB — file transfers and lateral movement

Confirm SMB1 vs SMB2 before choosing fields (see above). The SMB1 form:

```
query_packets(filter: "smb.file contains \".exe\" and smb.cmd == 0xa2",
              fields: ["frame.number", "ip.src", "ip.dst", "smb.file"])
```

`smb.cmd == 0xa2` (NT Create AndX) is the important part. Without it every read and
write against the same file lands in the result; with it you get the single open.

**Do not stop at the file transfer.** What happened *after* the write shows up in
`svcctl`:

```
query_packets(filter: "svcctl",
              fields: ["frame.number", "ip.src", "ip.dst",
                       "svcctl.servicename", "svcctl.displayname",
                       "svcctl.binarypathname"])
```

If `binarypathname` holds the `.exe` that was just written, that is **lateral movement
and persistence via service creation** — usually a more valuable finding than the list
of transferred files.

⚠️ **The typed fields are sometimes empty.** In a psexec capture, all 18 svcctl frames
had `svcctl.servicename` / `displayname` / `binarypathname` blank, while `_ws.col.Info`
alone carried the operations: `OpenSCManagerW request` → `OpenServiceW` →
`StartServiceW`. **Always select `_ws.col.Info` alongside them** (see "Reading the
results" below).

Hostnames come cheaply from NBNS registrations:

```
query_packets(filter: "nbns.flags.response == 0 and nbns.flags.opcode == 5",
              fields: ["ip.src", "nbns.name"])
```

They come back with the NetBIOS suffix (`QUINN-OFFICE-PC<00>`), which lets you attach
names to IP-only findings.

### SMTP — a host turned spambot

```
query_packets(filter: "smtp.req.command == \"MAIL\" or smtp.req.command == \"RCPT\"",
              fields: ["frame.number", "ip.src", "ip.dst",
                       "smtp.req.command", "smtp.req.parameter"])
```

One internal source address fanning out to external MX hosts is an infected endpoint.
Headers and bodies come out as `.eml` via `extract_objects(protocol: "imf")`.

**Count with `matched`** — there is no need to extract every message just to count them.

### FTP — the control channel answers most of it

```
query_packets(filter: "ftp.request.command or ftp.response.code",
              fields: ["frame.number", "ip.src", "ip.dst",
                       "ftp.request.command", "ftp.request.arg",
                       "ftp.response.code", "ftp.response.arg"])
```

One call yields all of:

| What you see | Meaning |
|---|---|
| `USER` / `PASS` | **Credentials in the clear** — it is FTP, so of course |
| `RETR` / `STOR` | Download vs. upload; uploads suggest exfiltration |
| `213` in reply to `SIZE` | Transfer size in bytes |
| `227` | The passive-mode data connection endpoint |

⚠️ `extract_objects(protocol: "ftp-data")` **does not export binary `RETR` transfers** —
no `.exe` comes out at all. The query above still gives you names and sizes, which is
enough for most investigations. Details in the [field notes](field-notes.md).

### DNS — tunnelling and zone transfers

**TXT-record C2 / tunnelling.** The signature is a burst of TXT queries under one
parent domain.

```
query_packets(filter: "dns.qry.type == 16",
              fields: ["frame.number", "ip.src", "ip.dst", "dns.flags.response",
                       "dns.qry.name", "dns.qry.name.len", "dns.count.labels"])
```

In the measured capture, 114 of 301 packets were TXT, and the names ran
`l.1.ns.example.tld` → `l.2.ns.example.tld` → `l.3...` — **only the leftmost label
changing, in sequence**. The parent domain stays fixed and the label count and name
length stay uniform.

Always select `dns.qry.name.len` and `dns.count.labels`. **Long names, many labels, and
concentration on a single domain** are the three tells.

**Zone transfers.** A type 252 (AXFR) that succeeded means the internal DNS records
walked out wholesale.

```
query_packets(filter: "dns.qry.type == 252",
              fields: ["frame.number", "ip.src", "ip.dst",
                       "dns.qry.name", "dns.count.answers"])
```

`dns.count.answers` on the response side (21 in the measured capture) is how many
records left.

### Kerberos — password spraying and user enumeration

**One query tells you which accounts exist, which failed, and which succeeded.**

```
query_packets(filter: "kerberos",
              fields: ["frame.number", "ip.src", "ip.dst", "kerberos.msg_type",
                       "kerberos.CNameString", "kerberos.realm",
                       "kerberos.error_code", "kerberos.etype"])
```

In `kerberos.msg_type`, 10 is AS-REQ, 11 is AS-REP and 30 is KRB-ERROR. The error code
is what classifies the attack.

| `error_code` | Meaning | To the attacker |
|---|---|---|
| 6 | `C_PRINCIPAL_UNKNOWN` | **That user does not exist** |
| 25 | `PREAUTH_REQUIRED` | **The user is real** (enumeration hit) |
| 24 | `PREAUTH_FAILED` | Real user, wrong password |
| 52 | `RESPONSE_TOO_BIG` | Merely a retry over TCP |

**Success is not an error — find it as `msg_type == 11` (AS-REP).** In the measured
capture, 33 frames of AS-REQs drew a wall of code 6 and 25 errors, and exactly one
AS-REP came back at the end. Its `CNameString` is **the account the spray broke into**.

**Encryption-type downgrade.** RC4 (`etype` 23) mixed into an environment that
otherwise uses AES (`etype` 17 / 18) suggests skeleton key or overpass-the-hash.

```
query_packets(filter: "kerberos.etype == 23",
              fields: ["frame.number", "ip.src", "ip.dst",
                       "kerberos.msg_type", "kerberos.CNameString"])
```

Establish the environment's baseline first — where RC4 is normal, this is not a finding.

### DCERPC / RPC — enumeration and remote execution

**Sweeping the endpoint mapper is reconnaissance.**

```
query_packets(filter: "epm",
              fields: ["frame.number", "ip.src", "ip.dst", "_ws.col.Info", "epm.uuid"])
```

`_ws.col.Info` resolves all the way to the service name —
`Lookup response, Service:CLIPSVC Default RPC Interface`. In the measured capture, 698
of 700 packets were epm: one host enumerating every RPC interface. The count alone is
the finding.

**`dcerpc.opnum` means nothing on its own.** Opnums are per-interface ordinals, so
without the BIND in the capture tshark cannot name them. Measured: on a DCSync capture
`drsuapi` returned `matched: 0`, and `dcerpc` gave only the bare number `opnum: 3`.
Never assert an operation name from an opnum when the BIND was not captured.

### Scanning and TCP anomalies

**Get just the open ports.** There is no need to look at every SYN the scanner sent.

```
query_packets(filter: "tcp.flags.syn == 1 and tcp.flags.ack == 1",
              fields: ["frame.number", "ip.src", "tcp.srcport", "ip.dst"])
```

Only the ports that answered with SYN-ACK come back. Measured: a 2,011-packet scan
produced 12 rows covering just three ports (22 / 53 / 80).

**Retransmissions, duplicate ACKs and zero windows come out together.**

```
query_packets(filter: "tcp.analysis.flags",
              fields: ["frame.number", "ip.src", "ip.dst",
                       "_ws.col.Info", "tcp.time_delta"])
```

Line up `tcp.time_delta` to see the retry interval. Measured: 0.206 → 0.6 → 1.2 → 2.4 →
4.8 seconds — **exponential backoff**, which says at a glance that the far end is not
answering.

## Reading the results

- **Always compare `matched` with `returned`.** If `matched` is large and `returned` is
  pinned at the limit, **tighten the filter** rather than raising `limit`. If you only
  wanted a count, `matched` already is the answer
- **Add `_ws.col.Info` as insurance.** It is Wireshark's Info column, and it **often
  carries a resolved operation name even when the typed fields come back empty.** In the
  psexec capture every `svcctl.*` field was blank while Info held
  `OpenSCManagerW request` / `StartServiceW request`; the same goes for `epm` service
  names and TCP's `[TCP Retransmission]`. **When `matched` is non-zero but every field
  is empty, look at Info first**
- **Ask for only the `fields` you need.** Many fields × many rows bloats the result and
  becomes awkward on the client side. Selecting `smb.file` and `smb2.filename` together
  across all SMB packets produced over 60,000 characters in practice
- **A wrong field name returns `invalid_arguments` with `details.invalid_fields`**
  naming the offenders. Read that instead of guessing
- **`limit: 0` exports everything as JSONL.** Hand it to data-toolbox-mcp when you want
  SQL over it (see [client setup](client-setup.md))
- **Use `async: true` on large captures.** Decide from `describe_workspace`'s
  `packet_count` and `file_size`. The server handles requests serially, so a long
  synchronous call blocks everything else

## Handling extracted files

- You get **metadata and a path, never the bytes**. That is deliberate
- Files are stored as `<sha256>.bin`, mode 0600, with no executable bit. The original
  name lives in the manifest
- **The SHA-256 usually finishes the investigation** — it pivots to threat intelligence
  without opening anything
- ⚠️ **With real malware, AV may quarantine the file mid-write**, in which case it lands
  in `skipped` with `operation not permitted` and no hash. That is not a tool bug, and
  the other objects still come back. Read the [field notes](field-notes.md) before
  reaching for an AV exclusion to recover it — it works, and it removes protection

## Pivoting to other MCP servers

Extracted values feed straight into the rest of the series.

| Value | Send it to |
|---|---|
| File SHA-256 | Threat intelligence (VirusTotal and friends) |
| Destination IP | `abuse-lookup` / `asn-lookup` / `tor-exit-lookup` |
| Domain | `whois-lookup` / `doh-lookup` |
| URL | `urlscan-lookup` (private scans by default) |
| MAC address | `mac-lookup` |

## Quick reference for common snags

| Symptom | Fix |
|---|---|
| `matched: 0` when it should be there | Wrong protocol generation (`smb.` vs `smb2.`). Check `protocol_hierarchy` |
| `matched` is non-zero but every field is empty | The typed fields did not populate. Add `_ws.col.Info` |
| `dcerpc.opnum` stays a number and never resolves | The BIND is not in the capture. Do not assert an operation name from the opnum |
| The result is too large to work with | Trim `fields`, tighten the filter, or use `limit: 0` to write a file |
| `invalid_arguments` | Read `details.invalid_fields` |
| `operation not permitted` appears in `skipped` | The host's AV quarantined it. The call still succeeded and the other objects came back. See [field notes](field-notes.md) |
| No `.exe` from `ftp-data` | A tshark limitation. An empty `skipped` proves the dissector never wrote them, so it is not the AV. Use the control-channel query instead |
| `payload_unavailable_truncated_capture` | Small snaplen; the payload was never recorded |
| A call never returns | Use `async: true` |

## See also

- [Sample captures][samples] — the eleven-step walkthrough on synthetic captures
- [Field notes](field-notes.md) — AV behaviour with real malware, and the ftp-data limitation
- [Client setup](client-setup.md) — registering the server and troubleshooting

[samples]: ../../../samples/README.md
