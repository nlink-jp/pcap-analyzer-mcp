# Field notes — analysing captures that carry real malware

> Date: 2026-07-26

What happens with **real malicious captures** and not with the synthetic ones under
`samples/`.

Source of the measurements: the five exercise pcaps from Unit 42's "Using Wireshark:
Exporting Objects from a pcap", analysed with v0.1.0 on 2026-07-26. All four of
HTTP / SMB / IMF / FTP-DATA were exercised.

## 1. Antivirus quarantine shows up as skipped objects

### Symptom

Run `extract_objects` against a pcap carrying real malware and some objects come back
under `skipped` instead of `objects`:

```json
{
  "source_name": "Invoice&MSO-Request.doc",
  "bytes": 60416,
  "reason": "could not be read (open /.../_raw/Invoice&MSO-Request.doc: operation not permitted) — on a host running antivirus this is normally the sample being quarantined mid-write, which is a true positive"
}
```

`operation not permitted` is EPERM. It is not a permission bug or a path-validation
problem in this server: **the host's AV grabbed and quarantined the file mid-write.**

Measured on macOS (Darwin 25.5) with Intego VirusBarrier real-time protection,
tshark 4.0.17.

> **v0.1.0 and v0.1.1 failed the whole call instead**, with code `analysis_failed`. In the
> first exercise pcap 2 of 3 objects were detected (`Invoice&MSO-Request.doc` and
> `knr.exe`) and nothing came back at all — not even the benign `ncsi.txt` — and `_raw`
> was rolled back, so there was nothing left to inspect either. Writing up this note is
> what identified it as a defect: over-size objects were already being skipped and
> recorded, and unreadable ones should have been too. Fixed since.

What this costs you is **the quarantined object only**: no SHA-256, because the bytes
were never readable. The rest of the extraction is unaffected.

### Why it happens

Exactly as ADR-0007's threat 2 predicted. What `--export-objects` emits is "a file
that might be malware", and writing it onto the user's Mac makes an AV reaction
**correct behaviour, not a malfunction**. The file really is malware, so this is a
**true positive**, not a false one.

### What defang does and does not address

Defanging (`<sha256>.bin`, mode 0600, no executable bit) lowers two risks, and AV
detection is **not** among them.

| What defang addresses | How |
|---|---|
| **Accidental execution** | Stored 0600 with no executable bit |
| **A filename that is itself an attack** | A name off the wire never reaches a path. tshark actually wrote `object1.text%2fplain`, which is directory traversal once decoded |

AV matches **content signatures, not filenames or extensions**, so renaming to
`<sha256>.bin` changes nothing about detection. And preventing that detection **is not
a goal**: suppressing a true positive would be evasion. "Defang is not an AV
countermeasure" means exactly that — not that the defang design falls short.

### Telling it apart

| Observation | Meaning |
|---|---|
| The same operation succeeds completely on a capture with only benign objects | The tool, podman and path config are fine — rule them out |
| EPERM only on captures carrying executables or documents | Usable as a signal that **the sample is genuine** |
| The filename in `source_name` matches the one in the AV's notification or quarantine log | Confirmed; no need to guess |

The `reason` always names a file under `_raw/`, which distinguishes this from a genuine
tool failure (`container_failed` when podman is not running, `path_not_allowed`).

### Excluding the workspace from AV, and the risk that brings

**Reach for this only if you need the quarantined object's own hash or bytes.** Since
the readable objects now come back regardless, most investigations do not need it at
all — and the skip list is itself a finding, because AV only fires on something real.

If you do need it, the workaround is to **add the workspace directory to the AV's
exclusion list**. This is a deliberate removal of protection, so choose it knowing
the cost.

⚠️ The moment the exclusion is in place:

- **Live malware written there stays unquarantined**
- Everything subsequently placed there is outside AV protection, including files that
  have nothing to do with the analysis
- Defang still applies, but what it covers is **accidental execution and filename-borne
  attacks** — the sample itself is not neutralised. Removing the AV layer leaves the
  defence genuinely thinner

Rules to hold to:

- Exclude **one disposable analysis-only directory**. Never the home directory or a
  whole project root
- When the analysis is done, **delete the extracted objects and restore the exclusion
  setting**
- Do not leave the exclusion in place indefinitely. Wanting to make it permanent is a
  sign the work belongs in the dedicated environment below

### Recommended: do not analyse on the host

The right answer is to run the analysis pipeline in a **disposable environment with no
AV** — a dedicated VM or a CI container.

- Nothing collides with AV
- Live samples never land in the user's day-to-day environment
- No permanent hole has to be opened in the host's protection

Reserve running it on the host Mac for quick interactive investigation, and follow the
rules above even then.

## 2. `ftp-data` does not export binary RETR transfers

### Symptom

On a capture where five malware executables are pulled down over FTP,
`extract_objects(protocol: "ftp-data")` returns **none of the `.exe` files**. Only the
ASCII-mode `STOR` from the same capture (the stolen-credential HTML log) comes out.

### What was ruled out

It is a limitation of tshark 4.0.17's ftp-data dissector:

- **Not AV quarantine** — re-running inside the AV-excluded path above gives the
  identical result (still one object)
- **Not this server** — the Wireshark GUI behaves the same way, and the Unit 42 article
  itself tells readers to use Follow TCP Stream → Save as Raw for the executables

### Working around it

When the bytes are not required, **metadata alone answers most of the investigation**:

```
query_packets(filter: "ftp.request.command or ftp.response.code",
              fields: ["ftp.request.command", "ftp.request.arg",
                       "ftp.response.code", "ftp.response.arg"])
```

That yields filenames, transfer direction (`RETR` / `STOR`), sizes (the `213` response
to `SIZE`) and credentials (`USER` / `PASS` travel in the clear). In the measured run
this recovered the names and exact byte sizes of all five executables.

When the bytes are required, get the data connection's stream index from
`list_conversations` and page through it with `follow_stream`.

## See also

- [Tips](tips.md) — the user-facing guide to running an investigation; its "handling extracted files" section points here
- [ADR-0007: Payload safety](../adr/0007-payload-safety.md) — threat 2 (writing live malware) and the defang design
- [Client setup](client-setup.md) — troubleshooting table
- [Architecture](architecture.md) — trust boundaries and the security model
