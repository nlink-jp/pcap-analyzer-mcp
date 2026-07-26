# ADR-0001: Choose tshark as the analysis backend

- Status: Accepted
- Date: 2026-07-26
- Driver: magi
- Generalises to: none

---

## Context

There are two realistic backend choices for analyzing pcap / pcapng files.

**tshark** (the Wireshark CLI):

- Display filters (`ip.addr == 10.0.0.1 && tcp.flags.syn == 1 && !tcp.analysis.retransmission`) are the de facto shared vocabulary of network analysis
- Over 3000 dissectors, covering even niche protocols
- Installs from a single Debian package; its `wireshark-common` dependency also brings `capinfos` / `editcap` / `mergecap` / `text2pcap`
- Output is unstructured, and `-T fields` / `-T ek` field names and `-z` statistic formats drift between versions

**Zeek**:

- `conn.log` / `dns.log` / `http.log` / `ssl.log` are tabular from the start and can be fed straight into SQL. This is also the standard log set in IR practice
- Installation is heavy, and once the scripting framework is included it no longer fits this project's "lean child-process dependency" stance

The primary consumer of this tool is an LLM agent. Agents already know display filter syntax (it is abundant in training data) but are relatively unfamiliar with Zeek's log schemas and scripting language. That asymmetry directly affects first-attempt success rate.

## Decision

**tshark is the sole backend for v1.**

- All analysis is delegated to tshark / capinfos inside the container (ADR-0003)
- `query_packets` and `list_conversations` accept a **display filter string directly from the agent** and pass it to tshark
- Zeek is **deferred**, not rejected. If it is needed later, the aggregation-style tools (`protocol_hierarchy`, `list_conversations`) could be re-implemented on top of Zeek logs

## Consequences

**Positive:**

- The agent's existing display filter knowledge transfers directly. No need to teach the syntax in tool descriptions
- A single package also provides `capinfos` (metadata), `mergecap` (joining split captures), and `editcap`, so features can grow without new dependencies
- Wireshark's dissector coverage extends the reach to niche protocols and pre-encryption application layers

**Negative:**

- **Display filters are tshark-specific syntax, and putting them in the tool's arguments couples the API tightly to tshark.** If Zeek is later added as a second backend, `query_packets(filter=...)` cannot stay argument-compatible. Realistically it would mean "new Zeek-derived tools" rather than "swapping the backend of the same tool". This ADR accepts that possibility in exchange for the first-attempt success rate available today
- Version-to-version output drift remains. That is addressed separately by pinning the version inside a container (ADR-0003)
- Zeek's "semantically interpreted per-session logs" must be assembled by hand. `list_conversations` covers part of that role

## See also

- ADR-0003: Lean tshark-only image and digest pin
- RFP §3 Design Decisions
