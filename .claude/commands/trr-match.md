# TRR Matcher

Given a threat intelligence article (URL or pasted text), identify which TRR
procedures are relevant and surface the emulation tests a defender can run to
verify coverage.

## Input

`$ARGUMENTS` is either:
- A URL to a threat intelligence article, **or**
- The full text of an article pasted directly

---

## Step 1 — Ingest the article

If `$ARGUMENTS` looks like a URL (starts with `http://` or `https://`), fetch
it with WebFetch. Use this prompt when calling WebFetch:

> "Extract the complete technical content of this threat intelligence article.
> Preserve all attack technique descriptions, tool names, commands, MITRE
> ATT&CK technique IDs, and observable behaviors. Do not summarize — return
> the full relevant text."

If `$ARGUMENTS` is plain text, use it directly.

---

## Step 2 — Extract attack techniques from the article

Read the article carefully and produce a structured list of every attack
technique, behavior, or tactic described. For each item capture:

- **Description**: what the attacker did or what capability is described
- **ATT&CK IDs**: any explicit T####.### identifiers mentioned in the article
- **Tool/malware names**: if specific tools are named (e.g. Mimikatz, Cobalt
  Strike, impacket)
- **Platform**: what platform the technique targets (Windows, Active Directory,
  Azure, Linux, macOS, etc.)
- **Tactic**: the attack phase (Initial Access, Execution, Persistence,
  Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral
  Movement, Collection, Exfiltration, Impact, etc.)

Be thorough — extract every distinct technique, even if described briefly.
Include both explicitly-named techniques and behaviors that imply a technique
(e.g. "the attacker dumped LSASS memory" implies credential dumping).

---

## Step 3 — Load TRR data

Read these two files from the repository:

1. `index.json` — TRR metadata: names, tactics, platforms, external ATT&CK
   IDs, and procedure summaries
2. `tools/procedure_extraction/procedures.json` — procedure-level detail
   including emulation test IDs (Atomic Red Team test references)

---

## Step 4 — Match article techniques to TRRs

For each technique identified in Step 2, find matching TRRs using these
criteria in order of confidence:

### High confidence (exact match)
- An ATT&CK ID from the article matches a TRR's `external_ids` field

### Medium confidence (strong semantic match)
- The behavior described in the article closely matches the TRR name or
  procedure titles (e.g. "dumped the NTDS.dit" → TRR0015 "Stealing Credentials
  from the NTDS.dit")
- The tactic and platform both align

### Low confidence (inferred)
- The article implies behavior that could map to a TRR but is not explicitly
  described (e.g. lateral movement observed but method unclear)

When multiple TRRs could apply, list all of them. Do not discard any
reasonable match.

---

## Step 5 — Build the results

For each matched TRR, look up its procedures in `procedures.json`. For each
procedure, note whether an emulation test is available (non-empty `Test ID`).

---

## Step 6 — Output

Print a structured report in this format:

---

### Threat Intel TRR Match Report

**Source:** [article title or URL]
**Article summary:** [1–2 sentence description of the attack described]
**Techniques identified:** [count]
**TRRs matched:** [count]

---

#### Matched TRRs

For each matched TRR, print a block like this:

```
TRR#### — [TRR Name]
  ATT&CK: [external_ids]   Tactic: [tactics]   Platform: [platforms]
  Match confidence: High / Medium / Low
  Reason: [brief explanation of why this TRR was matched to the article]

  Procedures:
    [ProcedureID]  [Procedure Title]
      Tests: [Test IDs if any, or "No emulation tests linked"]
    ...
```

---

#### Coverage Summary

| Coverage | Count |
|----------|-------|
| Techniques identified in article | N |
| TRRs matched | N |
| Procedures with emulation tests | N |
| Procedures without emulation tests | N |

---

#### Recommended Tests

List every procedure that has an emulation test linked, grouped by TRR, with
a plain-English description of what the test exercises and why it is relevant
to the article. This is the actionable output a defender uses to verify
coverage.

Format:

```
[ProcedureID] — [Procedure Title]
  Tests: [Test IDs]
  Why it matters: [1 sentence connecting this test to what the article describes]
```

---

#### Gaps

List any article techniques that could not be confidently mapped to a TRR.
These represent coverage gaps in the TRR library or areas needing further
research.

---

> **Note:** TRR procedures describe distinct execution paths for a technique.
> Running the linked emulation tests verifies whether your detection stack
> can observe that specific execution path. A procedure with no linked test
> does not mean it is undetectable — it means no pre-built test has been
> linked yet.
