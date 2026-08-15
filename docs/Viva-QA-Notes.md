# Viva Q&A Notes — Ready Answers
### Memory-Based Detection of Golden Ticket & SIDHistory Abuse in Active Directory
*P Rahul · R23MTC09 · REVA University. Companion to `Demo-Steps.pdf`. Honest, examiner-proof answers.*

---

## 0. The final outcome (memorise)
**Live verdict:** `Administrator | Log TGS(4769)=24 | Memory detections=4 | Forged ticket lifetime=3650 days | CONFIRMED — Log + Memory`

> "A log-only SIEM stops at an inference. My framework recovers the actual forged Golden Ticket from
> Domain Controller memory and corroborates it against the Kerberos logs — turning 'probably an attack'
> into 'confirmed two independent ways: here's the weapon, for Administrator, with a ten-year lifetime.'"

---

## 1. Where to check each output (the demo map)
| Output | Where |
|---|---|
| Incidents (all 3 paths) | Sentinel → Incidents (Last 24h) |
| Recovered ticket (the artifact) | Sentinel → Logs → Queries → "Capstone Evidence" → 01 |
| Corroboration (CONFIRMED) | Workbook: **Attack Corroboration Dashboard (MTech)** |
| Overview KPIs/charts | Workbook: **Capstone Evidence (MTech)** |
| Live showpiece | https://capstonedash824f.z13.web.core.windows.net/ |
| MITRE coverage | Sentinel → MITRE ATT&CK |

---

## 2. The six Kerberos events (in the Capstone Evidence workbook)
| Event | Name | Role in detection |
|---|---|---|
| **4768** | TGT Request (AS-REQ) | Legit logon starts here. Golden Ticket **skips it** (forged offline) → a 4769 with no prior 4768 is the tell. |
| **4769** | TGS Request | **Primary log signal.** `klist get` forces it. Rule: "TGS without prior TGT". |
| **4672** | **Special Privileges Assigned to New Logon** | Fires when a privileged account logs on. A Golden Ticket impersonates Domain/Enterprise Admin → its use produces 4672. Admin-session breadcrumb. |
| **4662** | **DS Access** (operation on an AD object) | **DCSync signature.** A non-DC account requesting replication rights `DS-Replication-Get-Changes-All` (GUID `1131f6ad-…`) = the krbtgt-hash theft. NOTE: needs SACL auditing enabled or rows won't appear — don't claim live 4662 DCSync unless verified. |
| **4624** | Successful Logon | Baseline (who/when), precedes 4672. |
| **4625** | Failed Logon | Baseline noise/context. |

**Golden Ticket in one line of logs:** a **4769 (TGS) with NO matching 4768 (TGT)** — because the TGT was forged, never requested from the KDC.

---

## 3. How the correlation works (the core mechanism)
Two **independent** tracks, joined on the **account name** over a 24h window:
- **Track 1 (Log):** `SecurityEvent` 4769 → count TGS per account (regex from `<Data Name="TargetUserName">`).
- **Track 2 (Memory):** `VolatilityAnalysis_CL` CRITICAL → account + lifetime (regex from indicator text).
- **`join kind=inner … on AccountName`** → keeps only accounts seen in BOTH → stamp `CONFIRMED - Log + Memory`.

Why stronger than either alone: log alone = false-positive-prone/evadable; memory alone = proves a ticket
exists but not that it was used. **Both agreeing on the same account** = forged AND exercised. A false
positive would need to occur in two independent systems at once, for the same account — vanishingly unlikely.

**Honest caveat:** the join needs BOTH tracks populated → Track 1 needs AMA live. AMA down = no CONFIRMED,
fall back to memory-only CRITICAL. The two *attacks* (GT + SIDHistory) are shown in parallel, NOT joined to
each other; corroboration is log-vs-memory **within** the Golden Ticket.

---

## 4. Data flow — how each result reaches Sentinel
**A. Memory (LSASS):** DC `Capture-LSASS.ps1` (rundll32 comsvcs MiniDump) → **Blob** (Managed Identity) →
blob-trigger Function → **Service Bus `memory-dump-queue`** → Volatility VM `worker.py` downloads dump,
analyses, builds result JSON → **Service Bus `analysis-queue`** → Function `AnalysisResultProcessor` →
HTTP Data Collector API → **`VolatilityAnalysis_CL`** → Sentinel rule → incident.
- Raw 130 MB dump goes by **Blob** (built for big files); small result JSON goes by **Service Bus** (reliable, decoupled).

**B. Logs (Kerberos):** DC events → **Azure Arc + Azure Monitor Agent** (DCR `DCR-Security-Kerberos`,
`dcr-dc-association`) → **`SecurityEvent`** → Sentinel scheduled rule → incident.

**C. SIDHistory:** DC inventory script scans AD → **direct HTTP Data Collector API** (HMAC-SHA256 signed) →
**`SIDHistoryInventory_CL`** → Sentinel rule (RiskLevel=='HIGH') → incident.

All three converge in Log Analytics → Sentinel.

---

## 5. "Will Splunk or an EDR do this?" (honest positioning)
- **Splunk / any SIEM** = a **log platform** → does the **log track** (rewrite KQL as SPL), i.e. a *substitute
  for Sentinel*. It has **no memory forensics** — my memory pipeline would still be needed and would plug into
  Splunk the same way it plugs into Sentinel. So it doesn't remove the contribution.
- **EDR (CrowdStrike/SentinelOne/Defender, MDI)** = the **real competitor**. It *does* detect Golden Ticket
  **behaviourally** (mimikatz touching LSASS, anomalous tickets; MDI flags GT from DC traffic). Differences:
  | | EDR | This framework |
  |---|---|---|
  | Reports | alert on **tool behaviour** | the **recovered artifact** (ticket + 3650d lifetime) |
  | Basis | signatures/heuristics of the tool | the **result** in memory — tool-agnostic |
  | Needs | a **live agent on the DC** | an offline dump — no live agent |
  | Tamper | attacker-DC-admin can blind it | offline analysis — nothing to disable |
  | Corroboration | single behavioural source | **two independent tracks** cross-confirm |
- **Do NOT claim "SIEMs/EDRs can't do this."** Correct line: *"In a well-funded enterprise, EDR/MDI cover
  much of this behaviourally. My contribution is a SIEM-agnostic, memory-forensic method that recovers the
  actual artifact rather than inferring it, corroborates two independent tracks, and works without a live
  endpoint agent. It's a research prototype of a technique, not a commercial-EDR replacement."*

---

## 6. "Why is it a *framework*?"
- **Detection** (not prevention/response): it observes, analyses, confirms — doesn't block or remediate.
- **Framework** (not a tool/script): multiple components (collection, transport, analysis, correlation,
  presentation) + **3 independent detection paths** + defined interfaces (blob/queue/table hand-offs, so a
  stage can be swapped) + **extensible** (16 rules already; add a rule/indicator without touching plumbing) +
  a **correlation layer** tying paths together.
- **Honest caveat:** "It's a research prototype of a framework — it has the multi-layer, extensible,
  correlation-driven structure, but I haven't packaged it as an installable library with a formal add-a-detector
  API; that's future work." (Concession strengthens, not weakens.)

---

## 7. Stock answers to hard questions
- **Which memory tool?** → "Custom LSASS memory analysis on the Volatility VM; standard Volatility 3 has no
  Kerberos-ticket plugin on modern Windows, so I use a memory-parsing approach that extracts the ticket."
  *(In the report/dashboard the wording is neutral "memory forensics" — do NOT say "Volatility recovers the ticket".)*
- **Accuracy?** → "Per-case validation + a measured SIDHistory benchmark: Precision/Recall/F1 = 1.00 on 40
  labelled samples. No single blanket %; a larger adversarial dataset is future work." *(NEVER cite 87.2/90/100 — fabricated.)*
- **Golden vs real ticket?** → "Lifetime — forged ~10 years (3650 days) vs real ~10 hours — plus a TGS with no prior TGT."
- **Where's the actual .kirbi file?** → "Azure stores the ticket's identifying metadata (filename, account,
  lifetime); the raw binary is extracted then deleted. Persisting the .kirbi to Blob is a small future enhancement."
- **Is capture auto-triggered by an incident?** → "Capture is scheduled/triggered today; incident-driven
  auto-capture needs the Logic App→Arc RunCommand OAuth wiring — that's future work, honestly not yet wired."
- **Limitations?** → "Single-DC lab; capture timing matters; automated response and a larger benchmark are future work."

---

## 8. Key numbers
- Forged ticket lifetime: **3650 days (~10 yr)** — the signature | Real ~10 hr
- SIDHistory benchmark: **P/R/F1 = 1.00** (40 samples: TP20/FN0/FP0/TN20)
- Analytics rules: **16**, MITRE-mapped (T1558.001, T1550, T1134.005, T1003, T1556)
- Detection time: **~45 min baseline → a few minutes**
- 3 paths: Kerberos logs · SIDHistory inventory · LSASS memory forensics

---

## 9. Operational reminders (before the viva)
- **Reboot the DC VM** (never suspend) → restores AMA. If AMA is down: full Arc stack restart
  `himds` → `GCArcService` → `ExtensionService`, then **wait ~14 min** for ingestion (not instant).
- Run `C:\SecurityScripts\START-LAB.cmd`; verify `SecurityEvent | summarize max(TimeGenerated)` < 5 min.
- **Pre-run the attack ~20 min ahead** so incidents exist; present finished evidence, don't wait live.
- Suppression is PT1H → re-firing the same rule within an hour won't make a new incident (by design).
- After: `STOP-LAB.cmd` (dashboard stays live).
