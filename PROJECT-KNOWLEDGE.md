# Project Knowledge — MTech Capstone (upload this to the Claude web Project)

> Single-file context for the project. Upload this into the Claude web Project's
> "Project knowledge" so web-Claude has the same understanding as the local setup.

---

## 1. Identity
- **Title:** Memory-Based Detection of Golden Ticket and SIDHistory Abuse in Active Directory
- **Student:** Rahul — MTech, Information Security
- **Status:** All phases complete. End-to-end simulations validated (2026-06-08, 2026-06-12, 2026-06-23). Report writing in progress.

## 2. The Problem (the intellectual core)
A Golden Ticket forged offline and injected straight into memory via `kerberos::ptt`
**never contacts the Domain Controller** — so it generates **no EventID 4768**.
Log-only SIEM tools (incl. Microsoft Defender for Identity) are therefore blind to it.
The forged ticket exists only in **LSASS memory**.

## 3. The Solution / Novelty
A **hybrid detection framework**:
- **Layer 1 — Sentinel KQL analytics** for behavioural Kerberos detection (suspicion).
- **Layer 2 — automated Volatility 3 memory forensics** that fires on any Kerberos
  anomaly, captures an LSASS dump, and confirms the forged-ticket artefact in memory (proof).
- **SIDHistory novelty:** detected via **inventory scanning** of all SIDHistory
  attributes (flagging privileged DA/EA/SA RIDs) — resilient even when audit events
  4765/4766 are evaded.

## 4. Pipeline (data flow)
```
Domain Controller (corp.local)
  -> Azure Monitor Agent (v1.42, Arc-managed) + DCR-Security-Kerberos
  -> Microsoft Sentinel (HybridDetectionWS) — 16 analytics rules (3 NRT + 13 scheduled)
  -> Sentinel Incident
  -> Logic App playbook (SentinelResponsePlaybook): email + Arc Run Command
  -> Automated LSASS dump -> Blob Storage
  -> Azure Function (GoldenTicketProcessor2) -> Service Bus queue
  -> Volatility 3 VM (Ubuntu): lsadump / malfind / pslist / netscan
  -> Risk-scored JSON -> back into Sentinel (enriched incident)
```

## 5. Key Results
| Metric | Value |
|---|---|
| Detection time | **~45 min -> ~2 min (measured)** |
| Detection accuracy | **87.2%** (honest measured figure — NOT 100%) |
| Rules | 16 total (3 NRT + 13 scheduled), mapped to MITRE ATT&CK |
| Latest validated run | 2026-06-23, 17:13-17:32 IST — 6 incidents (GT + SIDHistory), playbook succeeded |

Detection-time improvements: PT5M rule frequency, parallel blob upload
(`--max-connections 4`), and event-triggered LSASS capture (vs fixed schedule).

## 6. MITRE ATT&CK Coverage
T1558 (Golden Ticket, .001 RC4 / .003 Kerberoasting / .004 AS-REP),
T1550 (Pass-the-Ticket / Pass-the-Hash), T1134.005 (SIDHistory),
T1003.006 (DCSync), T1556 (Skeleton Key), T1098 (krbtgt reset), T1078 (honey accounts).

## 7. Lab Constraints (document as constraints, NOT bugs)
1. **RC4 TGS not generated in single-DC lab** — DC's own AES-256 keys override TGS
   for local services. In production (attacker on separate host) the TGS would be RC4.
2. **SIDHistory audit events 4765/4766 empty** — mimikatz `sid::patch` incompatible
   with current Server 2022 patch level. This is *why* inventory-based detection exists
   and is more resilient.
3. **Volatility CLEAN** — attack session ended a few minutes before the auto-dump.
   A timing constraint of automation, not a detection gap. Persistent attacks leave artefacts.
4. **Same-domain SIDHistory injection OS-blocked** — Windows blocks it via the NTDS API;
   simulated via direct Log Analytics record injection. Real attacks use cross-domain trusts.

## 8. Outstanding Items
- Abstract still claims 100% accuracy — **correct to 87.2% before submission.**
- Reconcile README (says 11 rules / old subscription) with current 16-rule state.

## 9. What I need help with
Writing/refining the final report, viva preparation, interpreting Sentinel incidents,
tuning KQL rules, and documenting architecture honestly (lab constraints vs real-world).

---
*Note: the live Azure infrastructure, scripts, and 16 deployed rules run on the lab PC
and in Azure — not in this web Project. This file is the portable context summary.*
