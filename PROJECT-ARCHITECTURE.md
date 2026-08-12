# Project Architecture & Detection Flow — MTech Capstone
### Memory-Based Detection of Golden Ticket and SIDHistory Abuse in Active Directory
**Student:** Rahul · MTech, Information Security
**Document purpose:** Authoritative architecture + detection-flow reference (upload to Claude web Project knowledge).
**Last verified:** 2026-06-27 (live end-to-end simulation; AMA auto-upgraded to v1.43.0.0).

---

## 1. Executive Summary

This project is a **hybrid detection framework** for two of the most dangerous Active Directory
attacks — **Golden Ticket** (Kerberos forgery) and **SIDHistory abuse** (stealthy privilege
escalation). It combines two detection layers:

1. **Layer 1 — Log-based behavioural analytics** in Microsoft Sentinel (KQL rules over Kerberos events).
2. **Layer 2 — On-demand memory forensics** using Volatility 3, automatically triggered when Layer 1
   raises suspicion, to confirm forged-ticket artefacts that exist only in LSASS memory.

**Core insight:** A Golden Ticket forged offline and injected via `kerberos::ptt` never contacts the
KDC, so it generates **no EventID 4768 (TGT request)**. Naive log rules that watch for TGT anomalies
miss it. But the moment the ticket is *used*, it produces a real **EventID 4769 (service-ticket
request)**. The framework keys on that footprint (4769 with no 4768) and then confirms it in memory.

---

## 2. Architecture Diagram (logical)

```
┌──────────────────────────────────────────────────────────────────────────┐
│ DOMAIN CONTROLLER  —  WIN-09GD99A8DPG.corp.local (Azure Arc-connected)      │
│                                                                            │
│   Kerberos activity ──► Security Event Log (4768 / 4769 / 4672 / 4624 ...)  │
│   LSASS memory (lsass.exe)                                                  │
│   PowerShell: SIDHistory inventory scan                                     │
└───────────────┬─────────────────────────────┬──────────────────────────────┘
                │                             │
   Azure Monitor Agent v1.43          SIDHistory-Inventory.ps1
   + DCR-Security-Kerberos            (HTTP Data Collector API)
                │                             │
                ▼                             ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ MICROSOFT SENTINEL  —  Log Analytics workspace HybridDetectionWS            │
│   SecurityEvent table  ◄── Kerberos events                                  │
│   SIDHistoryInventory_CL ◄── SIDHistory scan (custom log)                   │
│   VolatilityAnalysis_CL  ◄── memory forensics results (custom log)          │
│                                                                            │
│   16 ANALYTICS RULES  (3 NRT + 13 Scheduled)  ──►  INCIDENT                 │
└───────────────┬────────────────────────────────────────────────────────────┘
                │ incident created
                ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ AUTOMATED RESPONSE  —  Logic App: SentinelResponsePlaybook                  │
│   (1) Email alert to analyst                                               │
│   (2) Arc Run Command ──► Capture-LSASS.ps1 on the DC                      │
└───────────────┬────────────────────────────────────────────────────────────┘
                │ LSASS dump (.dmp)
                ▼
   Blob Storage (memorydumps...) ──► Azure Function (GoldenTicketProcessor2)
                                          │  LsassDumpTrigger
                                          ▼
                                  Service Bus  (memory-dump-queue)
                                          │
                                          ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ MEMORY FORENSICS  —  VolatilityAnalysisVM (Ubuntu, Standard_D2s_v3)         │
│   Volatility 3 plugins: windows.lsadump · malfind · pslist · netscan        │
│   Risk score (CRITICAL / HIGH / MEDIUM)                                      │
└───────────────┬────────────────────────────────────────────────────────────┘
                │ risk-scored JSON (AnalysisResultProcessor)
                ▼
   Sentinel  —  VolatilityAnalysis_CL ──► "Volatility Memory - High Risk" rule
                                          ──► ENRICHED INCIDENT (with memory evidence)
```

---

## 3. Deployed Azure Infrastructure (current)

| Component | Name / Value | Notes |
|---|---|---|
| Subscription | `8e710d8c-465e-4d5f-92ac-800e9c7abe1a` | Azure subscription 1 |
| Tenant | `cbd3eca8-6681-4a7a-95d3-ccfc8d7a1702` | |
| Resource Group | `HybridDetectionRG` | eastus |
| Log Analytics / Sentinel | `HybridDetectionWS` | Workspace ID `44739274-3306-42bc-abd8-e225a057a325` |
| Domain Controller (Arc) | `WIN-09GD99A8DPG.corp.local` | Domain `corp.local`, SID `S-1-5-21-3406634861-1234809508-3516503270` |
| Azure Monitor Agent | `AzureMonitorWindowsAgent` **v1.43.0.0** | Arc-managed processes; NO Windows service |
| Data Collection Rule | `DCR-Security-Kerberos` | Immutable ID `dcr-2e742bc9709f41b3b19ee1ffee100812`; assoc. `DCR-DC-Association` |
| Storage (LSASS) | `memorydumps202606122126` | Containers: artifacts, kerberos-logs |
| Storage (SIDHistory) | `sidhistory202606122126` | Container: sidhistory-logs |
| Service Bus | `HybridDetSB-8e710d8c` | Queues: memory-dump-queue, analysis-queue |
| Volatility VM | `VolatilityAnalysisVM` | westus2, Ubuntu, **dynamic public IP** (changes each start) |
| Function App | `GoldenTicketProcessor2` | Python 3.11, consumption plan |
| Logic App (playbook) | `SentinelResponsePlaybook` | Sentinel incident trigger; MSI has Arc Run Command role |
| Workbook | `AD Attack Detection Dashboard` | ID `8ea475c4-ee9f-413d-bd89-c74ff1902dcd` |
| Automation rules | `auto-triage-golden-ticket`, `auto-triage-sidhistory` | Auto-label incidents |

**DCR collects (xpath):** EventIDs `4768, 4769, 4672, 4624, 4625, 5136, 4662, 4723, 4724, 4741, 4742`
into the `Microsoft-SecurityEvent` stream.

---

## 4. Detection Rules (16 total: 3 NRT + 13 Scheduled)

### Near-Real-Time (fire ~every 1 min)
| Rule ID | Display Name | MITRE |
|---|---|---|
| gt-rc4-downgrade-nrt | Golden Ticket — RC4 Encryption Downgrade (NRT) | T1558.001 |
| gt-service-enum-nrt | Golden Ticket — Rapid Service Enumeration (NRT) | T1046, T1558 |
| sidhistory-high-risk-sid-nrt | SIDHistory — High Risk SID Entry (NRT) | T1134.005 |

### Scheduled
| Rule ID | Freq | MITRE |
|---|---|---|
| gt-ptt-detection | PT5M | T1550, T1558 |
| gt-aes-golden-ticket | PT15M | T1558 |
| gt-pass-the-hash | PT30M | T1550 |
| gt-skeleton-key | PT1H | T1556 |
| gt-indirect-indicators | PT2H | T1558, T1069 |
| sidhistory-delta-detection | PT5M | T1134 |
| sidhistory-privileged-logon-correlation | PT5M | T1134, T1078 |
| dc-sync-detection | PT5M | T1003.006 |
| krbtgt-password-reset | PT5M | T1098 |
| kerberoasting-detection | PT5M | T1558.003 |
| asrep-roasting-detection | PT5M | T1558.004 |
| honey-account-alert | PT5M | T1078 |
| volatility-high-risk-memory | PT30M | T1003, T1055 |

---

## 5. How the Golden Ticket Detection Works (in detail)

### 5.1 The attack
1. Attacker obtains the `krbtgt` account NTLM hash (via DCSync / domain compromise).
2. Using the hash, forges a **TGT offline** for any user (e.g. Administrator) — **no KDC contact, no 4768.**
3. Injects the forged TGT into the current session (`kerberos::ptt`).
4. Uses it to request service tickets and access resources.

### 5.2 The detectable footprint
- Forging/injection = invisible (no 4768).
- **Using** the ticket = the client sends a TGS-REQ to the KDC → DC logs **EventID 4769.**
- Result: an account with **4769 service-ticket requests but no preceding 4768 TGT request.**
- A legitimate user is always `4768 → 4769`. A Golden Ticket user is `4769` with **no 4768.**

### 5.3 The KQL logic (gt-aes-golden-ticket / gt-ptt-detection)
```kql
SecurityEvent
| where EventID in (4768, 4769)
| extend AccountName = coalesce(
    tostring(extract(@'<Data Name="TargetUserName">([^<]+)<', 1, EventData)),  // AMA stores EventData as XML
    tostring(extract(@'Account Name:\s+(\S+)', 1, EventData)))
| summarize TGTCount = countif(EventID == 4768),
            TGSCount = countif(EventID == 4769) by AccountName, bin(TimeGenerated, 15m)
| where TGSCount > 0
| extend Ratio = iff(TGTCount == 0, todouble(999), TGSCount * 1.0 / TGTCount)
| where Ratio > 5 or TGTCount == 0
```
A `Ratio = 999` (TGTCount = 0) is the unambiguous Golden Ticket signature.

### 5.4 Memory confirmation (the novelty)
When any Kerberos anomaly fires, the Logic App auto-captures an LSASS dump and Volatility 3
(`windows.lsadump`, `malfind`) searches memory for the forged-ticket artefact — evidence that logs
alone cannot provide. This is what differentiates the framework from log-only tools (e.g. Microsoft
Defender for Identity), which rely on event-log heuristics.

---

## 6. How the SIDHistory Detection Works

- Attack: inject a privileged SID (Domain Admin RID-512, Enterprise Admin RID-519, Schema Admin
  RID-518) into a normal account's `SIDHistory` attribute → silent admin inheritance.
- Audit events 4765/4766 can be evaded, so detection does **not** rely on them.
- Instead, a scheduled PowerShell job enumerates **all** SIDHistory attributes domain-wide and writes
  to `SIDHistoryInventory_CL`; rules flag any privileged SID. **Inventory-based detection works even
  when audit logging is bypassed** — this is the SIDHistory novelty.

---

## 7. End-to-End Flow (step by step)

1. DC generates Kerberos events → **AMA v1.43 + DCR** stream them to `SecurityEvent`.
2. **16 Sentinel rules** evaluate continuously (NRT ~1 min; scheduled PT5M–PT2H).
3. Threshold crossed → **Incident** created, auto-labeled by automation rule.
4. **Logic App playbook** runs: emails analyst + **Arc Run Command → Capture-LSASS.ps1.**
5. LSASS dump → **Blob** → **Function App** → **Service Bus** queue.
6. **Volatility VM** dequeues, runs plugins, computes risk score → posts JSON back.
7. Result lands in `VolatilityAnalysis_CL` → **enriched incident** with memory evidence.

---

## 8. Performance / Results

| Metric | Value |
|---|---|
| Detection time (before improvements) | ~45 min |
| Detection time (after improvements, measured) | **~2 min** |
| Detection accuracy (measured) | **87.2%** (honest figure — NOT 100%) |
| Rules | 16 (3 NRT + 13 scheduled), full MITRE mapping |

**Detection-time improvements:** PT5M rule frequency + suppression; parallel blob upload
(`--max-connections 4`, 3 min → 1 min); event-triggered LSASS capture (0–240 min → ~5 sec).

### Latest validated run — 2026-06-27
- Golden Ticket: 10× 4769 / 0× 4768 → 3 alerts (PTT, AES Ratio:999, Rapid Service Enum) → incident #130.
- SIDHistory: 3 HIGH-risk injections → incidents #135, #136.
- LSASS dumps captured automatically (`lsass_20260627-*.dmp`).
- **Operational note:** after the lab sits idle for days, the Arc-managed AMA goes dormant; the DCR
  association still shows green but event forwarding lags the heartbeat. Always wait ~3–5 min after
  Resume (until live SecurityEvents appear) before attacking.

---

## 9. Lab Constraints (document as constraints, NOT bugs)

1. **RC4 TGS not generated in single-DC lab** — the DC's own AES-256 keys override TGS issuance for
   local services. In production (attacker on a separate host) the TGS would be RC4. The
   `gt-rc4-downgrade` rule is valid for real deployments.
2. **SIDHistory audit events 4765/4766 empty** — mimikatz `sid::patch` is incompatible with the
   current Server 2022 patch level. This is *why* inventory-based detection is used and is more resilient.
3. **Volatility may report CLEAN** — if the attack session ends before the auto-dump is taken, the
   artefact is already gone. A timing constraint of automation, not a detection gap.
4. **Same-domain SIDHistory injection OS-blocked** — Windows blocks it via the NTDS API; simulated via
   direct Log Analytics record injection. Real attacks use cross-domain trusts.

---

## 10. Honest Claims Guidance (for report/viva)

- Accuracy is **87.2% measured** — never claim 100%.
- Do **not** say "a Golden Ticket is invisible to all log analysis." Correct framing: the *forging* is
  invisible (no 4768); *using* the ticket generates a real 4769; naive log rules miss it, behavioural
  rules catch the absence pattern, and memory forensics confirms it.
- Distinguish **real telemetry** (the Golden Ticket 4769 events) from the **simulated shortcut** (the
  SIDHistory records injected directly into Log Analytics).

---

## 11. MITRE ATT&CK Coverage

T1558 (Golden Ticket; .001 RC4, .003 Kerberoasting, .004 AS-REP) · T1550 (Pass-the-Ticket / Pass-the-Hash)
· T1134.005 (SIDHistory) · T1003.006 (DCSync) · T1556 (Skeleton Key) · T1098 (krbtgt reset) ·
T1078 (Valid Accounts / honey accounts) · T1046, T1069 (discovery) · T1055 (process injection, memory).
