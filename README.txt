================================================================================
  MEMORY-BASED DETECTION OF GOLDEN TICKET & SIDHISTORY ABUSE
  IN ACTIVE DIRECTORY
================================================================================
  A hybrid threat-detection framework on Microsoft Sentinel
  MTech Capstone Project | P Rahul (SRN R23MTC09) | REVA University
================================================================================


--------------------------------------------------------------------------------
 1. OVERVIEW
--------------------------------------------------------------------------------
Golden Ticket and SIDHistory abuse are among the stealthiest attacks against
Active Directory - they let an attacker impersonate a domain administrator and
persist almost invisibly. Traditional log-only SIEM tools can only INFER these
attacks from behaviour, and they never see the forged Kerberos ticket itself,
which resides in the Domain Controller's memory.

This project is a hybrid detection framework built on Microsoft Sentinel that:
  * Detects Golden Ticket and SIDHistory attacks through THREE independent paths
  * Recovers the actual forged Kerberos ticket directly from LSASS memory
  * CORROBORATES the log evidence against the memory artifact to produce a
    confirmed verdict ("CONFIRMED - Log + Memory")

The novel contribution is the memory-forensics path: it recovers the forged
ticket (identifiable by its anomalous ~10-year lifetime) - forensic proof that
log-only tools cannot provide.


--------------------------------------------------------------------------------
 2. ARCHITECTURE - THREE DETECTION PATHS
--------------------------------------------------------------------------------

                    DOMAIN CONTROLLER (corp.local)
        +-------------------+-------------------+---------------------+
        | Kerberos events   | SIDHistory scan   | LSASS memory capture|
        | (4768/4769/...)   | (AD attribute)    | (rundll32 MiniDump) |
        v                   v                   v
   [Azure Monitor       [HTTP Data          [Blob -> Service Bus ->
    Agent + DCR]         Collector API]       Function -> Volatility VM]
        v                   v                   v
   SecurityEvent    SIDHistoryInventory_CL    VolatilityAnalysis_CL
        +-------------------+-------------------+
                            v
             MICROSOFT SENTINEL (16 analytics rules -> incidents)
                            v
       Workbooks + Live Dashboard + Corroboration (Log intersect Memory)


--------------------------------------------------------------------------------
 3. PROJECT STRUCTURE
--------------------------------------------------------------------------------
  kql/                 Detection logic (Sentinel analytics rule queries)
  scripts/             Domain-Controller PowerShell (LSASS capture, SIDHistory)
  function-app/        Azure Functions - the memory pipeline glue
  azure/
    volatility-worker/ The memory-forensics engine (worker.py, runs on the VM)
    workbooks/         Sentinel dashboards (overview + corroboration)
    live-dashboard/    Live cloud SOC dashboard (HTML + Logic App API)
    lab-control/       Start/stop scripts (save cloud credits)
  attack-simulation/   Attack scripts for validation and demo
  diagrams/            Architecture and pipeline diagrams
  docs/                Report and viva materials, benchmark results

  See PROJECT-STRUCTURE (docs) for a file-by-file explanation.


--------------------------------------------------------------------------------
 4. KEY DETECTION LOGIC
--------------------------------------------------------------------------------
  Golden Ticket (log)  : a TGS request (4769) with NO preceding TGT request
                         (4768) = a pre-forged ticket injected into memory.

  Golden Ticket (mem)  : a forged TGT (service = krbtgt) for a user account,
                         resident in LSASS, with lifetime > 365 days.
                         Forged (mimikatz) ~= 3650 days; legitimate ~= 10 hours.

  SIDHistory           : an AD object whose sIDHistory attribute contains a
                         privileged RID (512 Domain Admins, 519 Enterprise
                         Admins, 518 Schema Admins, 520, 544).

  Corroboration        : CONFIRMED = { log-track accounts (4769) } intersect
                         { memory-track accounts (CRITICAL) }.


--------------------------------------------------------------------------------
 5. TECHNOLOGY STACK
--------------------------------------------------------------------------------
  Detection logic      KQL (Kusto Query Language) - Microsoft Sentinel
  DC-side automation   PowerShell
  Memory forensics     Python (on an Ubuntu Azure VM)
  Pipeline glue        Azure Functions (Python)
  Transport            Azure Blob Storage, Azure Service Bus
  Ingestion            Azure Monitor Agent + DCR, HTTP Data Collector API
  Visualisation        Sentinel Workbooks + an HTML/JS live dashboard
  Cloud platform       Microsoft Azure + Azure Arc (for the on-prem DC)


--------------------------------------------------------------------------------
 6. HOW TO RUN
--------------------------------------------------------------------------------
  1. Bring the lab up      : azure/lab-control/START-LAB.cmd
  2. Run an attack         : attack-simulation/Run-GoldenTicketAttack.ps1
  3. Watch detection       : Sentinel -> Incidents; VolatilityAnalysis_CL table;
                             the Attack Corroboration workbook
  4. Stop to save credits  : azure/lab-control/STOP-LAB.cmd


--------------------------------------------------------------------------------
 7. RESULTS
--------------------------------------------------------------------------------
  * Three detection paths converge into Microsoft Sentinel incidents.
  * Corroboration verdict: the same account confirmed by both the log track and
    the memory track (CONFIRMED - Log + Memory), with the recovered forged
    ticket showing a ~10-year lifetime.
  * SIDHistory detector benchmark: Precision / Recall / F1 = 1.00, zero false
    positives, on 40 labelled samples (20 malicious, 20 benign).
  * End-to-end detection completes in a few minutes, versus a ~45-minute
    manual baseline.

  MITRE ATT&CK coverage: T1558.001 (Golden Ticket), T1550 (Pass the Ticket),
  T1134.005 (SID-History Injection), T1003 (LSASS Credential Access).


--------------------------------------------------------------------------------
 8. NOTES / LAB CONSTRAINTS
--------------------------------------------------------------------------------
  * The RC4-downgrade rule is deployed but does not fire in a single-Domain-
    Controller lab (the DC's AES keys override for local services).
  * Automated detection, triage, and visualisation are fully implemented.
    Automated response actions (notification / auto-capture) are scaffolded and
    require interactive authorization - documented as future work.


================================================================================
  Author: P Rahul (R23MTC09), REVA University
================================================================================
