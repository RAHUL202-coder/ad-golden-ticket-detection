# Contribution: Memory-Based Golden Ticket Detection with pypykatz

## Problem
A Golden Ticket is a forged Kerberos TGT. Once injected (Pass-the-Ticket), the attacker appears
as a legitimate privileged user, so log-only detection can be evaded or delayed. A *memory-based*
approach — finding the forged ticket resident in LSASS — provides an independent, corroborating
signal. The project's original design assumed **Volatility 3** would extract the Kerberos tickets
from an LSASS memory dump.

## Finding (the contribution)
**Volatility 3 cannot extract Kerberos tickets from a modern-Windows LSASS dump.** There is no
working Kerberos-ticket plugin in Volatility 3; the pipeline was calling a plugin
(`windows.kerberos.Kerberos`) that does not exist, so every dump silently returned zero tickets and
was scored CLEAN. In effect, the memory-based detection never functioned as originally reported.

**Root cause:** unlike mimikatz/pypykatz — which read the running LSASS process (or its dump)
structures directly with knowledge of the encryption keys — Volatility 3 has no plugin that
reconstructs the Kerberos ticket cache on current Windows Server builds.

## Solution
Switch the memory analysis to **pypykatz** (the Python re-implementation of mimikatz's parsing),
which *can* parse a `comsvcs.dll` LSASS minidump on Windows Server 2022 and export the Kerberos
tickets (`pypykatz lsa minidump -k <dir> <dump>`).

**Detection rule:** a **TGT** (service = `krbtgt`) issued to a **user** account (not a machine
account ending in `$`) found **resident in the Domain Controller's LSASS** = an injected
Pass-the-Ticket **Golden Ticket** → `riskLevel = CRITICAL`, indicator `GOLDEN_TICKET_MEMORY`,
mapped to **MITRE T1558.001**.

## Evidence (live, reproducible)
On a post-attack dump, pypykatz extracted the forged ticket:
`TGT_CORP.LOCAL_Administrator_krbtgt_CORP.LOCAL.kirbi` — a TGT for **Administrator** resident in the
DC's memory. The worker scored it CRITICAL (≈20–23 tickets extracted) and Sentinel raised a
CRITICAL incident (observed: #264, #312). Volatility, on the identical dump, returned CLEAN.

## Why this matters
- It is a genuine, reproducible **negative result about a widely-used tool** (Volatility) plus a
  **working alternative** (pypykatz) — a real methodological contribution.
- The memory signal is **independent of log ingestion**, so it detects the attack even when
  log-based rules are evaded, delayed, or (as in this lab) when the agent is offline.
- It is the differentiator versus log-only SIEM detection.

## Implementation
- Worker: `azure/volatility-worker/worker.py` (`extract_kerberos_pypykatz`), deployed on
  `VolatilityAnalysisVM` as the systemd service `volatility-worker` (pypykatz installed
  system-wide). Volatility 3 is retained only for supporting scans: `mutantscan`, `pslist`,
  `cmdline`.
- Detection rule: `kql/volatility-memory-hit.kql` → Sentinel rule `volatility-high-risk-memory` (PT5M).

## Honest limitation
A dump is only useful if it is captured while the forged ticket is resident. In this lab the ticket
persists in the Administrator logon session, so a capture taken after the attack contains it. In a
short-lived real attack, capture timing matters — noted as future work (event-triggered capture,
Phase 2 of the continuation plan).
