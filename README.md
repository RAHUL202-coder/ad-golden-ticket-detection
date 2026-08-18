<div align="center">

# 🎫 Memory-Based Detection of Golden Ticket & SIDHistory Abuse

### A hybrid, memory-forensic threat-detection framework for Active Directory, built on Microsoft Sentinel

<br>

[![Platform](https://img.shields.io/badge/Platform-Microsoft%20Azure-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white)](https://azure.microsoft.com/)
[![SIEM](https://img.shields.io/badge/SIEM-Microsoft%20Sentinel-0078D4?style=for-the-badge)](https://learn.microsoft.com/azure/sentinel/)
[![Detection](https://img.shields.io/badge/Memory%20Forensics-LSASS-2E7D32?style=for-the-badge)](#-detection-logic)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1558.001%20%7C%20T1134.005-C1272D?style=for-the-badge)](https://attack.mitre.org/)

[![Detection Paths](https://img.shields.io/badge/Detection%20Paths-3%20Independent-44CC11?style=for-the-badge)](#-architecture--three-detection-paths)
[![Analytics Rules](https://img.shields.io/badge/Sentinel%20Rules-16%20Deployed-1E88E5?style=for-the-badge)](#-detection-logic)
[![Benchmark](https://img.shields.io/badge/SIDHistory%20P%2FR%2FF1-1.00-8E24AA?style=for-the-badge)](#-results--validation)

[![Last commit](https://img.shields.io/github/last-commit/RAHUL202-coder/ad-golden-ticket-detection?style=for-the-badge)](https://github.com/RAHUL202-coder/ad-golden-ticket-detection/commits)
[![Language](https://img.shields.io/badge/Built%20with-KQL%20·%20Python%20·%20PowerShell-2b7489?style=for-the-badge)](#-tech-stack--azure-components)

<br>

**Built with:** Microsoft Sentinel · Azure Monitor Agent + DCR · Log Analytics · KQL · Azure Functions · Azure Service Bus · Azure Blob Storage · Logic Apps · Python memory forensics · PowerShell / LDAP

</div>

<br>

> [!NOTE]
> **The novel contribution is the memory-forensics path.** It recovers the *actual forged Kerberos ticket* directly from Domain Controller LSASS memory — identifiable by its anomalous **~10-year (3650-day) lifetime** — producing forensic proof that log-only SIEM tools cannot provide. Where traditional detection can only *infer* an attack from behaviour, this framework corroborates the log evidence against the memory artifact to reach a **`CONFIRMED — Log + Memory`** verdict.

---

## 📑 Table of Contents

- [Overview](#-overview)
- [Architecture — Three Detection Paths](#-architecture--three-detection-paths)
- [What Makes This Different](#-what-makes-this-different)
- [Results & Validation](#-results--validation)
- [MITRE ATT&CK Mapping](#-mitre-attck-mapping)
- [Tech Stack & Azure Components](#-tech-stack--azure-components)
- [Repository Structure](#-repository-structure)
- [Deployment Overview](#-deployment-overview)
- [Detection Logic](#-detection-logic)
- [Scope & Limitations](#-scope--limitations)
- [Author](#-author)

---

## 🔍 Overview

Golden Ticket and SIDHistory abuse are among the stealthiest attacks against Active Directory — they let an attacker impersonate a domain administrator and persist almost invisibly. Traditional log-only SIEM tooling can only **infer** these attacks from behaviour; it never observes the forged Kerberos ticket itself, which resides in the Domain Controller's memory.

This project is a **hybrid detection framework** on Microsoft Sentinel that:

- Detects **Golden Ticket** (`T1558.001`) and **SIDHistory injection** (`T1134.005`) through **three independent detection paths**
- **Recovers** the forged Kerberos ticket directly from LSASS memory via offline memory forensics
- **Corroborates** the log evidence against the memory artifact to produce a confirmed, auditable verdict

The framework is positioned as an **academic proof-of-concept** whose differentiator is **forensic transparency, auditable open detection logic, and low-cost replication** — not a claim of speed or accuracy parity with commercial ITDR/EDR products.

---

## 🏗️ Architecture — Three Detection Paths

> 📌 **Interactive architecture diagram:** [`architecture-diagram.html`](architecture-diagram.html) — open in a browser for the full data-flow view.

| # | Path | Source Signal | Engine |
|---|------|---------------|--------|
| **1** | **Behavioural log detection** | Kerberos events (`4768` / `4769`), anomalous TGT lifetime, TGS-without-TGT | Microsoft Sentinel + KQL analytics rules |
| **2** | **Directory-state scanning** | `sIDHistory` attribute anomalies (privileged SID injection) | PowerShell + LDAP inventory → Log Analytics |
| **3** | **Memory forensics** | Forged TGT (krbtgt) for a user account inside LSASS | Offline memory analysis on an Ubuntu VM |

**Correlation flow:** DC telemetry → Azure Monitor Agent + DCR → Log Analytics / Sentinel; in parallel, LSASS memory → Blob Storage → Service Bus → analysis VM → `VolatilityAnalysis_CL`. A **`CONFIRMED — Log + Memory`** verdict is reached when the memory path and the log path independently implicate the **same account**.

> [!TIP]
> Telemetry ingestion uses the **Azure Monitor Agent (AMA) with Data Collection Rules (DCR)** — the supported successor to the legacy Microsoft Monitoring Agent (MMA), which Microsoft retired in **August 2024**. DCR gives per-source, filterable control over exactly which security events are forwarded.

---

## ✨ What Makes This Different

- **Sees the ticket, not just the behaviour.** The memory path recovers the forged TGT itself — the anomalous ~10-year lifetime is a hard forensic indicator, not a heuristic.
- **Independent corroboration.** The log track and the memory track must agree on the same account before a Golden Ticket is marked `CONFIRMED`, sharply reducing analyst uncertainty.
- **Auditable, open detection logic.** Every KQL rule and every step of the memory pipeline is transparent and reproducible — no black-box scoring.
- **Low-cost replication.** The entire lab runs on a single Azure subscription with open-source forensics tooling.
- **AES-evasion resilience.** When an attacker forges with AES to evade the RC4-oriented log filter, the ticket produces no log-side downgrade anomaly — yet the memory path still recovers it from LSASS. This is the central proof of the dual-track thesis: memory catches what logs miss.

---

## 📊 Results & Validation

> [!IMPORTANT]
> Metrics below are the **actually measured** results from the capstone lab. The SIDHistory detector was evaluated on a labelled dataset; the Golden Ticket path is validated per-case and by log-plus-memory corroboration rather than by a single blanket accuracy figure.

| Metric | Result |
|--------|--------|
| **SIDHistory detector — Precision / Recall / F1** | **1.00** (40 labelled samples: 20 malicious, 20 benign; 0 false positives) |
| **Golden Ticket — validation** | Per-case + **`CONFIRMED — Log + Memory`** corroboration (Administrator, 3650-day ticket) |
| **Forged ticket lifetime (memory signature)** | **~3650 days (10 years)** vs. legitimate ~10 hours |
| **End-to-end detection time** | **~a few minutes** (down from a ~45-minute manual baseline) |
| **Sentinel analytics rules deployed** | **16**, MITRE-mapped, all enabled |
| **Detection paths** | **3 independent** (log, directory-state, memory) converging in Sentinel |

<details>
<summary><b>Confusion matrix — SIDHistory detector (n = 40)</b></summary>

<br>

|                     | Predicted Malicious | Predicted Benign |
|---------------------|:-------------------:|:----------------:|
| **Actual Malicious** | 20 (TP)             | 0 (FN)           |
| **Actual Benign**    | 0 (FP)              | 20 (TN)          |

Precision = TP/(TP+FP) = 1.00 · Recall = TP/(TP+FN) = 1.00 · F1 = 1.00 · FPR = 0

</details>

---

## 🎯 MITRE ATT&CK Mapping

| Technique ID | Name | Detection Path(s) |
|--------------|------|-------------------|
| [`T1558.001`](https://attack.mitre.org/techniques/T1558/001/) | Steal or Forge Kerberos Tickets: Golden Ticket | Log (KQL) **+** Memory forensics |
| [`T1550`](https://attack.mitre.org/techniques/T1550/) | Use Alternate Authentication Material: Pass-the-Ticket | Log (KQL) |
| [`T1134.005`](https://attack.mitre.org/techniques/T1134/005/) | Access Token Manipulation: SID-History Injection | Directory-state (PowerShell/LDAP) |
| [`T1003`](https://attack.mitre.org/techniques/T1003/) | OS Credential Dumping (LSASS) | Memory forensics |

---

## 🧰 Tech Stack & Azure Components

| Layer | Components |
|-------|-----------|
| **Detection / SIEM** | Microsoft Sentinel, Log Analytics Workspace, 16 custom KQL analytics rules |
| **Ingestion** | Azure Monitor Agent (AMA) + Data Collection Rules (DCR) via Azure Arc |
| **Orchestration** | Azure Functions (`LsassDumpTrigger`, `AnalysisResultProcessor`), Azure Service Bus (`memory-dump-queue`, `analysis-queue`) |
| **Storage** | Azure Blob Storage (LSASS dumps + SIDHistory JSON logs) |
| **Memory forensics** | Python-based LSASS ticket recovery on an Ubuntu analysis VM (systemd worker) |
| **Endpoint / directory** | PowerShell + LDAP `sIDHistory` scanning on the Domain Controller |
| **Visualisation** | Sentinel Workbooks + a live cloud SOC dashboard |

---

## 📁 Repository Structure

```
ad-golden-ticket-detection/
├── kql/                       # Sentinel analytics rule queries (the detection logic)
│   ├── golden-ticket-ptt.kql
│   ├── golden-ticket-rc4-downgrade.kql
│   ├── sidhistory-high-risk.kql
│   └── volatility-memory-hit.kql
├── scripts/                   # Domain-Controller PowerShell
│   ├── Capture-LSASS.ps1              # LSASS dump → Blob (Managed Identity)
│   ├── SIDHistory-Inventory.ps1       # LDAP sIDHistory scan
│   └── Infra-HealthCheck.ps1          # 19-point infrastructure check
├── function-app/              # Azure Functions (memory pipeline glue)
│   ├── LsassDumpTrigger/              # blob → Service Bus queue
│   └── AnalysisResultProcessor/       # result → VolatilityAnalysis_CL
├── azure/
│   ├── volatility-worker/            # the memory-forensics engine (worker.py)
│   ├── workbooks/                    # Sentinel dashboards (overview + corroboration)
│   ├── live-dashboard/               # live cloud SOC dashboard
│   └── lab-control/                  # Start/Stop lab scripts (save credits)
├── attack-simulation/         # Attack scripts for validation & demo
├── diagrams/                  # Architecture & pipeline diagrams
└── docs/                      # Report & viva materials, benchmark results
```

---

## 🚀 Deployment Overview

<details>
<summary><b>Expand the 11-phase deployment sequence</b></summary>

<br>

1. **Azure environment** — Resource Group, Log Analytics Workspace, enable Microsoft Sentinel
2. **Domain Controller** — configure Windows audit policy (Kerberos / account-logon events)
3. **Ingestion** — Azure Monitor Agent via Azure Arc, author Data Collection Rules for security events
4. **Blob Storage** — containers for memory dumps and SIDHistory JSON logs
5. **Service Bus** — `memory-dump-queue` and `analysis-queue`
6. **Analysis VM** — provision Ubuntu VM, install the memory-forensics worker (systemd)
7. **Azure Functions** — deploy the pipeline glue (blob trigger + result processor)
8. **PowerShell** — SIDHistory scanning + LSASS capture scheduled tasks on the DC
9. **Sentinel analytics** — 16 KQL rules for Golden Ticket + SIDHistory + memory
10. **Workbooks / dashboard** — overview, corroboration, and live cloud dashboard
11. **Validation** — attack simulation and detection verification

</details>

> [!WARNING]
> Do **not** hardcode resource-specific values (analysis-VM IP, Service Bus connection strings, Storage SAS tokens) into scripts — these change on every redeploy and SAS tokens expire. Prefer **Managed Identity** for storage/queue access and resolve endpoints at runtime.

---

## 🧪 Detection Logic

**Golden Ticket — behavioural indicator (KQL):** a TGS request (`4769`) with **no preceding TGT request (`4768`)** for the same account — a pre-forged ticket injected into memory (implemented as a `leftanti` join). A parallel rule flags RC4 encryption downgrade.

**Golden Ticket — forensic confirmation (memory):** the analysis VM recovers Kerberos tickets from an LSASS dump and flags a **TGT for a user account (service = krbtgt) with a lifetime > 365 days** as `CRITICAL` — the forged Golden Ticket, independent of the log signal.

**SIDHistory abuse (PowerShell / LDAP):** enumerate the `sIDHistory` attribute across principals (`Get-ADObject -Filter { sIDHistory -like "*" }`), and flag injected privileged SIDs (Domain Admins `512`, Enterprise Admins `519`, Schema Admins `518`, …) that do not correspond to a legitimate migration.

**Corroboration:** `CONFIRMED = { log-track accounts (4769) } ∩ { memory-track accounts (CRITICAL) }` — an inner join on the account identity.

Full rules live in [`kql/`](kql/), [`azure/volatility-worker/`](azure/volatility-worker/), and [`scripts/`](scripts/).

---

## ⚖️ Scope & Limitations

- **Academic proof-of-concept.** A research framework demonstrating a memory-forensic detection approach — **not** a drop-in replacement for commercial ITDR/EDR (e.g. Microsoft Defender for Identity, CrowdStrike Falcon), and it does not claim to compete on latency or accuracy.
- **Lab environment.** Validated against a single-DC `corp.local` lab domain; enterprise-scale tuning is out of scope.
- **Documented lab constraints.** The RC4-downgrade rule does not fire in a single-DC lab (the DC's AES keys override for local services). Automated *response* actions (Teams/email alerting, incident-triggered capture) are scaffolded and require interactive OAuth — documented as future work; detection, triage, and visualisation are fully automated.
- **Value proposition:** forensic transparency, auditable open detection logic, and low-cost, reproducible replication for research and education.

---

## 👤 Author

**P. Rahul** — MTech (Cybersecurity), REVA University
Capstone project under REVA Academy for Corporate Excellence (RACE).

<div align="center">
<br>
⭐ If this project is useful to your research, consider starring the repo.
</div>
