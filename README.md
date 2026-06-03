# Memory-Based Detection of Golden Ticket and SIDHistory Abuse in Active Directory

**MTech Capstone Project — 2026**

A hybrid detection framework that combines **Microsoft Sentinel KQL analytics** with **live Volatility 3 memory forensics** to detect Golden Ticket attacks and SIDHistory abuse in Active Directory environments — catching attacks that event logs alone cannot surface.

---

## Architecture

![Pipeline](diagrams/detection-pipeline.md)

```
Domain Controller (corp.local)
    │  Kerberos Events 4768/4769
    ▼
Azure Monitor Agent v1.42.0.0  ──►  Microsoft Sentinel
    (Arc-managed, DCR-Security-Kerberos)       │
                                        11 KQL Rules fire
                                               │
                                        Sentinel Incident
                                               │
                                    GoldenTicketProcessor
                                      (Azure Function App)
                                        │           │
                                  LSASS dump    Enqueue job
                                  → Blob        → Service Bus
                                                       │
                                              Volatility VM
                                            (Ubuntu 20.04)
                                          lsadump · malfind
                                          pslist · netscan
                                                │
                                         Risk Score JSON
                                          → Sentinel
                                     (Enriched Incident)
```

---

## Repository Structure

```
├── function-app/           Azure Function App (Python) — LSASS trigger + result processor
├── scripts/                PowerShell scripts running on the Domain Controller
├── attack-simulation/      Controlled attack scripts for lab testing
├── azure/                  Pause/Resume scripts for Azure cost management
├── kql/                    Sentinel KQL detection rules
└── diagrams/               Architecture and pipeline diagrams (HTML + Mermaid)
```

---

## Detection Rules (11 custom KQL + 1 built-in)

| Rule | Technique | Severity |
|---|---|---|
| GT — RC4 Encryption Downgrade | Golden Ticket with weak encryption | High |
| GT — TGS Without Prior TGT | Pass-the-Ticket injection | High |
| GT — Abnormal Service Access Pattern | Unusual TGS targeting | Medium |
| GT — Indirect Pre/Post Indicators | Recon + lateral movement correlation | Medium |
| GT — AES with Abnormal TGS:TGT Ratio | Statistical anomaly detection | Medium |
| SID — High-Risk Privileged SID Injection | DA/EA SID in SIDHistory | Critical |
| SID — New Entry Delta Detection | Newly added SIDHistory entries | High |
| SID — Privileged Logon Correlation | SIDHistory used for privileged logon | Critical |
| Skeleton Key — krbtgt Modification | LSASS patching indicator | Critical |
| Pass-The-Hash — TGS w/o TGT | PTH lateral movement | High |
| Volatility Memory Analysis — HIGH/CRITICAL | In-memory artifact confirmed | Critical |

---

## Azure Infrastructure

| Resource | Type | Purpose |
|---|---|---|
| HybridDetectionWS | Log Analytics + Sentinel | SIEM and detection engine |
| GoldenTicketProcessor | Azure Function App | LSASS capture + result ingestion |
| HybridDetSB-76e0ae | Service Bus | Async job queue |
| memorydumps* | Blob Storage | LSASS dump staging |
| sidhistory* | Blob Storage | SIDHistory export storage |
| VolatilityAnalysisVM | Ubuntu VM (D2s_v3) | Volatility 3 analysis worker |
| WIN-09GD99A8DPG | Arc-connected DC | corp.local Domain Controller |

---

## Key Scripts

### Domain Controller Scripts (`scripts/`)
| Script | Purpose |
|---|---|
| `Capture-LSASS.ps1` | Dumps LSASS memory and uploads to Blob Storage |
| `SIDHistory-Inventory.ps1` | Enumerates all SIDHistory entries in the domain |
| `SIDHistory-Inventory-Upload.ps1` | Uploads SIDHistory JSON to Blob Storage |
| `Infra-HealthCheck.ps1` | Full 18-point infrastructure health check |

### Azure Management (`azure/`)
| Script | Purpose |
|---|---|
| `Pause-Azure.ps1` | Deallocates VM, stops Function App, disables Sentinel rules, removes DCR |
| `Resume-Azure.ps1` | Starts VM, updates dynamic IP in Function App, restores DCR, re-enables rules |

### Attack Simulation (`attack-simulation/`)
| Script | Purpose |
|---|---|
| `Start-AttackSim.ps1` | Pre-attack setup — verifies infra, drains queues, pauses scheduled tasks |
| `End-AttackSim.ps1` | Post-attack cleanup — restores scheduled tasks, drains evidence |

---

## Function App Environment Variables

The Function App requires these app settings (set in Azure Portal — never commit values):

```
MEMDUMP_STORAGE_CONN        Azure Storage connection string (memorydumps)
SERVICEBUS_CONNECTION       Service Bus connection string
LOG_ANALYTICS_WORKSPACE_ID  Log Analytics workspace ID
LOG_ANALYTICS_SHARED_KEY    Log Analytics shared key
VOLATILITY_VM_IP            Current public IP of VolatilityAnalysisVM (updated on resume)
```

---

## What Makes This Novel

Commercial tools like **Microsoft Defender for Identity** detect Golden Tickets via event log heuristics (EventID 4768/4769 patterns). However:

- A Golden Ticket forged offline and injected via `kerberos::ptt` **never contacts the KDC** — no 4768 is generated
- The forged ticket exists only in LSASS memory
- Standard SIEM rules miss it entirely

This framework adds a **memory forensics layer**: when Sentinel fires on any Kerberos anomaly, it automatically captures an LSASS dump and runs Volatility 3 plugins (`windows.lsadump`, `windows.malfind`) to confirm or rule out in-memory ticket artifacts — providing evidence that event logs cannot.

---

## Research Context

- **Domain:** corp.local (lab environment)
- **Attack tools used:** Mimikatz, Rubeus (controlled simulation only)
- **Detection stack:** Microsoft Sentinel + Azure Monitor Agent + Volatility 3
- **Platform:** Azure (HybridDetectionRG, subscription 76e0ae82)
