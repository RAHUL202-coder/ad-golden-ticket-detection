# MTech Capstone — Full Detection Pipeline Flowchart

```mermaid
flowchart TD
    %% ── Domain Controller ──────────────────────────────────────
    subgraph DC["🖥️ Domain Controller (WIN-09GD99A8DPG · corp.local)"]
        A1([Kerberos Activity\nEventID 4768 / 4769])
        A2([LSASS Memory\nlsass.exe])
        A3[PowerShell Script\nGet-ADUser SIDHistory scan]
    end

    %% ── Log Ingestion ───────────────────────────────────────────
    subgraph AMA["📡 Azure Monitor Agent v1.42.0.0 (Arc-managed)"]
        B1[DCR-Security-Kerberos\nData Collection Rule]
    end

    A1 -->|Security Event Log| B1

    %% ── Azure Sentinel ──────────────────────────────────────────
    subgraph SIEM["🛡️ Microsoft Sentinel (HybridDetectionWS)"]
        C1[(SecurityEvent Table)]
        C2{KQL Analytics Rules\n11 scheduled queries}
        C3([Sentinel Incident\nCreated])
    end

    B1 -->|Log ingestion| C1
    C1 --> C2
    C2 -->|Threshold exceeded| C3

    %% ── Azure Function App ──────────────────────────────────────
    subgraph FA["⚡ GoldenTicketProcessor (Function App)"]
        D1[Sentinel Alert Trigger\nHTTP / Logic App webhook]
        D2[Capture LSASS dump\nvia WinRM to DC]
        D3[Upload dump to\nBlob Storage]
        D4[Enqueue job\nService Bus message]
    end

    C3 -->|Alert fires| D1
    A2 -.->|WinRM remote dump| D2
    D1 --> D2 --> D3 --> D4

    %% ── Storage ─────────────────────────────────────────────────
    subgraph STOR["🗄️ Azure Storage"]
        E1[(memorydumps202605121306\nBlob Container)]
        E2[(sidhistory202605121306\nBlob Container)]
    end

    D3 -->|.dmp upload| E1
    A3 -->|SIDHistory JSON export| E2

    %% ── Service Bus ─────────────────────────────────────────────
    subgraph SB["📨 Service Bus (HybridDetSB-76e0ae)"]
        F1[memory-dump-queue]
    end

    D4 --> F1

    %% ── Volatility VM ───────────────────────────────────────────
    subgraph VOL["🔬 Volatility Analysis VM (Ubuntu 20.04 · Standard_D2s_v3)"]
        G1[Queue Listener\nPython service · systemd]
        G2[Download dump\nfrom Blob Storage]
        G3[Volatility 3 Analysis\nwindows.lsadump / malfind\npslist / cmdline / netscan]
        G4{Golden Ticket\nIndicators Found?}
        G5[Risk Score\nCalculation\nCRITICAL / HIGH / MED]
        G6[Upload JSON results\nto Blob Storage]
        G7[POST results\nto Function App callback]
    end

    F1 -->|Dequeue job| G1
    G1 --> G2
    E1 -->|Download .dmp| G2
    G2 --> G3
    G3 --> G4
    G4 -->|Yes — suspicious artifacts| G5
    G4 -->|No artifacts| G6
    G5 --> G6 --> G7

    %% ── Results back to Sentinel ────────────────────────────────
    subgraph RESULT["📊 Results → Sentinel"]
        H1[Volatility Memory Analysis\nAnalytics Rule fires]
        H2([HIGH / CRITICAL\nSentinel Incident])
        H3[Incident enriched with\nmemory forensic evidence])
    end

    G7 -->|Trigger enrichment| H1
    H1 --> H2 --> H3

    %% ── SIDHistory parallel path ────────────────────────────────
    A3 -->|Scheduled scan| E2
    E2 -.->|KQL cross-reference| C2

    %% ── Styles ──────────────────────────────────────────────────
    classDef azure fill:#0078d4,color:#fff,stroke:#005a9e
    classDef sentinel fill:#7719aa,color:#fff,stroke:#5a0e80
    classDef storage fill:#e8a000,color:#000,stroke:#b07800
    classDef vm fill:#1e7e34,color:#fff,stroke:#155724
    classDef alert fill:#d13438,color:#fff,stroke:#a4262c

    class B1,D1,D2,D3,D4,F1 azure
    class C1,C2,H1 sentinel
    class E1,E2 storage
    class G1,G2,G3,G5,G6,G7 vm
    class C3,H2,H3 alert
```

## Pipeline Summary

| Phase | Component | Role |
|---|---|---|
| 1 — Event Collection | AMA + DCR | Streams Kerberos events (4768/4769) from DC to Sentinel |
| 2 — Detection | Sentinel KQL (11 rules) | Detects RC4 downgrade, PTT, SIDHistory injection, AES ratio anomalies |
| 3 — Memory Trigger | GoldenTicketProcessor | Captures LSASS dump on alert, uploads to Blob, queues job |
| 4 — Forensics | Volatility VM | Dequeues job, runs Volatility 3 plugins, scores risk |
| 5 — Enrichment | Results → Sentinel | Posts JSON evidence back; Sentinel creates enriched incident |
| Parallel | SIDHistory scan | PowerShell on DC exports SIDHistory; KQL cross-references entries |
