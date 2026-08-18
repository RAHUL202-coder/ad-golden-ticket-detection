# Volatility Analysis VM — Memory-Forensics Worker

`worker.py` runs on `VolatilityAnalysisVM` (Ubuntu 20.04, eastus2) as the systemd
service `volatility-worker` (runs as **root**). It polls `memory-dump-queue`
(Service Bus), downloads each LSASS dump from blob storage, extracts Kerberos
tickets, scores the risk, and posts the result to `analysis-queue` — which the
`AnalysisResultProcessor` Function writes into `VolatilityAnalysis_CL`.

## ⚠️ Critical: pypykatz, NOT the Volatility Kerberos plugin

The original worker called `windows.kerberos.Kerberos` — **which does not exist
in Volatility 3** (there is no working Volatility Kerberos-ticket plugin on
modern Windows). It silently returned 0 tickets, so every dump scored `CLEAN`
and memory-based Golden Ticket detection never actually worked.

**Fix (2026-08-05):** ticket extraction now uses **pypykatz** (`pypykatz lsa
minidump -k`), which parses WS2022 LSASS minidumps and exports the tickets.

### Detection logic
A **TGT** (service = `krbtgt`) issued to a **USER** account (not a machine
account ending in `$`) found resident in the Domain Controller's LSASS memory =
injected Pass-the-Ticket **Golden Ticket** → `riskLevel = CRITICAL`, indicator
`GOLDEN_TICKET_MEMORY`, MITRE T1558.001.

Volatility 3 plugins still used for tool artifacts (these exist): `mutantscan`,
`pslist`, `cmdline`.

## Deployment / rebuild steps

```bash
# 1. Install dependencies (pypykatz must be system-wide because the worker runs as root)
sudo pip3 install pypykatz azure-servicebus azure-storage-blob

# 2. Deploy the worker
sudo cp worker.py /opt/volatility-worker/worker.py

# 3. Environment (/etc/volatility-worker.env) must define:
#    SERVICEBUS_CONNECTION=<Service Bus connection string>
#    MEMDUMP_STORAGE_CONN=<memorydumps storage account connection string>

# 4. systemd unit /etc/systemd/system/volatility-worker.service:
#    ExecStart=/usr/bin/python3 /opt/volatility-worker/worker.py
#    EnvironmentFile=/etc/volatility-worker.env

sudo systemctl daemon-reload
sudo systemctl restart volatility-worker
systemctl is-active volatility-worker      # -> active
```

## Verify end-to-end

```bash
# Re-enqueue a known dump and watch the log
sudo grep -iE "Analysis complete|GOLDEN|riskLevel" /var/log/volatility-worker.log | tail
# Expected on a post-Golden-Ticket dump:
#   Analysis complete: riskLevel=CRITICAL, tickets=20 ...
```

Config constants in `worker.py`: `PYPYKATZ = "/usr/local/bin/pypykatz"`,
`VOLATILITY = "/opt/volatility3/vol.py"`.
