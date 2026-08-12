#!/usr/bin/env python3
"""
Volatility Worker — AD Detection Framework
Runs on VolatilityAnalysisVM (Ubuntu 22.04).
Reads from memory-dump-queue, analyzes LSASS dumps with Volatility 3,
posts results to analysis-queue for the Function App to forward to Sentinel.

Deploy: copy to /opt/volatility-worker/worker.py
Run:    python3 /opt/volatility-worker/worker.py
"""

import os
import sys
import json
import time
import logging
import hashlib
import datetime
import subprocess
import tempfile
import re
import base64

from azure.servicebus import ServiceBusClient, ServiceBusMessage
from azure.storage.blob import BlobServiceClient

# ── Configuration ─────────────────────────────────────────────
SB_CONN_STR      = os.environ.get("SERVICEBUS_CONNECTION", "")
STORAGE_CONN_STR = os.environ.get("MEMDUMP_STORAGE_CONN", "")
INPUT_QUEUE      = "memory-dump-queue"
OUTPUT_QUEUE     = "analysis-queue"
VOLATILITY       = "/opt/volatility3/vol.py"
PYPYKATZ         = "/usr/local/bin/pypykatz"
WORK_DIR         = "/tmp/volatility-work"
POLL_INTERVAL    = 10   # seconds between queue polls
MAX_DUMP_SIZE_GB = 2.0  # reject dumps larger than this

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("/var/log/volatility-worker.log"),
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger(__name__)


# ── Volatility Runner ─────────────────────────────────────────
def run_plugin(dump_path: str, plugin: str, timeout: int = 300) -> str:
    cmd = [sys.executable, VOLATILITY, "-f", dump_path, plugin]
    log.info(f"Running: {plugin}")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        if result.returncode != 0 and result.stderr:
            log.warning(f"{plugin} stderr: {result.stderr[:500]}")
        return result.stdout
    except subprocess.TimeoutExpired:
        log.error(f"{plugin} timed out after {timeout}s")
        return ""
    except Exception as e:
        log.error(f"{plugin} failed: {e}")
        return ""


# ── Output Parsers ────────────────────────────────────────────
def parse_kerberos(output: str) -> list:
    """
    Parse windows.kerberos.Kerberos output.
    Columns: Offset  Name  PrincipalName  EncType  SessionKey  Start  End  RenewUntil  Flags
    """
    tickets = []
    for line in output.splitlines():
        if not line.strip() or line.startswith("Offset") or line.startswith("*"):
            continue
        parts = line.split()
        if len(parts) < 7:
            continue
        try:
            ticket = {
                "offset":        parts[0],
                "processName":   parts[1],
                "principalName": parts[2],
                "encType":       parts[3] if len(parts) > 3 else "unknown",
                "start":         parts[4] if len(parts) > 4 else "",
                "end":           parts[5] if len(parts) > 5 else "",
                "renewUntil":    parts[6] if len(parts) > 6 else "",
                "flags":         parts[7] if len(parts) > 7 else "",
            }
            tickets.append(ticket)
        except IndexError:
            continue
    return tickets


def parse_mutants(output: str) -> list:
    """
    Parse windows.mutantscan.MutantScan output.
    Look for Mimikatz-specific mutex names.
    """
    suspicious = []
    mimikatz_patterns = [
        r"(?i)mimikatz",
        r"(?i)sekurlsa",
        r"(?i)kerberos::",
        r"(?i)lsadump",
        r"(?i)wce_[0-9]",
        r"(?i)meterpreter",
    ]
    for line in output.splitlines():
        for pattern in mimikatz_patterns:
            if re.search(pattern, line):
                suspicious.append(line.strip())
                break
    return suspicious


def parse_pslist(output: str) -> list:
    """
    Parse windows.pslist.PsList output.
    Flag known attack tool processes.
    """
    suspicious_processes = [
        "mimikatz", "wce", "pwdump", "meterpreter",
        "cobalt", "beacon", "rubeus", "certify",
    ]
    found = []
    for line in output.splitlines():
        line_lower = line.lower()
        for proc in suspicious_processes:
            if proc in line_lower:
                found.append({"process": line.strip(), "indicator": proc})
    return found


def parse_cmdline(output: str) -> list:
    """
    Parse windows.cmdline.CmdLine output.
    Look for attack tool command lines.
    """
    attack_patterns = [
        r"(?i)mimikatz",
        r"(?i)sekurlsa::logonpasswords",
        r"(?i)kerberos::golden",
        r"(?i)kerberos::ptt",
        r"(?i)lsadump::dcsync",
        r"(?i)privilege::debug",
        r"(?i)comsvcs.*minidump",
        r"(?i)procdump.*lsass",
    ]
    found = []
    for line in output.splitlines():
        for pattern in attack_patterns:
            if re.search(pattern, line):
                found.append(line.strip())
                break
    return found


# ── Golden Ticket Indicator Analysis ─────────────────────────
def analyze_kerberos_tickets(tickets: list) -> dict:
    """
    Identify Golden Ticket indicators from Kerberos ticket list.
    """
    indicators = []
    rc4_tickets = []
    aes_tickets = []
    long_lived   = []

    now = datetime.datetime.utcnow()

    for t in tickets:
        enc = t.get("encType", "").lower()

        # RC4 (0x17 / 23 / rc4-hmac)
        if enc in ("0x17", "23", "rc4-hmac", "rc4"):
            rc4_tickets.append(t)

        # AES-256 (0x12 / 18)
        elif enc in ("0x12", "18", "aes256-cts-hmac-sha1-96", "aes"):
            aes_tickets.append(t)

        # Check ticket end time — Golden Tickets often valid 10 years
        try:
            end_str = t.get("end", "")
            if end_str and end_str not in ("N/A", "-", ""):
                end_dt = datetime.datetime.fromisoformat(end_str.replace("Z", ""))
                days_valid = (end_dt - now).days
                if days_valid > 365:
                    long_lived.append({**t, "daysValid": days_valid})
        except Exception:
            pass

    if rc4_tickets:
        indicators.append({
            "type":        "RC4_KERBEROS_TICKET",
            "severity":    "HIGH",
            "description": f"Found {len(rc4_tickets)} RC4-encrypted Kerberos ticket(s) in LSASS memory",
            "tickets":     rc4_tickets[:5],
            "mitre":       "T1558.001",
        })

    if long_lived:
        indicators.append({
            "type":        "LONG_LIVED_TICKET",
            "severity":    "CRITICAL",
            "description": f"Found {len(long_lived)} ticket(s) valid > 1 year — strong Golden Ticket indicator",
            "tickets":     long_lived[:5],
            "mitre":       "T1558.001",
        })

    if aes_tickets and len(aes_tickets) > len(rc4_tickets) * 2:
        indicators.append({
            "type":        "AES_TICKET_ANOMALY",
            "severity":    "MEDIUM",
            "description": f"Unusually high AES ticket count ({len(aes_tickets)}) — possible AES Golden Ticket",
            "tickets":     aes_tickets[:5],
            "mitre":       "T1558.001",
        })

    return {
        "totalTickets":  len(tickets),
        "rc4Count":      len(rc4_tickets),
        "aesCount":      len(aes_tickets),
        "longLivedCount": len(long_lived),
        "indicators":    indicators,
    }


# ── Risk Scorer ───────────────────────────────────────────────
def compute_risk(kerberos_analysis: dict, mutants: list, processes: list, cmdlines: list) -> str:
    score = 0

    # Kerberos signals
    if kerberos_analysis.get("longLivedCount", 0) > 0:
        score += 100   # Critical — almost certainly Golden Ticket
    if kerberos_analysis.get("rc4Count", 0) > 0:
        score += 40
    for ind in kerberos_analysis.get("indicators", []):
        if ind["severity"] == "CRITICAL":
            score += 50
        elif ind["severity"] == "HIGH":
            score += 30

    # Tool artifacts
    if mutants:
        score += 60    # Mimikatz mutex = high confidence
    if processes:
        score += 60
    if cmdlines:
        score += 50

    if score >= 100:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "CLEAN"


# ── Main Analysis Orchestrator ────────────────────────────────
def extract_kerberos_pypykatz(dump_path: str) -> dict:
    """
    Extract Kerberos tickets from an LSASS minidump using pypykatz.
    Volatility 3 has no working Kerberos-ticket plugin on modern Windows, so the
    old windows.kerberos.Kerberos call always returned 0 tickets (false CLEAN).

    Golden Ticket signature: a TGT (service = krbtgt) issued to a USER account
    (not a machine account ending in '$') found resident in the Domain Controller's
    LSASS memory = injected Pass-the-Ticket Golden Ticket.
    """
    import glob, shutil, tempfile
    tdir = tempfile.mkdtemp(prefix="ktix_", dir=WORK_DIR)
    tickets, golden = [], []
    try:
        subprocess.run([PYPYKATZ, "lsa", "minidump", "-k", tdir, dump_path],
                       capture_output=True, text=True, timeout=300)
        for f in glob.glob(os.path.join(tdir, "*.kirbi")):
            base    = os.path.basename(f)
            parts   = base.split("_")
            ttype   = parts[0] if len(parts) > 0 else ""
            client  = parts[2] if len(parts) > 2 else ""
            service = parts[3] if len(parts) > 3 else ""
            t = {"principalName": client, "service": service, "type": ttype, "file": base}
            tickets.append(t)
            if (ttype.upper() == "TGT" and service.lower().startswith("krbtgt")
                    and client and not client.endswith("$") and client.lower() != "krbtgt"):
                golden.append(t)
    except Exception as e:
        log.warning(f"pypykatz extraction failed: {e}")
    finally:
        shutil.rmtree(tdir, ignore_errors=True)

    indicators = []
    if golden:
        users = ", ".join(sorted(set(g["principalName"] for g in golden)))
        indicators.append({
            "type":        "GOLDEN_TICKET_MEMORY",
            "severity":    "CRITICAL",
            "description": f"Forged TGT for privileged user account(s) [{users}] found resident in DC LSASS memory - Pass-the-Ticket Golden Ticket",
            "tickets":     golden[:5],
            "mitre":       "T1558.001",
        })

    return {
        "totalTickets":   len(tickets),
        "rc4Count":       0,
        "aesCount":       0,
        "longLivedCount": len(golden),   # forces compute_risk() to CRITICAL
        "indicators":     indicators,
        "_tickets":       tickets,
    }


def analyze_dump(blob_name: str, storage_account: str, container: str) -> dict:
    os.makedirs(WORK_DIR, exist_ok=True)

    # Derive a safe local filename
    safe_name  = hashlib.md5(blob_name.encode()).hexdigest()[:12] + ".dmp"
    dump_path  = os.path.join(WORK_DIR, safe_name)

    # Download dump from Azure Blob
    # Azure Functions blob trigger includes container name in blob_name (e.g. "artifacts/lsass.dmp").
    # Strip it so BlobServiceClient doesn't double-prefix the path.
    blob_key = blob_name
    if blob_key.startswith(container + "/"):
        blob_key = blob_key[len(container) + 1:]

    log.info(f"Downloading {blob_key} from {storage_account}/{container}")
    try:
        blob_svc    = BlobServiceClient.from_connection_string(STORAGE_CONN_STR)
        blob_client = blob_svc.get_blob_client(container=container, blob=blob_key)
        size_bytes = blob_client.get_blob_properties().size

        size_gb = size_bytes / (1024 ** 3)
        if size_gb > MAX_DUMP_SIZE_GB:
            return {"error": f"Dump too large: {size_gb:.1f} GB (max {MAX_DUMP_SIZE_GB} GB)"}

        with open(dump_path, "wb") as f:
            f.write(blob_client.download_blob().readall())
        log.info(f"Downloaded: {dump_path} ({size_bytes / 1024 / 1024:.1f} MB)")
    except Exception as e:
        return {"error": f"Download failed: {e}"}

    results = {}

    try:
        # Run Volatility plugin chain
        log.info("Running Volatility plugin chain...")

        # Kerberos tickets via pypykatz (Volatility has no working Kerberos plugin)
        kerberos_analysis = extract_kerberos_pypykatz(dump_path)
        tickets = kerberos_analysis.pop("_tickets", [])

        # Tool artifacts still via Volatility (these plugins exist and work)
        mutants_raw  = run_plugin(dump_path, "windows.mutantscan.MutantScan", timeout=120)
        pslist_raw   = run_plugin(dump_path, "windows.pslist.PsList", timeout=60)
        cmdline_raw  = run_plugin(dump_path, "windows.cmdline.CmdLine", timeout=120)
        mutants    = parse_mutants(mutants_raw)
        processes  = parse_pslist(pslist_raw)
        cmdlines   = parse_cmdline(cmdline_raw)

        risk_level = compute_risk(kerberos_analysis, mutants, processes, cmdlines)

        results = {
            "TimeGenerated":     datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "blobName":          blob_name,
            "storageAccount":    storage_account,
            "dumpSizeMB":        round(size_bytes / 1024 / 1024, 1),
            "riskLevel":         risk_level,
            "kerberosAnalysis":  kerberos_analysis,
            "mimikatzMutants":   mutants,
            "suspiciousProcs":   processes,
            "attackCmdLines":    cmdlines,
            "indicator":         (
                kerberos_analysis["indicators"][0]["type"]
                if kerberos_analysis["indicators"]
                else "NONE"
            ),
            "pluginsRun":        ["pypykatz.lsa.minidump(kerberos)", "windows.mutantscan.MutantScan",
                                  "windows.pslist.PsList", "windows.cmdline.CmdLine"],
            "analysisSource":    "VolatilityWorker-v2-pypykatz",
        }

        log.info(f"Analysis complete: riskLevel={risk_level}, tickets={len(tickets)}, "
                 f"mutants={len(mutants)}, procs={len(processes)}, cmdlines={len(cmdlines)}")

    except Exception as e:
        log.error(f"Analysis error: {e}")
        results = {"error": str(e), "blobName": blob_name, "riskLevel": "UNKNOWN"}
    finally:
        # Always clean up dump file
        try:
            os.remove(dump_path)
            log.info(f"Cleaned up: {dump_path}")
        except Exception:
            pass

    return results


# ── Queue Worker Loop ─────────────────────────────────────────
def run_worker():
    if not SB_CONN_STR or not STORAGE_CONN_STR:
        log.error("SERVICEBUS_CONNECTION or MEMDUMP_STORAGE_CONN env vars not set. Exiting.")
        sys.exit(1)

    log.info(f"Volatility Worker starting. Polling {INPUT_QUEUE} every {POLL_INTERVAL}s")
    log.info(f"Volatility: {VOLATILITY}")

    sb_client = ServiceBusClient.from_connection_string(SB_CONN_STR)

    with sb_client:
        receiver = sb_client.get_queue_receiver(
            queue_name=INPUT_QUEUE,
            max_wait_time=POLL_INTERVAL
        )
        sender = sb_client.get_queue_sender(queue_name=OUTPUT_QUEUE)

        with receiver, sender:
            log.info("Ready. Waiting for LSASS dumps...")
            while True:
                try:
                    messages = receiver.receive_messages(max_message_count=1, max_wait_time=POLL_INTERVAL)

                    if not messages:
                        continue

                    msg = messages[0]
                    # Decode body — Azure Functions SB output binding wraps in base64
                    raw = msg.body if isinstance(msg.body, str) else b"".join(msg.body).decode("utf-8")
                    log.info(f"Received message (raw[:100]): {raw[:100]}")

                    # Try direct JSON first, then unwrap Azure Functions envelope
                    body_str = raw
                    try:
                        probe = json.loads(raw)
                        # Azure Functions wraps the actual message as {"Body": "<base64>"}
                        if isinstance(probe, dict) and "Body" in probe and len(probe) <= 3:
                            decoded = base64.b64decode(probe["Body"]).decode("utf-8")
                            body_str = decoded
                            log.info(f"Unwrapped Azure Functions envelope. Inner body: {body_str[:100]}")
                    except Exception:
                        pass

                    try:
                        payload = json.loads(body_str)
                    except json.JSONDecodeError:
                        log.error(f"Invalid JSON after decode — dead-lettering. body={body_str[:200]}")
                        receiver.dead_letter_message(msg, reason="InvalidJSON")
                        continue

                    blob_name   = payload.get("blobName", "")
                    storage_acc = payload.get("storageAccount", "memorydumps202605121306")
                    container   = payload.get("container", "artifacts")

                    if not blob_name:
                        log.error("No blobName in message — dead-lettering")
                        receiver.dead_letter_message(msg, reason="MissingBlobName")
                        continue

                    # Run analysis
                    result = analyze_dump(blob_name, storage_acc, container)

                    # Post result to analysis-queue for Function App to pick up
                    result_msg = ServiceBusMessage(json.dumps(result))
                    sender.send_messages(result_msg)
                    log.info(f"Result posted to {OUTPUT_QUEUE}: riskLevel={result.get('riskLevel','?')}")

                    # Complete (remove) the input message
                    receiver.complete_message(msg)

                except KeyboardInterrupt:
                    log.info("Worker stopped by user.")
                    break
                except Exception as e:
                    log.error(f"Worker loop error: {e}")
                    time.sleep(5)


if __name__ == "__main__":
    run_worker()
