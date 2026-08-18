# Lab Control — Start / Stop the AD Detection lab

Because the DC VM (VMware) can't run 24/7, use these to bring the whole hybrid
lab **up** and **down** cleanly. They live on the DC at `C:\SecurityScripts\`.

## Daily use (simplest)
1. **Power on** the DC VM in VMware.
2. Double-click **`START-LAB.cmd`** → brings the lab up.
3. Do your work / run the attack simulation.
4. Double-click **`STOP-LAB.cmd`** → tears the lab down cleanly (saves credits).
5. **Power off** the DC VM.

(Or run the PowerShell directly: `powershell -ExecutionPolicy Bypass -File C:\SecurityScripts\Start-Lab.ps1`)

## What START-LAB does
- Starts the **Volatility VM** and **Function App**
- Ensures the **DCR association** (log ingestion) is in place
- **Heals AMA**: if `SecurityEvent` ingestion is stale or the agent isn't running,
  it restarts the Arc agent stack and (if needed) reinstalls the AMA extension — the
  exact self-fix for the VMware-suspend problem
- Enables the DC **scheduled tasks**
- **Purges the old LSASS-dump backlog** so only *fresh* captures are analysed — old
  dumps are NOT re-sent to the cloud (this was the main ask)
- Options:
  - `-FreshCapture` — also trigger one new LSASS capture immediately
  - `-MaxDumpAgeMin 60` — freshness target (default 60 min)
  - `-SkipAzure` — local-only (no cloud calls)

## What STOP-LAB does
- **Purges the dump queues** (clean slate — nothing stale left for next start)
- **Deallocates the Volatility VM** (the main hourly cost)
- **Stops the Function App** (use `-KeepFunctionApp` to leave it running)
- Leaves everything in a clean state so the **next Start runs fine**

## Prerequisite — Azure sign-in (one-time per session)
The scripts use `az`. If not signed in, they'll tell you to run:
```
az login --tenant 48af447d-f55c-49f3-aa1e-982c0020e44a
```
The session persists, so you normally only do this occasionally.

## Optional — make them true .exe files
Install ps2exe once, then compile:
```powershell
Install-Module ps2exe -Scope CurrentUser
ps2exe C:\SecurityScripts\Start-Lab.ps1 C:\SecurityScripts\Start-Lab.exe
ps2exe C:\SecurityScripts\Stop-Lab.ps1  C:\SecurityScripts\Stop-Lab.exe
```
(The `.cmd` launchers already give you double-click behaviour without compiling.)

## Optional — auto-run Start on boot
```powershell
schtasks /Create /TN "Lab-AutoStart" /TR "powershell -ExecutionPolicy Bypass -File C:\SecurityScripts\Start-Lab.ps1" /SC ONSTART /RU SYSTEM /RL HIGHEST /F
```

## Notes
- "Skip old dumps" is enforced by purging the `memory-dump-queue` backlog on both
  start and stop. A future enhancement is an age-check inside the worker itself
  (skip any dump whose filename timestamp is > MaxDumpAgeMin) as belt-and-suspenders.
- These supersede the old `Desktop\Resume-Azure.ps1` / `Pause-Azure.ps1`, which were
  pinned to a dead subscription — do not use those.
