# ============================================================
# End-AttackSim.ps1
# Post-attack evidence capture -- run AFTER attack simulation,
# BEFORE reverting VMware snapshot.
# Saves all evidence to file so it persists after revert.
# ============================================================

param(
    [string]$SimId = "",         # Optional: match to Start-AttackSim state file
    [int]$LookbackHours = 4,     # How far back to query for evidence
    [switch]$PostRevert          # Run post-revert verification instead
)

$RG       = "HybridDetectionRG"
$SUB      = "76e0ae82-1f95-44ed-a9af-13a1df28a08c"
$WS_ID    = "7d7204bc-e286-48ba-946b-a570d511a9dc"
$SB_NS    = "HybridDetSB-76e0ae"
$QUEUE    = "memory-dump-queue"
$simDir   = "C:\SecurityLogs\AttackSim"
$token    = (az account get-access-token --query accessToken -o tsv 2>$null)

if (-not (Test-Path $simDir)) { New-Item -ItemType Directory -Path $simDir -Force | Out-Null }

# -- POST-REVERT MODE -----------------------------------------
if ($PostRevert) {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  POST-REVERT VERIFICATION" -ForegroundColor Cyan
    Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "[1/3] Checking Arc reconnection (wait up to 3 min after revert)..." -ForegroundColor Yellow
    $maxWait = 18
    $arcOk   = $false
    for ($i = 1; $i -le $maxWait; $i++) {
        $arcStatus = az connectedmachine show -g $RG -n WIN-09GD99A8DPG --query "status" -o tsv 2>$null
        if ($arcStatus -eq "Connected") {
            Write-Host "  Arc reconnected after $($i * 10)s." -ForegroundColor Green
            $arcOk = $true
            break
        }
        Write-Host "  Waiting for Arc... ($($i * 10)s)" -ForegroundColor DarkGray
        Start-Sleep -Seconds 10
    }
    if (-not $arcOk) {
        Write-Host "  Arc not reconnected after 3 min. Check himds service." -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "[2/3] Re-enabling scheduled tasks..." -ForegroundColor Yellow
    foreach ($task in @("AD-LSASS-Capture", "AD-SIDHistory-Inventory")) {
        schtasks /change /tn "\$task" /enable 2>&1 | Out-Null
        $state = (schtasks /query /tn "\$task" /fo LIST 2>&1 | Select-String "Status").ToString()
        Write-Host "  $task : $state" -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "[3/3] Quick health check..." -ForegroundColor Yellow
    powershell -ExecutionPolicy Bypass -File C:\SecurityScripts\Infra-HealthCheck.ps1

    Write-Host ""
    Write-Host "  Post-revert verification complete. Ready for next simulation." -ForegroundColor Green
    Write-Host ""
    exit 0
}

# -- EVIDENCE CAPTURE MODE ------------------------------------
$timestamp  = Get-Date -Format "yyyyMMdd-HHmmss"
$reportFile = "$simDir\evidence-$timestamp.txt"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  END-ATTACKSIM -- Evidence Capture" -ForegroundColor Cyan
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')   Lookback: $LookbackHours hour(s)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$report = @()
$report += "ATTACK SIMULATION EVIDENCE REPORT"
$report += "Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$report += "Lookback  : $LookbackHours hour(s)"
$report += "=" * 60

# -- Step 1: Service Bus Queue --------------------------------
Write-Host "[1/5] Checking Service Bus queue (pipeline activity)..." -ForegroundColor Yellow

$queueUrl  = "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.ServiceBus/namespaces/$SB_NS/queues/" + $QUEUE + "?api-version=2021-11-01"
$queueData = Invoke-RestMethod -Method Get -Uri $queueUrl -Headers @{"Authorization"="Bearer $token"} -ErrorAction SilentlyContinue
$msgCount  = $queueData.properties.countDetails.activeMessageCount
$dlqCount  = $queueData.properties.countDetails.deadLetterMessageCount

Write-Host "  memory-dump-queue  active: $msgCount   dead-letter: $dlqCount" -ForegroundColor Cyan
$report += ""
$report += "SERVICE BUS QUEUE"
$report += "  memory-dump-queue active  : $msgCount"
$report += "  memory-dump-queue DLQ     : $dlqCount"
if ($msgCount -gt 0) {
    Write-Host "  Pipeline fired -- $msgCount message(s) queued for Volatility analysis." -ForegroundColor Green
    $report += "  STATUS: PIPELINE FIRED"
} else {
    Write-Host "  No messages in queue. Either processed already or LSASS capture not triggered." -ForegroundColor DarkGray
    $report += "  STATUS: QUEUE EMPTY (check Function App logs)"
}

# -- Step 2: Kerberos Event Counts ----------------------------
Write-Host ""
Write-Host "[2/5] Querying Kerberos events from Log Analytics (last $LookbackHours h)..." -ForegroundColor Yellow

$kerbQuery = "SecurityEvent | where TimeGenerated > ago(" + $LookbackHours + "h) | where EventID in (4768, 4769, 4672, 4624, 4625, 5136) | summarize EventCount=count() by EventID | order by EventID asc"
$kerbResult = az monitor log-analytics query `
    -w $WS_ID `
    --analytics-query $kerbQuery `
    -o json 2>$null | ConvertFrom-Json

$report += ""
$report += "KERBEROS EVENTS (last $LookbackHours h)"
Write-Host "  EventID  Count" -ForegroundColor Cyan
Write-Host "  -------  -----" -ForegroundColor Cyan
if ($kerbResult) {
    foreach ($row in $kerbResult) {
        $line = "  EventID $($row.EventID)  :  $($row.EventCount) events"
        Write-Host $line -ForegroundColor White
        $report += $line
    }
} else {
    Write-Host "  (No Kerberos events in window or query unavailable)" -ForegroundColor DarkGray
    $report += "  (No results)"
}

# -- Step 3: Sentinel Incidents -------------------------------
Write-Host ""
Write-Host "[3/5] Querying Sentinel incidents (last $LookbackHours h)..." -ForegroundColor Yellow

$cutoff      = (Get-Date).ToUniversalTime().AddHours(-$LookbackHours).ToString("yyyy-MM-ddTHH:mm:ssZ")
$incidentUrl = "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.OperationalInsights/workspaces/HybridDetectionWS/providers/Microsoft.SecurityInsights/incidents?api-version=2023-02-01"
$incidents   = (Invoke-RestMethod -Method Get -Uri $incidentUrl -Headers @{"Authorization"="Bearer $token"} -ErrorAction SilentlyContinue).value | Where-Object {
    $_.properties.createdTimeUtc -ge $cutoff
}

$report += ""
$report += "SENTINEL INCIDENTS (last $LookbackHours h)"

if ($incidents -and $incidents.Count -gt 0) {
    Write-Host "  Found $($incidents.Count) incident(s):" -ForegroundColor Green
    $report += "  Total: $($incidents.Count) incident(s)"
    foreach ($inc in $incidents) {
        $title    = $inc.properties.title
        $severity = $inc.properties.severity
        $status   = $inc.properties.status
        $created  = $inc.properties.createdTimeUtc
        $line = "  [$severity] $title  |  $status  |  $created"
        Write-Host $line -ForegroundColor $(if ($severity -eq "High") { "Red" } elseif ($severity -eq "Medium") { "Yellow" } else { "White" })
        $report += $line
    }
} else {
    Write-Host "  No new incidents in the last $LookbackHours hour(s)." -ForegroundColor DarkGray
    Write-Host "  (Rules run on schedule -- check again in 30-60 min if attack was recent)" -ForegroundColor DarkGray
    $report += "  No incidents yet (rules may not have fired -- check again in 30-60 min)"
}

# -- Step 4: Function App -- Recent Invocations ---------------
Write-Host ""
Write-Host "[4/5] Checking Function App recent activity..." -ForegroundColor Yellow

$funcLogsQuery = "FunctionAppLogs | where TimeGenerated > ago(" + $LookbackHours + "h) | where Message contains 'LSASS' or Message contains 'Queued' or Message contains 'Analysis' | project TimeGenerated, FunctionName, Level, Message | order by TimeGenerated desc | take 10"
$funcLogs = az monitor log-analytics query `
    -w $WS_ID `
    --analytics-query $funcLogsQuery `
    -o json 2>$null | ConvertFrom-Json

$report += ""
$report += "FUNCTION APP RECENT LOGS (last $LookbackHours h, top 10)"
if ($funcLogs) {
    foreach ($log in $funcLogs) {
        $line = "  [$($log.TimeGenerated)] $($log.FunctionName): $($log.Message)"
        Write-Host $line -ForegroundColor DarkGray
        $report += $line
    }
} else {
    Write-Host "  No relevant Function App logs found." -ForegroundColor DarkGray
    $report += "  (No logs or query unavailable)"
}

# -- Step 5: Volatility Analysis Results ----------------------
Write-Host ""
Write-Host "[5/5] Checking for Volatility analysis results in Log Analytics..." -ForegroundColor Yellow

$volQuery   = "VolatilityAnalysis_CL | where TimeGenerated > ago(" + $LookbackHours + "h) | project TimeGenerated, blobName_s, riskLevel_s, indicator_s | order by TimeGenerated desc | take 10"
$volResults = az monitor log-analytics query `
    -w $WS_ID `
    --analytics-query $volQuery `
    -o json 2>$null | ConvertFrom-Json

$report += ""
$report += "VOLATILITY ANALYSIS RESULTS (last $LookbackHours h)"
if ($volResults) {
    foreach ($v in $volResults) {
        $line = "  [$($v.TimeGenerated)] $($v.blobName_s)  Risk: $($v.riskLevel_s)  Indicator: $($v.indicator_s)"
        $color = if ($v.riskLevel_s -in "HIGH","CRITICAL") { "Red" } else { "White" }
        Write-Host $line -ForegroundColor $color
        $report += $line
    }
} else {
    Write-Host "  No Volatility results yet (worker is placeholder -- actual analysis not yet wired up)." -ForegroundColor DarkGray
    $report += "  (Volatility worker is placeholder -- no actual memory analysis output)"
}

# -- Save Report ----------------------------------------------
$report += ""
$report += "=" * 60
$report += "Report saved: $reportFile"

$report | Out-File $reportFile -Encoding utf8
Write-Host ""
Write-Host "  Evidence report saved: $reportFile" -ForegroundColor Green

# -- Final Instructions ---------------------------------------
Write-Host ""
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host "  EVIDENCE CAPTURED -- DO THIS NOW:" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "  1. Screenshot Sentinel Incidents in Azure Portal" -ForegroundColor White
Write-Host "     portal.azure.com > Sentinel > HybridDetectionWS > Incidents" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  2. Screenshot Log Analytics KQL results" -ForegroundColor White
Write-Host "     Run: SecurityEvent | where EventID in (4768,4769,4672)" -ForegroundColor DarkGray
Write-Host "          | where TimeGenerated > ago($($LookbackHours)h)" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  3. Evidence file is at:" -ForegroundColor White
Write-Host "     $reportFile" -ForegroundColor Cyan
Write-Host "     (This file SURVIVES VMware snapshot revert -- it is on the DC)" -ForegroundColor DarkGray
Write-Host "     NOTE: Copy it somewhere else if you want to be safe." -ForegroundColor DarkGray
Write-Host ""
Write-Host "  4. REVERT VMware snapshot to baseline" -ForegroundColor White
Write-Host ""
Write-Host "  5. After revert -- run this to verify clean state:" -ForegroundColor White
Write-Host "     C:\Users\Administrator\Desktop\End-AttackSim.ps1 -PostRevert" -ForegroundColor Cyan
Write-Host ""
