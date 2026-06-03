# ============================================================
# Start-AttackSim.ps1
# Pre-attack setup — run BEFORE every attack simulation.
# Ensures infra is healthy, queue is clean, scheduled tasks
# are paused so auto-captures don't pollute your evidence.
# ============================================================

$RG           = "HybridDetectionRG"
$VM           = "VolatilityAnalysisVM"
$FUNCAPP      = "GoldenTicketProcessor"
$ARC_MACHINE  = "WIN-09GD99A8DPG"
$SUB          = "76e0ae82-1f95-44ed-a9af-13a1df28a08c"
$SB_NAMESPACE = "HybridDetSB-76e0ae"
$QUEUE        = "memory-dump-queue"
$ARC_RESOURCE = "/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.HybridCompute/machines/$ARC_MACHINE"

$pass = 0
$fail = 0

function Check($label, $result, $expected) {
    if ($result -match $expected) {
        Write-Host "  [PASS] $label : $result" -ForegroundColor Green
        $script:pass++
    } else {
        Write-Host "  [FAIL] $label : $result (expected: $expected)" -ForegroundColor Red
        $script:fail++
    }
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  START-ATTACKSIM — Pre-Attack Infrastructure Check" -ForegroundColor Cyan
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ── Step 1: Quick Infrastructure Check ───────────────────────
Write-Host "[1/5] Checking infrastructure readiness..." -ForegroundColor Yellow

$vmState = az vm show -g $RG -n $VM --show-details --query "powerState" -o tsv 2>$null
Check "Volatility VM" $vmState "VM running"

$funcState = az functionapp show -g $RG -n $FUNCAPP --query "state" -o tsv 2>$null
Check "Function App" $funcState "Running"

$arcStatus = az connectedmachine show -g $RG -n $ARC_MACHINE --query "status" -o tsv 2>$null
Check "Arc Machine" $arcStatus "Connected"

$dcrAssoc = az monitor data-collection rule association show --name DCR-DC-Association --resource $ARC_RESOURCE --query "name" -o tsv 2>$null
Check "DCR Association" "$dcrAssoc" "DCR-DC-Association"

$token = (az account get-access-token --query accessToken -o tsv 2>$null)
$rulesUrl = "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.OperationalInsights/workspaces/HybridDetectionWS/providers/Microsoft.SecurityInsights/alertRules?api-version=2024-03-01"
$rules = (Invoke-RestMethod -Method Get -Uri $rulesUrl -Headers @{"Authorization"="Bearer $token"}).value | Where-Object { $_.kind -eq "Scheduled" -and $_.properties.enabled -eq $true }
Check "Sentinel Rules Enabled" "$($rules.Count)/7" "7/7"

if ($fail -gt 0) {
    Write-Host ""
    Write-Host "  INFRASTRUCTURE NOT READY — fix $fail failing check(s) before attacking." -ForegroundColor Red
    Write-Host "  Run Resume-Azure.ps1 if resources are paused." -ForegroundColor Yellow
    exit 1
}

# ── Step 2: Drain Service Bus Queue ──────────────────────────
Write-Host ""
Write-Host "[2/5] Draining Service Bus queue (removing stale messages)..." -ForegroundColor Yellow

$connStr = az servicebus namespace authorization-rule keys list `
    --resource-group $RG --namespace-name $SB_NAMESPACE `
    --name RootManageSharedAccessKey --query "primaryConnectionString" -o tsv 2>$null

$parts    = $connStr -split ";"
$endpoint = ($parts | Where-Object { $_ -match "^Endpoint=" }) -replace "Endpoint=sb://","" -replace "/$",""
$keyName  = ($parts | Where-Object { $_ -match "^SharedAccessKeyName=" }) -replace "SharedAccessKeyName=",""
$key      = ($parts | Where-Object { $_ -match "^SharedAccessKey=" }) -replace "SharedAccessKey=",""

$expiry    = [int][double]::Parse((Get-Date -Date (Get-Date).ToUniversalTime().AddHours(1) -UFormat %s))
$uri       = [uri]::EscapeDataString("https://$endpoint/$QUEUE")
$strToSign = "$uri`n$expiry"
$hmac      = New-Object System.Security.Cryptography.HMACSHA256
$hmac.Key  = [Text.Encoding]::UTF8.GetBytes($key)
$sig       = [Convert]::ToBase64String($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($strToSign)))
$sasToken  = "SharedAccessSignature sr=$uri&sig=$([uri]::EscapeDataString($sig))&se=$expiry&skn=$keyName"

$drained = 0
for ($i = 1; $i -le 200; $i++) {
    try {
        $resp = Invoke-WebRequest -Method DELETE `
            -Uri "https://$endpoint/$QUEUE/messages/head?timeout=1" `
            -Headers @{"Authorization" = $sasToken} -ErrorAction Stop
        if ($resp.StatusCode -eq 200) { $drained++ } else { break }
    } catch { break }
}
Write-Host "  Drained $drained stale message(s) from $QUEUE." -ForegroundColor Green

# ── Step 3: Disable Scheduled Tasks ──────────────────────────
Write-Host ""
Write-Host "[3/5] Pausing scheduled tasks (prevents auto-captures polluting evidence)..." -ForegroundColor Yellow

$tasks = @("AD-LSASS-Capture", "AD-SIDHistory-Inventory")
foreach ($task in $tasks) {
    $result = schtasks /change /tn "\$task" /disable 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Disabled: $task" -ForegroundColor Green
    } else {
        Write-Host "  Could not disable: $task (may not exist)" -ForegroundColor DarkGray
    }
}

# ── Step 4: Record Baseline Kerberos Event Counts ────────────
Write-Host ""
Write-Host "[4/5] Recording baseline event counts (last 1 hour before attack)..." -ForegroundColor Yellow

$baselineQuery = "SecurityEvent | where TimeGenerated > ago(1h) | where EventID in (4768, 4769, 4672, 4624) | summarize BaselineCount=count() by EventID | order by EventID asc"
$baseline = az monitor log-analytics query `
    -w "7d7204bc-e286-48ba-946b-a570d511a9dc" `
    --analytics-query $baselineQuery `
    -o json 2>$null | ConvertFrom-Json

Write-Host "  Baseline Kerberos events (last 1h):" -ForegroundColor Cyan
if ($baseline) {
    $baseline | ForEach-Object {
        Write-Host "    EventID $($_.EventID)  :  $($_.BaselineCount) events" -ForegroundColor DarkGray
    }
} else {
    Write-Host "    (No events yet or Log Analytics query unavailable)" -ForegroundColor DarkGray
}

# ── Step 5: Save Sim Start Marker ────────────────────────────
Write-Host ""
Write-Host "[5/5] Saving simulation start marker..." -ForegroundColor Yellow

$simDir = "C:\SecurityLogs\AttackSim"
if (-not (Test-Path $simDir)) { New-Item -ItemType Directory -Path $simDir -Force | Out-Null }

$simId    = Get-Date -Format "yyyyMMdd-HHmmss"
$stateFile = "$simDir\sim-$simId-state.json"

$state = @{
    SimId         = $simId
    StartTime     = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    StartTimeUTC  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    InfraChecks   = "$pass pass / $fail fail"
    QueueDrained  = $drained
    TasksDisabled = $tasks
    VolatilityIP  = (az vm show -g $RG -n $VM -d --query "publicIps" -o tsv 2>$null)
} | ConvertTo-Json

$state | Out-File $stateFile -Encoding utf8
Write-Host "  State saved: $stateFile" -ForegroundColor Green

# ── Ready ─────────────────────────────────────────────────────
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  INFRA READY — $pass/5 checks passed" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Sim ID  : $simId" -ForegroundColor White
Write-Host "  Started : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host ""
Write-Host "  NEXT STEPS:" -ForegroundColor Yellow
Write-Host "  1. Take VMware snapshot RIGHT NOW (baseline for this sim)" -ForegroundColor Yellow
Write-Host "  2. Run your attack simulation" -ForegroundColor Yellow
Write-Host "  3. Manually trigger LSASS capture if needed:" -ForegroundColor Yellow
Write-Host "       C:\SecurityScripts\Capture-LSASS.ps1 -UploadToBlob" -ForegroundColor Cyan
Write-Host "  4. Wait 5-10 min for Sentinel to process events" -ForegroundColor Yellow
Write-Host "  5. Run End-AttackSim.ps1 to capture evidence" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Sim state file: $stateFile" -ForegroundColor DarkGray
Write-Host ""
