# Infrastructure Health Check — AD Detection Framework
# Run as Administrator on WIN-09GD99A8DPG

$SUB   = "76e0ae82-1f95-44ed-a9af-13a1df28a08c"
$RG    = "HybridDetectionRG"
$WS    = "HybridDetectionWS"
$PASS  = 0
$FAIL  = 0

function Check {
    param($label, $value, $expected, $pass)
    if ($pass) {
        Write-Host "  [PASS] $label : $value" -ForegroundColor Green
        $script:PASS++
    } else {
        Write-Host "  [FAIL] $label : $value (expected: $expected)" -ForegroundColor Red
        $script:FAIL++
    }
}

$token   = (az account get-access-token --query accessToken -o tsv)
$headers = @{ "Authorization" = "Bearer $token" }

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  AD Detection Framework Health Check" -ForegroundColor Cyan
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# ── Phase 1–3: Foundation ────────────────────────────────────────────────────
Write-Host ""
Write-Host "[Phase 1-3] Azure Foundation + AMA/DCR" -ForegroundColor Yellow

try {
    $arc = Invoke-RestMethod -Method Get -Uri "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.HybridCompute/machines/WIN-09GD99A8DPG?api-version=2022-12-27" -Headers $headers
    Check "Arc machine status" $arc.properties.status "Connected" ($arc.properties.status -eq "Connected")
} catch { Check "Arc machine" "ERROR: $_" "Connected" $false }

try {
    $extUrl = "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.HybridCompute/machines/WIN-09GD99A8DPG/extensions/AzureMonitorWindowsAgent?api-version=2022-12-27"
    $ama = Invoke-RestMethod -Method Get -Uri $extUrl -Headers $headers
    Check "AMA extension" $ama.properties.provisioningState "Succeeded" ($ama.properties.provisioningState -eq "Succeeded")
} catch { Check "AMA extension" "NOT FOUND" "Succeeded" $false }

try {
    $arcId = "/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.HybridCompute/machines/WIN-09GD99A8DPG"
    $dcrUrl = "https://management.azure.com$arcId/providers/Microsoft.Insights/dataCollectionRuleAssociations?api-version=2022-06-01"
    $dcrs = (Invoke-RestMethod -Method Get -Uri $dcrUrl -Headers $headers).value
    $found = $dcrs | Where-Object { $_.name -eq "DCR-DC-Association" }
    Check "DCR association" $(if ($found) { "DCR-DC-Association" } else { "MISSING" }) "DCR-DC-Association" ($null -ne $found)
} catch { Check "DCR association" "ERROR" "DCR-DC-Association" $false }

# ── Phase 4–5: Storage + Service Bus ─────────────────────────────────────────
Write-Host ""
Write-Host "[Phase 4-5] Storage + Service Bus" -ForegroundColor Yellow

$memKey = az storage account keys list --resource-group $RG --account-name memorydumps202605121306 --query "[0].value" -o tsv
$containers = az storage container list --account-name memorydumps202605121306 --account-key $memKey --query "[].name" -o tsv
Check "Memory storage: artifacts"     $(if ($containers -contains "artifacts") { "EXISTS" } else { "MISSING" }) "EXISTS" ($containers -contains "artifacts")
Check "Memory storage: kerberos-logs" $(if ($containers -contains "kerberos-logs") { "EXISTS" } else { "MISSING" }) "EXISTS" ($containers -contains "kerberos-logs")

$sidKey = az storage account keys list --resource-group $RG --account-name sidhistory202605121306 --query "[0].value" -o tsv
$sidContainers = az storage container list --account-name sidhistory202605121306 --account-key $sidKey --query "[].name" -o tsv
Check "SIDHistory storage: sidhistory-logs" $(if ($sidContainers -contains "sidhistory-logs") { "EXISTS" } else { "MISSING" }) "EXISTS" ($sidContainers -contains "sidhistory-logs")

try {
    $sbQ1 = Invoke-RestMethod -Method Get -Uri "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.ServiceBus/namespaces/HybridDetSB-76e0ae/queues/memory-dump-queue?api-version=2021-11-01" -Headers $headers
    Check "Service Bus: memory-dump-queue" "EXISTS" "EXISTS" $true
} catch { Check "Service Bus: memory-dump-queue" "MISSING" "EXISTS" $false }

try {
    $sbQ2 = Invoke-RestMethod -Method Get -Uri "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.ServiceBus/namespaces/HybridDetSB-76e0ae/queues/analysis-queue?api-version=2021-11-01" -Headers $headers
    Check "Service Bus: analysis-queue" "EXISTS" "EXISTS" $true
} catch { Check "Service Bus: analysis-queue" "MISSING" "EXISTS" $false }

# ── Phase 6: Volatility VM ────────────────────────────────────────────────────
Write-Host ""
Write-Host "[Phase 6] Volatility Analysis VM" -ForegroundColor Yellow

try {
    $vm = Invoke-RestMethod -Method Get -Uri "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Compute/virtualMachines/VolatilityAnalysisVM/instanceView?api-version=2023-03-01" -Headers $headers
    $vmStatus = ($vm.statuses | Where-Object { $_.code -like "PowerState/*" }).displayStatus
    Check "Volatility VM" $vmStatus "VM running" ($vmStatus -eq "VM running")
} catch { Check "Volatility VM" "ERROR" "VM running" $false }

# ── Phase 7: Azure Functions ──────────────────────────────────────────────────
Write-Host ""
Write-Host "[Phase 7] Azure Functions" -ForegroundColor Yellow

try {
    $fa = Invoke-RestMethod -Method Get -Uri "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Web/sites/GoldenTicketProcessor?api-version=2022-03-01" -Headers $headers
    Check "Function App state" $fa.properties.state "Running" ($fa.properties.state -eq "Running")

    $keyUrl = "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Web/sites/GoldenTicketProcessor/host/default/listkeys?api-version=2022-03-01"
    $keys = Invoke-RestMethod -Method Post -Uri $keyUrl -Headers $headers
    $funcs = Invoke-RestMethod -Method Get -Uri "https://goldenticketprocessor.azurewebsites.net/admin/functions" -Headers @{"x-functions-key"=$keys.masterKey}
    Check "Functions loaded" "$($funcs.Count) functions" "2 functions" ($funcs.Count -eq 2)
} catch { Check "Function App" "ERROR: $_" "Running + 2 functions" $false }

# ── Phase 8: Scheduled Tasks ──────────────────────────────────────────────────
Write-Host ""
Write-Host "[Phase 8] Scheduled Tasks" -ForegroundColor Yellow

$task1 = schtasks /query /tn "\AD-SIDHistory-Inventory" /fo LIST 2>&1 | Select-String "Status" | ForEach-Object { ($_ -split ":")[1].Trim() }
Check "AD-SIDHistory-Inventory" $task1 "Ready" ($task1 -eq "Ready")

$task2 = schtasks /query /tn "\AD-LSASS-Capture" /fo LIST 2>&1 | Select-String "Status" | ForEach-Object { ($_ -split ":")[1].Trim() }
Check "AD-LSASS-Capture" $task2 "Ready" ($task2 -eq "Ready")

# ── Phase 9: Sentinel Rules ───────────────────────────────────────────────────
Write-Host ""
Write-Host "[Phase 9] Sentinel KQL Analytics Rules" -ForegroundColor Yellow

try {
    $rulesUrl = "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.OperationalInsights/workspaces/$WS/providers/Microsoft.SecurityInsights/alertRules?api-version=2023-02-01"
    $rules = (Invoke-RestMethod -Method Get -Uri $rulesUrl -Headers $headers).value
    $custom = $rules | Where-Object { $_.kind -eq "Scheduled" }
    Check "Custom alert rules" "$($custom.Count) rules" "10 rules" ($custom.Count -ge 10)
    $allEnabled = ($custom | Where-Object { $_.properties.enabled }).Count
    Check "Rules enabled" "$allEnabled/$($custom.Count) enabled" "all enabled" ($allEnabled -eq $custom.Count)
} catch { Check "Sentinel rules" "ERROR" "10+ rules" $false }

# ── Phase 9b: Volatility Worker Service ──────────────────────────────────────
Write-Host ""
Write-Host "[Phase 9b] Volatility Worker (on VolatilityAnalysisVM)" -ForegroundColor Yellow

try {
    $sshKey = "C:\Users\Administrator\.ssh\VolatilityAnalysisVM_key.pem"
    # Try dynamic IP first; fall back to last-known IP if Compute perms unavailable
    $vmIP = az vm show -g $RG -n VolatilityAnalysisVM -d --query "publicIps" -o tsv 2>$null
    if (-not $vmIP) { $vmIP = "4.154.237.211" }
    $workerStatus = ssh -i $sshKey -o ConnectTimeout=8 -o StrictHostKeyChecking=no "azureuser@$vmIP" `
        "systemctl is-active volatility-worker" 2>$null
    Check "Volatility worker service" $workerStatus "active" ($workerStatus -eq "active")
} catch { Check "Volatility worker service" "ERROR" "active" $false }

# ── Phase 10: Logic Apps ──────────────────────────────────────────────────────
Write-Host ""
Write-Host "[Phase 10] Logic Apps + Automation Rules" -ForegroundColor Yellow

try {
    $la = Invoke-RestMethod -Method Get -Uri "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Logic/workflows/SentinelResponsePlaybook?api-version=2019-05-01" -Headers $headers
    Check "Logic App" $la.properties.state "Enabled" ($la.properties.state -eq "Enabled")
} catch { Check "Logic App" "MISSING" "Enabled" $false }

try {
    $arUrl = "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.OperationalInsights/workspaces/$WS/providers/Microsoft.SecurityInsights/automationRules?api-version=2023-02-01"
    $ar = (Invoke-RestMethod -Method Get -Uri $arUrl -Headers $headers).value
    Check "Automation rules" "$($ar.Count) rules" "2 rules" ($ar.Count -ge 2)
} catch { Check "Automation rules" "ERROR" "2 rules" $false }

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
$total = $PASS + $FAIL
$color = if ($FAIL -eq 0) { "Green" } else { "Red" }
Write-Host "  RESULT: $PASS/$total PASS  |  $FAIL FAIL" -ForegroundColor $color
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
