# ============================================================
# Resume-Azure.ps1  (subscription 824f770b — rebuilt 2026-07-23)
# Restarts all paused capstone resources on the CURRENT subscription.
# New architecture: the Volatility VM worker polls Service Bus directly,
# so the old "inject VM IP into Function App" step is obsolete and removed.
# ============================================================

$SUB        = "824f770b-79bf-485f-8664-3dba884fa425"
$RG         = "HybridDetectionRG"
$VM         = "VolatilityAnalysisVM"
$WORKSPACE  = "HybridDetectionWS"
$FUNCAPP    = "gtprocessor824f770b"
$SBNS       = "hybriddetsb-824f770b"
$SSHKEY     = "C:\Users\Administrator\.ssh\id_rsa"   # NOTE: id_rsa, not the old .pem
$ARC        = "/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.HybridCompute/machines/WIN-09GD99A8DPG"
$DCRID      = "/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Insights/dataCollectionRules/DCR-Security-Kerberos"

# All 16 scheduled analytics rules on this subscription
$rules = @(
    "gt-rc4-downgrade","gt-ptt-detection","gt-aes-golden-ticket","gt-pass-the-hash",
    "gt-skeleton-key","gt-indirect-indicators","gt-service-enum","dc-sync-detection",
    "krbtgt-password-reset","kerberoasting-detection","asrep-roasting-detection",
    "honey-account-alert","sidhistory-high-risk-sid","sidhistory-delta-detection",
    "sidhistory-privileged-logon-correlation","volatility-high-risk-memory"
)

az account set --subscription $SUB | Out-Null
Write-Host "`n=== RESUMING AZURE RESOURCES (sub 824f770b) ===`n" -ForegroundColor Cyan

# Step 1: Start Volatility VM
Write-Host "[1/6] Starting $VM..." -ForegroundColor Yellow
$state = az vm show -g $RG -n $VM --show-details --query "powerState" -o tsv 2>$null
if ($state -ne "VM running") { az vm start -g $RG -n $VM | Out-Null }
$ip = az vm show -g $RG -n $VM -d --query "publicIps" -o tsv 2>$null
Write-Host "      VM running. IP: $ip" -ForegroundColor Green

# Step 2: Verify Volatility worker daemon (worker polls Service Bus via Managed Identity)
Write-Host "[2/6] Verifying volatility-worker daemon over SSH..." -ForegroundColor Yellow
if ($ip) {
    $svc = ssh -i $SSHKEY -o ConnectTimeout=15 -o StrictHostKeyChecking=no "azureuser@$ip" "systemctl is-active volatility-worker" 2>$null
    if ($svc -eq "active") { Write-Host "      volatility-worker: ACTIVE" -ForegroundColor Green }
    else { Write-Host "      volatility-worker NOT active ($svc) - run: sudo systemctl start volatility-worker" -ForegroundColor Red }
}

# Step 3: Restore DCR association to resume Log Analytics ingestion
Write-Host "[3/6] Restoring DCR-DC-Association..." -ForegroundColor Yellow
$assoc = az monitor data-collection rule association show --name DCR-DC-Association --resource $ARC -o tsv 2>$null
if (-not $assoc) {
    az monitor data-collection rule association create --name DCR-DC-Association --resource $ARC --rule-id $DCRID 2>$null | Out-Null
    Write-Host "      DCR-DC-Association created. Kerberos events flowing." -ForegroundColor Green
} else { Write-Host "      DCR-DC-Association already active." -ForegroundColor Green }

# Step 4: Re-enable the 16 Sentinel analytics rules
Write-Host "[4/6] Re-enabling Sentinel analytics rules..." -ForegroundColor Yellow
foreach ($r in $rules) {
    az sentinel alert-rule update --resource-group $RG --workspace-name $WORKSPACE --rule-id $r --enabled true 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Host "      Enabled: $r" -ForegroundColor Green }
    else { Write-Host "      Skipped/failed: $r" -ForegroundColor DarkYellow }
}

# Step 5: Start Function App
Write-Host "[5/6] Starting Function App $FUNCAPP..." -ForegroundColor Yellow
az functionapp start -g $RG -n $FUNCAPP 2>$null | Out-Null
Write-Host "      $FUNCAPP started." -ForegroundColor Green

# Step 6: Re-enable DC scheduled tasks
Write-Host "[6/6] Re-enabling DC scheduled tasks..." -ForegroundColor Yellow
schtasks /change /tn "\AD-SIDHistory-Inventory" /enable 2>$null | Out-Null
schtasks /change /tn "\AD-LSASS-Capture" /enable 2>$null | Out-Null
Write-Host "      AD-SIDHistory-Inventory + AD-LSASS-Capture enabled." -ForegroundColor Green

Write-Host "`n=== ALL RESOURCES RESUMED ===" -ForegroundColor Cyan
Write-Host "  VM IP: $ip   (dynamic - changes each start; worker uses Managed Identity, no IP wiring needed)" -ForegroundColor Yellow
Write-Host "  To pause again: Pause-Azure.ps1`n" -ForegroundColor DarkGray
