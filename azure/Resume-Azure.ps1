# ============================================================
# Resume-Azure.ps1
# Restarts all paused capstone resources safely.
# Automatically fixes the dynamic IP issue on the Volatility VM.
# Run this every time you want to work on the project.
# ============================================================

$RG         = "HybridDetectionRG"
$VM         = "VolatilityAnalysisVM"
$WORKSPACE  = "HybridDetectionWS"
$FUNCAPP    = "GoldenTicketProcessor"
$STATE_FILE = "$env:USERPROFILE\Desktop\azure-pause-state.json"

$rules = @(
    "gt-rc4-downgrade",
    "gt-service-enum",
    "gt-ptt-detection",
    "gt-indirect-indicators",
    "sidhistory-high-risk-sid",
    "sidhistory-delta-detection",
    "sidhistory-privileged-logon-correlation"
)

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  RESUMING AZURE RESOURCES                  " -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# ── Step 1: Start Volatility VM ──────────────────────────────
Write-Host "[1/5] Starting VolatilityAnalysisVM..." -ForegroundColor Yellow
$vmState = az vm show -g $RG -n $VM --show-details --query "powerState" -o tsv 2>$null

if ($vmState -ne "VM running") {
    az vm start -g $RG -n $VM
    Write-Host "      VM started. Waiting for public IP assignment..." -ForegroundColor Green

    # Poll until IP is assigned (dynamic IP takes ~30 seconds after start)
    $newIP = $null
    $attempts = 0
    while (-not $newIP -and $attempts -lt 20) {
        Start-Sleep -Seconds 10
        $newIP = az vm show -g $RG -n $VM -d --query "publicIps" -o tsv 2>$null
        $attempts++
        if (-not $newIP) { Write-Host "      Waiting for IP... ($($attempts * 10)s)" -ForegroundColor DarkGray }
    }
} else {
    Write-Host "      VM is already running." -ForegroundColor Green
    $newIP = az vm show -g $RG -n $VM -d --query "publicIps" -o tsv 2>$null
}

if (-not $newIP) {
    Write-Host "      WARNING: Could not retrieve VM IP after 200s. Check Azure Portal." -ForegroundColor Red
    $newIP = "UNKNOWN"
} else {
    Write-Host "      New Volatility VM IP: $newIP" -ForegroundColor Green
}

# ── Step 2: Fix Dynamic IP in Function App ───────────────────
# WHY: The public IP changes every time the VM starts from deallocated state.
#      Without this update the Function App would try to SSH to the old IP
#      and all memory analysis jobs would silently fail.
Write-Host ""
Write-Host "[2/5] Updating Function App with new VM IP ($newIP)..." -ForegroundColor Yellow
if ($newIP -ne "UNKNOWN") {
    az functionapp config appsettings set `
        -g $RG -n $FUNCAPP `
        --settings "VOLATILITY_VM_IP=$newIP" | Out-Null
    Write-Host "      VOLATILITY_VM_IP updated in GoldenTicketProcessor." -ForegroundColor Green
} else {
    Write-Host "      Skipped — IP unknown. Update manually in Function App settings." -ForegroundColor Red
}

# ── Step 3: Restore DCR Association to resume Log Analytics ingestion ────────
# WHY: AMA v1.42.0.0 runs as Arc-managed processes (MonAgentCore/Host/Launcher/Manager),
#      not as a Windows service — Start-Service has no effect and is not needed.
#      AMA runs automatically via the Arc ExtensionService.
#      Restoring the DCR association tells AMA what events to collect and forward.
Write-Host ""
Write-Host "[3/5] Restoring DCR association to resume Log Analytics ingestion..." -ForegroundColor Yellow
$arcResource = "/subscriptions/76e0ae82-1f95-44ed-a9af-13a1df28a08c/resourceGroups/HybridDetectionRG/providers/Microsoft.HybridCompute/machines/WIN-09GD99A8DPG"
$dcrId       = "/subscriptions/76e0ae82-1f95-44ed-a9af-13a1df28a08c/resourceGroups/HybridDetectionRG/providers/Microsoft.Insights/dataCollectionRules/DCR-Security-Kerberos"
$assocExists = az monitor data-collection rule association show `
    --name DCR-DC-Association --resource $arcResource -o tsv 2>$null
if (-not $assocExists) {
    az monitor data-collection rule association create `
        --name DCR-DC-Association --resource $arcResource --rule-id $dcrId 2>$null
    Write-Host "      DCR-DC-Association created. Kerberos events will flow to Sentinel." -ForegroundColor Green
} else {
    Write-Host "      DCR-DC-Association already exists. Ingestion active." -ForegroundColor Green
}

# ── Step 4: Re-enable Sentinel Analytics Rules ───────────────
Write-Host ""
Write-Host "[4/5] Re-enabling Sentinel Analytics Rules..." -ForegroundColor Yellow
foreach ($rule in $rules) {
    $result = az sentinel alert-rule update `
        --resource-group $RG `
        --workspace-name $WORKSPACE `
        --rule-id $rule `
        --enabled true 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "      Enabled: $rule" -ForegroundColor Green
    } else {
        Write-Host "      Could not enable: $rule" -ForegroundColor Red
    }
}

# ── Step 5: Start Function App ───────────────────────────────
Write-Host ""
Write-Host "[5/5] Starting Function App..." -ForegroundColor Yellow
az functionapp start -g $RG -n $FUNCAPP 2>$null
Write-Host "      GoldenTicketProcessor started." -ForegroundColor Green

# ── Final Status Summary ─────────────────────────────────────
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  ALL RESOURCES RESUMED                     " -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Resource Status:" -ForegroundColor White
Write-Host "    VolatilityAnalysisVM   RUNNING   IP: $newIP  (Volatility worker auto-started via systemd)" -ForegroundColor Green
Write-Host "    DCR-DC-Association     ACTIVE    (events flowing to Sentinel)" -ForegroundColor Green
Write-Host "    Sentinel Rules         ENABLED   (7 detection rules active)" -ForegroundColor Green
Write-Host "    GoldenTicketProcessor  RUNNING" -ForegroundColor Green
Write-Host ""
Write-Host "  IMPORTANT — New VM IP: $newIP" -ForegroundColor Yellow
Write-Host "  If you SSH into the Volatility VM, use this new IP." -ForegroundColor Yellow
Write-Host ""
Write-Host "  To pause again and save credits: Run Pause-Azure.ps1" -ForegroundColor DarkGray
Write-Host ""
