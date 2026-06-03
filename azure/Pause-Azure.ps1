# ============================================================
# Pause-Azure.ps1
# Safely pauses all capstone resources to save free credits.
# Does NOT delete anything — safe to run anytime.
# Resume with: Resume-Azure.ps1
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
    "gt-aes-golden-ticket",
    "gt-skeleton-key",
    "gt-pass-the-hash",
    "sidhistory-high-risk-sid",
    "sidhistory-delta-detection",
    "sidhistory-privileged-logon-correlation",
    "volatility-high-risk-memory"
)

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  PAUSING AZURE RESOURCES — SAVING CREDITS " -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# ── Step 1: Deallocate Volatility VM ─────────────────────────
Write-Host "[1/4] Checking VolatilityAnalysisVM..." -ForegroundColor Yellow
$vmState = az vm show -g $RG -n $VM --show-details --query "powerState" -o tsv 2>$null

if ($vmState -eq "VM running") {
    Write-Host "      VM is running. Deallocating (this stops compute billing)..." -ForegroundColor Yellow
    az vm deallocate -g $RG -n $VM
    Write-Host "      VolatilityAnalysisVM deallocated. Saves ~Rs.8/hour." -ForegroundColor Green
} else {
    Write-Host "      VolatilityAnalysisVM is already stopped. No action needed." -ForegroundColor Green
}

# ── Step 2: Remove DCR Association to halt Log Analytics ingestion ───────────
# WHY: AMA v1.42.0.0 runs as Arc-managed processes (MonAgentCore/Host/Launcher/Manager),
#      not as a Windows service — Stop-Service has no effect.
#      Deleting the DCR association tells AMA to collect nothing, stopping ingestion billing.
Write-Host ""
Write-Host "[2/4] Removing DCR association to halt Log Analytics ingestion..." -ForegroundColor Yellow
$arcResource = "/subscriptions/76e0ae82-1f95-44ed-a9af-13a1df28a08c/resourceGroups/HybridDetectionRG/providers/Microsoft.HybridCompute/machines/WIN-09GD99A8DPG"
$assocExists = az monitor data-collection rule association show --name DCR-DC-Association --resource $arcResource -o tsv 2>$null
if ($assocExists) {
    az monitor data-collection rule association delete --name DCR-DC-Association --resource $arcResource --yes 2>$null
    Write-Host "      DCR-DC-Association deleted. AMA will collect no events." -ForegroundColor Green
    Write-Host "      Sentinel will stop receiving new events (saves Log Analytics ingestion cost)." -ForegroundColor Green
} else {
    Write-Host "      DCR-DC-Association not found — ingestion already halted." -ForegroundColor Green
}

# ── Step 3: Disable Sentinel Analytics Rules ─────────────────
# WHY: Scheduled analytics rules run queries on the workspace on a timer.
#      Disabling them prevents unnecessary query execution costs while paused.
Write-Host ""
Write-Host "[3/4] Disabling Sentinel Analytics Rules..." -ForegroundColor Yellow
$failedRules = @()
foreach ($rule in $rules) {
    $result = az sentinel alert-rule update `
        --resource-group $RG `
        --workspace-name $WORKSPACE `
        --rule-id $rule `
        --enabled false 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "      Disabled: $rule" -ForegroundColor Green
    } else {
        Write-Host "      Could not disable: $rule (may already be off)" -ForegroundColor DarkGray
        $failedRules += $rule
    }
}

# ── Step 4: Stop Function App ────────────────────────────────
# WHY: Function App on consumption plan is cheap but stopping it
#      prevents any accidental triggered runs while resources are paused.
Write-Host ""
Write-Host "[4/4] Stopping Function App..." -ForegroundColor Yellow
az functionapp stop -g $RG -n $FUNCAPP 2>$null
Write-Host "      GoldenTicketProcessor stopped." -ForegroundColor Green

# ── Save state for resume script ─────────────────────────────
$state = @{
    PausedAt      = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    VMWasRunning  = ($vmState -eq "VM running")
    RulesDisabled = $rules
    FailedRules   = $failedRules
}
$state | ConvertTo-Json | Out-File $STATE_FILE -Encoding utf8

# ── Summary ──────────────────────────────────────────────────
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  ALL RESOURCES PAUSED SUCCESSFULLY         " -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  What is still running (minimal cost):" -ForegroundColor White
Write-Host "    - Log Analytics Workspace  (base charge ~Rs.0/day if no ingestion)" -ForegroundColor DarkGray
Write-Host "    - Service Bus Namespace    (~Rs.0.70/day base)" -ForegroundColor DarkGray
Write-Host "    - Storage Accounts         (~Rs.0.10/day)" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  What is stopped (no charges):" -ForegroundColor White
Write-Host "    - VolatilityAnalysisVM     DEALLOCATED (Volatility worker stops with VM)" -ForegroundColor Green
Write-Host "    - DCR-DC-Association        DELETED (AMA collects nothing)" -ForegroundColor Green
Write-Host "    - Sentinel Analytics Rules DISABLED" -ForegroundColor Green
Write-Host "    - GoldenTicketProcessor    STOPPED" -ForegroundColor Green
Write-Host ""
Write-Host "  Run Resume-Azure.ps1 on your Desktop when ready to work again." -ForegroundColor Yellow
Write-Host "  State saved to: $STATE_FILE" -ForegroundColor DarkGray
Write-Host ""
