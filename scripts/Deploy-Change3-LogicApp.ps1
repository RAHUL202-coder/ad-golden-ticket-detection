
# Deploy-Change3-LogicApp.ps1
# Adds event-triggered LSASS capture to the SentinelResponsePlaybook Logic App.
# When a Golden Ticket incident fires, immediately runs Capture-LSASS.ps1 on the DC via Arc Run Command.
# Run as: powershell.exe -ExecutionPolicy Bypass -File ".\Deploy-Change3-LogicApp.ps1"

param([switch]$Rollback)

$SUB = "76e0ae82-1f95-44ed-a9af-13a1df28a08c"
$RG  = "HybridDetectionRG"
$ARC = "WIN-09GD99A8DPG"

Write-Host "=== Change 3: Event-Triggered LSASS Dump via Logic App ===" -ForegroundColor Cyan

$token = (az account get-access-token --query accessToken -o tsv)
if (-not $token) { Write-Error "az login required"; exit 1 }
$h = @{"Authorization"="Bearer $token"; "Content-Type"="application/json"}

$laUrl = "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Logic/workflows/SentinelResponsePlaybook?api-version=2019-05-01"

# ── ROLLBACK ──────────────────────────────────────────────────────────────────
if ($Rollback) {
    Write-Host "Rolling back: removing Trigger_LSASS_Capture_If_GT action..." -ForegroundColor Yellow
    $la = Invoke-RestMethod -Method GET -Uri $laUrl -Headers $h
    $la.properties.definition.actions.PSObject.Properties.Remove("Trigger_LSASS_Capture_If_GT")
    $rb = @{ location="eastus"; identity=$la.identity; properties=@{ definition=$la.properties.definition; parameters=$la.properties.parameters } } | ConvertTo-Json -Depth 30
    Invoke-RestMethod -Method PUT -Uri $laUrl -Headers $h -Body $rb | Out-Null
    Write-Host "Rollback complete." -ForegroundColor Green
    exit 0
}

# ── STEP 1: Ensure Logic App has System-Assigned Managed Identity ─────────────
Write-Host ""
Write-Host "[Step 1] Checking Logic App MSI..." -ForegroundColor Cyan
$la = Invoke-RestMethod -Method GET -Uri $laUrl -Headers $h

if ($la.identity -and $la.identity.type -match "SystemAssigned") {
    $MSI_PRINCIPAL = $la.identity.principalId
    Write-Host "  MSI already enabled. PrincipalId: $MSI_PRINCIPAL" -ForegroundColor Green
} else {
    Write-Host "  Enabling System-Assigned MSI on SentinelResponsePlaybook..."
    az logic workflow identity assign --name SentinelResponsePlaybook -g $RG --identities "[system]" | Out-Null
    Start-Sleep -Seconds 5
    $la = Invoke-RestMethod -Method GET -Uri $laUrl -Headers $h
    $MSI_PRINCIPAL = $la.identity.principalId
    Write-Host "  MSI enabled. PrincipalId: $MSI_PRINCIPAL" -ForegroundColor Green
}

# ── STEP 2: Assign Arc role to MSI (scoped to Arc machine only) ───────────────
Write-Host ""
Write-Host "[Step 2] Checking role assignment on Arc machine..." -ForegroundColor Cyan
$ARC_SCOPE = "/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.HybridCompute/machines/$ARC"
$roleCount = az role assignment list --assignee $MSI_PRINCIPAL --scope $ARC_SCOPE --query "length(@)" -o tsv 2>$null
if ([int]$roleCount -gt 0) {
    Write-Host "  Role already assigned on Arc scope." -ForegroundColor Green
} else {
    Write-Host "  Assigning Azure Connected Machine Resource Administrator to MSI..."
    az role assignment create `
        --role "Azure Connected Machine Resource Administrator" `
        --assignee $MSI_PRINCIPAL `
        --scope $ARC_SCOPE | Out-Null
    Write-Host "  Role assigned. Allow 1-2 min for propagation before testing." -ForegroundColor Green
}

# ── STEP 3: Add Arc Run Command action to Logic App definition ────────────────
Write-Host ""
Write-Host "[Step 3] Updating Logic App definition..." -ForegroundColor Cyan

$la = Invoke-RestMethod -Method GET -Uri $laUrl -Headers $h

if ($la.properties.definition.actions.PSObject.Properties["Trigger_LSASS_Capture_If_GT"]) {
    Write-Host "  Action already exists - removing to redeploy..." -ForegroundColor Yellow
    $la.properties.definition.actions.PSObject.Properties.Remove("Trigger_LSASS_Capture_If_GT")
}

# Store Logic App action as a JSON here-string to avoid PS 5.1 parsing @{} and ?['key'] as PS syntax.
# The strings like @{triggerBody()?['alertRuleName']} are Logic App expressions, not PowerShell.
$newActionJson = @'
{
  "runAfter": {},
  "type": "If",
  "expression": {
    "and": [
      {
        "contains": [
          "@{triggerBody()?['alertRuleName']}",
          "gt-"
        ]
      }
    ]
  },
  "actions": {
    "Arc_Run_LSASS_Capture": {
      "runAfter": {},
      "type": "Http",
      "inputs": {
        "method": "PUT",
        "uri": "@{concat('https://management.azure.com/subscriptions/76e0ae82-1f95-44ed-a9af-13a1df28a08c/resourceGroups/HybridDetectionRG/providers/Microsoft.HybridCompute/machines/WIN-09GD99A8DPG/runCommands/EventCapture-',replace(utcNow(),':','-'),'?api-version=2023-10-03-preview')}",
        "headers": {
          "Content-Type": "application/json"
        },
        "body": {
          "location": "eastus",
          "properties": {
            "source": {
              "script": "C:\\SecurityScripts\\Capture-LSASS.ps1 -UploadToBlob -StorageAccount memorydumps202605121306 -Container artifacts"
            },
            "runAsSystem": true,
            "timeoutInSeconds": 300,
            "asyncExecution": true
          }
        },
        "authentication": {
          "type": "ManagedServiceIdentity",
          "audience": "https://management.azure.com/"
        }
      }
    }
  },
  "else": {
    "actions": {}
  }
}
'@

$newActionObj = $newActionJson | ConvertFrom-Json
$la.properties.definition.actions | Add-Member -NotePropertyName "Trigger_LSASS_Capture_If_GT" -NotePropertyValue $newActionObj -Force

$putBody = @{
    location   = "eastus"
    identity   = $la.identity
    properties = @{ definition = $la.properties.definition; parameters = $la.properties.parameters }
} | ConvertTo-Json -Depth 30

$result = Invoke-RestMethod -Method PUT -Uri $laUrl -Headers $h -Body $putBody
Write-Host "  Logic App updated. State: $($result.properties.state)" -ForegroundColor Green
$actionNames = ($result.properties.definition.actions.PSObject.Properties | Select-Object -ExpandProperty Name) -join ", "
Write-Host "  Actions: $actionNames"

# ── STEP 4: Test by POSTing a fake Golden Ticket incident ─────────────────────
Write-Host ""
Write-Host "[Step 4] Testing with fake GT incident..." -ForegroundColor Cyan

$cbUrl = "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Logic/workflows/SentinelResponsePlaybook/triggers/manual/listCallbackUrl?api-version=2019-05-01"
$cb = Invoke-RestMethod -Method POST -Uri $cbUrl -Headers $h
$triggerUrl = $cb.value

$ts = Get-Date -Format "yyyyMMddHHmmss"
$fakePayload = "{`"incidentId`":`"test-$ts`",`"incidentName`":`"TEST: Golden Ticket - RC4 Downgrade`",`"severity`":`"High`",`"alertRuleName`":`"gt-rc4-downgrade`",`"description`":`"Automated test for event-triggered LSASS capture`"}"

try {
    Invoke-RestMethod -Method POST -Uri $triggerUrl -Body $fakePayload -ContentType "application/json" | Out-Null
    Write-Host "  Trigger fired. Waiting 20 seconds for run to complete..." -ForegroundColor Green
    Start-Sleep -Seconds 20
} catch {
    Write-Warning "  Trigger call failed: $_"
    Write-Host "  If MSI role was just assigned, wait 2 min for propagation and re-run." -ForegroundColor Yellow
}

# Check run history
$runsUrl = "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Logic/workflows/SentinelResponsePlaybook/runs?api-version=2019-05-01&`$top=1"
$run = (Invoke-RestMethod -Method GET -Uri $runsUrl -Headers $h).value[0]
$runStatus = $run.properties.status
Write-Host "  Latest run status: $runStatus"
if ($runStatus -eq "Succeeded") {
    Write-Host "  [PASS] Logic App run succeeded." -ForegroundColor Green
} elseif ($runStatus -eq "Failed") {
    Write-Host "  [FAIL] Run failed - check Azure Portal > Logic Apps > SentinelResponsePlaybook > Runs for details." -ForegroundColor Red
} else {
    Write-Host "  Run in state: $runStatus - may still be in progress." -ForegroundColor Yellow
}

# Check if Arc Run Command was created
Write-Host ""
Write-Host "  Checking Arc Run Commands (allow 90s for async dump to reach Succeeded)..."
$rcUrl = "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.HybridCompute/machines/$ARC/runCommands?api-version=2023-10-03-preview"
$rcs = (Invoke-RestMethod -Method GET -Uri $rcUrl -Headers $h).value | Where-Object { $_.name -like "EventCapture-*" }
if ($rcs.Count -gt 0) {
    $latest = $rcs | Sort-Object { $_.name } -Descending | Select-Object -First 1
    Write-Host "  Latest EventCapture command: $($latest.name) - $($latest.properties.provisioningState)" -ForegroundColor Green
} else {
    Write-Host "  No EventCapture run commands found yet. Check again in 30s or inspect Logic App run history." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Deploy-Change3 complete ===" -ForegroundColor Cyan
Write-Host "Rollback if needed: powershell.exe -File Deploy-Change3-LogicApp.ps1 -Rollback"
