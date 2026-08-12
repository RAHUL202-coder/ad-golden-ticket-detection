
# Deploy-Change2-SentinelRules.ps1
# Sets all 6 Sentinel analytics rules to PT5M query frequency with suppression enabled.
# Run as: powershell.exe -ExecutionPolicy Bypass -File ".\Deploy-Change2-SentinelRules.ps1"

$SUB = "76e0ae82-1f95-44ed-a9af-13a1df28a08c"
$RG  = "HybridDetectionRG"
$WS  = "HybridDetectionWS"

Write-Host "=== Change 2: Sentinel Rules to PT5M ===" -ForegroundColor Cyan

$token = (az account get-access-token --query accessToken -o tsv)
if (-not $token) { Write-Error "az login required"; exit 1 }
$h = @{"Authorization"="Bearer $token"; "Content-Type"="application/json"}

$ruleNames = @(
    "gt-rc4-downgrade",
    "gt-service-enum",
    "gt-ptt-detection",
    "sidhistory-high-risk-sid",
    "sidhistory-delta-detection",
    "sidhistory-privileged-logon-correlation"
)

$suppressionMap = @{
    "gt-rc4-downgrade"                        = "PT1H"
    "gt-service-enum"                         = "PT30M"
    "gt-ptt-detection"                        = "PT2H"
    "sidhistory-high-risk-sid"                = "PT1H"
    "sidhistory-delta-detection"              = "PT2H"
    "sidhistory-privileged-logon-correlation" = "PT1H"
}

$baseUrl = "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.OperationalInsights/workspaces/$WS/providers/Microsoft.SecurityInsights/alertRules"
$errors  = @()

foreach ($ruleName in $ruleNames) {
    $ruleUrl = "$baseUrl/$ruleName" + "?api-version=2023-02-01"

    try {
        $rule = Invoke-RestMethod -Method GET -Uri $ruleUrl -Headers $h -ErrorAction Stop
    } catch {
        Write-Warning "NOT FOUND: $ruleName"
        $errors += $ruleName
        continue
    }

    if ($rule.properties.queryFrequency -eq "PT5M" -and $rule.properties.suppressionEnabled -eq $true) {
        Write-Host "[SKIP] $ruleName already at PT5M with suppression" -ForegroundColor Green
        continue
    }

    $suppDur = $suppressionMap[$ruleName]
    $p = $rule.properties

    # Build PUT body with only writable properties (exclude lastModifiedUtc, createdTimeUtc, etc.)
    $writableProps = @{
        displayName          = $p.displayName
        enabled              = $p.enabled
        query                = $p.query
        queryFrequency       = "PT5M"
        queryPeriod          = $p.queryPeriod
        severity             = $p.severity
        triggerOperator      = $p.triggerOperator
        triggerThreshold     = $p.triggerThreshold
        suppressionEnabled   = $true
        suppressionDuration  = $suppDur
        tactics              = $p.tactics
        description          = $p.description
        incidentConfiguration = $p.incidentConfiguration
        eventGroupingSettings = $p.eventGroupingSettings
        alertDetailsOverride  = $p.alertDetailsOverride
        customDetails         = $p.customDetails
        entityMappings        = $p.entityMappings
    }
    # Remove null entries to keep body clean
    $nullKeys = @($writableProps.Keys | Where-Object { $null -eq $writableProps[$_] })
    foreach ($k in $nullKeys) { $writableProps.Remove($k) }

    $putBody = @{ kind = "Scheduled"; etag = $rule.etag; properties = $writableProps } | ConvertTo-Json -Depth 20
    $ph = $h.Clone()
    $ph["If-Match"] = $rule.etag

    try {
        Invoke-RestMethod -Method PUT -Uri $ruleUrl -Headers $ph -Body $putBody -ErrorAction Stop | Out-Null
        Write-Host "[OK] $ruleName => PT5M suppression=$suppDur" -ForegroundColor Green
    } catch {
        Write-Warning "FAIL: $ruleName - $_"
        $errors += $ruleName
    }
    Start-Sleep -Milliseconds 500
}

Write-Host ""
if ($errors.Count -eq 0) {
    Write-Host "All rules updated successfully." -ForegroundColor Green
} else {
    $failList = $errors -join " | "
    Write-Warning "Failed rules: $failList"
    Write-Host "Re-run this script to retry (etag is re-fetched each run)."
}

Write-Host ""
Write-Host "=== Verification ===" -ForegroundColor Cyan
$allRules = (Invoke-RestMethod -Method GET -Uri ($baseUrl + "?api-version=2023-02-01") -Headers $h).value
$allRules | Where-Object { $_.kind -eq "Scheduled" } |
    Select-Object `
        @{n="Rule";e={$_.name}},
        @{n="Freq";e={$_.properties.queryFrequency}},
        @{n="Supp";e={$_.properties.suppressionEnabled}},
        @{n="SuppDur";e={$_.properties.suppressionDuration}} |
    Format-Table -AutoSize
