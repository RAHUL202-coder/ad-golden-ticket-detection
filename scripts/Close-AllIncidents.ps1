
# Close-AllIncidents.ps1
# Closes all Active Sentinel incidents before a simulation run.

$SUB = "8e710d8c-465e-4d5f-92ac-800e9c7abe1a"
$RG  = "HybridDetectionRG"
$WS  = "HybridDetectionWS"

$token = (az account get-access-token --query accessToken -o tsv)
$h = @{"Authorization"="Bearer $token"; "Content-Type"="application/json"}
$baseUrl = "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.OperationalInsights/workspaces/$WS/providers/Microsoft.SecurityInsights/incidents"

$incidents = (Invoke-RestMethod -Method GET -Uri "${baseUrl}?api-version=2023-02-01&`$filter=properties/status eq 'Active'&`$top=100" -Headers $h).value
Write-Host "Found $($incidents.Count) active incidents. Closing..." -ForegroundColor Cyan

$closed = 0; $failed = 0
foreach ($inc in $incidents) {
    $body = @{
        properties = @{
            title                 = $inc.properties.title
            severity              = $inc.properties.severity
            status                = "Closed"
            classification        = "BenignPositive"
            classificationReason  = "SuspiciousButExpected"
            classificationComment = "Closed before simulation run - lab environment"
        }
    } | ConvertTo-Json -Depth 5

    try {
        Invoke-RestMethod -Method PUT -Uri "${baseUrl}/$($inc.name)?api-version=2023-02-01" -Headers $h -Body $body -ErrorAction Stop | Out-Null
        Write-Host "  [CLOSED] #$($inc.properties.incidentNumber) $($inc.properties.title)" -ForegroundColor Green
        $closed++
    } catch {
        Write-Host "  [FAIL]   #$($inc.properties.incidentNumber) $_" -ForegroundColor Red
        $failed++
    }
}

Write-Host ""
if ($failed -eq 0) {
    Write-Host "All $closed incidents closed." -ForegroundColor Green
} else {
    Write-Host "$closed closed, $failed failed." -ForegroundColor Yellow
}
