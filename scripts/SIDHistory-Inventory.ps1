# C:\SecurityScripts\SIDHistory-Inventory.ps1
param([switch]$Verbose, [string]$OutputPath = "C:\SecurityLogs\SIDHistory")
Import-Module ActiveDirectory -ErrorAction Stop
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

function Get-SIDRiskLevel { param([string]$SID)
    if ($SID -match "-512$" -or $SID -match "-519$" -or $SID -match "-518$") { return "HIGH" }
    if ($SID -match "-500$" -or $SID -match "-515$" -or $SID -match "-516$") { return "MEDIUM" }
    return "LOW"
}

$results = [System.Collections.Generic.List[hashtable]]::new()
$timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
try {
    $objs = Get-ADObject -Filter { sIDHistory -like "*" } -Properties sIDHistory,objectClass,distinguishedName,Name -ErrorAction Stop
} catch { Write-Error "AD query failed: $_"; exit 1 }

foreach ($obj in $objs) {
    foreach ($sidEntry in $obj.sIDHistory) {
        $sidString = $sidEntry.ToString()
        $sidName = "Unknown"
        try { $sidName = (New-Object System.Security.Principal.SecurityIdentifier($sidString)).Translate([System.Security.Principal.NTAccount]).Value } catch {}
        $results.Add(@{
            Timestamp=$timestamp; EventType="SIDHistoryInventory"; ObjectType=$obj.objectClass
            ObjectName=$obj.Name; DistinguishedName=$obj.DistinguishedName
            SIDHistoryEntry=$sidString; SIDHistoryName=$sidName
            RiskLevel=(Get-SIDRiskLevel -SID $sidString); Domain=$env:USERDNSDOMAIN; ScriptVersion="2.0"
        })
    }
}
if ($results.Count -eq 0) { Write-Host "No SIDHistory entries found."; exit 0 }
$outputFile = Join-Path $OutputPath "SIDHistory-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
$results | ConvertTo-Json -Depth 5 | Out-File -FilePath $outputFile -Encoding UTF8
Write-Host "Inventory complete: $($results.Count) entries -> $outputFile"
return $outputFile
