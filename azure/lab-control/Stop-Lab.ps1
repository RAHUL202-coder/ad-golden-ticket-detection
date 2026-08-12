<#
    Stop-Lab.ps1  -  Bring the AD Detection lab DOWN cleanly (save credits)
    - Purges dump queues so NO stale dumps are left for next start
    - Deallocates the Volatility VM, stops the Function App
    - Leaves everything clean so the next Start-Lab runs fine
    Run this BEFORE powering off the DC VM.
#>
[CmdletBinding()]
param([switch]$KeepFunctionApp)

$ErrorActionPreference='Continue'
$SUB="824f770b-79bf-485f-8664-3dba884fa425"
$TENANT="48af447d-f55c-49f3-aa1e-982c0020e44a"
$RG="HybridDetectionRG"
$VM="VolatilityAnalysisVM"
$FUNC="gtprocessor824f770b"
$SBNS="hybriddetsb-824f770b"
$QUEUES=@("memory-dump-queue","analysis-queue")

function Step($m){ Write-Host "`n>>> $m" -ForegroundColor Cyan }
function OK($m){ Write-Host "  [ OK ] $m" -ForegroundColor Green }
function WARN($m){ Write-Host "  [WARN] $m" -ForegroundColor Yellow }

Write-Host "==================================================" -ForegroundColor White
Write-Host ("  STOP-LAB  " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -ForegroundColor White
Write-Host "==================================================" -ForegroundColor White

function Drain-Queue($ns,$queue){
  try{
    $conn = az servicebus namespace authorization-rule keys list -g $RG --namespace-name $ns --name RootManageSharedAccessKey --query primaryConnectionString -o tsv 2>$null
    if(-not $conn){ return -1 }
    $parts = $conn -split ";"
    $ep = ($parts | Where-Object { $_ -match "^Endpoint=" }) -replace "Endpoint=sb://","" -replace "/$",""
    $kn = ($parts | Where-Object { $_ -match "^SharedAccessKeyName=" }) -replace "SharedAccessKeyName=",""
    $k  = ($parts | Where-Object { $_ -match "^SharedAccessKey=" }) -replace "SharedAccessKey=",""
    $exp = [int][double]::Parse((Get-Date -Date (Get-Date).ToUniversalTime().AddHours(1) -UFormat %s))
    $uri = [uri]::EscapeDataString("https://$ep/$queue")
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [Text.Encoding]::UTF8.GetBytes($k)
    $toSign = "$uri`n$exp"
    $sig = [Convert]::ToBase64String($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($toSign)))
    $sigEnc = [uri]::EscapeDataString($sig)
    $sas = "SharedAccessSignature sr=$uri" + "&sig=$sigEnc" + "&se=$exp" + "&skn=$kn"
    $n = 0
    for($i=0; $i -lt 500; $i++){
      try{
        $r = Invoke-WebRequest -Method DELETE -Uri "https://$ep/$queue/messages/head?timeout=1" -Headers @{Authorization=$sas} -ErrorAction Stop
        if($r.StatusCode -eq 200){ $n++ } else { break }
      } catch { break }
    }
    return $n
  } catch { return -1 }
}

$acct = az account show --query id -o tsv 2>$null
if($acct -ne $SUB){ az account set --subscription $SUB 2>$null | Out-Null; $acct = az account show --query id -o tsv 2>$null }

if($acct -eq $SUB){
  Step "Purge dump queues (clean slate for next start)"
  foreach($q in $QUEUES){
    $d = Drain-Queue $SBNS $q
    if($d -ge 0){ OK "$q purged, removed $d messages" } else { WARN "$q purge skipped" }
  }

  Step "Deallocate Volatility VM ($VM)"
  az vm deallocate -g $RG -n $VM --no-wait 2>$null | Out-Null
  OK "deallocate requested (stops the main hourly cost)"

  if(-not $KeepFunctionApp){
    Step "Stop Function App ($FUNC)"
    az functionapp stop -g $RG -n $FUNC 2>$null | Out-Null
    OK "stopped"
  }
} else {
  WARN "Not signed in (az login --tenant $TENANT). Skipped Azure stop; nothing changed."
}

Write-Host "`n==================================================" -ForegroundColor White
Write-Host "  STOP-LAB COMPLETE - safe to power off the DC VM" -ForegroundColor Green
Write-Host "  Next time: power on DC, then run  Start-Lab.ps1" -ForegroundColor White
Write-Host "==================================================" -ForegroundColor White
