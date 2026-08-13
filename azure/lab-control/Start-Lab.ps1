<#
    Start-Lab.ps1  -  Bring the AD Detection lab UP (local DC + Azure cloud)
    - Starts Volatility VM + Function App, ensures DCR/ingestion, heals AMA
    - PURGES the old LSASS-dump backlog so ONLY fresh captures get analysed
    - Self-troubleshoots common failures
    Run this after powering on the DC VM. Safe to run repeatedly (idempotent).
#>
[CmdletBinding()]
param(
    [int]$MaxDumpAgeMin = 60,
    [switch]$FreshCapture,
    [switch]$SkipAzure
)

$ErrorActionPreference = 'Continue'
$SUB   = "824f770b-79bf-485f-8664-3dba884fa425"
$TENANT= "48af447d-f55c-49f3-aa1e-982c0020e44a"
$RG    = "HybridDetectionRG"
$WSID  = "7697ee16-3b75-4bac-9191-463241dec30d"
$VM    = "VolatilityAnalysisVM"
$FUNC  = "gtprocessor824f770b"
$SBNS  = "hybriddetsb-824f770b"
$ARC   = "WIN-09GD99A8DPG"
$DCR   = "DCR-Security-Kerberos"
$ASSOC = "dcr-dc-association"
$QUEUES= @("memory-dump-queue","analysis-queue")
$TASKS = @("\AD-LSASS-Capture","\AD-SIDHistory-Inventory")
$DASH_URL = "https://capstonedash824f.z13.web.core.windows.net/"
$DASH_LA  = "capstone-dashboard-api"   # Logic App that feeds the live dashboard

function Step($m){ Write-Host "`n>>> $m" -ForegroundColor Cyan }
function OK($m){ Write-Host "  [ OK ] $m" -ForegroundColor Green }
function WARN($m){ Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function FAIL($m){ Write-Host "  [FAIL] $m" -ForegroundColor Red }

Write-Host "==================================================" -ForegroundColor White
Write-Host ("  START-LAB  " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -ForegroundColor White
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

# ---- 0. Azure auth ----
if(-not $SkipAzure){
  Step "Azure sign-in check"
  $acct = az account show --query id -o tsv 2>$null
  if($acct -ne $SUB){ az account set --subscription $SUB 2>$null | Out-Null; $acct = az account show --query id -o tsv 2>$null }
  if($acct -eq $SUB){ OK "Signed in to $SUB" }
  else { WARN "Not signed in. Run:  az login --tenant $TENANT   then re-run."; $SkipAzure = $true }
}

if(-not $SkipAzure){
  Step "Start Volatility VM ($VM)"
  $state = az vm get-instance-view -g $RG -n $VM --query "instanceView.statuses[1].displayStatus" -o tsv 2>$null
  if($state -eq "VM running"){ OK "already running" } else { az vm start -g $RG -n $VM 2>$null | Out-Null; OK "started" }

  Step "Start Function App ($FUNC)"
  $fstate = az functionapp show -g $RG -n $FUNC --query state -o tsv 2>$null
  if($fstate -eq "Running"){ OK "already running" } else { az functionapp start -g $RG -n $FUNC 2>$null | Out-Null; OK "started" }

  Step "Ensure DCR association ($ASSOC)"
  $a = az monitor data-collection rule association list --rule-name $DCR -g $RG --query "[].name" -o tsv 2>$null
  if($a -match $ASSOC){ OK "present" }
  else{
    $arcId = "/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.HybridCompute/machines/$ARC"
    $dcrId = "/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Insights/dataCollectionRules/$DCR"
    $url = "https://management.azure.com$arcId/providers/Microsoft.Insights/dataCollectionRuleAssociations/$ASSOC" + "?api-version=2022-06-01"
    $body = '{"properties":{"dataCollectionRuleId":"' + $dcrId + '"}}'
    az rest --method put --url $url --body $body 2>$null | Out-Null
    OK "recreated"
  }
}

# ---- 4. Heal AMA / confirm ingestion ----
Step "AMA ingestion health + self-heal"
$latest = az monitor log-analytics query -w $WSID --analytics-query "SecurityEvent | summarize m=max(TimeGenerated)" --query "[0].m" -o tsv 2>$null
$freshMin = if($latest){ [int]((Get-Date).ToUniversalTime() - ([datetimeoffset]$latest).UtcDateTime).TotalMinutes } else { 99999 }
$proc = Get-Process MonAgent* -ErrorAction SilentlyContinue
if($proc -and $freshMin -le 15){ OK "AMA running, ingestion fresh ($freshMin min old)" }
else{
  $hasProc = [bool]$proc
  WARN "AMA unhealthy (procs=$hasProc, ingestion age=$freshMin min). Restarting Arc agent stack."
  foreach($s in @('GCArcService','ExtensionService','himds')){ try{ Restart-Service $s -Force -ErrorAction Stop }catch{} }
  Start-Sleep -Seconds 45
  $proc = Get-Process MonAgent* -ErrorAction SilentlyContinue
  if($proc){ $pids = ($proc | Select-Object -Expand Id) -join ','; OK "AMA processes relaunched (PIDs $pids)" }
  else{
    WARN "AMA still down. Attempting extension reinstall."
    if(-not $SkipAzure){
      az connectedmachine extension create -g $RG --machine-name $ARC -n AzureMonitorWindowsAgent --publisher Microsoft.Azure.Monitor --type AzureMonitorWindowsAgent --location eastus --enable-auto-upgrade true 2>$null | Out-Null
      Start-Sleep -Seconds 30
      $proc = Get-Process MonAgent* -ErrorAction SilentlyContinue
      if($proc){ OK "AMA reinstalled and running" } else { FAIL "AMA still down. Ensure the DC VM stays powered on (no VMware suspend)." }
    }
  }
}

# ---- 5. Scheduled tasks ----
Step "Scheduled tasks enabled"
foreach($t in $TASKS){
  schtasks /Change /TN $t /ENABLE 2>$null | Out-Null
  $stat = schtasks /query /tn $t /fo LIST 2>$null | Select-String "Status"
  if($stat){ OK "$t enabled" } else { WARN "$t not found" }
}

# ---- 6. Purge old dump backlog ----
if(-not $SkipAzure){
  Step "Purge stale dump backlog (only fresh dumps get analysed)"
  foreach($q in $QUEUES){
    $d = Drain-Queue $SBNS $q
    if($d -ge 0){ OK "$q purged, removed $d stale messages" } else { WARN "$q purge skipped" }
  }
  OK "Only NEW captures will be processed from here (target <= $MaxDumpAgeMin min old)"
}

# ---- 7. Live dashboard health ----
if(-not $SkipAzure){
  Step "Live cloud dashboard"
  $la = az resource show --ids "/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Logic/workflows/$DASH_LA" --query "properties.state" -o tsv 2>$null
  if($la -eq "Enabled"){ OK "dashboard API ($DASH_LA) Enabled" }
  elseif($la){ WARN "dashboard API state = $la (expected Enabled)" }
  else { WARN "dashboard API not found" }
  try{
    $code = (Invoke-WebRequest -Uri $DASH_URL -Method Head -TimeoutSec 15 -UseBasicParsing).StatusCode
    if($code -eq 200){ OK "dashboard site serving (HTTP 200)" } else { WARN "dashboard site HTTP $code" }
  } catch { WARN "dashboard site not reachable: $($_.Exception.Message)" }
  Write-Host "  Live dashboard: $DASH_URL" -ForegroundColor Cyan
}

# ---- 8. Optional fresh capture ----
if($FreshCapture){
  Step "Trigger one fresh LSASS capture"
  schtasks /run /tn "\AD-LSASS-Capture" 2>$null | Out-Null
  OK "capture triggered"
}

Write-Host "`n==================================================" -ForegroundColor White
Write-Host "  START-LAB COMPLETE - lab is UP" -ForegroundColor Green
Write-Host "  Live dashboard : $DASH_URL" -ForegroundColor Cyan
Write-Host "  Run  Stop-Lab.ps1  before powering off the DC VM" -ForegroundColor White
Write-Host "==================================================" -ForegroundColor White
