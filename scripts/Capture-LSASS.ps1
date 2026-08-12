# C:\SecurityScripts\Capture-LSASS.ps1
# Purpose: Capture LSASS memory dump and upload to Azure Blob using Arc Managed Identity
param([switch]$UploadToBlob, [string]$StorageAccount = "memorydumps202605121306", [string]$Container = "artifacts")

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$dumpDir = "C:\SecurityLogs\Memory"
$dumpPath = Join-Path $dumpDir "lsass_$timestamp.dmp"
if (-not (Test-Path $dumpDir)) { New-Item -ItemType Directory -Path $dumpDir -Force | Out-Null }

try {
    $lsassProcess = Get-Process lsass -ErrorAction Stop
    $processId = $lsassProcess.Id
    rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump $processId $dumpPath full
    Start-Sleep -Seconds 3
    if (-not (Test-Path $dumpPath)) { throw "Dump file not created — check AV exclusions and permissions" }
    $sizeMB = [math]::Round((Get-Item $dumpPath).Length / 1MB, 1)
    Write-Host "LSASS captured: $dumpPath ($sizeMB MB)"
} catch {
    Write-Error "LSASS capture failed: $_"; exit 1
}

if ($UploadToBlob) {
    try {
        $blobName = "lsass_$timestamp.dmp"
        az login --identity --allow-no-subscriptions 2>&1 | Out-Null
        az storage blob upload `
            --account-name $StorageAccount `
            --container-name $Container `
            --name $blobName `
            --file $dumpPath `
            --auth-mode login `
            --max-connections 4 `
            --overwrite
        Write-Host "Uploaded: $blobName"
        Remove-Item $dumpPath -Force
        Write-Host "Local dump removed after upload."
    } catch {
        Write-Error "Upload failed: $_"
        Write-Warning "Local dump retained: $dumpPath"
    }
}
