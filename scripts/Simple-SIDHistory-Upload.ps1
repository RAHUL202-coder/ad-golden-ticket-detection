param(
    [string]$StorageAccountName,
    [string]$ContainerName = "sidhistory-logs"
)

$scriptPath = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "SIDHistory-Inventory.ps1"
$outputFile = & $scriptPath

if (Test-Path $outputFile) {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $blobName = "sidhistory-$timestamp.json"
    
    if ($StorageAccountName) {
        Write-Host "Uploading to Azure Blob Storage..."
        az storage blob upload --account-name $StorageAccountName --container-name $ContainerName --name $blobName --file $outputFile --auth-mode login
        
        if ($?) {
            Write-Host "File uploaded successfully: $blobName"
            Remove-Item $outputFile -Force
        } else {
            Write-Error "Failed to upload $outputFile"
        }
    } else {
        Write-Host "Storage account not provided. File remains locally at $outputFile"
    }
} else {
    Write-Error "Output file not found: $outputFile"
}
