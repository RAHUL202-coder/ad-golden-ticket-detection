# C:\SecurityScripts\SIDHistory-Inventory-Upload.ps1
# Runs SIDHistory scan and uploads result to Azure Blob using Arc Managed Identity
$outputFile = & "C:\SecurityScripts\SIDHistory-Inventory.ps1"
if ($outputFile -and (Test-Path $outputFile)) {
    $blobName = Split-Path $outputFile -Leaf
    # Uses Arc Managed Identity — NO hardcoded keys
    az login --identity --allow-no-subscriptions 2>&1 | Out-Null
    az storage blob upload `
        --account-name "sidhistory202605121306" `
        --container-name "sidhistory-logs" `
        --name $blobName `
        --file $outputFile `
        --auth-mode login `
        --overwrite
    Write-Host "Uploaded: $blobName to sidhistory202605121306/sidhistory-logs"
} else {
    Write-Host "No output file to upload (0 SIDHistory entries or script error)."
}
