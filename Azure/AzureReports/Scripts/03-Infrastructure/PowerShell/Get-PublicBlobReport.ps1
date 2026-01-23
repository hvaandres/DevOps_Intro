<#
.SYNOPSIS
    Detects publicly accessible blob containers in Azure Storage Accounts.

.DESCRIPTION
    This script scans all storage accounts and identifies containers with public access enabled.
    Public containers pose a security risk as they can be accessed without authentication.

.PARAMETER ExportPath
    Optional. The path where the CSV report will be saved. Defaults to current directory.

.EXAMPLE
    .\Get-PublicBlobReport.ps1

.NOTES
    Author: Azure Security Audit Team
    Requirements:
    - Az.Storage PowerShell module
    - Permissions: Storage Account Contributor or Reader
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ExportPath = "."
)

try {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Public Blob Container Detection" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $context = Get-AzContext
    if (-not $context) { Connect-AzAccount }

    $storageAccounts = Get-AzStorageAccount
    Write-Host "Scanning $($storageAccounts.Count) storage accounts...`n" -ForegroundColor Yellow

    $reportData = @()
    $publicContainersFound = 0

    foreach ($sa in $storageAccounts) {
        Write-Host "  Checking: $($sa.StorageAccountName)..." -ForegroundColor Gray
        
        try {
            $storageContext = New-AzStorageContext -StorageAccountName $sa.StorageAccountName -UseConnectedAccount -ErrorAction SilentlyContinue
            
            if ($storageContext) {
                $containers = Get-AzStorageContainer -Context $storageContext -ErrorAction SilentlyContinue
                
                foreach ($container in $containers) {
                    if ($container.PublicAccess -ne 'Off') {
                        $publicContainersFound++
                        
                        $reportData += [PSCustomObject]@{
                            StorageAccount = $sa.StorageAccountName
                            ResourceGroup = $sa.ResourceGroupName
                            Location = $sa.Location
                            ContainerName = $container.Name
                            PublicAccessLevel = $container.PublicAccess
                            LastModified = $container.LastModified
                            HasLease = $container.LeaseStatus
                            Risk = if ($container.PublicAccess -eq 'Container') { "HIGH" } else { "MEDIUM" }
                            Recommendation = "Set PublicAccess to Off"
                        }
                    }
                }
            }
        }
        catch {
            Write-Host "    Warning: Could not access $($sa.StorageAccountName)" -ForegroundColor Yellow
        }
    }

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Detection Summary" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    if ($publicContainersFound -eq 0) {
        Write-Host "No public containers found!" -ForegroundColor Green
    }
    else {
        Write-Host "Found $publicContainersFound public containers!" -ForegroundColor Red
        
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  Public Containers Detected" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Red
        
        $reportData | Format-Table StorageAccount, ContainerName, PublicAccessLevel, Risk -AutoSize
    }

    # Export
    if ($reportData.Count -gt 0) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $reportPath = Join-Path $ExportPath "PublicBlobs_Report_$timestamp.csv"
        $reportData | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8
        
        Write-Host "`nReport saved to: $reportPath" -ForegroundColor Green
    }

    Write-Host "`nRecommendations:" -ForegroundColor Cyan
    Write-Host "  1. Set container PublicAccess to 'Off'" -ForegroundColor White
    Write-Host "  2. Use SAS tokens for temporary access" -ForegroundColor White
    Write-Host "  3. Implement Azure AD authentication`n" -ForegroundColor White
}
catch {
    Write-Host "`nError: $_" -ForegroundColor Red
    exit 1
}
