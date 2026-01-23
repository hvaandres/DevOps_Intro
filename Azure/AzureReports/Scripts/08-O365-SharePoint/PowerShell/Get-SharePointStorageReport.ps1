<#
.SYNOPSIS
    Reports storage usage for all SharePoint sites.

.DESCRIPTION
    This script analyzes storage usage across SharePoint Online sites,
    identifies sites approaching quota limits, and provides capacity planning insights.

.PARAMETER ExportPath
    Optional. The path where the CSV report will be saved. Defaults to current directory.

.PARAMETER WarningThreshold
    Optional. Percentage threshold for storage warning. Default is 80%.

.EXAMPLE
    .\Get-SharePointStorageReport.ps1

.EXAMPLE
    .\Get-SharePointStorageReport.ps1 -WarningThreshold 75

.NOTES
    Author: Azure Security Audit Team
    Requirements:
    - Microsoft.Online.SharePoint.PowerShell module
    - Permissions: SharePoint Administrator or Global Administrator
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ExportPath = ".",
    
    [Parameter(Mandatory=$false)]
    [int]$WarningThreshold = 80
)

function Test-RequiredModule {
    param([string]$ModuleName)
    
    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        Write-Host "Installing $ModuleName module..." -ForegroundColor Yellow
        Install-Module -Name $ModuleName -Force -AllowClobber -Scope CurrentUser
    }
    
    if (-not (Get-Module -Name $ModuleName)) {
        Import-Module $ModuleName -ErrorAction Stop
    }
}

try {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  SharePoint Site Storage Usage Report" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    # Ensure required modules are available
    Test-RequiredModule -ModuleName "Microsoft.Online.SharePoint.PowerShell"

    # Get tenant URL
    $tenantName = Read-Host "Enter your SharePoint tenant name (e.g., contoso)"
    $adminUrl = "https://$tenantName-admin.sharepoint.com"

    # Connect to SharePoint Online
    Write-Host "Connecting to SharePoint Online..." -ForegroundColor Yellow
    Connect-SPOService -Url $adminUrl -ErrorAction Stop
    Write-Host "Connected successfully.`n" -ForegroundColor Green

    # Get all sites
    Write-Host "Fetching site collections and storage data..." -ForegroundColor Yellow
    $sites = Get-SPOSite -Limit All -IncludePersonalSite $true
    Write-Host "Found $($sites.Count) sites (including OneDrive). Analyzing storage...`n" -ForegroundColor Green

    $storageData = @()
    $counter = 0

    foreach ($site in $sites) {
        $counter++
        Write-Progress -Activity "Analyzing Site Storage" -Status $site.Title -PercentComplete (($counter / $sites.Count) * 100)
        
        # Calculate storage metrics
        $storageUsedGB = [math]::Round($site.StorageUsageCurrent / 1024, 2)
        $storageQuotaGB = [math]::Round($site.StorageQuota / 1024, 2)
        $storageWarningGB = [math]::Round($site.StorageWarning / 1024, 2)
        
        $percentUsed = if ($site.StorageQuota -gt 0) {
            [math]::Round(($site.StorageUsageCurrent / $site.StorageQuota) * 100, 2)
        } else { 0 }
        
        $remainingGB = $storageQuotaGB - $storageUsedGB
        
        # Determine status
        $status = "Normal"
        if ($percentUsed -ge 95) {
            $status = "Critical - Nearly Full"
        }
        elseif ($percentUsed -ge $WarningThreshold) {
            $status = "Warning - High Usage"
        }
        elseif ($site.StorageQuota -eq 0) {
            $status = "No Quota Set"
        }
        
        # Identify site type
        $siteType = "Team Site"
        if ($site.Template -like "*SPSPERS*") {
            $siteType = "OneDrive"
        }
        elseif ($site.Template -like "*STS*") {
            $siteType = "Team Site"
        }
        elseif ($site.Template -like "*SITEPAGEPUBLISHING*") {
            $siteType = "Communication Site"
        }
        elseif ($site.Template -like "*GROUP*") {
            $siteType = "Microsoft 365 Group"
        }
        
        $storageData += [PSCustomObject]@{
            SiteUrl = $site.Url
            Title = $site.Title
            Owner = $site.Owner
            SiteType = $siteType
            Template = $site.Template
            StorageUsedGB = $storageUsedGB
            StorageQuotaGB = $storageQuotaGB
            StorageWarningGB = $storageWarningGB
            RemainingGB = $remainingGB
            PercentUsed = $percentUsed
            Status = $status
            LastContentModified = $site.LastContentModifiedDate
            LockState = $site.LockState
        }
    }

    Write-Progress -Activity "Analyzing Site Storage" -Completed

    # Summary Statistics
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Storage Usage Summary" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $totalUsedGB = ($storageData | Measure-Object -Property StorageUsedGB -Sum).Sum
    $totalQuotaGB = ($storageData | Measure-Object -Property StorageQuotaGB -Sum).Sum
    $avgPercentUsed = ($storageData | Measure-Object -Property PercentUsed -Average).Average
    
    $criticalSites = $storageData | Where-Object { $_.PercentUsed -ge 95 }
    $warningSites = $storageData | Where-Object { $_.PercentUsed -ge $WarningThreshold -and $_.PercentUsed -lt 95 }
    $oneDriveSites = $storageData | Where-Object { $_.SiteType -eq "OneDrive" }

    Write-Host "Total Sites:                     $($storageData.Count)" -ForegroundColor White
    Write-Host "Total Storage Used:              $([math]::Round($totalUsedGB, 2)) GB" -ForegroundColor Yellow
    Write-Host "Total Storage Quota:             $([math]::Round($totalQuotaGB, 2)) GB" -ForegroundColor White
    Write-Host "Average Usage:                   $([math]::Round($avgPercentUsed, 2))%" -ForegroundColor Cyan
    Write-Host "`nStorage Alerts:" -ForegroundColor Cyan
    Write-Host "  - Critical (95%+):             $($criticalSites.Count)" -ForegroundColor Red
    Write-Host "  - Warning ($WarningThreshold%+):             $($warningSites.Count)" -ForegroundColor Yellow

    # Critical storage sites
    if ($criticalSites.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  CRITICAL: Sites Nearly Out of Storage" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Red
        
        $criticalSites | Sort-Object -Property PercentUsed -Descending |
            Select-Object Title, SiteType, StorageUsedGB, StorageQuotaGB, PercentUsed |
            Format-Table -AutoSize
    }

    # Warning sites
    if ($warningSites.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Yellow
        Write-Host "  WARNING: Sites with High Storage Usage (First 15)" -ForegroundColor Yellow
        Write-Host "========================================`n" -ForegroundColor Yellow
        
        $warningSites | Sort-Object -Property PercentUsed -Descending |
            Select-Object Title, SiteType, StorageUsedGB, PercentUsed -First 15 |
            Format-Table -AutoSize
    }

    # Top 20 storage consumers
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Top 20 Storage Consumers" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    $storageData | Sort-Object -Property StorageUsedGB -Descending |
        Select-Object Title, SiteType, StorageUsedGB, PercentUsed, Owner -First 20 |
        Format-Table -AutoSize

    # Storage by site type
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Storage Usage by Site Type" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    $storageData | Group-Object -Property SiteType |
        Select-Object Name, Count, @{Name="TotalGB";Expression={[math]::Round(($_.Group | Measure-Object -Property StorageUsedGB -Sum).Sum, 2)}} |
        Sort-Object TotalGB -Descending |
        Format-Table -AutoSize

    # OneDrive statistics
    if ($oneDriveSites.Count -gt 0) {
        $oneDriveTotalGB = ($oneDriveSites | Measure-Object -Property StorageUsedGB -Sum).Sum
        $oneDriveAvgGB = ($oneDriveSites | Measure-Object -Property StorageUsedGB -Average).Average
        
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "  OneDrive Storage Statistics" -ForegroundColor Cyan
        Write-Host "========================================`n" -ForegroundColor Cyan
        
        Write-Host "OneDrive Sites:                  $($oneDriveSites.Count)" -ForegroundColor White
        Write-Host "Total OneDrive Storage:          $([math]::Round($oneDriveTotalGB, 2)) GB" -ForegroundColor Yellow
        Write-Host "Average per User:                $([math]::Round($oneDriveAvgGB, 2)) GB" -ForegroundColor Cyan
        
        # Top OneDrive users
        Write-Host "`nTop 10 OneDrive Users by Storage:" -ForegroundColor Cyan
        $oneDriveSites | Sort-Object -Property StorageUsedGB -Descending |
            Select-Object Owner, StorageUsedGB, PercentUsed -First 10 |
            Format-Table -AutoSize
    }

    # Inactive sites with storage
    $inactiveSites = $storageData | Where-Object {
        $_.LastContentModified -and
        $_.LastContentModified -lt (Get-Date).AddDays(-180) -and
        $_.StorageUsedGB -gt 1
    }
    
    if ($inactiveSites.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Yellow
        Write-Host "  Inactive Sites Using Storage (180+ days)" -ForegroundColor Yellow
        Write-Host "========================================`n" -ForegroundColor Yellow
        
        Write-Host "Count: $($inactiveSites.Count) sites" -ForegroundColor White
        $inactiveTotalGB = ($inactiveSites | Measure-Object -Property StorageUsedGB -Sum).Sum
        Write-Host "Total Storage: $([math]::Round($inactiveTotalGB, 2)) GB (potential reclamation)`n" -ForegroundColor Yellow
        
        $inactiveSites | Sort-Object -Property StorageUsedGB -Descending |
            Select-Object Title, StorageUsedGB, LastContentModified -First 10 |
            Format-Table -AutoSize
    }

    # Export
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPath = Join-Path $ExportPath "SharePointStorage_Report_$timestamp.csv"
    $storageData | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Report saved to: $reportPath" -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Green

    # Recommendations
    Write-Host "Storage Management Recommendations:" -ForegroundColor Cyan
    if ($criticalSites.Count -gt 0) {
        Write-Host "  1. [CRITICAL] Increase quota for $($criticalSites.Count) sites near capacity" -ForegroundColor Red
    }
    if ($warningSites.Count -gt 0) {
        Write-Host "  2. [HIGH] Monitor $($warningSites.Count) sites approaching limits" -ForegroundColor Yellow
    }
    if ($inactiveSites.Count -gt 0) {
        Write-Host "  3. [MEDIUM] Review $($inactiveSites.Count) inactive sites for archival ($([math]::Round($inactiveTotalGB, 2)) GB)" -ForegroundColor Yellow
    }
    Write-Host "  4. Implement site lifecycle policies" -ForegroundColor White
    Write-Host "  5. Enable version history limits" -ForegroundColor White
    Write-Host "  6. Configure recycle bin retention policies" -ForegroundColor White
    Write-Host "  7. Regular storage audits and cleanup`n" -ForegroundColor White

    Disconnect-SPOService
}
catch {
    Write-Host "`nError: $_" -ForegroundColor Red
    try { Disconnect-SPOService } catch { }
    exit 1
}
