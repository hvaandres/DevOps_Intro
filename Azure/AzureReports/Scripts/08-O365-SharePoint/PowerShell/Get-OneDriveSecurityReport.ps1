<#
.SYNOPSIS
    Monitors OneDrive usage and security across the tenant.

.DESCRIPTION
    This script analyzes OneDrive sites for security configurations, usage patterns,
    sharing settings, and identifies potential security risks.

.PARAMETER ExportPath
    Optional. The path where the CSV report will be saved. Defaults to current directory.

.PARAMETER InactiveDaysThreshold
    Optional. Number of days to consider OneDrive inactive. Default is 90 days.

.EXAMPLE
    .\Get-OneDriveSecurityReport.ps1

.EXAMPLE
    .\Get-OneDriveSecurityReport.ps1 -InactiveDaysThreshold 60

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
    [int]$InactiveDaysThreshold = 90
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
    Write-Host "  OneDrive Usage & Security Monitoring" -ForegroundColor Cyan
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

    # Get all OneDrive sites
    Write-Host "Fetching OneDrive sites..." -ForegroundColor Yellow
    $oneDriveSites = Get-SPOSite -IncludePersonalSite $true -Limit All -Filter "Url -like '-my.sharepoint.com/personal/'"
    Write-Host "Found $($oneDriveSites.Count) OneDrive sites. Analyzing security...`n" -ForegroundColor Green

    $reportData = @()
    $counter = 0
    $cutoffDate = (Get-Date).AddDays(-$InactiveDaysThreshold)

    foreach ($site in $oneDriveSites) {
        $counter++
        Write-Progress -Activity "Analyzing OneDrive Sites" -Status $site.Owner -PercentComplete (($counter / $oneDriveSites.Count) * 100)
        
        # Extract user info from URL
        $userEmail = $site.Owner
        
        # Storage metrics
        $storageUsedGB = [math]::Round($site.StorageUsageCurrent / 1024, 2)
        $storageQuotaGB = [math]::Round($site.StorageQuota / 1024, 2)
        $percentUsed = if ($site.StorageQuota -gt 0) {
            [math]::Round(($site.StorageUsageCurrent / $site.StorageQuota) * 100, 2)
        } else { 0 }
        
        # Activity analysis
        $lastModified = $site.LastContentModifiedDate
        $isInactive = $false
        $daysSinceModified = $null
        
        if ($lastModified) {
            $daysSinceModified = (New-TimeSpan -Start $lastModified -End (Get-Date)).Days
            $isInactive = ($lastModified -lt $cutoffDate)
        }
        
        # Risk scoring
        $riskScore = 0
        $riskFactors = @()
        $securityIssues = @()
        
        # External sharing enabled
        if ($site.SharingCapability -ne "Disabled") {
            $riskScore += 20
            $riskFactors += "External sharing: $($site.SharingCapability)"
            $securityIssues += "ExternalSharing"
        }
        
        # Anonymous sharing
        if ($site.SharingCapability -eq "ExternalUserAndGuestSharing") {
            $riskScore += 25
            $riskFactors += "Anonymous sharing enabled"
            $securityIssues += "AnonymousSharing"
        }
        
        # No domain restrictions
        if ($site.SharingDomainRestrictionMode -eq "None" -and $site.SharingCapability -ne "Disabled") {
            $riskScore += 15
            $riskFactors += "No domain restrictions"
            $securityIssues += "NoDomainRestrictions"
        }
        
        # Legacy authentication
        if ($site.DenyAddAndCustomizePages -eq $false) {
            $riskScore += 10
            $riskFactors += "Custom scripts allowed"
            $securityIssues += "CustomScripts"
        }
        
        # Inactive with high storage
        if ($isInactive -and $storageUsedGB -gt 10) {
            $riskScore += 15
            $riskFactors += "Inactive with high storage ($storageUsedGB GB)"
            $securityIssues += "InactiveHighStorage"
        }
        
        # Storage near limit
        if ($percentUsed -ge 90) {
            $riskScore += 10
            $riskFactors += "Near storage limit ($percentUsed%)"
            $securityIssues += "StorageLimit"
        }
        
        # Conditional Access
        $hasConditionalAccess = ($site.ConditionalAccessPolicy -ne "AllowFullAccess")
        if (-not $hasConditionalAccess) {
            $riskScore += 5
            $riskFactors += "No conditional access policy"
            $securityIssues += "NoConditionalAccess"
        }
        
        # Determine risk level
        $riskLevel = "Low"
        if ($riskScore -ge 60) { $riskLevel = "Critical" }
        elseif ($riskScore -ge 40) { $riskLevel = "High" }
        elseif ($riskScore -ge 20) { $riskLevel = "Medium" }
        
        # Activity status
        $activityStatus = "Active"
        if ($isInactive) {
            $activityStatus = "Inactive ($daysSinceModified days)"
        }
        elseif ($daysSinceModified -gt 30) {
            $activityStatus = "Low Activity ($daysSinceModified days)"
        }
        
        $reportData += [PSCustomObject]@{
            Owner = $userEmail
            SiteUrl = $site.Url
            StorageUsedGB = $storageUsedGB
            StorageQuotaGB = $storageQuotaGB
            PercentUsed = $percentUsed
            LastModified = if ($lastModified) { $lastModified.ToString("yyyy-MM-dd") } else { "Never" }
            DaysSinceModified = $daysSinceModified
            ActivityStatus = $activityStatus
            SharingCapability = $site.SharingCapability
            DomainRestriction = $site.SharingDomainRestrictionMode
            ConditionalAccessPolicy = $site.ConditionalAccessPolicy
            CustomScriptsAllowed = (-not $site.DenyAddAndCustomizePages)
            LockState = $site.LockState
            RiskScore = $riskScore
            RiskLevel = $riskLevel
            SecurityIssues = if ($securityIssues.Count -gt 0) { ($securityIssues -join ', ') } else { "None" }
            RiskFactors = if ($riskFactors.Count -gt 0) { ($riskFactors -join '; ') } else { "None" }
        }
    }

    Write-Progress -Activity "Analyzing OneDrive Sites" -Completed

    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  OneDrive Security Summary" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $totalStorageGB = ($reportData | Measure-Object -Property StorageUsedGB -Sum).Sum
    $avgStorageGB = ($reportData | Measure-Object -Property StorageUsedGB -Average).Average
    $avgPercentUsed = ($reportData | Measure-Object -Property PercentUsed -Average).Average
    
    $criticalRisk = $reportData | Where-Object { $_.RiskLevel -eq "Critical" }
    $highRisk = $reportData | Where-Object { $_.RiskLevel -eq "High" }
    $externalSharing = $reportData | Where-Object { $_.SharingCapability -ne "Disabled" }
    $anonymousSharing = $reportData | Where-Object { $_.SharingCapability -eq "ExternalUserAndGuestSharing" }
    $inactiveSites = $reportData | Where-Object { $_.ActivityStatus -like "Inactive*" }
    $nearLimit = $reportData | Where-Object { $_.PercentUsed -ge 90 }

    Write-Host "Total OneDrive Sites:            $($reportData.Count)" -ForegroundColor White
    Write-Host "Total Storage Used:              $([math]::Round($totalStorageGB, 2)) GB" -ForegroundColor Yellow
    Write-Host "Average per User:                $([math]::Round($avgStorageGB, 2)) GB" -ForegroundColor Cyan
    Write-Host "Average Usage:                   $([math]::Round($avgPercentUsed, 2))%" -ForegroundColor Cyan
    Write-Host "`nSecurity Assessment:" -ForegroundColor Cyan
    Write-Host "  - Critical Risk:               $($criticalRisk.Count)" -ForegroundColor Red
    Write-Host "  - High Risk:                   $($highRisk.Count)" -ForegroundColor Red
    Write-Host "  - External Sharing Enabled:    $($externalSharing.Count)" -ForegroundColor Yellow
    Write-Host "  - Anonymous Sharing:           $($anonymousSharing.Count)" -ForegroundColor Red
    Write-Host "`nUsage Concerns:" -ForegroundColor Cyan
    Write-Host "  - Inactive ($InactiveDaysThreshold+ days):      $($inactiveSites.Count)" -ForegroundColor Yellow
    Write-Host "  - Near Storage Limit (90%+):   $($nearLimit.Count)" -ForegroundColor Yellow

    # Critical risk OneDrive
    if ($criticalRisk.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  CRITICAL RISK: OneDrive Security Issues" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Red
        
        $criticalRisk | Select-Object Owner, RiskScore, SharingCapability, ActivityStatus, RiskFactors -First 15 |
            Format-Table -AutoSize -Wrap
    }

    # Anonymous sharing
    if ($anonymousSharing.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  CRITICAL: OneDrive with Anonymous Sharing" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Red
        
        $anonymousSharing | Select-Object Owner, StorageUsedGB, DomainRestriction -First 15 |
            Format-Table -AutoSize
    }

    # Inactive with high storage
    $inactiveHighStorage = $reportData | Where-Object { 
        $_.ActivityStatus -like "Inactive*" -and $_.StorageUsedGB -gt 10 
    }
    
    if ($inactiveHighStorage.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Yellow
        Write-Host "  Inactive OneDrive with High Storage" -ForegroundColor Yellow
        Write-Host "========================================`n" -ForegroundColor Yellow
        
        $inactiveStorageTotal = ($inactiveHighStorage | Measure-Object -Property StorageUsedGB -Sum).Sum
        Write-Host "Count: $($inactiveHighStorage.Count) sites" -ForegroundColor White
        Write-Host "Total Storage: $([math]::Round($inactiveStorageTotal, 2)) GB (potential reclamation)`n" -ForegroundColor Yellow
        
        $inactiveHighStorage | Sort-Object -Property StorageUsedGB -Descending |
            Select-Object Owner, StorageUsedGB, DaysSinceModified -First 10 |
            Format-Table -AutoSize
    }

    # Top storage consumers
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Top 15 OneDrive Storage Consumers" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    $reportData | Sort-Object -Property StorageUsedGB -Descending |
        Select-Object Owner, StorageUsedGB, PercentUsed, RiskLevel -First 15 |
        Format-Table -AutoSize

    # Near storage limit
    if ($nearLimit.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Yellow
        Write-Host "  OneDrive Near Storage Limit" -ForegroundColor Yellow
        Write-Host "========================================`n" -ForegroundColor Yellow
        
        $nearLimit | Sort-Object -Property PercentUsed -Descending |
            Select-Object Owner, StorageUsedGB, StorageQuotaGB, PercentUsed |
            Format-Table -AutoSize
    }

    # Security issues breakdown
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Security Issues Distribution" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    $allIssues = $reportData | Where-Object { $_.SecurityIssues -ne "None" } | 
        Select-Object -ExpandProperty SecurityIssues
    
    if ($allIssues.Count -gt 0) {
        $issuesSplit = $allIssues -split ',' | ForEach-Object { $_.Trim() }
        $issuesSplit | Group-Object | 
            Select-Object Name, Count | 
            Sort-Object Count -Descending |
            Format-Table -AutoSize
    }
    else {
        Write-Host "No security issues detected.`n" -ForegroundColor Green
    }

    # Export
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPath = Join-Path $ExportPath "OneDriveSecurity_Report_$timestamp.csv"
    $reportData | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Report saved to: $reportPath" -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Green

    # Recommendations
    Write-Host "Priority Actions:" -ForegroundColor Cyan
    if ($criticalRisk.Count -gt 0) {
        Write-Host "  1. [CRITICAL] Review $($criticalRisk.Count) high-risk OneDrive sites" -ForegroundColor Red
    }
    if ($anonymousSharing.Count -gt 0) {
        Write-Host "  2. [CRITICAL] Disable anonymous sharing for $($anonymousSharing.Count) OneDrive sites" -ForegroundColor Red
    }
    if ($inactiveHighStorage.Count -gt 0) {
        Write-Host "  3. [HIGH] Review $($inactiveHighStorage.Count) inactive sites ($([math]::Round(($inactiveHighStorage | Measure-Object -Property StorageUsedGB -Sum).Sum, 2)) GB)" -ForegroundColor Yellow
    }
    Write-Host "  4. Implement conditional access policies for OneDrive" -ForegroundColor White
    Write-Host "  5. Restrict external sharing to approved domains" -ForegroundColor White
    Write-Host "  6. Enable DLP policies for sensitive content" -ForegroundColor White
    Write-Host "  7. Regular audits of OneDrive sharing and access`n" -ForegroundColor White

    Disconnect-SPOService
}
catch {
    Write-Host "`nError: $_" -ForegroundColor Red
    try { Disconnect-SPOService } catch { }
    exit 1
}
