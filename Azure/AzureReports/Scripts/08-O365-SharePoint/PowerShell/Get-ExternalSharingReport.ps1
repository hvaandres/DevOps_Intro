<#
.SYNOPSIS
    Detects external sharing across SharePoint and OneDrive.

.DESCRIPTION
    This script identifies all externally shared content in SharePoint and OneDrive,
    analyzes sharing patterns, and identifies potential security risks.

.PARAMETER ExportPath
    Optional. The path where the CSV report will be saved. Defaults to current directory.

.PARAMETER IncludeOneDrive
    Optional. Include OneDrive sites in analysis. Default is $true.

.EXAMPLE
    .\Get-ExternalSharingReport.ps1

.EXAMPLE
    .\Get-ExternalSharingReport.ps1 -IncludeOneDrive $false

.NOTES
    Author: Azure Security Audit Team
    Requirements:
    - Microsoft.Online.SharePoint.PowerShell module
    - PnP.PowerShell module (optional for detailed analysis)
    - Permissions: SharePoint Administrator or Global Administrator
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ExportPath = ".",
    
    [Parameter(Mandatory=$false)]
    [bool]$IncludeOneDrive = $true
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
    Write-Host "  External Sharing Detection" -ForegroundColor Cyan
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
    Write-Host "Fetching sites..." -ForegroundColor Yellow
    if ($IncludeOneDrive) {
        $sites = Get-SPOSite -Limit All -IncludePersonalSite $true
    }
    else {
        $sites = Get-SPOSite -Limit All | Where-Object { $_.Template -notlike "*SPSPERS*" }
    }
    
    Write-Host "Found $($sites.Count) sites. Analyzing external sharing...`n" -ForegroundColor Green

    $externalSharingData = @()
    $counter = 0

    foreach ($site in $sites) {
        $counter++
        Write-Progress -Activity "Analyzing External Sharing" -Status $site.Title -PercentComplete (($counter / $sites.Count) * 100)
        
        # Skip if external sharing is disabled
        if ($site.SharingCapability -eq "Disabled") {
            continue
        }
        
        # Identify site type
        $siteType = "Team Site"
        if ($site.Template -like "*SPSPERS*") {
            $siteType = "OneDrive"
        }
        elseif ($site.Template -like "*SITEPAGEPUBLISHING*") {
            $siteType = "Communication Site"
        }
        elseif ($site.Template -like "*GROUP*") {
            $siteType = "Microsoft 365 Group"
        }
        
        # Get external users for this site
        try {
            $externalUsers = Get-SPOExternalUser -SiteUrl $site.Url -ErrorAction SilentlyContinue
            $externalUserCount = if ($externalUsers) { $externalUsers.Count } else { 0 }
        }
        catch {
            $externalUserCount = "Unable to retrieve"
        }
        
        # Risk assessment
        $riskScore = 0
        $riskFactors = @()
        
        # Anonymous sharing
        if ($site.SharingCapability -eq "ExternalUserAndGuestSharing") {
            $riskScore += 40
            $riskFactors += "Anonymous sharing enabled"
        }
        elseif ($site.SharingCapability -eq "ExternalUserSharingOnly") {
            $riskScore += 20
            $riskFactors += "External user sharing"
        }
        
        # No domain restrictions
        if ($site.SharingDomainRestrictionMode -eq "None") {
            $riskScore += 20
            $riskFactors += "No domain restrictions"
        }
        
        # External users present
        if ($externalUserCount -is [int] -and $externalUserCount -gt 0) {
            if ($externalUserCount -gt 50) {
                $riskScore += 30
                $riskFactors += "High external user count ($externalUserCount)"
            }
            elseif ($externalUserCount -gt 10) {
                $riskScore += 20
                $riskFactors += "Moderate external user count ($externalUserCount)"
            }
            else {
                $riskScore += 10
                $riskFactors += "External users present ($externalUserCount)"
            }
        }
        
        # Anonymous access links
        if ($site.AllowDownloadingNonWebViewableFiles) {
            $riskScore += 10
            $riskFactors += "Download of non-web-viewable files allowed"
        }
        
        # No conditional access
        if ($site.ConditionalAccessPolicy -eq "AllowFullAccess") {
            $riskScore += 10
            $riskFactors += "No conditional access restrictions"
        }
        
        $riskLevel = "Low"
        if ($riskScore -ge 70) { $riskLevel = "Critical" }
        elseif ($riskScore -ge 50) { $riskLevel = "High" }
        elseif ($riskScore -ge 30) { $riskLevel = "Medium" }
        
        $externalSharingData += [PSCustomObject]@{
            SiteUrl = $site.Url
            Title = $site.Title
            Owner = $site.Owner
            SiteType = $siteType
            SharingCapability = $site.SharingCapability
            DomainRestriction = $site.SharingDomainRestrictionMode
            ExternalUserCount = $externalUserCount
            AllowDownload = $site.AllowDownloadingNonWebViewableFiles
            ConditionalAccess = $site.ConditionalAccessPolicy
            LastModified = if ($site.LastContentModifiedDate) { $site.LastContentModifiedDate.ToString("yyyy-MM-dd") } else { "Unknown" }
            StorageUsedGB = [math]::Round($site.StorageUsageCurrent / 1024, 2)
            RiskScore = $riskScore
            RiskLevel = $riskLevel
            RiskFactors = if ($riskFactors.Count -gt 0) { ($riskFactors -join '; ') } else { "Low risk" }
        }
    }

    Write-Progress -Activity "Analyzing External Sharing" -Completed

    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  External Sharing Summary" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $totalSitesAnalyzed = $sites.Count
    $sitesWithExternalSharing = $externalSharingData.Count
    $criticalRisk = $externalSharingData | Where-Object { $_.RiskLevel -eq "Critical" }
    $highRisk = $externalSharingData | Where-Object { $_.RiskLevel -eq "High" }
    $anonymousSharing = $externalSharingData | Where-Object { $_.SharingCapability -eq "ExternalUserAndGuestSharing" }
    $noDomainRestrictions = $externalSharingData | Where-Object { $_.DomainRestriction -eq "None" }
    
    $totalExternalUsers = 0
    foreach ($site in $externalSharingData) {
        if ($site.ExternalUserCount -is [int]) {
            $totalExternalUsers += $site.ExternalUserCount
        }
    }

    Write-Host "Total Sites Analyzed:            $totalSitesAnalyzed" -ForegroundColor White
    Write-Host "Sites with External Sharing:     $sitesWithExternalSharing" -ForegroundColor Yellow
    Write-Host "Total External Users:            $totalExternalUsers" -ForegroundColor Yellow
    Write-Host "`nRisk Assessment:" -ForegroundColor Cyan
    Write-Host "  - Critical Risk:               $($criticalRisk.Count)" -ForegroundColor Red
    Write-Host "  - High Risk:                   $($highRisk.Count)" -ForegroundColor Red
    Write-Host "  - Anonymous Sharing:           $($anonymousSharing.Count)" -ForegroundColor Red
    Write-Host "  - No Domain Restrictions:      $($noDomainRestrictions.Count)" -ForegroundColor Yellow

    # Critical risk sites
    if ($criticalRisk.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  CRITICAL RISK: Highly Exposed Sites" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Red
        
        $criticalRisk | Sort-Object -Property RiskScore -Descending |
            Select-Object Title, SiteType, SharingCapability, ExternalUserCount, RiskFactors -First 15 |
            Format-Table -AutoSize -Wrap
    }

    # Anonymous sharing sites
    if ($anonymousSharing.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  CRITICAL: Sites with Anonymous Sharing" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Red
        
        $anonymousSharing | Select-Object Title, SiteType, ExternalUserCount, DomainRestriction -First 15 |
            Format-Table -AutoSize
    }

    # Sites with most external users
    $topExternalUsers = $externalSharingData | Where-Object { $_.ExternalUserCount -is [int] } |
        Sort-Object -Property ExternalUserCount -Descending | Select-Object -First 15
    
    if ($topExternalUsers.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Yellow
        Write-Host "  Top 15 Sites by External User Count" -ForegroundColor Yellow
        Write-Host "========================================`n" -ForegroundColor Yellow
        
        $topExternalUsers | Select-Object Title, SiteType, ExternalUserCount, SharingCapability, RiskLevel |
            Format-Table -AutoSize
    }

    # Sharing by site type
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  External Sharing by Site Type" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    $externalSharingData | Group-Object -Property SiteType |
        Select-Object Name, Count, @{Name="HighRisk";Expression={($_.Group | Where-Object { $_.RiskLevel -in @("Critical","High") }).Count}} |
        Sort-Object Count -Descending |
        Format-Table -AutoSize

    # Domain restriction analysis
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Domain Restriction Analysis" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    $externalSharingData | Group-Object -Property DomainRestriction |
        Select-Object Name, Count |
        Format-Table -AutoSize

    # Export
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPath = Join-Path $ExportPath "ExternalSharing_Report_$timestamp.csv"
    $externalSharingData | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Report saved to: $reportPath" -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Green

    # Recommendations
    Write-Host "Priority Actions:" -ForegroundColor Cyan
    if ($criticalRisk.Count -gt 0) {
        Write-Host "  1. [CRITICAL] Review $($criticalRisk.Count) critical risk sites immediately" -ForegroundColor Red
    }
    if ($anonymousSharing.Count -gt 0) {
        Write-Host "  2. [CRITICAL] Disable anonymous sharing for $($anonymousSharing.Count) sites" -ForegroundColor Red
    }
    if ($noDomainRestrictions.Count -gt 0) {
        Write-Host "  3. [HIGH] Implement domain restrictions for $($noDomainRestrictions.Count) sites" -ForegroundColor Yellow
    }
    Write-Host "  4. Set organization-wide sharing policies" -ForegroundColor White
    Write-Host "  5. Implement approved domain allow-lists" -ForegroundColor White
    Write-Host "  6. Enable expiration for anonymous links" -ForegroundColor White
    Write-Host "  7. Regular audits of external users and access" -ForegroundColor White
    Write-Host "  8. User training on secure sharing practices`n" -ForegroundColor White

    Disconnect-SPOService
}
catch {
    Write-Host "`nError: $_" -ForegroundColor Red
    try { Disconnect-SPOService } catch { }
    exit 1
}
