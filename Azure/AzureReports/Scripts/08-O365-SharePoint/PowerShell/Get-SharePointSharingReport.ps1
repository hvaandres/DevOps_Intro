<#
.SYNOPSIS
    Analyzes SharePoint sharing settings and configurations.

.DESCRIPTION
    This script reviews SharePoint Online sharing policies, external sharing settings,
    and identifies security risks across all site collections.

.PARAMETER ExportPath
    Optional. The path where the CSV report will be saved. Defaults to current directory.

.EXAMPLE
    .\Get-SharePointSharingReport.ps1

.EXAMPLE
    .\Get-SharePointSharingReport.ps1 -ExportPath "C:\Reports"

.NOTES
    Author: Azure Security Audit Team
    Requirements:
    - SharePointPnPPowerShellOnline or PnP.PowerShell module
    - Microsoft.Online.SharePoint.PowerShell module
    - Permissions: SharePoint Administrator or Global Administrator
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ExportPath = "."
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
    Write-Host "  SharePoint Sharing Settings Analysis" -ForegroundColor Cyan
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

    $assessmentResults = @()
    $siteReports = @()
    $securityScore = 0
    $maxScore = 0

    # 1. Tenant-level sharing settings
    Write-Host "Analyzing tenant sharing settings..." -ForegroundColor Yellow
    $tenant = Get-SPOTenant
    
    # External sharing
    $maxScore += 10
    if ($tenant.SharingCapability -eq "Disabled") {
        $securityScore += 10
        $assessmentResults += [PSCustomObject]@{
            Category = "Tenant Sharing"
            Setting = "External Sharing"
            CurrentValue = "Disabled"
            Status = "SECURE"
            Risk = "None"
            Recommendation = "External sharing is disabled"
        }
    }
    elseif ($tenant.SharingCapability -eq "ExternalUserSharingOnly") {
        $securityScore += 7
        $assessmentResults += [PSCustomObject]@{
            Category = "Tenant Sharing"
            Setting = "External Sharing"
            CurrentValue = "Existing Guests Only"
            Status = "SECURE"
            Risk = "Low"
            Recommendation = "Only existing external users can be shared with"
        }
    }
    elseif ($tenant.SharingCapability -eq "ExternalUserAndGuestSharing") {
        $securityScore += 5
        $assessmentResults += [PSCustomObject]@{
            Category = "Tenant Sharing"
            Setting = "External Sharing"
            CurrentValue = "New and Existing Guests"
            Status = "WARNING"
            Risk = "Medium"
            Recommendation = "Consider restricting to existing guests only"
        }
    }
    else {
        $assessmentResults += [PSCustomObject]@{
            Category = "Tenant Sharing"
            Setting = "External Sharing"
            CurrentValue = $tenant.SharingCapability
            Status = "WARNING"
            Risk = "High"
            Recommendation = "Anonymous sharing enabled - high risk"
        }
    }
    
    # Anonymous link expiration
    $maxScore += 10
    if ($tenant.RequireAnonymousLinksExpireInDays -gt 0) {
        $securityScore += 10
        $assessmentResults += [PSCustomObject]@{
            Category = "Anonymous Links"
            Setting = "Link Expiration"
            CurrentValue = "$($tenant.RequireAnonymousLinksExpireInDays) days"
            Status = "SECURE"
            Risk = "None"
            Recommendation = "Anonymous links expire automatically"
        }
    }
    else {
        $assessmentResults += [PSCustomObject]@{
            Category = "Anonymous Links"
            Setting = "Link Expiration"
            CurrentValue = "No expiration"
            Status = "WARNING"
            Risk = "High"
            Recommendation = "Set expiration for anonymous links (recommended: 30 days)"
        }
    }
    
    # Default link type
    $maxScore += 5
    if ($tenant.DefaultSharingLinkType -eq "Internal") {
        $securityScore += 5
        $assessmentResults += [PSCustomObject]@{
            Category = "Default Links"
            Setting = "Default Link Type"
            CurrentValue = "Internal"
            Status = "SECURE"
            Risk = "None"
            Recommendation = "Default sharing links are internal only"
        }
    }
    elseif ($tenant.DefaultSharingLinkType -eq "Direct") {
        $securityScore += 3
        $assessmentResults += [PSCustomObject]@{
            Category = "Default Links"
            Setting = "Default Link Type"
            CurrentValue = "Direct (Specific People)"
            Status = "SECURE"
            Risk = "Low"
            Recommendation = "Links shared with specific people"
        }
    }
    else {
        $assessmentResults += [PSCustomObject]@{
            Category = "Default Links"
            Setting = "Default Link Type"
            CurrentValue = $tenant.DefaultSharingLinkType
            Status = "WARNING"
            Risk = "Medium"
            Recommendation = "Consider setting to Internal or Direct"
        }
    }
    
    # OneDrive sharing
    $maxScore += 5
    if ($tenant.OneDriveSharingCapability -eq "Disabled") {
        $securityScore += 5
        $assessmentResults += [PSCustomObject]@{
            Category = "OneDrive Sharing"
            Setting = "External Sharing"
            CurrentValue = "Disabled"
            Status = "SECURE"
            Risk = "None"
            Recommendation = "OneDrive external sharing disabled"
        }
    }
    else {
        $assessmentResults += [PSCustomObject]@{
            Category = "OneDrive Sharing"
            Setting = "External Sharing"
            CurrentValue = $tenant.OneDriveSharingCapability
            Status = "INFO"
            Risk = "Medium"
            Recommendation = "OneDrive external sharing enabled"
        }
    }
    
    # Legacy authentication
    $maxScore += 10
    if ($tenant.LegacyAuthProtocolsEnabled -eq $false) {
        $securityScore += 10
        $assessmentResults += [PSCustomObject]@{
            Category = "Authentication"
            Setting = "Legacy Protocols"
            CurrentValue = "Blocked"
            Status = "SECURE"
            Risk = "None"
            Recommendation = "Legacy authentication protocols are blocked"
        }
    }
    else {
        $assessmentResults += [PSCustomObject]@{
            Category = "Authentication"
            Setting = "Legacy Protocols"
            CurrentValue = "Allowed"
            Status = "WARNING"
            Risk = "High"
            Recommendation = "Block legacy authentication protocols"
        }
    }

    # 2. Analyze individual sites
    Write-Host "Fetching site collections..." -ForegroundColor Yellow
    $sites = Get-SPOSite -Limit All | Where-Object { $_.Template -notlike "*App*" }
    Write-Host "Found $($sites.Count) site collections. Analyzing sharing settings...`n" -ForegroundColor Green

    $counter = 0
    foreach ($site in $sites) {
        $counter++
        Write-Progress -Activity "Analyzing Sites" -Status $site.Title -PercentComplete (($counter / $sites.Count) * 100)
        
        # Risk scoring
        $riskScore = 0
        $riskFactors = @()
        
        # External sharing enabled
        if ($site.SharingCapability -ne "Disabled") {
            $riskScore += 20
            $riskFactors += "External sharing: $($site.SharingCapability)"
        }
        
        # Anonymous sharing
        if ($site.SharingCapability -eq "ExternalUserAndGuestSharing") {
            $riskScore += 30
            $riskFactors += "Anonymous sharing enabled"
        }
        
        # No sharing restrictions
        if ($site.SharingDomainRestrictionMode -eq "None") {
            $riskScore += 15
            $riskFactors += "No domain restrictions"
        }
        
        # Lock state
        if ($site.LockState -ne "Unlock") {
            $riskScore -= 10
            $riskFactors += "Site locked: $($site.LockState)"
        }
        
        $riskLevel = "Low"
        if ($riskScore -ge 50) { $riskLevel = "Critical" }
        elseif ($riskScore -ge 30) { $riskLevel = "High" }
        elseif ($riskScore -ge 15) { $riskLevel = "Medium" }
        
        $siteReports += [PSCustomObject]@{
            SiteUrl = $site.Url
            Title = $site.Title
            Owner = $site.Owner
            Template = $site.Template
            SharingCapability = $site.SharingCapability
            DomainRestriction = $site.SharingDomainRestrictionMode
            AllowDownloadingNonWebViewable = $site.AllowDownloadingNonWebViewableFiles
            ConditionalAccessPolicy = $site.ConditionalAccessPolicy
            LockState = $site.LockState
            StorageQuota = $site.StorageQuota
            RiskScore = $riskScore
            RiskLevel = $riskLevel
            RiskFactors = if ($riskFactors.Count -gt 0) { ($riskFactors -join '; ') } else { "None" }
        }
    }

    Write-Progress -Activity "Analyzing Sites" -Completed

    # Calculate final score
    $finalScore = if ($maxScore -gt 0) { [math]::Round(($securityScore / $maxScore) * 100, 2) } else { 0 }

    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  SharePoint Sharing Assessment" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    Write-Host "Security Score: $securityScore / $maxScore " -ForegroundColor White -NoNewline
    if ($finalScore -ge 80) {
        Write-Host "($finalScore%) - EXCELLENT" -ForegroundColor Green
    }
    elseif ($finalScore -ge 60) {
        Write-Host "($finalScore%) - GOOD" -ForegroundColor Yellow
    }
    else {
        Write-Host "($finalScore%) - NEEDS IMPROVEMENT" -ForegroundColor Red
    }

    $warnings = $assessmentResults | Where-Object { $_.Status -eq "WARNING" }
    $criticalSites = $siteReports | Where-Object { $_.RiskLevel -eq "Critical" }
    $highRiskSites = $siteReports | Where-Object { $_.RiskLevel -eq "High" }
    $externalSharingSites = $siteReports | Where-Object { $_.SharingCapability -ne "Disabled" }
    
    Write-Host "`nTenant Configuration:" -ForegroundColor Cyan
    Write-Host "  - Configuration Warnings:      $($warnings.Count)" -ForegroundColor Yellow
    Write-Host "`nSite Analysis:" -ForegroundColor Cyan
    Write-Host "  - Total Sites:                 $($siteReports.Count)" -ForegroundColor White
    Write-Host "  - Critical Risk Sites:         $($criticalSites.Count)" -ForegroundColor Red
    Write-Host "  - High Risk Sites:             $($highRiskSites.Count)" -ForegroundColor Red
    Write-Host "  - External Sharing Enabled:    $($externalSharingSites.Count)" -ForegroundColor Yellow

    # Tenant warnings
    if ($warnings.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Yellow
        Write-Host "  Tenant Configuration Warnings" -ForegroundColor Yellow
        Write-Host "========================================`n" -ForegroundColor Yellow
        
        $warnings | Select-Object Category, Setting, CurrentValue, Risk, Recommendation |
            Format-Table -AutoSize -Wrap
    }

    # Critical sites
    if ($criticalSites.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  CRITICAL RISK: Sites Requiring Attention" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Red
        
        $criticalSites | Select-Object Title, SiteUrl, SharingCapability, RiskFactors -First 10 |
            Format-Table -AutoSize -Wrap
    }

    # High risk sites
    if ($highRiskSites.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Yellow
        Write-Host "  High Risk Sites (First 15)" -ForegroundColor Yellow
        Write-Host "========================================`n" -ForegroundColor Yellow
        
        $highRiskSites | Select-Object Title, SharingCapability, DomainRestriction, RiskLevel -First 15 |
            Format-Table -AutoSize
    }

    # Tenant configuration
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Complete Tenant Assessment" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    $assessmentResults | Select-Object Category, Setting, CurrentValue, Status, Risk |
        Format-Table -AutoSize

    # Export
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    $tenantReportPath = Join-Path $ExportPath "SharePointTenant_Report_$timestamp.csv"
    $assessmentResults | Export-Csv -Path $tenantReportPath -NoTypeInformation -Encoding UTF8
    
    $sitesReportPath = Join-Path $ExportPath "SharePointSites_Report_$timestamp.csv"
    $siteReports | Export-Csv -Path $sitesReportPath -NoTypeInformation -Encoding UTF8

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Reports saved:" -ForegroundColor Green
    Write-Host "  - Tenant Config:  $tenantReportPath" -ForegroundColor White
    Write-Host "  - Site Analysis:  $sitesReportPath" -ForegroundColor White
    Write-Host "Security Score: $finalScore%" -ForegroundColor $(if ($finalScore -ge 80) { "Green" } elseif ($finalScore -ge 60) { "Yellow" } else { "Red" })
    Write-Host "========================================`n" -ForegroundColor Green

    # Recommendations
    Write-Host "Priority Actions:" -ForegroundColor Cyan
    if ($criticalSites.Count -gt 0) {
        Write-Host "  1. [CRITICAL] Review $($criticalSites.Count) critical risk sites" -ForegroundColor Red
    }
    if ($warnings.Count -gt 0) {
        Write-Host "  2. [HIGH] Address $($warnings.Count) tenant configuration warnings" -ForegroundColor Yellow
    }
    Write-Host "  3. Implement domain restrictions for external sharing" -ForegroundColor White
    Write-Host "  4. Set expiration for anonymous links (30 days)" -ForegroundColor White
    Write-Host "  5. Enable DLP policies for sensitive content" -ForegroundColor White
    Write-Host "  6. Regular audits of sharing settings and permissions`n" -ForegroundColor White

    Disconnect-SPOService
}
catch {
    Write-Host "`nError: $_" -ForegroundColor Red
    try { Disconnect-SPOService } catch { }
    exit 1
}
