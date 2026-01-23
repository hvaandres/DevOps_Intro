<#
.SYNOPSIS
    Audits externally shared files and sharing links in OneDrive.

.DESCRIPTION
    This script audits all sharing links in OneDrive, identifies anonymous links,
    analyzes access levels, and provides detailed security recommendations.

.PARAMETER ExportPath
    Optional. The path where the CSV report will be saved. Defaults to current directory.

.PARAMETER MaxSites
    Optional. Maximum number of OneDrive sites to analyze. Default is 100 (0 = all).

.EXAMPLE
    .\Get-OneDriveSharingLinksReport.ps1

.EXAMPLE
    .\Get-OneDriveSharingLinksReport.ps1 -MaxSites 50

.NOTES
    Author: Azure Security Audit Team
    Requirements:
    - PnP.PowerShell module
    - Microsoft.Online.SharePoint.PowerShell module
    - Permissions: SharePoint Administrator or Global Administrator
    Note: This script requires PnP PowerShell for detailed file sharing analysis
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ExportPath = ".",
    
    [Parameter(Mandatory=$false)]
    [int]$MaxSites = 100
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
    Write-Host "  OneDrive Sharing Links Audit" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    # Ensure required modules are available
    Test-RequiredModule -ModuleName "Microsoft.Online.SharePoint.PowerShell"
    Test-RequiredModule -ModuleName "PnP.PowerShell"

    # Get tenant URL
    $tenantName = Read-Host "Enter your SharePoint tenant name (e.g., contoso)"
    $adminUrl = "https://$tenantName-admin.sharepoint.com"

    # Connect to SharePoint Online
    Write-Host "Connecting to SharePoint Online..." -ForegroundColor Yellow
    Connect-SPOService -Url $adminUrl -ErrorAction Stop
    Write-Host "Connected successfully.`n" -ForegroundColor Green

    # Get OneDrive sites
    Write-Host "Fetching OneDrive sites..." -ForegroundColor Yellow
    $oneDriveSites = Get-SPOSite -IncludePersonalSite $true -Limit All -Filter "Url -like '-my.sharepoint.com/personal/'"
    
    if ($MaxSites -gt 0 -and $oneDriveSites.Count -gt $MaxSites) {
        Write-Host "Limiting analysis to $MaxSites sites (out of $($oneDriveSites.Count))..." -ForegroundColor Yellow
        $oneDriveSites = $oneDriveSites | Select-Object -First $MaxSites
    }
    
    Write-Host "Analyzing $($oneDriveSites.Count) OneDrive sites for sharing links...`n" -ForegroundColor Green

    $sharingLinksData = @()
    $siteSummary = @()
    $counter = 0

    foreach ($site in $oneDriveSites) {
        $counter++
        Write-Progress -Activity "Auditing Sharing Links" -Status "$($site.Owner) ($counter of $($oneDriveSites.Count))" -PercentComplete (($counter / $oneDriveSites.Count) * 100)
        
        # Skip if external sharing is disabled
        if ($site.SharingCapability -eq "Disabled") {
            continue
        }
        
        $siteLinks = @()
        $anonymousLinkCount = 0
        $externalLinkCount = 0
        $internalLinkCount = 0
        
        try {
            # Connect to the OneDrive site using PnP
            Connect-PnPOnline -Url $site.Url -Interactive -ErrorAction Stop
            
            # Get all files with sharing links
            $files = Get-PnPListItem -List "Documents" -PageSize 1000 -ErrorAction SilentlyContinue
            
            foreach ($file in $files) {
                if ($file.FileSystemObjectType -eq "File") {
                    # Get sharing information
                    try {
                        $sharingInfo = Get-PnPFileSharingLink -Identity $file.Id -ErrorAction SilentlyContinue
                        
                        foreach ($link in $sharingInfo) {
                            $linkType = "Unknown"
                            $accessLevel = "Unknown"
                            $expirationDate = "No expiration"
                            
                            if ($link.ShareLink) {
                                $linkType = $link.ShareLink.Type
                                if ($link.ShareLink.Expiration) {
                                    $expirationDate = $link.ShareLink.Expiration.ToString("yyyy-MM-dd")
                                }
                            }
                            
                            # Determine link category
                            if ($linkType -like "*Anonymous*") {
                                $anonymousLinkCount++
                                $linkCategory = "Anonymous"
                            }
                            elseif ($linkType -like "*External*") {
                                $externalLinkCount++
                                $linkCategory = "External"
                            }
                            else {
                                $internalLinkCount++
                                $linkCategory = "Internal"
                            }
                            
                            # Risk assessment
                            $riskScore = 0
                            $riskFactors = @()
                            
                            if ($linkCategory -eq "Anonymous") {
                                $riskScore += 50
                                $riskFactors += "Anonymous link"
                            }
                            elseif ($linkCategory -eq "External") {
                                $riskScore += 30
                                $riskFactors += "External sharing"
                            }
                            
                            if ($expirationDate -eq "No expiration") {
                                $riskScore += 20
                                $riskFactors += "No expiration set"
                            }
                            
                            if ($link.ShareLink.IsEditLink) {
                                $riskScore += 20
                                $riskFactors += "Edit permissions"
                                $accessLevel = "Edit"
                            }
                            else {
                                $accessLevel = "View"
                            }
                            
                            $riskLevel = "Low"
                            if ($riskScore -ge 70) { $riskLevel = "Critical" }
                            elseif ($riskScore -ge 50) { $riskLevel = "High" }
                            elseif ($riskScore -ge 30) { $riskLevel = "Medium" }
                            
                            $siteLinks += [PSCustomObject]@{
                                Owner = $site.Owner
                                SiteUrl = $site.Url
                                FileName = $file.FieldValues.FileLeafRef
                                FilePath = $file.FieldValues.FileRef
                                FileSize = [math]::Round($file.FieldValues.File_x0020_Size / 1MB, 2)
                                LinkType = $linkType
                                LinkCategory = $linkCategory
                                AccessLevel = $accessLevel
                                ExpirationDate = $expirationDate
                                Created = if ($link.ShareLink.Created) { $link.ShareLink.Created.ToString("yyyy-MM-dd") } else { "Unknown" }
                                RiskScore = $riskScore
                                RiskLevel = $riskLevel
                                RiskFactors = if ($riskFactors.Count -gt 0) { ($riskFactors -join '; ') } else { "Low risk" }
                            }
                        }
                    }
                    catch {
                        # Skip files without sharing or with access errors
                    }
                }
            }
            
            $sharingLinksData += $siteLinks
            
            # Site summary
            if ($siteLinks.Count -gt 0) {
                $siteSummary += [PSCustomObject]@{
                    Owner = $site.Owner
                    SiteUrl = $site.Url
                    TotalLinks = $siteLinks.Count
                    AnonymousLinks = $anonymousLinkCount
                    ExternalLinks = $externalLinkCount
                    InternalLinks = $internalLinkCount
                    CriticalRiskLinks = ($siteLinks | Where-Object { $_.RiskLevel -eq "Critical" }).Count
                    HighRiskLinks = ($siteLinks | Where-Object { $_.RiskLevel -eq "High" }).Count
                    LinksWithoutExpiration = ($siteLinks | Where-Object { $_.ExpirationDate -eq "No expiration" }).Count
                }
            }
            
            Disconnect-PnPOnline
        }
        catch {
            Write-Host "Warning: Could not analyze $($site.Owner): $_" -ForegroundColor Yellow
        }
    }

    Write-Progress -Activity "Auditing Sharing Links" -Completed

    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Sharing Links Audit Summary" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $totalLinks = $sharingLinksData.Count
    $anonymousLinks = $sharingLinksData | Where-Object { $_.LinkCategory -eq "Anonymous" }
    $externalLinks = $sharingLinksData | Where-Object { $_.LinkCategory -eq "External" }
    $criticalLinks = $sharingLinksData | Where-Object { $_.RiskLevel -eq "Critical" }
    $highRiskLinks = $sharingLinksData | Where-Object { $_.RiskLevel -eq "High" }
    $noExpiration = $sharingLinksData | Where-Object { $_.ExpirationDate -eq "No expiration" }
    $editPermission = $sharingLinksData | Where-Object { $_.AccessLevel -eq "Edit" }

    Write-Host "OneDrive Sites Analyzed:         $($oneDriveSites.Count)" -ForegroundColor White
    Write-Host "Total Sharing Links Found:       $totalLinks" -ForegroundColor Yellow
    Write-Host "`nLink Types:" -ForegroundColor Cyan
    Write-Host "  - Anonymous Links:             $($anonymousLinks.Count)" -ForegroundColor Red
    Write-Host "  - External Links:              $($externalLinks.Count)" -ForegroundColor Yellow
    Write-Host "  - Internal Links:              $(($sharingLinksData | Where-Object { $_.LinkCategory -eq 'Internal' }).Count)" -ForegroundColor Green
    Write-Host "`nRisk Assessment:" -ForegroundColor Cyan
    Write-Host "  - Critical Risk Links:         $($criticalLinks.Count)" -ForegroundColor Red
    Write-Host "  - High Risk Links:             $($highRiskLinks.Count)" -ForegroundColor Red
    Write-Host "  - Links without Expiration:    $($noExpiration.Count)" -ForegroundColor Yellow
    Write-Host "  - Links with Edit Access:      $($editPermission.Count)" -ForegroundColor Yellow

    if ($totalLinks -eq 0) {
        Write-Host "`nNo sharing links found in analyzed OneDrive sites.`n" -ForegroundColor Green
    }
    else {
        # Critical risk links
        if ($criticalLinks.Count -gt 0) {
            Write-Host "`n========================================" -ForegroundColor Red
            Write-Host "  CRITICAL: High Risk Sharing Links (First 20)" -ForegroundColor Red
            Write-Host "========================================`n" -ForegroundColor Red
            
            $criticalLinks | Sort-Object -Property RiskScore -Descending |
                Select-Object Owner, FileName, LinkCategory, AccessLevel, ExpirationDate, RiskFactors -First 20 |
                Format-Table -AutoSize -Wrap
        }

        # Anonymous links
        if ($anonymousLinks.Count -gt 0) {
            Write-Host "`n========================================" -ForegroundColor Red
            Write-Host "  CRITICAL: Anonymous Sharing Links (First 20)" -ForegroundColor Red
            Write-Host "========================================`n" -ForegroundColor Red
            
            $anonymousLinks | Select-Object Owner, FileName, AccessLevel, ExpirationDate -First 20 |
                Format-Table -AutoSize
        }

        # Links without expiration
        if ($noExpiration.Count -gt 0) {
            Write-Host "`n========================================" -ForegroundColor Yellow
            Write-Host "  WARNING: Links Without Expiration (First 20)" -ForegroundColor Yellow
            Write-Host "========================================`n" -ForegroundColor Yellow
            
            $noExpiration | Select-Object Owner, FileName, LinkCategory, AccessLevel -First 20 |
                Format-Table -AutoSize
        }

        # User summary
        if ($siteSummary.Count -gt 0) {
            Write-Host "`n========================================" -ForegroundColor Cyan
            Write-Host "  Top 15 Users by Sharing Link Count" -ForegroundColor Cyan
            Write-Host "========================================`n" -ForegroundColor Cyan
            
            $siteSummary | Sort-Object -Property TotalLinks -Descending |
                Select-Object Owner, TotalLinks, AnonymousLinks, ExternalLinks, CriticalRiskLinks -First 15 |
                Format-Table -AutoSize
        }
    }

    # Export
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    if ($sharingLinksData.Count -gt 0) {
        $linksReportPath = Join-Path $ExportPath "OneDriveSharingLinks_Report_$timestamp.csv"
        $sharingLinksData | Export-Csv -Path $linksReportPath -NoTypeInformation -Encoding UTF8
    }
    
    if ($siteSummary.Count -gt 0) {
        $summaryReportPath = Join-Path $ExportPath "OneDriveSharingSummary_Report_$timestamp.csv"
        $siteSummary | Export-Csv -Path $summaryReportPath -NoTypeInformation -Encoding UTF8
    }

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Reports saved:" -ForegroundColor Green
    if ($sharingLinksData.Count -gt 0) {
        Write-Host "  - Detailed Links:  $linksReportPath" -ForegroundColor White
    }
    if ($siteSummary.Count -gt 0) {
        Write-Host "  - User Summary:    $summaryReportPath" -ForegroundColor White
    }
    Write-Host "========================================`n" -ForegroundColor Green

    # Recommendations
    Write-Host "Priority Actions:" -ForegroundColor Cyan
    if ($criticalLinks.Count -gt 0) {
        Write-Host "  1. [CRITICAL] Review/revoke $($criticalLinks.Count) high-risk sharing links" -ForegroundColor Red
    }
    if ($anonymousLinks.Count -gt 0) {
        Write-Host "  2. [CRITICAL] Audit $($anonymousLinks.Count) anonymous sharing links" -ForegroundColor Red
    }
    if ($noExpiration.Count -gt 0) {
        Write-Host "  3. [HIGH] Set expiration for $($noExpiration.Count) links without expiry" -ForegroundColor Yellow
    }
    Write-Host "  4. Enforce organization-wide link expiration policies" -ForegroundColor White
    Write-Host "  5. Require authentication for sharing links" -ForegroundColor White
    Write-Host "  6. Implement regular sharing link audits" -ForegroundColor White
    Write-Host "  7. User training on secure sharing practices" -ForegroundColor White
    Write-Host "  8. Enable audit logging for sharing activities`n" -ForegroundColor White

    Disconnect-SPOService
}
catch {
    Write-Host "`nError: $_" -ForegroundColor Red
    try { Disconnect-SPOService } catch { }
    exit 1
}
