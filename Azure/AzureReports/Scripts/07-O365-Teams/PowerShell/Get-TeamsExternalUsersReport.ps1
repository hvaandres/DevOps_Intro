<#
.SYNOPSIS
    Reports on Teams with external users and guests.

.DESCRIPTION
    This script identifies all Teams that have guest or external users,
    providing detailed analysis of external collaboration risks.

.PARAMETER ExportPath
    Optional. The path where the CSV report will be saved. Defaults to current directory.

.EXAMPLE
    .\Get-TeamsExternalUsersReport.ps1

.EXAMPLE
    .\Get-TeamsExternalUsersReport.ps1 -ExportPath "C:\Reports"

.NOTES
    Author: Azure Security Audit Team
    Requirements:
    - MicrosoftTeams PowerShell module
    - Microsoft.Graph PowerShell module
    - Permissions: Teams Administrator, User.Read.All, Group.Read.All
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
    Write-Host "  Teams with External Users Report" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    # Ensure required modules are available
    Test-RequiredModule -ModuleName "MicrosoftTeams"
    Test-RequiredModule -ModuleName "Microsoft.Graph.Groups"
    Test-RequiredModule -ModuleName "Microsoft.Graph.Users"

    # Connect to services
    Write-Host "Connecting to Microsoft Teams..." -ForegroundColor Yellow
    Connect-MicrosoftTeams -ErrorAction Stop | Out-Null
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
    Connect-MgGraph -Scopes "User.Read.All", "Group.Read.All", "TeamMember.Read.All" -ErrorAction Stop
    Write-Host "Connected successfully.`n" -ForegroundColor Green

    # Get all Teams
    Write-Host "Fetching all Teams..." -ForegroundColor Yellow
    $teams = Get-Team
    Write-Host "Found $($teams.Count) Teams. Analyzing membership...`n" -ForegroundColor Green

    $reportData = @()
    $counter = 0

    foreach ($team in $teams) {
        $counter++
        Write-Progress -Activity "Analyzing Teams" -Status $team.DisplayName -PercentComplete (($counter / $teams.Count) * 100)
        
        # Get team members
        try {
            $members = Get-TeamUser -GroupId $team.GroupId
            
            $guestMembers = $members | Where-Object { $_.UserType -eq "Guest" }
            $memberCount = $members.Count
            $guestCount = $guestMembers.Count
            $internalCount = $memberCount - $guestCount
            
            # Only include teams with guests
            if ($guestCount -gt 0) {
                # Get team details
                $group = Get-MgGroup -GroupId $team.GroupId -Property "Visibility,CreatedDateTime,Description" -ErrorAction SilentlyContinue
                
                # Calculate risk score
                $riskScore = 0
                $riskFactors = @()
                
                # High guest count
                if ($guestCount -gt 10) {
                    $riskScore += 20
                    $riskFactors += "High guest count ($guestCount)"
                }
                elseif ($guestCount -gt 5) {
                    $riskScore += 10
                    $riskFactors += "Moderate guest count ($guestCount)"
                }
                else {
                    $riskScore += 5
                    $riskFactors += "Low guest count ($guestCount)"
                }
                
                # Guest percentage
                $guestPercentage = [math]::Round(($guestCount / $memberCount) * 100, 2)
                if ($guestPercentage -gt 50) {
                    $riskScore += 30
                    $riskFactors += "Majority guests ($guestPercentage%)"
                }
                elseif ($guestPercentage -gt 25) {
                    $riskScore += 15
                    $riskFactors += "High guest ratio ($guestPercentage%)"
                }
                
                # Public team with guests
                if ($group.Visibility -eq "Public") {
                    $riskScore += 20
                    $riskFactors += "Public visibility"
                }
                
                # Determine risk level
                $riskLevel = "Low"
                if ($riskScore -ge 50) { $riskLevel = "Critical" }
                elseif ($riskScore -ge 35) { $riskLevel = "High" }
                elseif ($riskScore -ge 20) { $riskLevel = "Medium" }
                
                # Get guest details
                $guestEmails = @()
                $guestDomains = @()
                foreach ($guest in $guestMembers) {
                    $guestEmails += $guest.User
                    if ($guest.User -match '@(.+)$') {
                        $domain = $matches[1] -replace '#EXT#.*$', ''
                        $guestDomains += $domain
                    }
                }
                
                $uniqueDomains = $guestDomains | Select-Object -Unique
                
                $reportData += [PSCustomObject]@{
                    TeamName = $team.DisplayName
                    TeamId = $team.GroupId
                    Visibility = $group.Visibility
                    Description = $team.Description
                    TotalMembers = $memberCount
                    InternalMembers = $internalCount
                    GuestMembers = $guestCount
                    GuestPercentage = $guestPercentage
                    UniqueDomains = $uniqueDomains.Count
                    ExternalDomains = ($uniqueDomains -join '; ')
                    Archived = $team.Archived
                    CreatedDate = if ($group.CreatedDateTime) { $group.CreatedDateTime.ToString("yyyy-MM-dd") } else { "Unknown" }
                    RiskScore = $riskScore
                    RiskLevel = $riskLevel
                    RiskFactors = ($riskFactors -join '; ')
                }
            }
        }
        catch {
            Write-Host "Error processing team $($team.DisplayName): $_" -ForegroundColor Red
        }
    }

    Write-Progress -Activity "Analyzing Teams" -Completed

    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Teams External Collaboration Summary" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $totalTeamsWithGuests = $reportData.Count
    $totalGuests = ($reportData | Measure-Object -Property GuestMembers -Sum).Sum
    $criticalRisk = $reportData | Where-Object { $_.RiskLevel -eq "Critical" }
    $highRisk = $reportData | Where-Object { $_.RiskLevel -eq "High" }
    $publicTeams = $reportData | Where-Object { $_.Visibility -eq "Public" }

    Write-Host "Total Teams Analyzed:            $($teams.Count)" -ForegroundColor White
    Write-Host "Teams with Guests:               $totalTeamsWithGuests" -ForegroundColor Yellow
    Write-Host "Total Guest Members:             $totalGuests" -ForegroundColor Yellow
    Write-Host "`nRisk Assessment:" -ForegroundColor Cyan
    Write-Host "  - Critical Risk:               $($criticalRisk.Count)" -ForegroundColor Red
    Write-Host "  - High Risk:                   $($highRisk.Count)" -ForegroundColor Red
    Write-Host "  - Public Teams with Guests:    $($publicTeams.Count)" -ForegroundColor Yellow

    if ($totalTeamsWithGuests -eq 0) {
        Write-Host "`nNo Teams with guest users found.`n" -ForegroundColor Green
    }
    else {
        # Critical risk teams
        if ($criticalRisk.Count -gt 0) {
            Write-Host "`n========================================" -ForegroundColor Red
            Write-Host "  CRITICAL RISK: Teams with High Guest Exposure" -ForegroundColor Red
            Write-Host "========================================`n" -ForegroundColor Red
            
            $criticalRisk | Select-Object TeamName, GuestMembers, GuestPercentage, Visibility, RiskFactors |
                Format-Table -AutoSize -Wrap
        }

        # Public teams with guests
        if ($publicTeams.Count -gt 0) {
            Write-Host "`n========================================" -ForegroundColor Yellow
            Write-Host "  WARNING: Public Teams with Guest Access" -ForegroundColor Yellow
            Write-Host "========================================`n" -ForegroundColor Yellow
            
            $publicTeams | Select-Object TeamName, GuestMembers, GuestPercentage, UniqueDomains |
                Format-Table -AutoSize
        }

        # Top 10 teams by guest count
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "  Top 10 Teams by Guest Count" -ForegroundColor Cyan
        Write-Host "========================================`n" -ForegroundColor Cyan
        
        $reportData | Sort-Object -Property GuestMembers -Descending |
            Select-Object TeamName, TotalMembers, GuestMembers, GuestPercentage, RiskLevel -First 10 |
            Format-Table -AutoSize

        # Domain statistics
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "  External Domain Statistics" -ForegroundColor Cyan
        Write-Host "========================================`n" -ForegroundColor Cyan
        
        $allDomains = @()
        foreach ($team in $reportData) {
            if ($team.ExternalDomains) {
                $allDomains += $team.ExternalDomains -split '; '
            }
        }
        
        $domainStats = $allDomains | Group-Object | 
            Select-Object Name, Count | 
            Sort-Object Count -Descending | 
            Select-Object -First 10
        
        $domainStats | Format-Table -AutoSize

        # All teams with guests
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "  All Teams with Guest Users" -ForegroundColor Cyan
        Write-Host "========================================`n" -ForegroundColor Cyan
        
        $reportData | Sort-Object -Property RiskScore -Descending |
            Select-Object TeamName, GuestMembers, GuestPercentage, Visibility, RiskLevel |
            Format-Table -AutoSize
    }

    # Export
    if ($reportData.Count -gt 0) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $reportPath = Join-Path $ExportPath "TeamsExternalUsers_Report_$timestamp.csv"
        $reportData | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

        Write-Host "`n========================================" -ForegroundColor Green
        Write-Host "Report saved to: $reportPath" -ForegroundColor Green
        Write-Host "========================================`n" -ForegroundColor Green
    }

    # Recommendations
    Write-Host "Security Recommendations:" -ForegroundColor Cyan
    if ($criticalRisk.Count -gt 0) {
        Write-Host "  1. [CRITICAL] Review $($criticalRisk.Count) teams with high guest exposure" -ForegroundColor Red
    }
    if ($publicTeams.Count -gt 0) {
        Write-Host "  2. [HIGH] Convert $($publicTeams.Count) public teams to private" -ForegroundColor Yellow
    }
    Write-Host "  3. Implement guest access reviews and expiration policies" -ForegroundColor White
    Write-Host "  4. Monitor and audit external collaboration activities" -ForegroundColor White
    Write-Host "  5. Train team owners on guest management best practices" -ForegroundColor White
    Write-Host "  6. Use sensitivity labels for teams with external users" -ForegroundColor White
    Write-Host "  7. Regular cleanup of inactive guest accounts`n" -ForegroundColor White

    Disconnect-MicrosoftTeams | Out-Null
    Disconnect-MgGraph | Out-Null
}
catch {
    Write-Host "`nError: $_" -ForegroundColor Red
    try { Disconnect-MicrosoftTeams | Out-Null } catch { }
    try { Disconnect-MgGraph | Out-Null } catch { }
    exit 1
}
