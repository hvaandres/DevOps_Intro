<#
.SYNOPSIS
    Reports current membership of all Teams channels.

.DESCRIPTION
    This script provides detailed reporting on Teams channel membership including
    standard and private channels, member counts, and access analysis.

.PARAMETER ExportPath
    Optional. The path where the CSV report will be saved. Defaults to current directory.

.PARAMETER TeamName
    Optional. Specific team name to analyze. If not provided, all teams are analyzed.

.EXAMPLE
    .\Get-TeamsChannelMembershipReport.ps1

.EXAMPLE
    .\Get-TeamsChannelMembershipReport.ps1 -TeamName "Sales Team"

.NOTES
    Author: Azure Security Audit Team
    Requirements:
    - MicrosoftTeams PowerShell module
    - Microsoft.Graph PowerShell module
    - Permissions: Teams Administrator, TeamMember.Read.All, Channel.ReadBasic.All
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ExportPath = ".",
    
    [Parameter(Mandatory=$false)]
    [string]$TeamName = $null
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
    Write-Host "  Teams Channel Membership Report" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    # Ensure required modules are available
    Test-RequiredModule -ModuleName "MicrosoftTeams"
    Test-RequiredModule -ModuleName "Microsoft.Graph.Teams"
    Test-RequiredModule -ModuleName "Microsoft.Graph.Users"

    # Connect to services
    Write-Host "Connecting to Microsoft Teams..." -ForegroundColor Yellow
    Connect-MicrosoftTeams -ErrorAction Stop | Out-Null
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
    Connect-MgGraph -Scopes "TeamMember.Read.All", "Channel.ReadBasic.All", "User.Read.All" -ErrorAction Stop
    Write-Host "Connected successfully.`n" -ForegroundColor Green

    # Get teams
    Write-Host "Fetching Teams..." -ForegroundColor Yellow
    if ($TeamName) {
        $teams = Get-Team -DisplayName $TeamName
        if (-not $teams) {
            Write-Host "Team '$TeamName' not found.`n" -ForegroundColor Red
            exit 1
        }
    }
    else {
        $teams = Get-Team
    }
    
    Write-Host "Found $($teams.Count) team(s). Analyzing channels...`n" -ForegroundColor Green

    $channelData = @()
    $membershipDetails = @()
    $counter = 0

    foreach ($team in $teams) {
        $counter++
        Write-Progress -Activity "Analyzing Teams Channels" -Status "$($team.DisplayName)" -PercentComplete (($counter / $teams.Count) * 100)
        
        # Get all channels (standard and private)
        try {
            $channels = Get-TeamChannel -GroupId $team.GroupId
            
            foreach ($channel in $channels) {
                # Get channel members
                try {
                    $channelMembers = @()
                    
                    if ($channel.MembershipType -eq "Private") {
                        # Private channel - get specific members
                        $channelMembers = Get-TeamChannelUser -GroupId $team.GroupId -DisplayName $channel.DisplayName
                    }
                    else {
                        # Standard channel - all team members have access
                        $channelMembers = Get-TeamUser -GroupId $team.GroupId
                    }
                    
                    $memberCount = $channelMembers.Count
                    $ownerCount = ($channelMembers | Where-Object { $_.Role -eq "Owner" }).Count
                    $memberOnlyCount = ($channelMembers | Where-Object { $_.Role -eq "Member" }).Count
                    $guestCount = ($channelMembers | Where-Object { $_.UserType -eq "Guest" }).Count
                    
                    # Risk assessment
                    $riskScore = 0
                    $riskFactors = @()
                    
                    # Private channel with guests
                    if ($channel.MembershipType -eq "Private" -and $guestCount -gt 0) {
                        $riskScore += 20
                        $riskFactors += "Private channel with $guestCount guest(s)"
                    }
                    
                    # High guest ratio
                    if ($memberCount -gt 0) {
                        $guestPercentage = [math]::Round(($guestCount / $memberCount) * 100, 2)
                        if ($guestPercentage -gt 30) {
                            $riskScore += 15
                            $riskFactors += "High guest ratio ($guestPercentage%)"
                        }
                    }
                    else {
                        $guestPercentage = 0
                    }
                    
                    # No owners
                    if ($ownerCount -eq 0) {
                        $riskScore += 25
                        $riskFactors += "No channel owners"
                    }
                    elseif ($ownerCount -eq 1) {
                        $riskScore += 10
                        $riskFactors += "Single owner (bus factor)"
                    }
                    
                    # Large member count
                    if ($memberCount -gt 100) {
                        $riskScore += 5
                        $riskFactors += "Large member count ($memberCount)"
                    }
                    
                    $riskLevel = "Low"
                    if ($riskScore -ge 40) { $riskLevel = "High" }
                    elseif ($riskScore -ge 20) { $riskLevel = "Medium" }
                    
                    $channelData += [PSCustomObject]@{
                        TeamName = $team.DisplayName
                        TeamId = $team.GroupId
                        ChannelName = $channel.DisplayName
                        ChannelId = $channel.Id
                        ChannelType = $channel.MembershipType
                        Description = $channel.Description
                        TotalMembers = $memberCount
                        Owners = $ownerCount
                        Members = $memberOnlyCount
                        Guests = $guestCount
                        GuestPercentage = $guestPercentage
                        RiskScore = $riskScore
                        RiskLevel = $riskLevel
                        RiskFactors = if ($riskFactors.Count -gt 0) { ($riskFactors -join '; ') } else { "None" }
                    }
                    
                    # Capture individual member details
                    foreach ($member in $channelMembers) {
                        $membershipDetails += [PSCustomObject]@{
                            TeamName = $team.DisplayName
                            ChannelName = $channel.DisplayName
                            ChannelType = $channel.MembershipType
                            MemberName = $member.Name
                            MemberEmail = $member.User
                            Role = $member.Role
                            UserType = $member.UserType
                        }
                    }
                }
                catch {
                    Write-Host "Error processing channel $($channel.DisplayName): $_" -ForegroundColor Red
                }
            }
        }
        catch {
            Write-Host "Error processing team $($team.DisplayName): $_" -ForegroundColor Red
        }
    }

    Write-Progress -Activity "Analyzing Teams Channels" -Completed

    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Teams Channel Summary" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $totalChannels = $channelData.Count
    $privateChannels = $channelData | Where-Object { $_.ChannelType -eq "Private" }
    $standardChannels = $channelData | Where-Object { $_.ChannelType -eq "Standard" }
    $channelsWithGuests = $channelData | Where-Object { $_.Guests -gt 0 }
    $highRiskChannels = $channelData | Where-Object { $_.RiskLevel -eq "High" }
    $noOwnerChannels = $channelData | Where-Object { $_.Owners -eq 0 }

    Write-Host "Total Channels Analyzed:         $totalChannels" -ForegroundColor White
    Write-Host "  - Standard Channels:           $($standardChannels.Count)" -ForegroundColor White
    Write-Host "  - Private Channels:            $($privateChannels.Count)" -ForegroundColor White
    Write-Host "`nSecurity Concerns:" -ForegroundColor Cyan
    Write-Host "  - Channels with Guests:        $($channelsWithGuests.Count)" -ForegroundColor Yellow
    Write-Host "  - High Risk Channels:          $($highRiskChannels.Count)" -ForegroundColor Red
    Write-Host "  - Channels without Owners:     $($noOwnerChannels.Count)" -ForegroundColor Red

    # High risk channels
    if ($highRiskChannels.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  HIGH RISK: Channels Requiring Attention" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Red
        
        $highRiskChannels | Select-Object TeamName, ChannelName, ChannelType, TotalMembers, Guests, RiskFactors |
            Format-Table -AutoSize -Wrap
    }

    # Channels without owners
    if ($noOwnerChannels.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  CRITICAL: Channels Without Owners" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Red
        
        $noOwnerChannels | Select-Object TeamName, ChannelName, ChannelType, TotalMembers |
            Format-Table -AutoSize
    }

    # Private channels with guests
    $privateWithGuests = $channelData | Where-Object { $_.ChannelType -eq "Private" -and $_.Guests -gt 0 }
    if ($privateWithGuests.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Yellow
        Write-Host "  Private Channels with Guest Access" -ForegroundColor Yellow
        Write-Host "========================================`n" -ForegroundColor Yellow
        
        $privateWithGuests | Select-Object TeamName, ChannelName, TotalMembers, Guests, GuestPercentage |
            Format-Table -AutoSize
    }

    # Channel statistics by team
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Channel Statistics by Team" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    $teamStats = $channelData | Group-Object -Property TeamName |
        Select-Object Name, Count, @{Name="Private";Expression={($_.Group | Where-Object { $_.ChannelType -eq "Private" }).Count}}, @{Name="WithGuests";Expression={($_.Group | Where-Object { $_.Guests -gt 0 }).Count}}
    
    $teamStats | Format-Table -AutoSize

    # All channels
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  All Channels" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    $channelData | Select-Object TeamName, ChannelName, ChannelType, TotalMembers, Owners, Guests, RiskLevel |
        Format-Table -AutoSize

    # Export
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    # Export channel summary
    $channelReportPath = Join-Path $ExportPath "TeamsChannelSummary_Report_$timestamp.csv"
    $channelData | Export-Csv -Path $channelReportPath -NoTypeInformation -Encoding UTF8
    
    # Export detailed membership
    $membershipReportPath = Join-Path $ExportPath "TeamsChannelMembership_Report_$timestamp.csv"
    $membershipDetails | Export-Csv -Path $membershipReportPath -NoTypeInformation -Encoding UTF8

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Reports saved:" -ForegroundColor Green
    Write-Host "  - Channel Summary:    $channelReportPath" -ForegroundColor White
    Write-Host "  - Member Details:     $membershipReportPath" -ForegroundColor White
    Write-Host "========================================`n" -ForegroundColor Green

    # Recommendations
    Write-Host "Security Recommendations:" -ForegroundColor Cyan
    if ($noOwnerChannels.Count -gt 0) {
        Write-Host "  1. [CRITICAL] Assign owners to $($noOwnerChannels.Count) channels without owners" -ForegroundColor Red
    }
    if ($highRiskChannels.Count -gt 0) {
        Write-Host "  2. [HIGH] Review $($highRiskChannels.Count) high-risk channels" -ForegroundColor Yellow
    }
    if ($privateWithGuests.Count -gt 0) {
        Write-Host "  3. [MEDIUM] Audit $($privateWithGuests.Count) private channels with guest access" -ForegroundColor Yellow
    }
    Write-Host "  4. Implement regular access reviews for private channels" -ForegroundColor White
    Write-Host "  5. Ensure all channels have at least two owners" -ForegroundColor White
    Write-Host "  6. Monitor guest access and set expiration policies" -ForegroundColor White
    Write-Host "  7. Use sensitivity labels for channels with sensitive data`n" -ForegroundColor White

    Disconnect-MicrosoftTeams | Out-Null
    Disconnect-MgGraph | Out-Null
}
catch {
    Write-Host "`nError: $_" -ForegroundColor Red
    try { Disconnect-MicrosoftTeams | Out-Null } catch { }
    try { Disconnect-MgGraph | Out-Null } catch { }
    exit 1
}
