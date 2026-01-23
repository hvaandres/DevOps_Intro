<#
.SYNOPSIS
    Reviews Microsoft Teams external access configuration.

.DESCRIPTION
    This script analyzes Teams external access settings, federation policies,
    and guest access configurations to identify security risks.

.PARAMETER ExportPath
    Optional. The path where the CSV report will be saved. Defaults to current directory.

.EXAMPLE
    .\Get-TeamsExternalAccessReport.ps1

.EXAMPLE
    .\Get-TeamsExternalAccessReport.ps1 -ExportPath "C:\Reports"

.NOTES
    Author: Azure Security Audit Team
    Requirements:
    - MicrosoftTeams PowerShell module
    - Microsoft.Graph PowerShell module
    - Permissions: Teams Administrator or Global Reader
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
    Write-Host "  Teams External Access Configuration Review" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    # Ensure required modules are available
    Test-RequiredModule -ModuleName "MicrosoftTeams"

    # Connect to Microsoft Teams
    Write-Host "Connecting to Microsoft Teams..." -ForegroundColor Yellow
    Connect-MicrosoftTeams -ErrorAction Stop | Out-Null
    Write-Host "Connected successfully.`n" -ForegroundColor Green

    $assessmentResults = @()
    $securityScore = 0
    $maxScore = 0

    # 1. Teams Client Configuration
    Write-Host "Checking Teams client configuration..." -ForegroundColor Yellow
    $teamsConfig = Get-CsTeamsClientConfiguration
    
    # External access settings
    $maxScore += 10
    if ($teamsConfig.AllowExternalAccess -eq $false) {
        $securityScore += 10
        $assessmentResults += [PSCustomObject]@{
            Category = "External Access"
            Setting = "Allow External Access"
            CurrentValue = $false
            Status = "SECURE"
            Risk = "None"
            Recommendation = "External access is disabled"
        }
    }
    else {
        $assessmentResults += [PSCustomObject]@{
            Category = "External Access"
            Setting = "Allow External Access"
            CurrentValue = $true
            Status = "INFO"
            Risk = "Medium"
            Recommendation = "External access enabled - ensure federation policies are properly configured"
        }
    }
    
    # Guest access
    $maxScore += 10
    if ($teamsConfig.AllowGuestUser -eq $false) {
        $securityScore += 5
        $assessmentResults += [PSCustomObject]@{
            Category = "Guest Access"
            Setting = "Allow Guest Users"
            CurrentValue = $false
            Status = "SECURE"
            Risk = "None"
            Recommendation = "Guest access is disabled"
        }
    }
    else {
        $securityScore += 0
        $assessmentResults += [PSCustomObject]@{
            Category = "Guest Access"
            Setting = "Allow Guest Users"
            CurrentValue = $true
            Status = "WARNING"
            Risk = "Medium"
            Recommendation = "Guest access enabled - ensure proper governance and monitoring"
        }
    }

    # 2. Guest Configuration Policy
    Write-Host "Checking guest configuration policy..." -ForegroundColor Yellow
    $guestConfig = Get-CsTeamsGuestMessagingConfiguration
    
    # Guest can delete messages
    $maxScore += 5
    if ($guestConfig.AllowUserDeleteMessage -eq $false) {
        $securityScore += 5
        $assessmentResults += [PSCustomObject]@{
            Category = "Guest Permissions"
            Setting = "Guest Can Delete Messages"
            CurrentValue = $false
            Status = "SECURE"
            Risk = "None"
            Recommendation = "Guests cannot delete messages"
        }
    }
    else {
        $assessmentResults += [PSCustomObject]@{
            Category = "Guest Permissions"
            Setting = "Guest Can Delete Messages"
            CurrentValue = $true
            Status = "WARNING"
            Risk = "Low"
            Recommendation = "Consider preventing guests from deleting messages"
        }
    }
    
    # Guest can edit messages
    $maxScore += 5
    if ($guestConfig.AllowUserEditMessage -eq $false) {
        $securityScore += 5
        $assessmentResults += [PSCustomObject]@{
            Category = "Guest Permissions"
            Setting = "Guest Can Edit Messages"
            CurrentValue = $false
            Status = "SECURE"
            Risk = "None"
            Recommendation = "Guests cannot edit messages"
        }
    }
    else {
        $assessmentResults += [PSCustomObject]@{
            Category = "Guest Permissions"
            Setting = "Guest Can Edit Messages"
            CurrentValue = $true
            Status = "INFO"
            Risk = "Low"
            Recommendation = "Guests can edit their messages"
        }
    }

    # 3. External Access Policy (Federation)
    Write-Host "Checking external access policy..." -ForegroundColor Yellow
    $externalAccessPolicy = Get-CsTenantFederationConfiguration
    
    # Allow federated users
    $maxScore += 10
    if ($externalAccessPolicy.AllowFederatedUsers -eq $false) {
        $securityScore += 10
        $assessmentResults += [PSCustomObject]@{
            Category = "Federation"
            Setting = "Allow Federated Users"
            CurrentValue = $false
            Status = "SECURE"
            Risk = "None"
            Recommendation = "Federation with external organizations is disabled"
        }
    }
    else {
        $assessmentResults += [PSCustomObject]@{
            Category = "Federation"
            Setting = "Allow Federated Users"
            CurrentValue = $true
            Status = "INFO"
            Risk = "Medium"
            Recommendation = "Federation enabled - review allowed/blocked domain lists"
        }
    }
    
    # Open federation (allow all domains)
    $maxScore += 10
    if ($externalAccessPolicy.AllowPublicUsers -eq $false) {
        $securityScore += 10
        $assessmentResults += [PSCustomObject]@{
            Category = "Federation"
            Setting = "Allow Public Users"
            CurrentValue = $false
            Status = "SECURE"
            Risk = "None"
            Recommendation = "Public/anonymous access is disabled"
        }
    }
    else {
        $assessmentResults += [PSCustomObject]@{
            Category = "Federation"
            Setting = "Allow Public Users"
            CurrentValue = $true
            Status = "WARNING"
            Risk = "Medium"
            Recommendation = "Consider disabling public user access"
        }
    }
    
    # Teams with Skype consumer
    $maxScore += 5
    if ($externalAccessPolicy.AllowTeamsConsumer -eq $false) {
        $securityScore += 5
        $assessmentResults += [PSCustomObject]@{
            Category = "Federation"
            Setting = "Allow Teams Consumer"
            CurrentValue = $false
            Status = "SECURE"
            Risk = "None"
            Recommendation = "Teams consumer (personal) access disabled"
        }
    }
    else {
        $assessmentResults += [PSCustomObject]@{
            Category = "Federation"
            Setting = "Allow Teams Consumer"
            CurrentValue = $true
            Status = "WARNING"
            Risk = "Medium"
            Recommendation = "Consider disabling Teams consumer access for business accounts"
        }
    }

    # 4. Meeting Policies
    Write-Host "Checking meeting policies..." -ForegroundColor Yellow
    $meetingPolicies = Get-CsTeamsMeetingPolicy
    
    foreach ($policy in $meetingPolicies) {
        if ($policy.Identity -eq "Global") {
            # Anonymous users can join meetings
            $maxScore += 5
            if ($policy.AllowAnonymousUsersToJoinMeeting -eq $false) {
                $securityScore += 5
                $assessmentResults += [PSCustomObject]@{
                    Category = "Meeting Security"
                    Setting = "Anonymous Join (Global)"
                    CurrentValue = $false
                    Status = "SECURE"
                    Risk = "None"
                    Recommendation = "Anonymous users cannot join meetings"
                }
            }
            else {
                $assessmentResults += [PSCustomObject]@{
                    Category = "Meeting Security"
                    Setting = "Anonymous Join (Global)"
                    CurrentValue = $true
                    Status = "INFO"
                    Risk = "Medium"
                    Recommendation = "Anonymous access allowed - ensure lobby is enabled"
                }
            }
            
            # Lobby bypass
            $maxScore += 5
            if ($policy.AutoAdmittedUsers -eq "EveryoneInCompany") {
                $securityScore += 5
                $assessmentResults += [PSCustomObject]@{
                    Category = "Meeting Security"
                    Setting = "Auto-Admit (Global)"
                    CurrentValue = "EveryoneInCompany"
                    Status = "SECURE"
                    Risk = "None"
                    Recommendation = "Only company users bypass lobby"
                }
            }
            elseif ($policy.AutoAdmittedUsers -eq "Everyone") {
                $assessmentResults += [PSCustomObject]@{
                    Category = "Meeting Security"
                    Setting = "Auto-Admit (Global)"
                    CurrentValue = "Everyone"
                    Status = "WARNING"
                    Risk = "High"
                    Recommendation = "Everyone bypasses lobby - security risk"
                }
            }
            else {
                $securityScore += 3
                $assessmentResults += [PSCustomObject]@{
                    Category = "Meeting Security"
                    Setting = "Auto-Admit (Global)"
                    CurrentValue = $policy.AutoAdmittedUsers
                    Status = "INFO"
                    Risk = "Low"
                    Recommendation = "Lobby configuration: $($policy.AutoAdmittedUsers)"
                }
            }
            
            # External participants can give control
            $maxScore += 5
            if ($policy.AllowExternalParticipantGiveRequestControl -eq $false) {
                $securityScore += 5
                $assessmentResults += [PSCustomObject]@{
                    Category = "Meeting Security"
                    Setting = "External Control (Global)"
                    CurrentValue = $false
                    Status = "SECURE"
                    Risk = "None"
                    Recommendation = "External users cannot give/request control"
                }
            }
            else {
                $assessmentResults += [PSCustomObject]@{
                    Category = "Meeting Security"
                    Setting = "External Control (Global)"
                    CurrentValue = $true
                    Status = "WARNING"
                    Risk = "Medium"
                    Recommendation = "External users can give/request control - potential risk"
                }
            }
        }
    }

    # 5. Allowed/Blocked Domain Lists
    Write-Host "Checking allowed/blocked domains..." -ForegroundColor Yellow
    $allowedDomains = $externalAccessPolicy.AllowedDomains
    $blockedDomains = $externalAccessPolicy.BlockedDomains
    
    $maxScore += 5
    if ($allowedDomains -and $allowedDomains.Count -gt 0) {
        $securityScore += 5
        $assessmentResults += [PSCustomObject]@{
            Category = "Domain Control"
            Setting = "Allowed Domains"
            CurrentValue = "$($allowedDomains.Count) domains"
            Status = "SECURE"
            Risk = "None"
            Recommendation = "Allow-list configured with $($allowedDomains.Count) approved domains"
        }
    }
    elseif ($blockedDomains -and $blockedDomains.Count -gt 0) {
        $securityScore += 3
        $assessmentResults += [PSCustomObject]@{
            Category = "Domain Control"
            Setting = "Blocked Domains"
            CurrentValue = "$($blockedDomains.Count) domains"
            Status = "INFO"
            Risk = "Low"
            Recommendation = "Block-list configured with $($blockedDomains.Count) blocked domains"
        }
    }
    else {
        $assessmentResults += [PSCustomObject]@{
            Category = "Domain Control"
            Setting = "Domain Lists"
            CurrentValue = "Open federation"
            Status = "WARNING"
            Risk = "High"
            Recommendation = "No domain restrictions - all external domains allowed"
        }
    }

    # Calculate final score
    $finalScore = if ($maxScore -gt 0) { [math]::Round(($securityScore / $maxScore) * 100, 2) } else { 0 }

    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Teams External Access Assessment" -ForegroundColor Cyan
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

    $vulnerabilities = $assessmentResults | Where-Object { $_.Status -eq "WARNING" }
    $secure = $assessmentResults | Where-Object { $_.Status -eq "SECURE" }
    
    Write-Host "`nFindings:" -ForegroundColor Cyan
    Write-Host "  - Security Warnings:           $($vulnerabilities.Count)" -ForegroundColor Yellow
    Write-Host "  - Secure Settings:             $($secure.Count)" -ForegroundColor Green
    Write-Host "  - Informational:               $(($assessmentResults | Where-Object { $_.Status -eq 'INFO' }).Count)" -ForegroundColor White

    # Warnings
    if ($vulnerabilities.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Yellow
        Write-Host "  Security Warnings" -ForegroundColor Yellow
        Write-Host "========================================`n" -ForegroundColor Yellow
        
        $vulnerabilities | Select-Object Category, Setting, CurrentValue, Risk, Recommendation |
            Format-Table -AutoSize -Wrap
    }

    # All findings
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Complete Assessment" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    $assessmentResults | Select-Object Category, Setting, CurrentValue, Status, Risk |
        Format-Table -AutoSize

    # Export
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPath = Join-Path $ExportPath "TeamsExternalAccess_Report_$timestamp.csv"
    $assessmentResults | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Report saved to: $reportPath" -ForegroundColor Green
    Write-Host "Security Score: $finalScore%" -ForegroundColor $(if ($finalScore -ge 80) { "Green" } elseif ($finalScore -ge 60) { "Yellow" } else { "Red" })
    Write-Host "========================================`n" -ForegroundColor Green

    # Recommendations
    Write-Host "Security Recommendations:" -ForegroundColor Cyan
    if ($vulnerabilities.Count -gt 0) {
        Write-Host "  1. [HIGH] Review and address $($vulnerabilities.Count) security warnings" -ForegroundColor Yellow
    }
    Write-Host "  2. Implement allow-list for external domains instead of open federation" -ForegroundColor White
    Write-Host "  3. Enable meeting lobby for external participants" -ForegroundColor White
    Write-Host "  4. Regular audits of guest and external access" -ForegroundColor White
    Write-Host "  5. Monitor Teams usage with external users" -ForegroundColor White
    Write-Host "  6. Implement expiration policies for guest accounts`n" -ForegroundColor White

    Disconnect-MicrosoftTeams | Out-Null
}
catch {
    Write-Host "`nError: $_" -ForegroundColor Red
    try { Disconnect-MicrosoftTeams | Out-Null } catch { }
    exit 1
}
