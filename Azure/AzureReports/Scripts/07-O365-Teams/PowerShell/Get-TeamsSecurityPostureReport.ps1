<#
.SYNOPSIS
    Comprehensive Microsoft Teams security posture assessment.

.DESCRIPTION
    This script performs a complete security assessment of Microsoft Teams including
    policies, configurations, access controls, and compliance settings.

.PARAMETER ExportPath
    Optional. The path where the CSV report will be saved. Defaults to current directory.

.EXAMPLE
    .\Get-TeamsSecurityPostureReport.ps1

.EXAMPLE
    .\Get-TeamsSecurityPostureReport.ps1 -ExportPath "C:\Reports"

.NOTES
    Author: Azure Security Audit Team
    Requirements:
    - MicrosoftTeams PowerShell module
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
    Write-Host "  Teams Security Posture Assessment" -ForegroundColor Cyan
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

    # 1. Messaging Policies
    Write-Host "Analyzing messaging policies..." -ForegroundColor Yellow
    $messagingPolicies = Get-CsTeamsMessagingPolicy
    
    foreach ($policy in $messagingPolicies) {
        if ($policy.Identity -eq "Global") {
            # Chat with yourself
            $maxScore += 3
            if ($policy.AllowUserChat -eq $true) {
                $securityScore += 3
                $status = "INFO"
            }
            else {
                $status = "WARNING"
            }
            
            $assessmentResults += [PSCustomObject]@{
                Category = "Messaging"
                Setting = "Allow User Chat"
                CurrentValue = $policy.AllowUserChat
                Status = $status
                Risk = "Low"
                Recommendation = "Chat enabled for collaboration"
            }
            
            # Remove messages
            $maxScore += 3
            if ($policy.AllowUserDeleteMessage -eq $false) {
                $securityScore += 3
                $assessmentResults += [PSCustomObject]@{
                    Category = "Messaging"
                    Setting = "Allow Delete Messages"
                    CurrentValue = $false
                    Status = "SECURE"
                    Risk = "None"
                    Recommendation = "Message deletion restricted for compliance"
                }
            }
            else {
                $assessmentResults += [PSCustomObject]@{
                    Category = "Messaging"
                    Setting = "Allow Delete Messages"
                    CurrentValue = $true
                    Status = "INFO"
                    Risk = "Low"
                    Recommendation = "Users can delete their messages"
                }
            }
            
            # Giphy content rating
            $maxScore += 5
            if ($policy.AllowGiphy -eq $false) {
                $securityScore += 5
                $assessmentResults += [PSCustomObject]@{
                    Category = "Content Control"
                    Setting = "Allow Giphy"
                    CurrentValue = $false
                    Status = "SECURE"
                    Risk = "None"
                    Recommendation = "Giphy disabled"
                }
            }
            elseif ($policy.GiphyRatingType -eq "Strict") {
                $securityScore += 4
                $assessmentResults += [PSCustomObject]@{
                    Category = "Content Control"
                    Setting = "Giphy Rating"
                    CurrentValue = "Strict"
                    Status = "SECURE"
                    Risk = "Low"
                    Recommendation = "Giphy content set to strict rating"
                }
            }
            else {
                $assessmentResults += [PSCustomObject]@{
                    Category = "Content Control"
                    Setting = "Giphy Rating"
                    CurrentValue = $policy.GiphyRatingType
                    Status = "WARNING"
                    Risk = "Low"
                    Recommendation = "Consider setting Giphy rating to Strict"
                }
            }
        }
    }

    # 2. Meeting Policies
    Write-Host "Analyzing meeting policies..." -ForegroundColor Yellow
    $meetingPolicies = Get-CsTeamsMeetingPolicy
    
    foreach ($policy in $meetingPolicies) {
        if ($policy.Identity -eq "Global") {
            # Screen sharing
            $maxScore += 5
            if ($policy.ScreenSharingMode -eq "EntireScreen" -or $policy.ScreenSharingMode -eq "SingleApplication") {
                $securityScore += 3
                $status = "INFO"
                $risk = "Low"
            }
            elseif ($policy.ScreenSharingMode -eq "Disabled") {
                $securityScore += 5
                $status = "SECURE"
                $risk = "None"
            }
            else {
                $status = "INFO"
                $risk = "Low"
            }
            
            $assessmentResults += [PSCustomObject]@{
                Category = "Meeting Security"
                Setting = "Screen Sharing Mode"
                CurrentValue = $policy.ScreenSharingMode
                Status = $status
                Risk = $risk
                Recommendation = "Screen sharing configured"
            }
            
            # Recording
            $maxScore += 5
            if ($policy.AllowCloudRecording -eq $false) {
                $securityScore += 5
                $assessmentResults += [PSCustomObject]@{
                    Category = "Meeting Security"
                    Setting = "Cloud Recording"
                    CurrentValue = $false
                    Status = "SECURE"
                    Risk = "None"
                    Recommendation = "Cloud recording disabled for data protection"
                }
            }
            else {
                $securityScore += 2
                $assessmentResults += [PSCustomObject]@{
                    Category = "Meeting Security"
                    Setting = "Cloud Recording"
                    CurrentValue = $true
                    Status = "INFO"
                    Risk = "Medium"
                    Recommendation = "Recording enabled - ensure proper storage security"
                }
            }
            
            # Allow PowerPoint sharing
            $maxScore += 3
            if ($policy.AllowPowerPointSharing -eq $true) {
                $securityScore += 3
                $assessmentResults += [PSCustomObject]@{
                    Category = "Collaboration"
                    Setting = "PowerPoint Sharing"
                    CurrentValue = $true
                    Status = "INFO"
                    Risk = "Low"
                    Recommendation = "PowerPoint sharing enabled"
                }
            }
            
            # Meeting chat
            $maxScore += 3
            if ($policy.MeetingChatEnabledType -eq "Disabled") {
                $securityScore += 3
                $assessmentResults += [PSCustomObject]@{
                    Category = "Meeting Security"
                    Setting = "Meeting Chat"
                    CurrentValue = "Disabled"
                    Status = "SECURE"
                    Risk = "None"
                    Recommendation = "Meeting chat disabled"
                }
            }
            else {
                $assessmentResults += [PSCustomObject]@{
                    Category = "Meeting Security"
                    Setting = "Meeting Chat"
                    CurrentValue = $policy.MeetingChatEnabledType
                    Status = "INFO"
                    Risk = "Low"
                    Recommendation = "Meeting chat enabled"
                }
            }
        }
    }

    # 3. App Policies
    Write-Host "Analyzing app policies..." -ForegroundColor Yellow
    $appPolicies = Get-CsTeamsAppPermissionPolicy
    
    foreach ($policy in $appPolicies) {
        if ($policy.Identity -eq "Global") {
            # Third-party apps
            $maxScore += 10
            if ($policy.DefaultCatalogAppsType -eq "BlockedAppList") {
                $securityScore += 10
                $assessmentResults += [PSCustomObject]@{
                    Category = "App Security"
                    Setting = "Default Catalog Apps"
                    CurrentValue = "BlockedAppList"
                    Status = "SECURE"
                    Risk = "None"
                    Recommendation = "Third-party apps use block-list approach"
                }
            }
            elseif ($policy.DefaultCatalogAppsType -eq "AllowedAppList") {
                $securityScore += 8
                $assessmentResults += [PSCustomObject]@{
                    Category = "App Security"
                    Setting = "Default Catalog Apps"
                    CurrentValue = "AllowedAppList"
                    Status = "SECURE"
                    Risk = "Low"
                    Recommendation = "Third-party apps use allow-list (most restrictive)"
                }
            }
            else {
                $assessmentResults += [PSCustomObject]@{
                    Category = "App Security"
                    Setting = "Default Catalog Apps"
                    CurrentValue = $policy.DefaultCatalogAppsType
                    Status = "WARNING"
                    Risk = "High"
                    Recommendation = "Consider restricting third-party apps"
                }
            }
            
            # Global apps (Microsoft apps)
            $maxScore += 5
            if ($policy.GlobalCatalogAppsType -eq "AllowedAppList") {
                $securityScore += 3
                $assessmentResults += [PSCustomObject]@{
                    Category = "App Security"
                    Setting = "Global Catalog Apps"
                    CurrentValue = "AllowedAppList"
                    Status = "SECURE"
                    Risk = "Low"
                    Recommendation = "Microsoft apps use allow-list"
                }
            }
            else {
                $securityScore += 5
                $assessmentResults += [PSCustomObject]@{
                    Category = "App Security"
                    Setting = "Global Catalog Apps"
                    CurrentValue = $policy.GlobalCatalogAppsType
                    Status = "INFO"
                    Risk = "Low"
                    Recommendation = "Microsoft apps policy: $($policy.GlobalCatalogAppsType)"
                }
            }
        }
    }

    # 4. Calling Policies
    Write-Host "Analyzing calling policies..." -ForegroundColor Yellow
    $callingPolicies = Get-CsTeamsCallingPolicy
    
    foreach ($policy in $callingPolicies) {
        if ($policy.Identity -eq "Global") {
            # Call forwarding
            $maxScore += 3
            if ($policy.AllowCallForwardingToUser -eq $false) {
                $securityScore += 3
                $assessmentResults += [PSCustomObject]@{
                    Category = "Calling Security"
                    Setting = "Call Forwarding"
                    CurrentValue = $false
                    Status = "SECURE"
                    Risk = "None"
                    Recommendation = "Call forwarding disabled"
                }
            }
            else {
                $assessmentResults += [PSCustomObject]@{
                    Category = "Calling Security"
                    Setting = "Call Forwarding"
                    CurrentValue = $true
                    Status = "INFO"
                    Risk = "Low"
                    Recommendation = "Call forwarding enabled"
                }
            }
            
            # Private calling
            $maxScore += 5
            if ($policy.AllowPrivateCalling -eq $true) {
                $securityScore += 5
                $assessmentResults += [PSCustomObject]@{
                    Category = "Calling"
                    Setting = "Private Calling"
                    CurrentValue = $true
                    Status = "INFO"
                    Risk = "Low"
                    Recommendation = "Private calling enabled"
                }
            }
        }
    }

    # 5. Live Events Policies
    Write-Host "Analyzing live events policies..." -ForegroundColor Yellow
    $liveEventPolicies = Get-CsTeamsMeetingBroadcastPolicy
    
    foreach ($policy in $liveEventPolicies) {
        if ($policy.Identity -eq "Global") {
            # Allow broadcast recording
            $maxScore += 5
            if ($policy.AllowBroadcastRecording -eq $false) {
                $securityScore += 5
                $assessmentResults += [PSCustomObject]@{
                    Category = "Live Events"
                    Setting = "Broadcast Recording"
                    CurrentValue = $false
                    Status = "SECURE"
                    Risk = "None"
                    Recommendation = "Live event recording disabled"
                }
            }
            else {
                $securityScore += 2
                $assessmentResults += [PSCustomObject]@{
                    Category = "Live Events"
                    Setting = "Broadcast Recording"
                    CurrentValue = $true
                    Status = "INFO"
                    Risk = "Medium"
                    Recommendation = "Live event recording enabled"
                }
            }
        }
    }

    # 6. External Access Summary
    Write-Host "Checking external access configuration..." -ForegroundColor Yellow
    $federationConfig = Get-CsTenantFederationConfiguration
    
    $maxScore += 10
    if ($federationConfig.AllowFederatedUsers -eq $false -and $federationConfig.AllowPublicUsers -eq $false) {
        $securityScore += 10
        $assessmentResults += [PSCustomObject]@{
            Category = "External Access"
            Setting = "Federation Status"
            CurrentValue = "Disabled"
            Status = "SECURE"
            Risk = "None"
            Recommendation = "External access completely disabled"
        }
    }
    elseif ($federationConfig.AllowedDomains -and $federationConfig.AllowedDomains.Count -gt 0) {
        $securityScore += 8
        $assessmentResults += [PSCustomObject]@{
            Category = "External Access"
            Setting = "Federation Status"
            CurrentValue = "Allow-list ($($federationConfig.AllowedDomains.Count) domains)"
            Status = "SECURE"
            Risk = "Low"
            Recommendation = "External access restricted to approved domains"
        }
    }
    else {
        $assessmentResults += [PSCustomObject]@{
            Category = "External Access"
            Setting = "Federation Status"
            CurrentValue = "Open"
            Status = "WARNING"
            Risk = "High"
            Recommendation = "Consider restricting external access to specific domains"
        }
    }

    # Calculate final score
    $finalScore = if ($maxScore -gt 0) { [math]::Round(($securityScore / $maxScore) * 100, 2) } else { 0 }

    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Teams Security Posture Results" -ForegroundColor Cyan
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
    $secure = $assessmentResults | Where-Object { $_.Status -eq "SECURE" }
    
    Write-Host "`nFindings:" -ForegroundColor Cyan
    Write-Host "  - Security Warnings:           $($warnings.Count)" -ForegroundColor Yellow
    Write-Host "  - Secure Settings:             $($secure.Count)" -ForegroundColor Green
    Write-Host "  - Informational:               $(($assessmentResults | Where-Object { $_.Status -eq 'INFO' }).Count)" -ForegroundColor White

    # Warnings
    if ($warnings.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Yellow
        Write-Host "  Security Warnings" -ForegroundColor Yellow
        Write-Host "========================================`n" -ForegroundColor Yellow
        
        $warnings | Select-Object Category, Setting, CurrentValue, Risk, Recommendation |
            Format-Table -AutoSize -Wrap
    }

    # Security by category
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Security by Category" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    $categoryStats = $assessmentResults | Group-Object -Property Category |
        Select-Object Name, Count, @{Name="Secure";Expression={($_.Group | Where-Object { $_.Status -eq "SECURE" }).Count}}, @{Name="Warnings";Expression={($_.Group | Where-Object { $_.Status -eq "WARNING" }).Count}}
    
    $categoryStats | Format-Table -AutoSize

    # All findings
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Complete Assessment" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    $assessmentResults | Select-Object Category, Setting, CurrentValue, Status, Risk |
        Format-Table -AutoSize

    # Export
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPath = Join-Path $ExportPath "TeamsSecurityPosture_Report_$timestamp.csv"
    $assessmentResults | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Report saved to: $reportPath" -ForegroundColor Green
    Write-Host "Security Score: $finalScore%" -ForegroundColor $(if ($finalScore -ge 80) { "Green" } elseif ($finalScore -ge 60) { "Yellow" } else { "Red" })
    Write-Host "========================================`n" -ForegroundColor Green

    # Recommendations
    Write-Host "Priority Actions:" -ForegroundColor Cyan
    if ($warnings.Count -gt 0) {
        Write-Host "  1. [HIGH] Address $($warnings.Count) security warnings" -ForegroundColor Yellow
    }
    Write-Host "  2. Implement Data Loss Prevention (DLP) policies for Teams" -ForegroundColor White
    Write-Host "  3. Enable sensitivity labels for Teams" -ForegroundColor White
    Write-Host "  4. Configure retention policies for compliance" -ForegroundColor White
    Write-Host "  5. Regular security audits and monitoring" -ForegroundColor White
    Write-Host "  6. User training on secure collaboration practices`n" -ForegroundColor White

    Disconnect-MicrosoftTeams | Out-Null
}
catch {
    Write-Host "`nError: $_" -ForegroundColor Red
    try { Disconnect-MicrosoftTeams | Out-Null } catch { }
    exit 1
}
