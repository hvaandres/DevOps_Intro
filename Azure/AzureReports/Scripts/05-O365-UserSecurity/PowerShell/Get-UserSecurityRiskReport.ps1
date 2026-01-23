<#
.SYNOPSIS
    Comprehensive security risk assessment for Office 365 user accounts.

.DESCRIPTION
    This script performs a comprehensive security risk assessment of user accounts including
    sign-in patterns, MFA status, privileged access, inactive accounts, and other security indicators.

.PARAMETER ExportPath
    Optional. The path where the CSV report will be saved. Defaults to current directory.

.PARAMETER InactiveDaysThreshold
    Optional. Number of days to consider an account inactive. Default is 90 days.

.EXAMPLE
    .\Get-UserSecurityRiskReport.ps1

.EXAMPLE
    .\Get-UserSecurityRiskReport.ps1 -InactiveDaysThreshold 60

.NOTES
    Author: Azure Security Audit Team
    Requirements:
    - Microsoft.Graph PowerShell module
    - Permissions: User.Read.All, UserAuthenticationMethod.Read.All, Directory.Read.All, AuditLog.Read.All, RoleManagement.Read.All
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ExportPath = ".",
    
    [Parameter(Mandatory=$false)]
    [int]$InactiveDaysThreshold = 90
)

try {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  User Account Security Risk Assessment" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    # Connect to Microsoft Graph
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
    Connect-MgGraph -Scopes "User.Read.All", "UserAuthenticationMethod.Read.All", "Directory.Read.All", "AuditLog.Read.All", "RoleManagement.Read.All" -ErrorAction Stop
    Write-Host "Connected successfully.`n" -ForegroundColor Green

    $cutoffDate = (Get-Date).AddDays(-$InactiveDaysThreshold)
    
    # Get privileged role assignments
    Write-Host "Fetching privileged role assignments..." -ForegroundColor Yellow
    $roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -All
    $privilegedUserIds = $roleAssignments | Select-Object -ExpandProperty PrincipalId -Unique

    # Get all users
    Write-Host "Fetching user accounts..." -ForegroundColor Yellow
    $users = Get-MgUser -All -Property Id, UserPrincipalName, DisplayName, AccountEnabled, UserType, CreatedDateTime, AssignedLicenses, SignInActivity, Mail, OnPremisesSyncEnabled, PasswordPolicies

    Write-Host "Found $($users.Count) users. Analyzing security posture...`n" -ForegroundColor Green

    $reportData = @()
    $counter = 0

    foreach ($user in $users) {
        $counter++
        Write-Progress -Activity "Analyzing Security Risks" -Status $user.UserPrincipalName -PercentComplete (($counter / $users.Count) * 100)
        
        # Sign-in analysis
        $lastSignIn = $null
        $daysInactive = $null
        $isInactive = $false
        
        if ($user.SignInActivity -and $user.SignInActivity.LastSignInDateTime) {
            $lastSignIn = $user.SignInActivity.LastSignInDateTime
            $daysInactive = (New-TimeSpan -Start $lastSignIn -End (Get-Date)).Days
            $isInactive = ($lastSignIn -lt $cutoffDate)
        }
        else {
            $daysInactive = "Never"
            $isInactive = $true
        }
        
        # Check if privileged account
        $isPrivileged = $privilegedUserIds -contains $user.Id
        
        # Get MFA status
        $mfaStatus = "Unknown"
        $mfaMethods = @()
        try {
            $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue
            if ($authMethods) {
                $mfaMethods = $authMethods | Where-Object { 
                    $_.'@odata.type' -ne '#microsoft.graph.passwordAuthenticationMethod' 
                }
                if ($mfaMethods.Count -gt 0) {
                    $mfaStatus = "Enabled"
                } else {
                    $mfaStatus = "Disabled"
                }
            }
        }
        catch {
            $mfaStatus = "Unable to check"
        }
        
        # Account age
        $accountAge = if ($user.CreatedDateTime) {
            (New-TimeSpan -Start $user.CreatedDateTime -End (Get-Date)).Days
        } else { 0 }
        
        # Password policy check
        $passwordNeverExpires = ($user.PasswordPolicies -like "*DisablePasswordExpiration*")
        
        # Risk scoring and factors
        $riskScore = 0
        $riskFactors = @()
        $securityIssues = @()
        
        # Critical risks (20 points each)
        if ($isPrivileged -and $mfaStatus -eq "Disabled") {
            $riskScore += 20
            $riskFactors += "CRITICAL: Privileged account without MFA"
            $securityIssues += "Privileged-NoMFA"
        }
        
        if ($isPrivileged -and $isInactive) {
            $riskScore += 20
            $riskFactors += "CRITICAL: Inactive privileged account"
            $securityIssues += "Privileged-Inactive"
        }
        
        # High risks (10 points each)
        if ($mfaStatus -eq "Disabled" -and $user.AccountEnabled -and $user.AssignedLicenses.Count -gt 0) {
            $riskScore += 10
            $riskFactors += "HIGH: Active licensed user without MFA"
            $securityIssues += "NoMFA"
        }
        
        if ($isInactive -and $user.AccountEnabled -and $user.AssignedLicenses.Count -gt 0) {
            $riskScore += 10
            $riskFactors += "HIGH: Inactive account with licenses still enabled"
            $securityIssues += "Inactive-Licensed"
        }
        
        if ($passwordNeverExpires -and $user.AccountEnabled) {
            $riskScore += 10
            $riskFactors += "HIGH: Password set to never expire"
            $securityIssues += "Password-NeverExpires"
        }
        
        # Medium risks (5 points each)
        if ($user.UserType -eq "Guest" -and $isInactive) {
            $riskScore += 5
            $riskFactors += "MEDIUM: Inactive guest account"
            $securityIssues += "Guest-Inactive"
        }
        
        if ($daysInactive -eq "Never" -and $accountAge -gt 30) {
            $riskScore += 5
            $riskFactors += "MEDIUM: Account created but never used"
            $securityIssues += "Never-Used"
        }
        
        if (-not $user.OnPremisesSyncEnabled -and $isPrivileged) {
            $riskScore += 5
            $riskFactors += "MEDIUM: Cloud-only privileged account"
            $securityIssues += "CloudOnly-Privileged"
        }
        
        # Low risks (2 points each)
        if ($user.UserType -eq "Guest" -and -not $isInactive) {
            $riskScore += 2
            $riskFactors += "LOW: Active guest account (monitor)"
            $securityIssues += "Guest-Active"
        }
        
        # Determine overall risk level
        $riskLevel = "Low"
        if ($riskScore -ge 20) { $riskLevel = "CRITICAL" }
        elseif ($riskScore -ge 15) { $riskLevel = "High" }
        elseif ($riskScore -ge 8) { $riskLevel = "Medium" }
        elseif ($riskScore -gt 0) { $riskLevel = "Low" }
        else { $riskLevel = "Normal" }
        
        $reportData += [PSCustomObject]@{
            UserPrincipalName = $user.UserPrincipalName
            DisplayName = $user.DisplayName
            UserType = $user.UserType
            AccountEnabled = $user.AccountEnabled
            IsPrivileged = $isPrivileged
            MFAStatus = $mfaStatus
            MFAMethodsCount = $mfaMethods.Count
            LastSignIn = if ($lastSignIn) { $lastSignIn.ToString("yyyy-MM-dd") } else { "Never" }
            DaysInactive = $daysInactive
            AccountAge = $accountAge
            IsLicensed = ($user.AssignedLicenses.Count -gt 0)
            IsSynced = $user.OnPremisesSyncEnabled
            PasswordNeverExpires = $passwordNeverExpires
            RiskScore = $riskScore
            RiskLevel = $riskLevel
            SecurityIssues = ($securityIssues -join ', ')
            RiskFactors = ($riskFactors -join '; ')
        }
    }

    Write-Progress -Activity "Analyzing Security Risks" -Completed

    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Security Risk Summary" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $criticalRisk = $reportData | Where-Object { $_.RiskLevel -eq "CRITICAL" }
    $highRisk = $reportData | Where-Object { $_.RiskLevel -eq "High" }
    $mediumRisk = $reportData | Where-Object { $_.RiskLevel -eq "Medium" }
    $lowRisk = $reportData | Where-Object { $_.RiskLevel -eq "Low" }
    
    $privilegedNoMFA = $reportData | Where-Object { $_.IsPrivileged -and $_.MFAStatus -eq "Disabled" }
    $activeNoMFA = $reportData | Where-Object { $_.AccountEnabled -and $_.MFAStatus -eq "Disabled" -and $_.UserType -eq "Member" }
    $inactivePrivileged = $reportData | Where-Object { $_.IsPrivileged -and ($_.DaysInactive -eq "Never" -or $_.DaysInactive -ge $InactiveDaysThreshold) }

    Write-Host "Total Users Analyzed:            $($reportData.Count)" -ForegroundColor White
    Write-Host "`nRisk Distribution:" -ForegroundColor Cyan
    Write-Host "  - CRITICAL Risk:               $($criticalRisk.Count)" -ForegroundColor Red
    Write-Host "  - High Risk:                   $($highRisk.Count)" -ForegroundColor Red
    Write-Host "  - Medium Risk:                 $($mediumRisk.Count)" -ForegroundColor Yellow
    Write-Host "  - Low Risk:                    $($lowRisk.Count)" -ForegroundColor Yellow
    Write-Host "`nKey Security Issues:" -ForegroundColor Cyan
    Write-Host "  - Privileged without MFA:      $($privilegedNoMFA.Count)" -ForegroundColor Red
    Write-Host "  - Active users without MFA:    $($activeNoMFA.Count)" -ForegroundColor Red
    Write-Host "  - Inactive privileged:         $($inactivePrivileged.Count)" -ForegroundColor Red

    # Critical risks
    if ($criticalRisk.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  CRITICAL RISK Accounts" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Red
        
        $criticalRisk | Select-Object UserPrincipalName, IsPrivileged, MFAStatus, DaysInactive, RiskScore, RiskFactors |
            Format-Table -AutoSize -Wrap
    }

    # Privileged accounts without MFA
    if ($privilegedNoMFA.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  CRITICAL: Privileged Accounts without MFA" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Red
        
        $privilegedNoMFA | Select-Object UserPrincipalName, DisplayName, AccountEnabled, LastSignIn |
            Format-Table -AutoSize
    }

    # Inactive privileged accounts
    if ($inactivePrivileged.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  CRITICAL: Inactive Privileged Accounts" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Red
        
        $inactivePrivileged | Select-Object UserPrincipalName, DisplayName, DaysInactive, MFAStatus |
            Format-Table -AutoSize
    }

    # High risk accounts
    if ($highRisk.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Yellow
        Write-Host "  High Risk Accounts (First 15)" -ForegroundColor Yellow
        Write-Host "========================================`n" -ForegroundColor Yellow
        
        $highRisk | Select-Object UserPrincipalName, RiskScore, MFAStatus, DaysInactive, RiskFactors -First 15 |
            Format-Table -AutoSize -Wrap
    }

    # Top 20 highest risk scores
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Top 20 Highest Risk Scores" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $reportData | Sort-Object -Property RiskScore -Descending |
        Select-Object UserPrincipalName, RiskScore, RiskLevel, IsPrivileged, MFAStatus, DaysInactive -First 20 |
        Format-Table -AutoSize

    # MFA statistics
    $mfaEnabled = $reportData | Where-Object { $_.MFAStatus -eq "Enabled" }
    $mfaDisabled = $reportData | Where-Object { $_.MFAStatus -eq "Disabled" }
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  MFA Adoption Statistics" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    $mfaPercentage = if ($reportData.Count -gt 0) { [math]::Round(($mfaEnabled.Count / $reportData.Count) * 100, 2) } else { 0 }
    Write-Host "MFA Enabled:  $($mfaEnabled.Count) users ($mfaPercentage%)" -ForegroundColor Green
    Write-Host "MFA Disabled: $($mfaDisabled.Count) users ($([math]::Round(100 - $mfaPercentage, 2))%)" -ForegroundColor Red

    # Export
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPath = Join-Path $ExportPath "UserSecurityRisk_Report_$timestamp.csv"
    $reportData | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Report saved to: $reportPath" -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Green

    # Recommendations
    Write-Host "Priority Security Actions:" -ForegroundColor Cyan
    Write-Host "  1. [IMMEDIATE] Enable MFA for $($privilegedNoMFA.Count) privileged accounts" -ForegroundColor Red
    Write-Host "  2. [IMMEDIATE] Review/disable $($inactivePrivileged.Count) inactive privileged accounts" -ForegroundColor Red
    Write-Host "  3. [HIGH] Enforce MFA for $($activeNoMFA.Count) active users" -ForegroundColor Yellow
    Write-Host "  4. [HIGH] Address $($criticalRisk.Count) critical risk accounts" -ForegroundColor Yellow
    Write-Host "  5. [MEDIUM] Review $($highRisk.Count) high-risk accounts" -ForegroundColor Yellow
    Write-Host "  6. Implement Conditional Access policies" -ForegroundColor White
    Write-Host "  7. Enable security defaults or enforce MFA organization-wide" -ForegroundColor White
    Write-Host "  8. Regular access reviews for privileged accounts" -ForegroundColor White
    Write-Host "  9. Implement automated risk-based alerts`n" -ForegroundColor White

    Disconnect-MgGraph | Out-Null
}
catch {
    Write-Host "`nError: $_" -ForegroundColor Red
    try { Disconnect-MgGraph | Out-Null } catch { }
    exit 1
}
