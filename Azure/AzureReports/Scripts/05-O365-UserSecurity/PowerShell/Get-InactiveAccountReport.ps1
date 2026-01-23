<#
.SYNOPSIS
    Detects inactive Office 365 user accounts.

.DESCRIPTION
    This script identifies user accounts that have not signed in for a specified period (default 90+ days)
    and provides detailed analysis of account activity.

.PARAMETER ExportPath
    Optional. The path where the CSV report will be saved. Defaults to current directory.

.PARAMETER InactiveDaysThreshold
    Optional. Number of days to consider an account inactive. Default is 90 days.

.EXAMPLE
    .\Get-InactiveAccountReport.ps1

.EXAMPLE
    .\Get-InactiveAccountReport.ps1 -InactiveDaysThreshold 60 -ExportPath "C:\Reports"

.NOTES
    Author: Azure Security Audit Team
    Requirements:
    - Microsoft.Graph PowerShell module
    - Permissions: User.Read.All, AuditLog.Read.All
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
    Write-Host "  Inactive Account Detection" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    # Connect to Microsoft Graph
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
    Connect-MgGraph -Scopes "User.Read.All", "AuditLog.Read.All" -ErrorAction Stop
    Write-Host "Connected successfully.`n" -ForegroundColor Green

    $cutoffDate = (Get-Date).AddDays(-$InactiveDaysThreshold)
    
    # Get all users with sign-in activity
    Write-Host "Fetching user accounts and sign-in activity..." -ForegroundColor Yellow
    $users = Get-MgUser -All -Property Id, UserPrincipalName, DisplayName, AccountEnabled, UserType, CreatedDateTime, AssignedLicenses, SignInActivity, Mail, JobTitle, Department

    Write-Host "Found $($users.Count) total users.`n" -ForegroundColor Green

    $reportData = @()
    $counter = 0

    foreach ($user in $users) {
        $counter++
        Write-Progress -Activity "Analyzing User Accounts" -Status $user.UserPrincipalName -PercentComplete (($counter / $users.Count) * 100)
        
        # Determine last sign-in
        $lastSignIn = $null
        $lastInteractiveSignIn = $null
        $daysInactive = $null
        $isInactive = $false
        $activityStatus = "Unknown"
        
        if ($user.SignInActivity) {
            if ($user.SignInActivity.LastSignInDateTime) {
                $lastSignIn = $user.SignInActivity.LastSignInDateTime
            }
            if ($user.SignInActivity.LastNonInteractiveSignInDateTime) {
                $lastInteractiveSignIn = $user.SignInActivity.LastNonInteractiveSignInDateTime
            }
        }
        
        # Use the most recent sign-in
        $mostRecentSignIn = $lastSignIn
        if ($lastInteractiveSignIn -and (-not $mostRecentSignIn -or $lastInteractiveSignIn -gt $mostRecentSignIn)) {
            $mostRecentSignIn = $lastInteractiveSignIn
        }
        
        if ($mostRecentSignIn) {
            $daysInactive = (New-TimeSpan -Start $mostRecentSignIn -End (Get-Date)).Days
            $isInactive = ($mostRecentSignIn -lt $cutoffDate)
            
            if ($isInactive) {
                $activityStatus = "Inactive ($daysInactive days)"
            } else {
                $activityStatus = "Active (last $daysInactive days ago)"
            }
        }
        else {
            $activityStatus = "Never Signed In"
            $daysInactive = "Never"
            $isInactive = $true
        }
        
        # Calculate account age
        $accountAge = if ($user.CreatedDateTime) {
            (New-TimeSpan -Start $user.CreatedDateTime -End (Get-Date)).Days
        } else { "Unknown" }
        
        # Determine risk level
        $riskLevel = "Low"
        $riskFactors = @()
        
        if (-not $user.AccountEnabled) {
            $riskLevel = "Info"
            $riskFactors += "Account Disabled"
        }
        elseif ($activityStatus -eq "Never Signed In" -and $accountAge -ne "Unknown" -and $accountAge -gt 30) {
            $riskLevel = "High"
            $riskFactors += "Never used (old account)"
        }
        elseif ($isInactive -and $user.AssignedLicenses.Count -gt 0) {
            $riskLevel = "High"
            $riskFactors += "Inactive with licenses"
        }
        elseif ($isInactive -and $user.AccountEnabled) {
            $riskLevel = "Medium"
            $riskFactors += "Inactive enabled account"
        }
        
        # Check for additional risk factors
        if ($user.UserType -eq "Guest" -and $isInactive) {
            $riskFactors += "Inactive guest account"
            if ($riskLevel -eq "Low") { $riskLevel = "Medium" }
        }
        
        $reportData += [PSCustomObject]@{
            UserPrincipalName = $user.UserPrincipalName
            DisplayName = $user.DisplayName
            UserType = $user.UserType
            AccountEnabled = $user.AccountEnabled
            LastSignIn = if ($mostRecentSignIn) { $mostRecentSignIn.ToString("yyyy-MM-dd HH:mm") } else { "Never" }
            DaysInactive = $daysInactive
            ActivityStatus = $activityStatus
            AccountAge = $accountAge
            IsLicensed = ($user.AssignedLicenses.Count -gt 0)
            LicenseCount = $user.AssignedLicenses.Count
            Department = $user.Department
            JobTitle = $user.JobTitle
            RiskLevel = $riskLevel
            RiskFactors = ($riskFactors -join '; ')
        }
    }

    Write-Progress -Activity "Analyzing User Accounts" -Completed

    # Summary statistics
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Inactive Account Summary" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $inactiveAccounts = $reportData | Where-Object { $_.DaysInactive -eq "Never" -or ($_.DaysInactive -ne "Never" -and $_.DaysInactive -ge $InactiveDaysThreshold) }
    $neverSignedIn = $reportData | Where-Object { $_.DaysInactive -eq "Never" }
    $inactiveEnabled = $inactiveAccounts | Where-Object { $_.AccountEnabled }
    $inactiveLicensed = $inactiveAccounts | Where-Object { $_.IsLicensed }
    $highRisk = $reportData | Where-Object { $_.RiskLevel -eq "High" }
    $mediumRisk = $reportData | Where-Object { $_.RiskLevel -eq "Medium" }

    Write-Host "Total User Accounts:             $($reportData.Count)" -ForegroundColor White
    Write-Host "Inactive Accounts ($InactiveDaysThreshold+ days):   $($inactiveAccounts.Count) " -ForegroundColor Red -NoNewline
    Write-Host "($([math]::Round(($inactiveAccounts.Count / $reportData.Count) * 100, 2))%)" -ForegroundColor Red
    Write-Host "  - Never Signed In:             $($neverSignedIn.Count)" -ForegroundColor Yellow
    Write-Host "  - Inactive & Enabled:          $($inactiveEnabled.Count)" -ForegroundColor Yellow
    Write-Host "  - Inactive & Licensed:         $($inactiveLicensed.Count)" -ForegroundColor Yellow
    Write-Host "`nRisk Assessment:" -ForegroundColor Cyan
    Write-Host "  - High Risk:                   $($highRisk.Count)" -ForegroundColor Red
    Write-Host "  - Medium Risk:                 $($mediumRisk.Count)" -ForegroundColor Yellow

    # High risk accounts
    if ($highRisk.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  HIGH RISK: Inactive Accounts (First 20)" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Red
        
        $highRisk | Select-Object UserPrincipalName, ActivityStatus, DaysInactive, IsLicensed, RiskFactors -First 20 |
            Format-Table -AutoSize -Wrap
    }

    # Never signed in accounts
    if ($neverSignedIn.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  Never Signed In Accounts (First 15)" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Red
        
        $neverSignedIn | Select-Object UserPrincipalName, DisplayName, AccountEnabled, AccountAge, IsLicensed -First 15 |
            Format-Table -AutoSize
    }

    # Inactive licensed accounts
    if ($inactiveLicensed.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Yellow
        Write-Host "  Inactive Licensed Accounts (First 15)" -ForegroundColor Yellow
        Write-Host "========================================`n" -ForegroundColor Yellow
        
        $inactiveLicensed | Select-Object UserPrincipalName, LastSignIn, DaysInactive, LicenseCount, Department -First 15 |
            Format-Table -AutoSize
        
        Write-Host "Action: Review and reclaim licenses from these accounts`n" -ForegroundColor Yellow
    }

    # Inactive by department
    $inactiveDepts = $inactiveAccounts | Where-Object { $_.Department } | 
        Group-Object -Property Department | 
        Sort-Object Count -Descending | 
        Select-Object -First 5

    if ($inactiveDepts.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "  Top 5 Departments with Inactive Accounts" -ForegroundColor Cyan
        Write-Host "========================================`n" -ForegroundColor Cyan
        
        $inactiveDepts | ForEach-Object {
            Write-Host "$($_.Name): $($_.Count) inactive accounts" -ForegroundColor White
        }
        Write-Host ""
    }

    # Guest account analysis
    $inactiveGuests = $inactiveAccounts | Where-Object { $_.UserType -eq "Guest" }
    if ($inactiveGuests.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Yellow
        Write-Host "  Inactive Guest Accounts" -ForegroundColor Yellow
        Write-Host "========================================`n" -ForegroundColor Yellow
        
        Write-Host "Total Inactive Guests: $($inactiveGuests.Count)" -ForegroundColor White
        Write-Host "Action: Review and remove unnecessary guest access`n" -ForegroundColor Yellow
    }

    # Export to CSV
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPath = Join-Path $ExportPath "InactiveAccounts_Report_$timestamp.csv"
    $reportData | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Report saved to: $reportPath" -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Green

    # Recommendations
    Write-Host "Security Recommendations:" -ForegroundColor Cyan
    Write-Host "  1. [CRITICAL] Disable or delete $($highRisk.Count) high-risk inactive accounts" -ForegroundColor Red
    Write-Host "  2. [HIGH] Investigate $($neverSignedIn.Count) accounts that never signed in" -ForegroundColor Yellow
    Write-Host "  3. [HIGH] Reclaim licenses from $($inactiveLicensed.Count) inactive licensed accounts" -ForegroundColor Yellow
    Write-Host "  4. [MEDIUM] Review $($mediumRisk.Count) medium-risk accounts" -ForegroundColor Yellow
    Write-Host "  5. Implement automated account lifecycle policy" -ForegroundColor White
    Write-Host "  6. Set up alerts for inactive accounts" -ForegroundColor White
    Write-Host "  7. Regular access reviews for guest accounts`n" -ForegroundColor White

    Disconnect-MgGraph | Out-Null
}
catch {
    Write-Host "`nError: $_" -ForegroundColor Red
    try { Disconnect-MgGraph | Out-Null } catch { }
    exit 1
}
