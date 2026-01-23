<#
.SYNOPSIS
    Identifies licensed but inactive Office 365 accounts.

.DESCRIPTION
    This script detects accounts with active licenses that have not signed in for a specified period,
    providing detailed cost analysis and recommendations for license reclamation.

.PARAMETER ExportPath
    Optional. The path where the CSV report will be saved. Defaults to current directory.

.PARAMETER InactiveDaysThreshold
    Optional. Number of days to consider an account inactive. Default is 90 days.

.EXAMPLE
    .\Get-LicensedInactiveAccountReport.ps1

.EXAMPLE
    .\Get-LicensedInactiveAccountReport.ps1 -InactiveDaysThreshold 60

.NOTES
    Author: Azure Security Audit Team
    Requirements:
    - Microsoft.Graph PowerShell module
    - Permissions: User.Read.All, Organization.Read.All, AuditLog.Read.All
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
    Write-Host "  Licensed Inactive Account Detection" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    # Connect to Microsoft Graph
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
    Connect-MgGraph -Scopes "User.Read.All", "Organization.Read.All", "AuditLog.Read.All" -ErrorAction Stop
    Write-Host "Connected successfully.`n" -ForegroundColor Green

    $cutoffDate = (Get-Date).AddDays(-$InactiveDaysThreshold)
    
    # Get SKU information for cost calculation
    Write-Host "Fetching license information..." -ForegroundColor Yellow
    $skus = Get-MgSubscribedSku
    $skuCosts = @{}
    foreach ($sku in $skus) {
        $cost = switch -Wildcard ($sku.SkuPartNumber) {
            "*E1*" { 8 }
            "*E3*" { 20 }
            "*E5*" { 35 }
            "*F1*" { 4 }
            "*F3*" { 8 }
            "*BUSINESS_BASIC*" { 5 }
            "*BUSINESS_STANDARD*" { 12.50 }
            "*BUSINESS_PREMIUM*" { 22 }
            "*VISIO*" { 15 }
            "*PROJECT*" { 30 }
            "*POWER_BI*" { 10 }
            "*EMS*" { 8 }
            default { 10 }
        }
        $skuCosts[$sku.SkuId] = @{
            Name = $sku.SkuPartNumber
            Cost = $cost
        }
    }

    # Get all licensed users
    Write-Host "Fetching licensed users and activity data..." -ForegroundColor Yellow
    $users = Get-MgUser -All -Property Id, UserPrincipalName, DisplayName, AccountEnabled, UserType, CreatedDateTime, AssignedLicenses, SignInActivity, Department, JobTitle, Manager

    $licensedUsers = $users | Where-Object { $_.AssignedLicenses.Count -gt 0 }
    Write-Host "Found $($licensedUsers.Count) licensed users.`n" -ForegroundColor Green

    $reportData = @()
    $counter = 0
    $totalWastedCost = 0

    foreach ($user in $licensedUsers) {
        $counter++
        Write-Progress -Activity "Analyzing Licensed Users" -Status $user.UserPrincipalName -PercentComplete (($counter / $licensedUsers.Count) * 100)
        
        # Determine last sign-in
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
        
        # Only include inactive accounts
        if (-not $isInactive) { continue }
        
        # Calculate license cost
        $userLicenseCost = 0
        $licenseNames = @()
        foreach ($license in $user.AssignedLicenses) {
            if ($skuCosts.ContainsKey($license.SkuId)) {
                $userLicenseCost += $skuCosts[$license.SkuId].Cost
                $licenseNames += $skuCosts[$license.SkuId].Name
            }
        }
        
        $totalWastedCost += $userLicenseCost
        
        # Calculate account age
        $accountAge = if ($user.CreatedDateTime) {
            (New-TimeSpan -Start $user.CreatedDateTime -End (Get-Date)).Days
        } else { "Unknown" }
        
        # Determine severity
        $severity = "Low"
        $recommendation = "Review account activity"
        
        if (-not $user.AccountEnabled) {
            $severity = "CRITICAL"
            $recommendation = "IMMEDIATE: Remove all licenses - account disabled"
        }
        elseif ($daysInactive -eq "Never") {
            $severity = "CRITICAL"
            $recommendation = "IMMEDIATE: Remove licenses - never used"
        }
        elseif ($daysInactive -gt 180) {
            $severity = "High"
            $recommendation = "Remove licenses - inactive 180+ days"
        }
        elseif ($daysInactive -ge $InactiveDaysThreshold) {
            $severity = "Medium"
            $recommendation = "Contact user or remove licenses"
        }
        
        $reportData += [PSCustomObject]@{
            UserPrincipalName = $user.UserPrincipalName
            DisplayName = $user.DisplayName
            UserType = $user.UserType
            AccountEnabled = $user.AccountEnabled
            LastSignIn = if ($lastSignIn) { $lastSignIn.ToString("yyyy-MM-dd") } else { "Never" }
            DaysInactive = $daysInactive
            AccountAge = $accountAge
            LicenseCount = $user.AssignedLicenses.Count
            Licenses = ($licenseNames -join '; ')
            MonthlyCost = [math]::Round($userLicenseCost, 2)
            AnnualCost = [math]::Round($userLicenseCost * 12, 2)
            Department = $user.Department
            JobTitle = $user.JobTitle
            Severity = $severity
            Recommendation = $recommendation
        }
    }

    Write-Progress -Activity "Analyzing Licensed Users" -Completed

    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Licensed Inactive Account Summary" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $criticalAccounts = $reportData | Where-Object { $_.Severity -eq "CRITICAL" }
    $highSeverity = $reportData | Where-Object { $_.Severity -eq "High" }
    $mediumSeverity = $reportData | Where-Object { $_.Severity -eq "Medium" }
    $disabledAccounts = $reportData | Where-Object { -not $_.AccountEnabled }
    $neverUsed = $reportData | Where-Object { $_.DaysInactive -eq "Never" }

    Write-Host "Total Licensed Users:            $($licensedUsers.Count)" -ForegroundColor White
    Write-Host "Inactive Licensed Users:         $($reportData.Count) " -ForegroundColor Red -NoNewline
    Write-Host "($([math]::Round(($reportData.Count / $licensedUsers.Count) * 100, 2))%)" -ForegroundColor Red
    Write-Host "`nBy Severity:" -ForegroundColor Cyan
    Write-Host "  - CRITICAL:                    $($criticalAccounts.Count)" -ForegroundColor Red
    Write-Host "  - High:                        $($highSeverity.Count)" -ForegroundColor Red
    Write-Host "  - Medium:                      $($mediumSeverity.Count)" -ForegroundColor Yellow
    Write-Host "`nSpecial Cases:" -ForegroundColor Cyan
    Write-Host "  - Disabled with Licenses:      $($disabledAccounts.Count)" -ForegroundColor Red
    Write-Host "  - Licensed Never Used:         $($neverUsed.Count)" -ForegroundColor Red
    Write-Host "`nFinancial Impact:" -ForegroundColor Cyan
    Write-Host "  - Monthly Wasted Cost:         `$$([math]::Round($totalWastedCost, 2)) USD" -ForegroundColor Red
    Write-Host "  - Annual Wasted Cost:          `$$([math]::Round($totalWastedCost * 12, 2)) USD" -ForegroundColor Red

    # Critical accounts - Disabled with licenses
    if ($disabledAccounts.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  CRITICAL: Disabled Accounts with Licenses" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Red
        
        $disabledAccounts | Select-Object UserPrincipalName, DisplayName, LicenseCount, Licenses, MonthlyCost |
            Format-Table -AutoSize -Wrap
        
        $disabledCost = ($disabledAccounts | Measure-Object -Property MonthlyCost -Sum).Sum
        Write-Host "Immediate Monthly Savings: `$$([math]::Round($disabledCost, 2))`n" -ForegroundColor Green
    }

    # Never used licenses
    if ($neverUsed.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  CRITICAL: Licensed Accounts Never Used (First 15)" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Red
        
        $neverUsed | Select-Object UserPrincipalName, DisplayName, AccountAge, LicenseCount, MonthlyCost -First 15 |
            Format-Table -AutoSize
    }

    # Top cost opportunities
    Write-Host "`n========================================" -ForegroundColor Yellow
    Write-Host "  Top 15 Cost Recovery Opportunities" -ForegroundColor Yellow
    Write-Host "========================================`n" -ForegroundColor Yellow

    $reportData | Sort-Object -Property MonthlyCost -Descending |
        Select-Object UserPrincipalName, DaysInactive, MonthlyCost, AnnualCost, Severity, Recommendation -First 15 |
        Format-Table -AutoSize -Wrap

    # Department breakdown
    $deptBreakdown = $reportData | Where-Object { $_.Department } |
        Group-Object -Property Department |
        Select-Object Name, Count, @{Name="TotalMonthlyCost";Expression={($_.Group | Measure-Object -Property MonthlyCost -Sum).Sum}} |
        Sort-Object TotalMonthlyCost -Descending |
        Select-Object -First 10

    if ($deptBreakdown.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "  Inactive Licensed Users by Department" -ForegroundColor Cyan
        Write-Host "========================================`n" -ForegroundColor Cyan
        
        $deptBreakdown | ForEach-Object {
            Write-Host "$($_.Name): $($_.Count) users, `$$([math]::Round($_.TotalMonthlyCost, 2))/month wasted" -ForegroundColor White
        }
        Write-Host ""
    }

    # Long-term inactive (180+ days)
    $longTermInactive = $reportData | Where-Object { $_.DaysInactive -ne "Never" -and $_.DaysInactive -gt 180 }
    if ($longTermInactive.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  Extremely Inactive (180+ days)" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Red
        
        Write-Host "Count: $($longTermInactive.Count) accounts" -ForegroundColor White
        $longTermCost = ($longTermInactive | Measure-Object -Property MonthlyCost -Sum).Sum
        Write-Host "Monthly Cost: `$$([math]::Round($longTermCost, 2))`n" -ForegroundColor Red
    }

    # Export
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPath = Join-Path $ExportPath "LicensedInactiveAccounts_Report_$timestamp.csv"
    $reportData | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Report saved to: $reportPath" -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Green

    # Priority actions
    Write-Host "Priority Actions:" -ForegroundColor Cyan
    Write-Host "  1. [IMMEDIATE] Remove licenses from $($disabledAccounts.Count) disabled accounts" -ForegroundColor Red
    Write-Host "  2. [IMMEDIATE] Review $($neverUsed.Count) licensed accounts never used" -ForegroundColor Red
    Write-Host "  3. [HIGH] Audit $($longTermInactive.Count) accounts inactive 180+ days" -ForegroundColor Yellow
    Write-Host "  4. [HIGH] Contact managers for $($highSeverity.Count) high-severity accounts" -ForegroundColor Yellow
    Write-Host "  5. [MEDIUM] Review $($mediumSeverity.Count) medium-severity accounts" -ForegroundColor Yellow
    Write-Host "  6. Implement automated license reclamation workflow" -ForegroundColor White
    Write-Host "  7. Set up monthly inactive account reviews" -ForegroundColor White
    Write-Host "  8. Configure alerts for inactive licensed accounts`n" -ForegroundColor White

    Disconnect-MgGraph | Out-Null
}
catch {
    Write-Host "`nError: $_" -ForegroundColor Red
    try { Disconnect-MgGraph | Out-Null } catch { }
    exit 1
}
