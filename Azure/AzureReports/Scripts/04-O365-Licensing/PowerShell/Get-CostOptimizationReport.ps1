<#
.SYNOPSIS
    Provides cost optimization recommendations for Office 365 licenses.

.DESCRIPTION
    This script analyzes license usage patterns and identifies opportunities for cost savings
    including unused licenses, inactive users with licenses, and optimization strategies.

.PARAMETER ExportPath
    Optional. The path where the CSV report will be saved. Defaults to current directory.

.PARAMETER InactiveDaysThreshold
    Optional. Number of days to consider a user inactive. Default is 90 days.

.EXAMPLE
    .\Get-CostOptimizationReport.ps1

.EXAMPLE
    .\Get-CostOptimizationReport.ps1 -InactiveDaysThreshold 60

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
    Write-Host "  License Cost Optimization Analysis" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    # Connect to Microsoft Graph
    Connect-MgGraph -Scopes "User.Read.All", "Organization.Read.All", "AuditLog.Read.All" -ErrorAction Stop
    Write-Host "Connected to Microsoft Graph.`n" -ForegroundColor Green

    $cutoffDate = (Get-Date).AddDays(-$InactiveDaysThreshold)

    # Get users with licenses
    Write-Host "Fetching licensed users..." -ForegroundColor Yellow
    $users = Get-MgUser -All -Property Id, UserPrincipalName, DisplayName, AccountEnabled, AssignedLicenses, SignInActivity, CreatedDateTime

    $licensedUsers = $users | Where-Object { $_.AssignedLicenses.Count -gt 0 }
    Write-Host "Found $($licensedUsers.Count) licensed users.`n" -ForegroundColor Green

    # Get license costs (approximate monthly costs)
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
            default { 10 }
        }
        $skuCosts[$sku.SkuId] = @{
            Name = $sku.SkuPartNumber
            Cost = $cost
        }
    }

    # Analyze each licensed user
    $reportData = @()
    $counter = 0
    $totalWastedCost = 0

    foreach ($user in $licensedUsers) {
        $counter++
        Write-Progress -Activity "Analyzing Licensed Users" -Status $user.UserPrincipalName -PercentComplete (($counter / $licensedUsers.Count) * 100)
        
        # Calculate inactivity
        $lastSignIn = $null
        $daysInactive = $null
        $isInactive = $false
        
        if ($user.SignInActivity -and $user.SignInActivity.LastSignInDateTime) {
            $lastSignIn = $user.SignInActivity.LastSignInDateTime
            $daysInactive = (New-TimeSpan -Start $lastSignIn -End (Get-Date)).Days
            $isInactive = ($lastSignIn -lt $cutoffDate)
        }
        else {
            $daysInactive = "Never signed in"
            $isInactive = $true
        }
        
        # Calculate license cost
        $userLicenseCost = 0
        $licenseNames = @()
        foreach ($license in $user.AssignedLicenses) {
            if ($skuCosts.ContainsKey($license.SkuId)) {
                $userLicenseCost += $skuCosts[$license.SkuId].Cost
                $licenseNames += $skuCosts[$license.SkuId].Name
            }
        }
        
        # Determine waste status
        $wasteStatus = "Active"
        $recommendation = "None"
        $monthlySavings = 0
        
        if (-not $user.AccountEnabled) {
            $wasteStatus = "WASTE - Disabled Account"
            $recommendation = "Remove licenses immediately"
            $monthlySavings = $userLicenseCost
            $totalWastedCost += $userLicenseCost
        }
        elseif ($isInactive) {
            if ($daysInactive -eq "Never signed in") {
                $wasteStatus = "WASTE - Never Used"
                $recommendation = "Remove licenses or follow up with user"
                $monthlySavings = $userLicenseCost
                $totalWastedCost += $userLicenseCost
            }
            else {
                $wasteStatus = "WASTE - Inactive User"
                $recommendation = "Review and consider removing licenses"
                $monthlySavings = $userLicenseCost
                $totalWastedCost += $userLicenseCost
            }
        }
        
        $reportData += [PSCustomObject]@{
            UserPrincipalName = $user.UserPrincipalName
            DisplayName = $user.DisplayName
            AccountEnabled = $user.AccountEnabled
            LastSignIn = if ($lastSignIn) { $lastSignIn.ToString("yyyy-MM-dd") } else { "Never" }
            DaysInactive = $daysInactive
            LicenseCount = $user.AssignedLicenses.Count
            Licenses = ($licenseNames -join '; ')
            MonthlyCost = [math]::Round($userLicenseCost, 2)
            WasteStatus = $wasteStatus
            PotentialMonthlySavings = [math]::Round($monthlySavings, 2)
            Recommendation = $recommendation
        }
    }

    Write-Progress -Activity "Analyzing Licensed Users" -Completed

    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Cost Optimization Summary" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $wastedLicenses = $reportData | Where-Object { $_.WasteStatus -ne "Active" }
    $disabledAccountLicenses = $reportData | Where-Object { -not $_.AccountEnabled }
    $inactiveLicenses = $reportData | Where-Object { $_.WasteStatus -eq "WASTE - Inactive User" }
    $neverUsedLicenses = $reportData | Where-Object { $_.WasteStatus -eq "WASTE - Never Used" }

    Write-Host "Total Licensed Users:            $($reportData.Count)" -ForegroundColor White
    Write-Host "Wasted Licenses:                 $($wastedLicenses.Count) " -ForegroundColor Red -NoNewline
    Write-Host "($([math]::Round(($wastedLicenses.Count / $reportData.Count) * 100, 2))%)" -ForegroundColor Red
    Write-Host "  - Disabled Accounts:           $($disabledAccountLicenses.Count)" -ForegroundColor Yellow
    Write-Host "  - Inactive Users ($InactiveDaysThreshold+ days):   $($inactiveLicenses.Count)" -ForegroundColor Yellow
    Write-Host "  - Never Used:                  $($neverUsedLicenses.Count)" -ForegroundColor Yellow
    Write-Host "`nPotential Monthly Savings:       `$$([math]::Round($totalWastedCost, 2)) USD" -ForegroundColor Green
    Write-Host "Potential Annual Savings:        `$$([math]::Round($totalWastedCost * 12, 2)) USD" -ForegroundColor Green

    # Critical issues
    if ($disabledAccountLicenses.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  CRITICAL: Disabled Accounts with Licenses" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Red
        
        $disabledAccountLicenses | Select-Object UserPrincipalName, Licenses, MonthlyCost |
            Format-Table -AutoSize
        
        $disabledCost = ($disabledAccountLicenses | Measure-Object -Property MonthlyCost -Sum).Sum
        Write-Host "Immediate Savings Available: `$$([math]::Round($disabledCost, 2))/month`n" -ForegroundColor Green
    }

    # Never used licenses
    if ($neverUsedLicenses.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  Licenses Never Used (First 15)" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Red
        
        $neverUsedLicenses | Select-Object UserPrincipalName, DisplayName, Licenses, MonthlyCost -First 15 |
            Format-Table -AutoSize
    }

    # High-cost inactive users
    $topWaste = $reportData | Where-Object { $_.WasteStatus -ne "Active" } |
        Sort-Object -Property MonthlyCost -Descending | Select-Object -First 10

    if ($topWaste.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Yellow
        Write-Host "  Top 10 Cost Optimization Opportunities" -ForegroundColor Yellow
        Write-Host "========================================`n" -ForegroundColor Yellow
        
        $topWaste | Select-Object UserPrincipalName, WasteStatus, DaysInactive, MonthlyCost, Recommendation |
            Format-Table -AutoSize -Wrap
    }

    # Export
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPath = Join-Path $ExportPath "CostOptimization_Report_$timestamp.csv"
    $reportData | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Report saved to: $reportPath" -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Green

    # Action items
    Write-Host "Priority Actions:" -ForegroundColor Cyan
    Write-Host "  1. [IMMEDIATE] Remove licenses from $($disabledAccountLicenses.Count) disabled accounts" -ForegroundColor Red
    Write-Host "  2. [HIGH] Review $($neverUsedLicenses.Count) never-used licenses" -ForegroundColor Yellow
    Write-Host "  3. [MEDIUM] Audit $($inactiveLicenses.Count) inactive user licenses" -ForegroundColor Yellow
    Write-Host "  4. Implement automated license reclamation policy" -ForegroundColor White
    Write-Host "  5. Set up alerts for unused licenses`n" -ForegroundColor White

    Disconnect-MgGraph | Out-Null
}
catch {
    Write-Host "`nError: $_" -ForegroundColor Red
    try { Disconnect-MgGraph | Out-Null } catch { }
    exit 1
}
