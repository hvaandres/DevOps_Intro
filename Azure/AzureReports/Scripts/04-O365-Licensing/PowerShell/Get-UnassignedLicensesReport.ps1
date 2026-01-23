<#
.SYNOPSIS
    Detects and reports on unassigned Office 365 licenses.

.DESCRIPTION
    This script identifies available (unassigned) licenses in your O365 tenant
    and calculates the cost of unused licenses.

.PARAMETER ExportPath
    Optional. The path where the CSV report will be saved. Defaults to current directory.

.EXAMPLE
    .\Get-UnassignedLicensesReport.ps1

.EXAMPLE
    .\Get-UnassignedLicensesReport.ps1 -ExportPath "C:\Reports"

.NOTES
    Author: Azure Security Audit Team
    Requirements:
    - Microsoft.Graph PowerShell module
    - Permissions: Organization.Read.All, Directory.Read.All
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ExportPath = "."
)

try {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Unassigned License Detection" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    # Connect to Microsoft Graph
    Connect-MgGraph -Scopes "Organization.Read.All", "Directory.Read.All" -ErrorAction Stop
    Write-Host "Connected to Microsoft Graph.`n" -ForegroundColor Green

    # Get all subscribed SKUs
    Write-Host "Fetching license information..." -ForegroundColor Yellow
    $skus = Get-MgSubscribedSku

    if ($skus.Count -eq 0) {
        Write-Host "No licenses found.`n" -ForegroundColor Yellow
        Disconnect-MgGraph
        exit 0
    }

    Write-Host "Analyzing $($skus.Count) license types...`n" -ForegroundColor Green

    $reportData = @()
    $totalUnassignedValue = 0
    $totalUnassignedCount = 0

    foreach ($sku in $skus) {
        $total = if ($sku.PrepaidUnits) { $sku.PrepaidUnits.Enabled } else { 0 }
        $consumed = if ($sku.ConsumedUnits) { $sku.ConsumedUnits } else { 0 }
        $unassigned = $total - $consumed
        
        if ($total -eq 0) { continue }
        
        # Estimate cost per license
        $monthlyCostPerLicense = switch -Wildcard ($sku.SkuPartNumber) {
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
            "*FLOW*" { 15 }
            "*EMS*" { 8 }
            default { 10 }
        }
        
        $unassignedValue = $unassigned * $monthlyCostPerLicense
        $totalUnassignedValue += $unassignedValue
        $totalUnassignedCount += $unassigned
        
        # Determine status
        $status = "Normal"
        $recommendation = "Monitor"
        
        if ($unassigned -eq 0) {
            $status = "Fully Utilized"
            $recommendation = "Consider purchasing more if needed"
        }
        elseif ($consumed -eq 0) {
            $status = "ALERT: Completely Unused"
            $recommendation = "Consider canceling subscription"
        }
        elseif ($unassigned -ge $total * 0.5) {
            $status = "WARNING: Highly Underutilized"
            $recommendation = "Reduce license count"
        }
        elseif ($unassigned -le 3 -and $total -gt 10) {
            $status = "Low Availability"
            $recommendation = "Consider purchasing more licenses"
        }
        
        $reportData += [PSCustomObject]@{
            LicenseType = $sku.SkuPartNumber
            SkuId = $sku.SkuId
            TotalLicenses = $total
            AssignedLicenses = $consumed
            UnassignedLicenses = $unassigned
            UtilizationPercent = if ($total -gt 0) { [math]::Round(($consumed / $total) * 100, 2) } else { 0 }
            CostPerLicense = $monthlyCostPerLicense
            UnassignedMonthlyCost = [math]::Round($unassignedValue, 2)
            UnassignedAnnualCost = [math]::Round($unassignedValue * 12, 2)
            Status = $status
            Recommendation = $recommendation
        }
    }

    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Unassigned License Summary" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    Write-Host "Total Unassigned Licenses:       $totalUnassignedCount" -ForegroundColor Yellow
    Write-Host "Monthly Cost of Unassigned:      `$$([math]::Round($totalUnassignedValue, 2)) USD" -ForegroundColor Red
    Write-Host "Annual Cost of Unassigned:       `$$([math]::Round($totalUnassignedValue * 12, 2)) USD" -ForegroundColor Red

    # Display all unassigned licenses
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Unassigned License Details" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $reportData | Sort-Object -Property UnassignedMonthlyCost -Descending |
        Select-Object LicenseType, TotalLicenses, AssignedLicenses, UnassignedLicenses, UnassignedMonthlyCost, Status |
        Format-Table -AutoSize

    # Critical alerts
    $completelyUnused = $reportData | Where-Object { $_.Status -eq "ALERT: Completely Unused" }
    if ($completelyUnused.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  CRITICAL: Completely Unused Licenses" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Red
        
        $completelyUnused | Select-Object LicenseType, TotalLicenses, UnassignedMonthlyCost |
            Format-Table -AutoSize
        
        $wastedCost = ($completelyUnused | Measure-Object -Property UnassignedMonthlyCost -Sum).Sum
        Write-Host "Total Wasted: `$$([math]::Round($wastedCost, 2))/month or `$$([math]::Round($wastedCost * 12, 2))/year`n" -ForegroundColor Red
    }

    # High underutilization
    $highUnderutilization = $reportData | Where-Object { $_.Status -eq "WARNING: Highly Underutilized" }
    if ($highUnderutilization.Count -gt 0) {
        Write-Host "`n========================================\" -ForegroundColor Yellow
        Write-Host "  Highly Underutilized Licenses" -ForegroundColor Yellow
        Write-Host "========================================`n" -ForegroundColor Yellow
        
        $highUnderutilization | Select-Object LicenseType, TotalLicenses, AssignedLicenses, UnassignedLicenses, UtilizationPercent |
            Format-Table -AutoSize
    }

    # Top cost opportunities
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Top 5 Cost Saving Opportunities" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $reportData | Sort-Object -Property UnassignedMonthlyCost -Descending |
        Select-Object LicenseType, UnassignedLicenses, UnassignedMonthlyCost, UnassignedAnnualCost, Recommendation -First 5 |
        Format-Table -AutoSize

    # Low availability warnings
    $lowAvailability = $reportData | Where-Object { $_.Status -eq "Low Availability" }
    if ($lowAvailability.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Yellow
        Write-Host "  Low License Availability" -ForegroundColor Yellow
        Write-Host "========================================`n" -ForegroundColor Yellow
        
        $lowAvailability | Select-Object LicenseType, TotalLicenses, UnassignedLicenses |
            Format-Table -AutoSize
        
        Write-Host "Consider purchasing more licenses before you run out.`n" -ForegroundColor Yellow
    }

    # Export
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPath = Join-Path $ExportPath "UnassignedLicenses_Report_$timestamp.csv"
    $reportData | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Report saved to: $reportPath" -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Green

    # Recommendations
    Write-Host "Recommendations:" -ForegroundColor Cyan
    if ($completelyUnused.Count -gt 0) {
        Write-Host "  1. [CRITICAL] Cancel $($completelyUnused.Count) unused license subscriptions" -ForegroundColor Red
    }
    if ($highUnderutilization.Count -gt 0) {
        Write-Host "  2. [HIGH] Reduce license counts for underutilized SKUs" -ForegroundColor Yellow
    }
    if ($lowAvailability.Count -gt 0) {
        Write-Host "  3. [MEDIUM] Purchase additional licenses for low-availability SKUs" -ForegroundColor Yellow
    }
    Write-Host "  4. Implement license assignment automation" -ForegroundColor White
    Write-Host "  5. Set up monthly license utilization reviews" -ForegroundColor White
    Write-Host "  6. Consider rightsizing license purchases`n" -ForegroundColor White

    Disconnect-MgGraph | Out-Null
}
catch {
    Write-Host "`nError: $_" -ForegroundColor Red
    try { Disconnect-MgGraph | Out-Null } catch { }
    exit 1
}
