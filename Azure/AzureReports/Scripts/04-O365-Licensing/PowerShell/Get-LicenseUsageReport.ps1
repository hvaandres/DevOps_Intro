<#
.SYNOPSIS
    Comprehensive Office 365 license usage analysis.

.DESCRIPTION
    This script analyzes O365 license assignments, usage, and availability across your tenant.
    Provides detailed statistics and identifies optimization opportunities.

.PARAMETER ExportPath
    Optional. The path where the CSV report will be saved. Defaults to current directory.

.EXAMPLE
    .\Get-LicenseUsageReport.ps1

.EXAMPLE
    .\Get-LicenseUsageReport.ps1 -ExportPath "C:\Reports"

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
    Write-Host "  O365 License Usage Analysis" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    # Connect to Microsoft Graph
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
    Connect-MgGraph -Scopes "Organization.Read.All", "Directory.Read.All" -ErrorAction Stop
    Write-Host "Connected successfully.`n" -ForegroundColor Green

    # Get all subscribed SKUs
    Write-Host "Fetching license information..." -ForegroundColor Yellow
    $skus = Get-MgSubscribedSku

    if ($skus.Count -eq 0) {
        Write-Host "No licenses found.`n" -ForegroundColor Yellow
        Disconnect-MgGraph
        exit 0
    }

    Write-Host "Found $($skus.Count) license types.`n" -ForegroundColor Green

    $licenseData = @()
    $counter = 0

    foreach ($sku in $skus) {
        $counter++
        Write-Progress -Activity "Analyzing Licenses" -Status $sku.SkuPartNumber -PercentComplete (($counter / $skus.Count) * 100)
        
        $total = if ($sku.PrepaidUnits) { $sku.PrepaidUnits.Enabled } else { 0 }
        $consumed = if ($sku.ConsumedUnits) { $sku.ConsumedUnits } else { 0 }
        $warning = if ($sku.PrepaidUnits) { $sku.PrepaidUnits.Warning } else { 0 }
        $suspended = if ($sku.PrepaidUnits) { $sku.PrepaidUnits.Suspended } else { 0 }
        $available = $total - $consumed
        $utilization = if ($total -gt 0) { [math]::Round(($consumed / $total) * 100, 2) } else { 0 }
        
        # Cost estimation (approximate monthly costs)
        $estimatedCost = switch -Wildcard ($sku.SkuPartNumber) {
            "*E1*" { $consumed * 8 }
            "*E3*" { $consumed * 20 }
            "*E5*" { $consumed * 35 }
            "*F1*" { $consumed * 4 }
            "*F3*" { $consumed * 8 }
            "*BUSINESS_BASIC*" { $consumed * 5 }
            "*BUSINESS_STANDARD*" { $consumed * 12.50 }
            "*BUSINESS_PREMIUM*" { $consumed * 22 }
            default { $consumed * 10 }
        }
        
        # Status determination
        $status = "Normal"
        if ($utilization -ge 95) { $status = "Critical - Nearly Full" }
        elseif ($utilization -ge 85) { $status = "Warning - High Usage" }
        elseif ($utilization -le 30 -and $consumed -gt 0) { $status = "Underutilized" }
        elseif ($consumed -eq 0) { $status = "Unused" }
        
        $licenseData += [PSCustomObject]@{
            SkuPartNumber = $sku.SkuPartNumber
            SkuId = $sku.SkuId
            TotalLicenses = $total
            ConsumedLicenses = $consumed
            AvailableLicenses = $available
            WarningUnits = $warning
            SuspendedUnits = $suspended
            UtilizationPercent = $utilization
            EstimatedMonthlyCost = [math]::Round($estimatedCost, 2)
            Status = $status
            ServicePlansCount = $sku.ServicePlans.Count
        }
    }

    Write-Progress -Activity "Analyzing Licenses" -Completed

    # Display summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  License Summary" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $totalLicenses = ($licenseData | Measure-Object -Property TotalLicenses -Sum).Sum
    $totalConsumed = ($licenseData | Measure-Object -Property ConsumedLicenses -Sum).Sum
    $totalAvailable = ($licenseData | Measure-Object -Property AvailableLicenses -Sum).Sum
    $totalCost = ($licenseData | Measure-Object -Property EstimatedMonthlyCost -Sum).Sum
    $overallUtilization = if ($totalLicenses -gt 0) { [math]::Round(($totalConsumed / $totalLicenses) * 100, 2) } else { 0 }

    Write-Host "Total Licenses:         $totalLicenses" -ForegroundColor White
    Write-Host "Consumed:               $totalConsumed " -ForegroundColor Yellow -NoNewline
    Write-Host "($overallUtilization%)" -ForegroundColor Yellow
    Write-Host "Available:              $totalAvailable" -ForegroundColor Green
    Write-Host "Estimated Monthly Cost: `$$totalCost USD" -ForegroundColor Cyan

    # Display by utilization
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  License Utilization Overview" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $licenseData | Sort-Object -Property UtilizationPercent -Descending |
        Select-Object SkuPartNumber, TotalLicenses, ConsumedLicenses, AvailableLicenses, UtilizationPercent, Status |
        Format-Table -AutoSize

    # Underutilized licenses
    $underutilized = $licenseData | Where-Object { $_.Status -eq "Underutilized" -or $_.Status -eq "Unused" }
    if ($underutilized.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Yellow
        Write-Host "  Underutilized/Unused Licenses" -ForegroundColor Yellow
        Write-Host "========================================`n" -ForegroundColor Yellow
        
        $underutilized | Select-Object SkuPartNumber, TotalLicenses, ConsumedLicenses, UtilizationPercent, EstimatedMonthlyCost |
            Format-Table -AutoSize
        
        $potentialSavings = ($underutilized | Measure-Object -Property EstimatedMonthlyCost -Sum).Sum
        Write-Host "Potential Monthly Savings: `$$([math]::Round($potentialSavings * 0.7, 2)) USD (if optimized)`n" -ForegroundColor Green
    }

    # High utilization licenses
    $highUtil = $licenseData | Where-Object { $_.UtilizationPercent -ge 85 }
    if ($highUtil.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  High Utilization Licenses (Action Required)" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Red
        
        $highUtil | Select-Object SkuPartNumber, TotalLicenses, ConsumedLicenses, AvailableLicenses, UtilizationPercent |
            Format-Table -AutoSize
    }

    # Cost breakdown
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Cost Breakdown (Top 5)" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $licenseData | Sort-Object -Property EstimatedMonthlyCost -Descending |
        Select-Object SkuPartNumber, ConsumedLicenses, EstimatedMonthlyCost -First 5 |
        Format-Table -AutoSize

    # Export to CSV
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPath = Join-Path $ExportPath "LicenseUsage_Report_$timestamp.csv"
    $licenseData | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Report saved to: $reportPath" -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Green

    # Recommendations
    Write-Host "Recommendations:" -ForegroundColor Cyan
    if ($underutilized.Count -gt 0) {
        Write-Host "  1. Review underutilized licenses for potential cost savings" -ForegroundColor White
    }
    if ($highUtil.Count -gt 0) {
        Write-Host "  2. Purchase additional licenses for high-utilization SKUs" -ForegroundColor White
    }
    Write-Host "  3. Regularly audit license assignments" -ForegroundColor White
    Write-Host "  4. Remove licenses from inactive users" -ForegroundColor White
    Write-Host "  5. Consider license bundling for cost optimization`n" -ForegroundColor White

    Disconnect-MgGraph | Out-Null
}
catch {
    Write-Host "`nError: $_" -ForegroundColor Red
    try { Disconnect-MgGraph | Out-Null } catch { }
    exit 1
}
