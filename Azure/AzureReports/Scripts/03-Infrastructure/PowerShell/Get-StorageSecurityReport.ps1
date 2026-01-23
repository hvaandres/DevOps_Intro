<#
.SYNOPSIS
    Audits Azure Storage Account security configurations.

.DESCRIPTION
    This script analyzes all Azure Storage Accounts for security misconfigurations
    including HTTPS enforcement, TLS version, public access, firewall rules, and encryption settings.

.PARAMETER ExportPath
    Optional. The path where the CSV report will be saved. Defaults to current directory.

.EXAMPLE
    .\Get-StorageSecurityReport.ps1
    
.EXAMPLE
    .\Get-StorageSecurityReport.ps1 -ExportPath "C:\Reports"

.NOTES
    Author: Azure Security Audit Team
    Requirements:
    - Az.Storage PowerShell module
    - Permissions: Reader or Storage Account Contributor
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ExportPath = "."
)

try {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Storage Account Security Audit" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    # Connect to Azure
    $context = Get-AzContext
    if (-not $context) { Connect-AzAccount }

    $storageAccounts = Get-AzStorageAccount
    Write-Host "Found $($storageAccounts.Count) storage accounts.`n" -ForegroundColor Green

    $reportData = @()
    $counter = 0

    foreach ($sa in $storageAccounts) {
        $counter++
        Write-Progress -Activity "Analyzing Storage Accounts" -Status $sa.StorageAccountName -PercentComplete (($counter / $storageAccounts.Count) * 100)
        
        $networkRules = Get-AzStorageAccountNetworkRuleSet -ResourceGroupName $sa.ResourceGroupName -Name $sa.StorageAccountName
        
        # Security checks
        $httpsOnly = $sa.EnableHttpsTrafficOnly
        $tlsVersion = $sa.MinimumTlsVersion
        $publicAccess = $sa.AllowBlobPublicAccess
        $networkDefaultAction = $networkRules.DefaultAction
        $hasFirewallRules = $networkRules.IpRules.Count -gt 0
        $hasVNetRules = $networkRules.VirtualNetworkRules.Count -gt 0
        
        # Security score
        $securityScore = 0
        if ($httpsOnly) { $securityScore += 25 }
        if ($tlsVersion -in @('TLS1_2', 'TLS1_3')) { $securityScore += 25 }
        if (-not $publicAccess) { $securityScore += 20 }
        if ($networkDefaultAction -eq 'Deny') { $securityScore += 15 }
        if ($hasFirewallRules -or $hasVNetRules) { $securityScore += 15 }
        
        # Issues
        $issues = @()
        if (-not $httpsOnly) { $issues += "HTTPS not enforced" }
        if ($tlsVersion -in @('TLS1_0', 'TLS1_1')) { $issues += "Weak TLS version" }
        if ($publicAccess) { $issues += "Public blob access enabled" }
        if ($networkDefaultAction -eq 'Allow') { $issues += "No network restrictions" }
        
        $reportData += [PSCustomObject]@{
            StorageAccountName = $sa.StorageAccountName
            ResourceGroup = $sa.ResourceGroupName
            Location = $sa.Location
            SKU = $sa.Sku.Name
            HTTPSOnly = $httpsOnly
            MinTLSVersion = $tlsVersion
            AllowBlobPublicAccess = $publicAccess
            NetworkDefaultAction = $networkDefaultAction
            FirewallRulesCount = $networkRules.IpRules.Count
            VNetRulesCount = $networkRules.VirtualNetworkRules.Count
            SupportsHttpsTrafficOnly = $sa.EnableHttpsTrafficOnly
            SecurityScore = $securityScore
            Issues = ($issues -join '; ')
            Recommendation = if ($issues.Count -eq 0) { "Secure" } else { "Review issues" }
        }
    }

    Write-Progress -Activity "Analyzing Storage Accounts" -Completed

    # Display summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Security Summary" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $secure = ($reportData | Where-Object { $_.SecurityScore -ge 80 }).Count
    $atRisk = ($reportData | Where-Object { $_.SecurityScore -lt 60 }).Count

    Write-Host "Total Storage Accounts: $($reportData.Count)" -ForegroundColor White
    Write-Host "Secure (80+ score): $secure" -ForegroundColor Green
    Write-Host "At Risk (<60 score): $atRisk" -ForegroundColor Red

    # Display accounts at risk
    if ($atRisk -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  Storage Accounts At Risk" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Red
        
        $reportData | Where-Object { $_.SecurityScore -lt 60 } |
            Select-Object StorageAccountName, SecurityScore, Issues |
            Format-Table -AutoSize -Wrap
    }

    # Export
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPath = Join-Path $ExportPath "StorageSecurity_Report_$timestamp.csv"
    $reportData | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Report saved to: $reportPath" -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Green

    Write-Host "Recommendations:" -ForegroundColor Cyan
    Write-Host "  1. Enable HTTPS-only traffic" -ForegroundColor White
    Write-Host "  2. Use TLS 1.2 or higher" -ForegroundColor White
    Write-Host "  3. Disable public blob access" -ForegroundColor White
    Write-Host "  4. Configure network rules (firewall/VNet)`n" -ForegroundColor White
}
catch {
    Write-Host "`nError: $_" -ForegroundColor Red
    exit 1
}
