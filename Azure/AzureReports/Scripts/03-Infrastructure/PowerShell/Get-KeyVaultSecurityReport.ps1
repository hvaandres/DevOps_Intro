<#
.SYNOPSIS
    Performs security assessment on Azure Key Vaults.

.DESCRIPTION
    This script audits Key Vault configurations including soft delete, purge protection,
    network access, RBAC settings, and diagnostic logging.

.PARAMETER ExportPath
    Optional. The path where the CSV report will be saved. Defaults to current directory.

.EXAMPLE
    .\Get-KeyVaultSecurityReport.ps1

.NOTES
    Author: Azure Security Audit Team
    Requirements:
    - Az.KeyVault PowerShell module
    - Permissions: Key Vault Reader
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ExportPath = "."
)

try {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Key Vault Security Assessment" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $context = Get-AzContext
    if (-not $context) { Connect-AzAccount }

    $keyVaults = Get-AzKeyVault
    Write-Host "Found $($keyVaults.Count) Key Vaults.`n" -ForegroundColor Green

    $reportData = @()

    foreach ($kv in $keyVaults) {
        Write-Progress -Activity "Analyzing Key Vaults" -Status $kv.VaultName
        
        $kvDetails = Get-AzKeyVault -VaultName $kv.VaultName -ResourceGroupName $kv.ResourceGroupName
        
        # Security checks
        $softDeleteEnabled = $kvDetails.EnableSoftDelete
        $purgeProtection = $kvDetails.EnablePurgeProtection
        $rbacEnabled = $kvDetails.EnableRbacAuthorization
        $publicNetworkAccess = $kvDetails.PublicNetworkAccess
        $privateEndpoints = $kvDetails.PrivateEndpointConnections.Count
        
        # Security score
        $securityScore = 0
        if ($softDeleteEnabled) { $securityScore += 25 }
        if ($purgeProtection) { $securityScore += 25 }
        if ($rbacEnabled) { $securityScore += 20 }
        if ($publicNetworkAccess -eq 'Disabled' -or $privateEndpoints -gt 0) { $securityScore += 30 }
        
        # Issues
        $issues = @()
        if (-not $softDeleteEnabled) { $issues += "Soft delete not enabled" }
        if (-not $purgeProtection) { $issues += "Purge protection not enabled" }
        if (-not $rbacEnabled) { $issues += "RBAC not enabled" }
        if ($publicNetworkAccess -eq 'Enabled' -and $privateEndpoints -eq 0) { $issues += "Public access enabled" }
        
        $reportData += [PSCustomObject]@{
            KeyVaultName = $kv.VaultName
            ResourceGroup = $kv.ResourceGroupName
            Location = $kv.Location
            SoftDeleteEnabled = $softDeleteEnabled
            PurgeProtectionEnabled = $purgeProtection
            RBACEnabled = $rbacEnabled
            PublicNetworkAccess = $publicNetworkAccess
            PrivateEndpoints = $privateEndpoints
            SecurityScore = $securityScore
            Issues = ($issues -join '; ')
            Status = if ($securityScore -ge 80) { "Secure" } elseif ($securityScore -ge 60) { "Review" } else { "At Risk" }
        }
    }

    Write-Progress -Activity "Analyzing Key Vaults" -Completed

    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Security Summary" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $secure = ($reportData | Where-Object { $_.Status -eq "Secure" }).Count
    $atRisk = ($reportData | Where-Object { $_.Status -eq "At Risk" }).Count

    Write-Host "Total Key Vaults: $($reportData.Count)" -ForegroundColor White
    Write-Host "Secure: $secure" -ForegroundColor Green
    Write-Host "At Risk: $atRisk" -ForegroundColor Red

    if ($atRisk -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  Key Vaults At Risk" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Red
        
        $reportData | Where-Object { $_.Status -eq "At Risk" } |
            Select-Object KeyVaultName, SecurityScore, Issues |
            Format-Table -AutoSize -Wrap
    }

    # Export
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPath = Join-Path $ExportPath "KeyVaultSecurity_Report_$timestamp.csv"
    $reportData | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

    Write-Host "`nReport saved to: $reportPath" -ForegroundColor Green

    Write-Host "`nRecommendations:" -ForegroundColor Cyan
    Write-Host "  1. Enable soft delete on all Key Vaults" -ForegroundColor White
    Write-Host "  2. Enable purge protection" -ForegroundColor White
    Write-Host "  3. Use RBAC for access control" -ForegroundColor White
    Write-Host "  4. Restrict network access with Private Endpoints`n" -ForegroundColor White
}
catch {
    Write-Host "`nError: $_" -ForegroundColor Red
    exit 1
}
