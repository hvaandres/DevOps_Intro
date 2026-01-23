<#
.SYNOPSIS
    Monitors certificate expiration in Azure Key Vaults.

.DESCRIPTION
    This script checks all certificates in Key Vaults and identifies those
    expiring soon or already expired.

.PARAMETER ExportPath
    Optional. The path where the CSV report will be saved. Defaults to current directory.

.PARAMETER DaysThreshold
    Optional. Number of days to consider for expiring soon. Default is 30 days.

.EXAMPLE
    .\Get-CertificateExpirationReport.ps1

.EXAMPLE
    .\Get-CertificateExpirationReport.ps1 -DaysThreshold 60

.NOTES
    Author: Azure Security Audit Team
    Requirements:
    - Az.KeyVault PowerShell module
    - Permissions: Key Vault Reader, Certificate Get
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ExportPath = ".",
    
    [Parameter(Mandatory=$false)]
    [int]$DaysThreshold = 30
)

try {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Certificate Expiration Monitor" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $context = Get-AzContext
    if (-not $context) { Connect-AzAccount }

    $keyVaults = Get-AzKeyVault
    Write-Host "Scanning $($keyVaults.Count) Key Vaults...`n" -ForegroundColor Yellow

    $reportData = @()
    $expiredCount = 0
    $expiringSoonCount = 0

    foreach ($kv in $keyVaults) {
        Write-Host "  Checking: $($kv.VaultName)..." -ForegroundColor Gray
        
        try {
            $certificates = Get-AzKeyVaultCertificate -VaultName $kv.VaultName -ErrorAction SilentlyContinue
            
            foreach ($cert in $certificates) {
                $certDetails = Get-AzKeyVaultCertificate -VaultName $kv.VaultName -Name $cert.Name
                
                if ($certDetails.Expires) {
                    $daysUntilExpiry = ($certDetails.Expires - (Get-Date)).Days
                    
                    $status = "Valid"
                    $priority = "Low"
                    
                    if ($daysUntilExpiry -lt 0) {
                        $status = "Expired"
                        $priority = "CRITICAL"
                        $expiredCount++
                    }
                    elseif ($daysUntilExpiry -le $DaysThreshold) {
                        $status = "Expiring Soon"
                        $priority = "HIGH"
                        $expiringSoonCount++
                    }
                    elseif ($daysUntilExpiry -le 60) {
                        $status = "Monitor"
                        $priority = "MEDIUM"
                    }
                    
                    $reportData += [PSCustomObject]@{
                        KeyVault = $kv.VaultName
                        CertificateName = $cert.Name
                        Enabled = $cert.Enabled
                        Created = $certDetails.Created
                        Expires = $certDetails.Expires
                        DaysUntilExpiry = $daysUntilExpiry
                        Status = $status
                        Priority = $priority
                        Thumbprint = $certDetails.Thumbprint
                        Subject = $certDetails.Certificate.Subject
                    }
                }
            }
        }
        catch {
            Write-Host "    Warning: Could not access $($kv.VaultName)" -ForegroundColor Yellow
        }
    }

    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Expiration Summary" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    Write-Host "Total Certificates: $($reportData.Count)" -ForegroundColor White
    Write-Host "Expired: $expiredCount" -ForegroundColor Red
    Write-Host "Expiring Soon ($DaysThreshold days): $expiringSoonCount" -ForegroundColor Yellow

    # Display critical certificates
    if ($expiredCount -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  EXPIRED Certificates" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Red
        
        $reportData | Where-Object { $_.Status -eq "Expired" } |
            Select-Object KeyVault, CertificateName, Expires, DaysUntilExpiry |
            Format-Table -AutoSize
    }

    if ($expiringSoonCount -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Yellow
        Write-Host "  Certificates Expiring Soon" -ForegroundColor Yellow
        Write-Host "========================================`n" -ForegroundColor Yellow
        
        $reportData | Where-Object { $_.Status -eq "Expiring Soon" } |
            Select-Object KeyVault, CertificateName, Expires, DaysUntilExpiry |
            Sort-Object DaysUntilExpiry |
            Format-Table -AutoSize
    }

    # Export
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPath = Join-Path $ExportPath "CertificateExpiration_Report_$timestamp.csv"
    $reportData | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

    Write-Host "`nReport saved to: $reportPath" -ForegroundColor Green

    Write-Host "`nRecommendations:" -ForegroundColor Cyan
    Write-Host "  1. Renew expired certificates immediately" -ForegroundColor White
    Write-Host "  2. Plan renewal for expiring certificates" -ForegroundColor White
    Write-Host "  3. Set up auto-renewal where possible" -ForegroundColor White
    Write-Host "  4. Configure Key Vault alerts for expiration`n" -ForegroundColor White
}
catch {
    Write-Host "`nError: $_" -ForegroundColor Red
    exit 1
}
