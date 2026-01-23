<#
.SYNOPSIS
    Detects dangerous firewall rules in Azure.

.DESCRIPTION
    This script identifies firewall rules that pose security risks including
    overly permissive rules, unrestricted access, and exposed sensitive ports.

.PARAMETER ExportPath
    Optional. The path where the CSV report will be saved. Defaults to current directory.

.EXAMPLE
    .\Get-FirewallRulesReport.ps1

.NOTES
    Author: Azure Security Audit Team
    Requirements:
    - Az.Network PowerShell module
    - Permissions: Network Reader
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ExportPath = "."
)

try {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Dangerous Firewall Rules Detection" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $context = Get-AzContext
    if (-not $context) { Connect-AzAccount }

    # Check NSGs
    $nsgs = Get-AzNetworkSecurityGroup
    Write-Host "Analyzing $($nsgs.Count) Network Security Groups...`n" -ForegroundColor Yellow

    $reportData = @()
    $criticalCount = 0
    $highCount = 0

    # Dangerous port definitions
    $sensitivePorts = @{
        '22' = 'SSH'
        '3389' = 'RDP'
        '1433' = 'SQL Server'
        '3306' = 'MySQL'
        '5432' = 'PostgreSQL'
        '27017' = 'MongoDB'
        '6379' = 'Redis'
        '5984' = 'CouchDB'
        '9200' = 'Elasticsearch'
        '11211' = 'Memcached'
    }

    foreach ($nsg in $nsgs) {
        foreach ($rule in $nsg.SecurityRules) {
            if ($rule.Direction -eq 'Inbound' -and $rule.Access -eq 'Allow') {
                $severity = "Low"
                $issues = @()
                
                # Check source
                if ($rule.SourceAddressPrefix -eq '*' -or $rule.SourceAddressPrefix -eq 'Internet' -or $rule.SourceAddressPrefix -eq '0.0.0.0/0') {
                    $issues += "Allows from ANY source"
                    
                    # Check if it exposes sensitive ports
                    foreach ($port in $sensitivePorts.Keys) {
                        if ($rule.DestinationPortRange -contains $port -or $rule.DestinationPortRange -eq '*') {
                            $severity = "CRITICAL"
                            $issues += "Exposes $($sensitivePorts[$port]) (port $port) to Internet"
                            $criticalCount++
                            break
                        }
                    }
                    
                    if ($severity -ne "CRITICAL") {
                        if ($rule.DestinationPortRange -eq '*') {
                            $severity = "CRITICAL"
                            $issues += "Allows ALL ports from Internet"
                            $criticalCount++
                        }
                        else {
                            $severity = "HIGH"
                            $highCount++
                        }
                    }
                }
                
                # Check for overly broad port ranges
                if ($rule.DestinationPortRange -eq '*' -and $severity -eq "Low") {
                    $severity = "MEDIUM"
                    $issues += "Allows ALL ports"
                }
                
                if ($issues.Count -gt 0) {
                    $reportData += [PSCustomObject]@{
                        NSG = $nsg.Name
                        ResourceGroup = $nsg.ResourceGroupName
                        RuleName = $rule.Name
                        Priority = $rule.Priority
                        SourceAddress = $rule.SourceAddressPrefix
                        DestinationPort = $rule.DestinationPortRange
                        Protocol = $rule.Protocol
                        Severity = $severity
                        Issues = ($issues -join '; ')
                        Recommendation = if ($severity -eq "CRITICAL") { "Immediately restrict access" } else { "Review and restrict" }
                    }
                }
            }
        }
    }

    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Detection Summary" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    Write-Host "Total Dangerous Rules: $($reportData.Count)" -ForegroundColor White
    Write-Host "CRITICAL: $criticalCount" -ForegroundColor Red
    Write-Host "HIGH: $highCount" -ForegroundColor Yellow

    if ($criticalCount -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  CRITICAL: Immediate Action Required" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Red
        
        $reportData | Where-Object { $_.Severity -eq "CRITICAL" } |
            Select-Object NSG, RuleName, SourceAddress, DestinationPort, Issues |
            Format-Table -AutoSize -Wrap
    }

    if ($reportData.Count -eq 0) {
        Write-Host "No dangerous firewall rules detected!" -ForegroundColor Green
    }

    # Export
    if ($reportData.Count -gt 0) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $reportPath = Join-Path $ExportPath "FirewallRules_Report_$timestamp.csv"
        $reportData | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8
        
        Write-Host "`nReport saved to: $reportPath" -ForegroundColor Green
    }

    Write-Host "`nRecommendations:" -ForegroundColor Cyan
    Write-Host "  1. NEVER allow SSH/RDP from 0.0.0.0/0" -ForegroundColor White
    Write-Host "  2. Use Azure Bastion for remote access" -ForegroundColor White
    Write-Host "  3. Restrict database ports to application subnets only" -ForegroundColor White
    Write-Host "  4. Implement Just-In-Time (JIT) VM access" -ForegroundColor White
    Write-Host "  5. Use Service Tags instead of * for source`n" -ForegroundColor White
}
catch {
    Write-Host "`nError: $_" -ForegroundColor Red
    exit 1
}
