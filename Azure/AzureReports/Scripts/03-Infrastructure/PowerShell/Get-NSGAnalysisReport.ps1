<#
.SYNOPSIS
    Analyzes Network Security Groups (NSG) for security issues.

.DESCRIPTION
    This script examines all NSGs and identifies overly permissive rules,
    dangerous configurations, and provides security recommendations.

.PARAMETER ExportPath
    Optional. The path where the CSV report will be saved. Defaults to current directory.

.EXAMPLE
    .\Get-NSGAnalysisReport.ps1

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
    Write-Host "  Network Security Group Analysis" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $context = Get-AzContext
    if (-not $context) { Connect-AzAccount }

    $nsgs = Get-AzNetworkSecurityGroup
    Write-Host "Found $($nsgs.Count) Network Security Groups.`n" -ForegroundColor Green

    $reportData = @()
    $dangerousRulesFound = 0

    foreach ($nsg in $nsgs) {
        Write-Progress -Activity "Analyzing NSGs" -Status $nsg.Name
        
        $dangerousInboundRules = @()
        $allInboundRules = $nsg.SecurityRules | Where-Object { $_.Direction -eq 'Inbound' }
        
        foreach ($rule in $allInboundRules) {
            $isDangerous = $false
            $reasons = @()
            
            # Check for overly permissive source
            if ($rule.SourceAddressPrefix -eq '*' -or $rule.SourceAddressPrefix -eq 'Internet') {
                $isDangerous = $true
                $reasons += "Allows from ANY source"
            }
            
            # Check for wide port ranges
            if ($rule.DestinationPortRange -eq '*') {
                $isDangerous = $true
                $reasons += "Allows ALL ports"
            }
            
            # Check for risky ports
            $riskyPorts = @('22', '3389', '1433', '3306', '5432', '27017')
            foreach ($port in $riskyPorts) {
                if ($rule.DestinationPortRange -contains $port -or $rule.DestinationPortRange -eq '*') {
                    if ($rule.SourceAddressPrefix -eq '*') {
                        $isDangerous = $true
                        $reasons += "Exposes risky port $port to Internet"
                    }
                }
            }
            
            # Check if rule allows access
            if ($rule.Access -eq 'Allow' -and $isDangerous) {
                $dangerousRulesFound++
                $dangerousInboundRules += [PSCustomObject]@{
                    RuleName = $rule.Name
                    Priority = $rule.Priority
                    SourceAddress = $rule.SourceAddressPrefix
                    DestinationPort = $rule.DestinationPortRange
                    Protocol = $rule.Protocol
                    Reasons = ($reasons -join '; ')
                }
            }
        }
        
        # Calculate risk score
        $riskScore = $dangerousInboundRules.Count * 10
        if ($riskScore -gt 100) { $riskScore = 100 }
        
        $reportData += [PSCustomObject]@{
            NSGName = $nsg.Name
            ResourceGroup = $nsg.ResourceGroupName
            Location = $nsg.Location
            TotalRules = $nsg.SecurityRules.Count
            InboundRules = $allInboundRules.Count
            DangerousRules = $dangerousInboundRules.Count
            RiskScore = $riskScore
            RiskLevel = if ($riskScore -eq 0) { "Low" } elseif ($riskScore -le 30) { "Medium" } else { "High" }
            DangerousRuleDetails = if ($dangerousInboundRules.Count -gt 0) { 
                ($dangerousInboundRules | ForEach-Object { "$($_.RuleName): $($_.Reasons)" }) -join ' | '
            } else { "None" }
            AttachedTo = if ($nsg.NetworkInterfaces.Count -gt 0 -or $nsg.Subnets.Count -gt 0) { 
                "NICs: $($nsg.NetworkInterfaces.Count), Subnets: $($nsg.Subnets.Count)" 
            } else { "Not attached" }
        }
    }

    Write-Progress -Activity "Analyzing NSGs" -Completed

    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  NSG Security Summary" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $highRisk = ($reportData | Where-Object { $_.RiskLevel -eq "High" }).Count
    $mediumRisk = ($reportData | Where-Object { $_.RiskLevel -eq "Medium" }).Count
    $lowRisk = ($reportData | Where-Object { $_.RiskLevel -eq "Low" }).Count

    Write-Host "Total NSGs: $($reportData.Count)" -ForegroundColor White
    Write-Host "High Risk: $highRisk" -ForegroundColor Red
    Write-Host "Medium Risk: $mediumRisk" -ForegroundColor Yellow
    Write-Host "Low Risk: $lowRisk" -ForegroundColor Green
    Write-Host "Total Dangerous Rules: $dangerousRulesFound" -ForegroundColor Red

    if ($highRisk -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  High Risk NSGs" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Red
        
        $reportData | Where-Object { $_.RiskLevel -eq "High" } |
            Select-Object NSGName, DangerousRules, RiskScore |
            Format-Table -AutoSize
    }

    # Export
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPath = Join-Path $ExportPath "NSGAnalysis_Report_$timestamp.csv"
    $reportData | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

    Write-Host "`nReport saved to: $reportPath" -ForegroundColor Green

    Write-Host "`nRecommendations:" -ForegroundColor Cyan
    Write-Host "  1. Restrict source IPs to known ranges" -ForegroundColor White
    Write-Host "  2. Avoid allowing traffic from Internet (*)" -ForegroundColor White
    Write-Host "  3. Limit port ranges to only required ports" -ForegroundColor White
    Write-Host "  4. Use Application Security Groups" -ForegroundColor White
    Write-Host "  5. Regularly review and update NSG rules`n" -ForegroundColor White
}
catch {
    Write-Host "`nError: $_" -ForegroundColor Red
    exit 1
}
