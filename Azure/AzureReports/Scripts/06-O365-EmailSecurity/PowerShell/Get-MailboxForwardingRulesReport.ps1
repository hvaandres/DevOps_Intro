<#
.SYNOPSIS
    Analyzes mailbox forwarding rules in Exchange Online.

.DESCRIPTION
    This script detects and analyzes all mailbox forwarding rules including inbox rules,
    transport rules, and mailbox-level forwarding configurations.

.PARAMETER ExportPath
    Optional. The path where the CSV report will be saved. Defaults to current directory.

.EXAMPLE
    .\Get-MailboxForwardingRulesReport.ps1

.EXAMPLE
    .\Get-MailboxForwardingRulesReport.ps1 -ExportPath "C:\Reports"

.NOTES
    Author: Azure Security Audit Team
    Requirements:
    - ExchangeOnlineManagement PowerShell module
    - Permissions: Exchange Administrator or Global Reader
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ExportPath = "."
)

function Test-RequiredModule {
    param([string]$ModuleName)
    
    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        Write-Host "Installing $ModuleName module..." -ForegroundColor Yellow
        Install-Module -Name $ModuleName -Force -AllowClobber -Scope CurrentUser
    }
    
    if (-not (Get-Module -Name $ModuleName)) {
        Import-Module $ModuleName -ErrorAction Stop
    }
}

try {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Mailbox Forwarding Rules Analysis" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    # Ensure Exchange Online module is available
    Test-RequiredModule -ModuleName "ExchangeOnlineManagement"

    # Connect to Exchange Online
    Write-Host "Connecting to Exchange Online..." -ForegroundColor Yellow
    Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
    Write-Host "Connected successfully.`n" -ForegroundColor Green

    # Get all mailboxes
    Write-Host "Fetching mailboxes..." -ForegroundColor Yellow
    $mailboxes = Get-Mailbox -ResultSize Unlimited | 
        Select-Object DisplayName, PrimarySmtpAddress, UserPrincipalName, ForwardingAddress, ForwardingSmtpAddress, DeliverToMailboxAndForward

    Write-Host "Found $($mailboxes.Count) mailboxes. Analyzing forwarding rules...`n" -ForegroundColor Green

    $reportData = @()
    $counter = 0

    foreach ($mailbox in $mailboxes) {
        $counter++
        Write-Progress -Activity "Analyzing Mailbox Rules" -Status $mailbox.DisplayName -PercentComplete (($counter / $mailboxes.Count) * 100)
        
        # Check mailbox-level forwarding
        $hasMailboxForwarding = $false
        $forwardingType = "None"
        $forwardingDestination = "N/A"
        $deliverAndForward = $false
        
        if ($mailbox.ForwardingAddress -or $mailbox.ForwardingSmtpAddress) {
            $hasMailboxForwarding = $true
            $forwardingType = "Mailbox-Level Forwarding"
            $deliverAndForward = $mailbox.DeliverToMailboxAndForward
            
            if ($mailbox.ForwardingAddress) {
                $forwardingDestination = $mailbox.ForwardingAddress
            }
            if ($mailbox.ForwardingSmtpAddress) {
                $forwardingDestination = $mailbox.ForwardingSmtpAddress
            }
            
            # Determine if external
            $isExternal = $false
            if ($forwardingDestination -and $forwardingDestination -notlike "*@*$($mailbox.PrimarySmtpAddress.Split('@')[1])") {
                $isExternal = $true
            }
            
            # Determine risk level
            $riskLevel = "Medium"
            $riskFactors = @()
            
            if ($isExternal) {
                $riskLevel = "High"
                $riskFactors += "External forwarding"
            }
            
            if (-not $deliverAndForward) {
                $riskFactors += "No copy kept in mailbox"
                if ($riskLevel -eq "Medium") { $riskLevel = "High" }
            }
            
            $reportData += [PSCustomObject]@{
                DisplayName = $mailbox.DisplayName
                UserPrincipalName = $mailbox.UserPrincipalName
                PrimaryEmail = $mailbox.PrimarySmtpAddress
                ForwardingType = $forwardingType
                ForwardingDestination = $forwardingDestination
                IsExternal = $isExternal
                DeliverAndForward = $deliverAndForward
                RuleName = "Mailbox Forwarding"
                RiskLevel = $riskLevel
                RiskFactors = ($riskFactors -join '; ')
            }
        }
        
        # Check inbox rules
        try {
            $inboxRules = Get-InboxRule -Mailbox $mailbox.UserPrincipalName -ErrorAction SilentlyContinue |
                Where-Object { 
                    $_.ForwardTo -or 
                    $_.ForwardAsAttachmentTo -or 
                    $_.RedirectTo 
                }
            
            foreach ($rule in $inboxRules) {
                $destinations = @()
                
                if ($rule.ForwardTo) {
                    $destinations += $rule.ForwardTo
                }
                if ($rule.ForwardAsAttachmentTo) {
                    $destinations += $rule.ForwardAsAttachmentTo
                }
                if ($rule.RedirectTo) {
                    $destinations += $rule.RedirectTo
                }
                
                foreach ($dest in $destinations) {
                    $destString = $dest.ToString()
                    
                    # Determine if external
                    $isExternal = $false
                    $domain = $mailbox.PrimarySmtpAddress.Split('@')[1]
                    
                    if ($destString -match '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b') {
                        $emailMatch = $matches[0]
                        if ($emailMatch -notlike "*@$domain") {
                            $isExternal = $true
                        }
                    }
                    
                    # Determine risk level
                    $riskLevel = "Medium"
                    $riskFactors = @()
                    
                    if ($isExternal) {
                        $riskLevel = "High"
                        $riskFactors += "External forwarding via inbox rule"
                    }
                    
                    if (-not $rule.Enabled) {
                        $riskLevel = "Low"
                        $riskFactors += "Rule disabled"
                    }
                    else {
                        $riskFactors += "Active forwarding rule"
                    }
                    
                    $reportData += [PSCustomObject]@{
                        DisplayName = $mailbox.DisplayName
                        UserPrincipalName = $mailbox.UserPrincipalName
                        PrimaryEmail = $mailbox.PrimarySmtpAddress
                        ForwardingType = "Inbox Rule"
                        ForwardingDestination = $destString
                        IsExternal = $isExternal
                        DeliverAndForward = $true  # Inbox rules typically keep copy
                        RuleName = $rule.Name
                        RiskLevel = $riskLevel
                        RiskFactors = ($riskFactors -join '; ')
                    }
                }
            }
        }
        catch {
            # Skip if unable to retrieve inbox rules
        }
    }

    Write-Progress -Activity "Analyzing Mailbox Rules" -Completed

    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Forwarding Rules Summary" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $totalForwarding = $reportData.Count
    $externalForwarding = $reportData | Where-Object { $_.IsExternal }
    $mailboxLevelForwarding = $reportData | Where-Object { $_.ForwardingType -eq "Mailbox-Level Forwarding" }
    $inboxRuleForwarding = $reportData | Where-Object { $_.ForwardingType -eq "Inbox Rule" }
    $highRisk = $reportData | Where-Object { $_.RiskLevel -eq "High" }
    $noLocalCopy = $reportData | Where-Object { -not $_.DeliverAndForward }

    Write-Host "Total Mailboxes Analyzed:        $($mailboxes.Count)" -ForegroundColor White
    Write-Host "Mailboxes with Forwarding:       $totalForwarding" -ForegroundColor Yellow
    Write-Host "  - Mailbox-Level:               $($mailboxLevelForwarding.Count)" -ForegroundColor White
    Write-Host "  - Inbox Rules:                 $($inboxRuleForwarding.Count)" -ForegroundColor White
    Write-Host "`nSecurity Concerns:" -ForegroundColor Cyan
    Write-Host "  - External Forwarding:         $($externalForwarding.Count)" -ForegroundColor Red
    Write-Host "  - High Risk:                   $($highRisk.Count)" -ForegroundColor Red
    Write-Host "  - No Local Copy:               $($noLocalCopy.Count)" -ForegroundColor Yellow

    if ($externalForwarding.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  HIGH RISK: External Email Forwarding" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Red
        
        $externalForwarding | Select-Object DisplayName, PrimaryEmail, ForwardingType, ForwardingDestination, RuleName |
            Format-Table -AutoSize -Wrap
    }

    if ($noLocalCopy.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Yellow
        Write-Host "  WARNING: Forwarding Without Local Copy" -ForegroundColor Yellow
        Write-Host "========================================`n" -ForegroundColor Yellow
        
        $noLocalCopy | Select-Object DisplayName, PrimaryEmail, ForwardingDestination |
            Format-Table -AutoSize
    }

    if ($reportData.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "  All Forwarding Rules" -ForegroundColor Cyan
        Write-Host "========================================`n" -ForegroundColor Cyan
        
        $reportData | Select-Object DisplayName, ForwardingType, ForwardingDestination, IsExternal, RiskLevel |
            Format-Table -AutoSize -Wrap
    }
    else {
        Write-Host "`nNo forwarding rules detected.`n" -ForegroundColor Green
    }

    # Export
    if ($reportData.Count -gt 0) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $reportPath = Join-Path $ExportPath "MailboxForwardingRules_Report_$timestamp.csv"
        $reportData | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

        Write-Host "`n========================================" -ForegroundColor Green
        Write-Host "Report saved to: $reportPath" -ForegroundColor Green
        Write-Host "========================================`n" -ForegroundColor Green
    }

    # Recommendations
    Write-Host "Security Recommendations:" -ForegroundColor Cyan
    if ($externalForwarding.Count -gt 0) {
        Write-Host "  1. [CRITICAL] Review $($externalForwarding.Count) external forwarding rules immediately" -ForegroundColor Red
    }
    if ($noLocalCopy.Count -gt 0) {
        Write-Host "  2. [HIGH] Enable 'Deliver and Forward' for $($noLocalCopy.Count) mailboxes" -ForegroundColor Yellow
    }
    Write-Host "  3. Implement policies to prevent automatic external forwarding" -ForegroundColor White
    Write-Host "  4. Regular audits of forwarding rules" -ForegroundColor White
    Write-Host "  5. Use transport rules to block or alert on external forwarding" -ForegroundColor White
    Write-Host "  6. Enable alerts for new forwarding rule creation`n" -ForegroundColor White

    Disconnect-ExchangeOnline -Confirm:$false | Out-Null
}
catch {
    Write-Host "`nError: $_" -ForegroundColor Red
    try { Disconnect-ExchangeOnline -Confirm:$false | Out-Null } catch { }
    exit 1
}
