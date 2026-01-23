<#
.SYNOPSIS
    Detects external email forwarding in Exchange Online.

.DESCRIPTION
    This script specifically focuses on detecting email forwarding to external domains,
    identifying potential data exfiltration risks and policy violations.

.PARAMETER ExportPath
    Optional. The path where the CSV report will be saved. Defaults to current directory.

.PARAMETER InternalDomains
    Optional. Array of internal domain names to exclude from external forwarding detection.
    Automatically includes the primary domain.

.EXAMPLE
    .\Get-ExternalForwardingReport.ps1

.EXAMPLE
    .\Get-ExternalForwardingReport.ps1 -InternalDomains @("contoso.com", "subsidiary.com")

.NOTES
    Author: Azure Security Audit Team
    Requirements:
    - ExchangeOnlineManagement PowerShell module
    - Permissions: Exchange Administrator or Global Reader
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ExportPath = ".",
    
    [Parameter(Mandatory=$false)]
    [string[]]$InternalDomains = @()
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
    Write-Host "  External Email Forwarding Detection" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    # Ensure Exchange Online module is available
    Test-RequiredModule -ModuleName "ExchangeOnlineManagement"

    # Connect to Exchange Online
    Write-Host "Connecting to Exchange Online..." -ForegroundColor Yellow
    Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
    Write-Host "Connected successfully.`n" -ForegroundColor Green

    # Get organization config
    $orgConfig = Get-OrganizationConfig
    $acceptedDomains = Get-AcceptedDomain | Select-Object -ExpandProperty DomainName
    
    # Merge internal domains
    $allInternalDomains = $acceptedDomains + $InternalDomains | Select-Object -Unique
    
    Write-Host "Internal Domains: $($allInternalDomains -join ', ')`n" -ForegroundColor Cyan

    # Get all mailboxes
    Write-Host "Fetching mailboxes..." -ForegroundColor Yellow
    $mailboxes = Get-Mailbox -ResultSize Unlimited | 
        Select-Object DisplayName, PrimarySmtpAddress, UserPrincipalName, ForwardingAddress, ForwardingSmtpAddress, DeliverToMailboxAndForward, RecipientTypeDetails

    Write-Host "Found $($mailboxes.Count) mailboxes. Checking for external forwarding...`n" -ForegroundColor Green

    $externalForwardingData = @()
    $counter = 0

    foreach ($mailbox in $mailboxes) {
        $counter++
        Write-Progress -Activity "Checking External Forwarding" -Status $mailbox.DisplayName -PercentComplete (($counter / $mailboxes.Count) * 100)
        
        # Check mailbox-level forwarding
        $forwardingAddress = $null
        $isMailboxForwarding = $false
        
        if ($mailbox.ForwardingSmtpAddress) {
            $forwardingAddress = $mailbox.ForwardingSmtpAddress -replace "smtp:", ""
            $isMailboxForwarding = $true
        }
        elseif ($mailbox.ForwardingAddress) {
            # Resolve the forwarding address
            try {
                $recipient = Get-Recipient $mailbox.ForwardingAddress -ErrorAction SilentlyContinue
                if ($recipient) {
                    $forwardingAddress = $recipient.PrimarySmtpAddress
                    $isMailboxForwarding = $true
                }
            }
            catch {
                $forwardingAddress = $mailbox.ForwardingAddress
                $isMailboxForwarding = $true
            }
        }
        
        if ($isMailboxForwarding -and $forwardingAddress) {
            # Check if external
            $isExternal = $true
            $forwardingDomain = ($forwardingAddress -split '@')[1]
            
            foreach ($domain in $allInternalDomains) {
                if ($forwardingDomain -like "*$domain*") {
                    $isExternal = $false
                    break
                }
            }
            
            if ($isExternal) {
                # Determine risk score
                $riskScore = 50
                $riskFactors = @("External mailbox forwarding")
                
                if (-not $mailbox.DeliverToMailboxAndForward) {
                    $riskScore += 30
                    $riskFactors += "No local copy retained"
                }
                
                if ($mailbox.RecipientTypeDetails -eq "SharedMailbox") {
                    $riskScore += 10
                    $riskFactors += "Shared mailbox"
                }
                
                # Check domain reputation (basic check)
                $suspiciousDomains = @("gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "protonmail.com")
                if ($forwardingDomain -in $suspiciousDomains) {
                    $riskScore += 10
                    $riskFactors += "Public email provider"
                }
                
                $externalForwardingData += [PSCustomObject]@{
                    DisplayName = $mailbox.DisplayName
                    UserPrincipalName = $mailbox.UserPrincipalName
                    MailboxType = $mailbox.RecipientTypeDetails
                    SourceEmail = $mailbox.PrimarySmtpAddress
                    ForwardingMethod = "Mailbox-Level"
                    ForwardingDestination = $forwardingAddress
                    DestinationDomain = $forwardingDomain
                    KeepsLocalCopy = $mailbox.DeliverToMailboxAndForward
                    RiskScore = $riskScore
                    RiskFactors = ($riskFactors -join '; ')
                }
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
                
                if ($rule.ForwardTo) { $destinations += $rule.ForwardTo }
                if ($rule.ForwardAsAttachmentTo) { $destinations += $rule.ForwardAsAttachmentTo }
                if ($rule.RedirectTo) { $destinations += $rule.RedirectTo }
                
                foreach ($dest in $destinations) {
                    $destString = $dest.ToString()
                    
                    # Extract email address
                    if ($destString -match '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b') {
                        $destEmail = $matches[0]
                        $destDomain = ($destEmail -split '@')[1]
                        
                        # Check if external
                        $isExternal = $true
                        foreach ($domain in $allInternalDomains) {
                            if ($destDomain -like "*$domain*") {
                                $isExternal = $false
                                break
                            }
                        }
                        
                        if ($isExternal) {
                            # Determine risk score
                            $riskScore = 60
                            $riskFactors = @("External inbox rule forwarding")
                            
                            if (-not $rule.Enabled) {
                                $riskScore = 20
                                $riskFactors += "Rule currently disabled"
                            }
                            else {
                                $riskFactors += "Active rule"
                            }
                            
                            # Check for suspicious patterns
                            if ($rule.Name -like "*hack*" -or $rule.Name -like "*forward*" -or $rule.Name -like "*auto*") {
                                $riskScore += 15
                                $riskFactors += "Suspicious rule name"
                            }
                            
                            # Check domain
                            $suspiciousDomains = @("gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "protonmail.com")
                            if ($destDomain -in $suspiciousDomains) {
                                $riskScore += 10
                                $riskFactors += "Public email provider"
                            }
                            
                            $externalForwardingData += [PSCustomObject]@{
                                DisplayName = $mailbox.DisplayName
                                UserPrincipalName = $mailbox.UserPrincipalName
                                MailboxType = $mailbox.RecipientTypeDetails
                                SourceEmail = $mailbox.PrimarySmtpAddress
                                ForwardingMethod = "Inbox Rule: $($rule.Name)"
                                ForwardingDestination = $destEmail
                                DestinationDomain = $destDomain
                                KeepsLocalCopy = $true
                                RiskScore = $riskScore
                                RiskFactors = ($riskFactors -join '; ')
                            }
                        }
                    }
                }
            }
        }
        catch {
            # Skip if unable to retrieve inbox rules
        }
    }

    Write-Progress -Activity "Checking External Forwarding" -Completed

    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  External Forwarding Summary" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    Write-Host "Total Mailboxes Analyzed:        $($mailboxes.Count)" -ForegroundColor White
    Write-Host "External Forwarding Detected:    $($externalForwardingData.Count)" -ForegroundColor Red
    
    if ($externalForwardingData.Count -gt 0) {
        $criticalRisk = $externalForwardingData | Where-Object { $_.RiskScore -ge 70 }
        $highRisk = $externalForwardingData | Where-Object { $_.RiskScore -ge 50 -and $_.RiskScore -lt 70 }
        $noLocalCopy = $externalForwardingData | Where-Object { -not $_.KeepsLocalCopy }
        
        Write-Host "`nRisk Levels:" -ForegroundColor Cyan
        Write-Host "  - Critical (70+):              $($criticalRisk.Count)" -ForegroundColor Red
        Write-Host "  - High (50-69):                $($highRisk.Count)" -ForegroundColor Yellow
        Write-Host "  - No Local Copy:               $($noLocalCopy.Count)" -ForegroundColor Red

        # Critical risk
        if ($criticalRisk.Count -gt 0) {
            Write-Host "`n========================================" -ForegroundColor Red
            Write-Host "  CRITICAL RISK: External Forwarding" -ForegroundColor Red
            Write-Host "========================================`n" -ForegroundColor Red
            
            $criticalRisk | Select-Object DisplayName, SourceEmail, ForwardingDestination, RiskScore, RiskFactors |
                Format-Table -AutoSize -Wrap
        }

        # Domain analysis
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "  External Domains Receiving Mail" -ForegroundColor Cyan
        Write-Host "========================================`n" -ForegroundColor Cyan
        
        $domainStats = $externalForwardingData | 
            Group-Object -Property DestinationDomain | 
            Select-Object Name, Count | 
            Sort-Object Count -Descending
        
        $domainStats | Format-Table -AutoSize

        # Mailbox type analysis
        $sharedMailboxes = $externalForwardingData | Where-Object { $_.MailboxType -eq "SharedMailbox" }
        if ($sharedMailboxes.Count -gt 0) {
            Write-Host "`n========================================" -ForegroundColor Yellow
            Write-Host "  WARNING: Shared Mailboxes with External Forwarding" -ForegroundColor Yellow
            Write-Host "========================================`n" -ForegroundColor Yellow
            
            $sharedMailboxes | Select-Object DisplayName, ForwardingDestination, RiskScore |
                Format-Table -AutoSize
        }

        # All external forwarding
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "  All External Forwarding Rules" -ForegroundColor Cyan
        Write-Host "========================================`n" -ForegroundColor Cyan
        
        $externalForwardingData | 
            Sort-Object RiskScore -Descending |
            Select-Object DisplayName, ForwardingMethod, ForwardingDestination, RiskScore |
            Format-Table -AutoSize -Wrap
    }
    else {
        Write-Host "`nNo external forwarding detected. Excellent!`n" -ForegroundColor Green
    }

    # Export
    if ($externalForwardingData.Count -gt 0) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $reportPath = Join-Path $ExportPath "ExternalForwarding_Report_$timestamp.csv"
        $externalForwardingData | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

        Write-Host "`n========================================" -ForegroundColor Green
        Write-Host "Report saved to: $reportPath" -ForegroundColor Green
        Write-Host "========================================`n" -ForegroundColor Green
    }

    # Recommendations
    Write-Host "Security Recommendations:" -ForegroundColor Cyan
    if ($externalForwardingData.Count -gt 0) {
        Write-Host "  1. [CRITICAL] Investigate all $($externalForwardingData.Count) external forwarding rules immediately" -ForegroundColor Red
        Write-Host "  2. [HIGH] Disable automatic external forwarding at organization level" -ForegroundColor Red
    }
    Write-Host "  3. Create transport rule to block external auto-forwarding" -ForegroundColor White
    Write-Host "  4. Enable alert policy for new forwarding rules" -ForegroundColor White
    Write-Host "  5. Use Data Loss Prevention (DLP) policies" -ForegroundColor White
    Write-Host "  6. Regular audits of forwarding configurations" -ForegroundColor White
    Write-Host "  7. User training on email security risks`n" -ForegroundColor White

    Disconnect-ExchangeOnline -Confirm:$false | Out-Null
}
catch {
    Write-Host "`nError: $_" -ForegroundColor Red
    try { Disconnect-ExchangeOnline -Confirm:$false | Out-Null } catch { }
    exit 1
}
