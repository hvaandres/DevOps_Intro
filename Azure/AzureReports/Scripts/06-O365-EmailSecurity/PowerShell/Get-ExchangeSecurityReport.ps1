<#
.SYNOPSIS
    Comprehensive Exchange Online security assessment.

.DESCRIPTION
    This script performs a comprehensive security assessment of Exchange Online including
    authentication policies, anti-spam/malware settings, transport rules, and security best practices.

.PARAMETER ExportPath
    Optional. The path where the CSV report will be saved. Defaults to current directory.

.EXAMPLE
    .\Get-ExchangeSecurityReport.ps1

.EXAMPLE
    .\Get-ExchangeSecurityReport.ps1 -ExportPath "C:\Reports"

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
    Write-Host "  Exchange Online Security Assessment" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    # Ensure Exchange Online module is available
    Test-RequiredModule -ModuleName "ExchangeOnlineManagement"

    # Connect to Exchange Online
    Write-Host "Connecting to Exchange Online..." -ForegroundColor Yellow
    Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
    Write-Host "Connected successfully.`n" -ForegroundColor Green

    $assessmentResults = @()
    $securityScore = 0
    $maxScore = 0

    # 1. Organization Configuration
    Write-Host "Checking organization configuration..." -ForegroundColor Yellow
    $orgConfig = Get-OrganizationConfig
    
    # External forwarding
    $maxScore += 10
    if ($orgConfig.AutoForwardEnabled -eq $false) {
        $securityScore += 10
        $assessmentResults += [PSCustomObject]@{
            Category = "Organization Config"
            Setting = "Auto-Forward Enabled"
            CurrentValue = $false
            Status = "SECURE"
            Risk = "None"
            Recommendation = "External auto-forwarding is properly disabled"
        }
    }
    else {
        $assessmentResults += [PSCustomObject]@{
            Category = "Organization Config"
            Setting = "Auto-Forward Enabled"
            CurrentValue = $true
            Status = "VULNERABLE"
            Risk = "High"
            Recommendation = "Disable external auto-forwarding to prevent data exfiltration"
        }
    }
    
    # Modern authentication
    $maxScore += 10
    if ($orgConfig.OAuth2ClientProfileEnabled -eq $true) {
        $securityScore += 10
        $assessmentResults += [PSCustomObject]@{
            Category = "Authentication"
            Setting = "Modern Authentication"
            CurrentValue = $true
            Status = "SECURE"
            Risk = "None"
            Recommendation = "Modern authentication is enabled"
        }
    }
    else {
        $assessmentResults += [PSCustomObject]@{
            Category = "Authentication"
            Setting = "Modern Authentication"
            CurrentValue = $false
            Status = "VULNERABLE"
            Risk = "High"
            Recommendation = "Enable modern authentication (OAuth2)"
        }
    }

    # 2. Anti-Spam Policies
    Write-Host "Analyzing anti-spam policies..." -ForegroundColor Yellow
    $hostedContentPolicies = Get-HostedContentFilterPolicy
    
    foreach ($policy in $hostedContentPolicies) {
        $maxScore += 5
        
        # Check if spam is being deleted or quarantined (not just moved to junk)
        $spamAction = $policy.SpamAction
        if ($spamAction -in @("Quarantine", "Delete")) {
            $securityScore += 3
            $status = "SECURE"
            $risk = "Low"
        }
        else {
            $status = "WARNING"
            $risk = "Medium"
        }
        
        $assessmentResults += [PSCustomObject]@{
            Category = "Anti-Spam"
            Setting = "Spam Action ($($policy.Name))"
            CurrentValue = $spamAction
            Status = $status
            Risk = $risk
            Recommendation = "Consider quarantining or deleting spam instead of moving to junk"
        }
        
        # Check high confidence spam action
        $maxScore += 5
        if ($policy.HighConfidenceSpamAction -in @("Quarantine", "Delete")) {
            $securityScore += 5
            $assessmentResults += [PSCustomObject]@{
                Category = "Anti-Spam"
                Setting = "High Confidence Spam Action"
                CurrentValue = $policy.HighConfidenceSpamAction
                Status = "SECURE"
                Risk = "None"
                Recommendation = "High confidence spam is being properly handled"
            }
        }
        else {
            $assessmentResults += [PSCustomObject]@{
                Category = "Anti-Spam"
                Setting = "High Confidence Spam Action"
                CurrentValue = $policy.HighConfidenceSpamAction
                Status = "VULNERABLE"
                Risk = "High"
                Recommendation = "Quarantine or delete high confidence spam"
            }
        }
    }

    # 3. Anti-Malware Policies
    Write-Host "Analyzing anti-malware policies..." -ForegroundColor Yellow
    $malwarePolicies = Get-MalwareFilterPolicy
    
    foreach ($policy in $malwarePolicies) {
        $maxScore += 5
        
        # Check if common attachment filter is enabled
        if ($policy.EnableFileFilter -eq $true) {
            $securityScore += 5
            $assessmentResults += [PSCustomObject]@{
                Category = "Anti-Malware"
                Setting = "File Filter ($($policy.Name))"
                CurrentValue = $true
                Status = "SECURE"
                Risk = "None"
                Recommendation = "Common attachment types are being filtered"
            }
        }
        else {
            $assessmentResults += [PSCustomObject]@{
                Category = "Anti-Malware"
                Setting = "File Filter ($($policy.Name))"
                CurrentValue = $false
                Status = "WARNING"
                Risk = "Medium"
                Recommendation = "Enable common attachment type filtering"
            }
        }
        
        # Check notification settings
        $maxScore += 3
        if ($policy.EnableInternalSenderAdminNotifications -eq $true) {
            $securityScore += 3
            $status = "SECURE"
        }
        else {
            $status = "INFO"
        }
        
        $assessmentResults += [PSCustomObject]@{
            Category = "Anti-Malware"
            Setting = "Admin Notifications"
            CurrentValue = $policy.EnableInternalSenderAdminNotifications
            Status = $status
            Risk = "Low"
            Recommendation = "Consider enabling admin notifications for malware detections"
        }
    }

    # 4. Transport Rules
    Write-Host "Analyzing transport rules..." -ForegroundColor Yellow
    $transportRules = Get-TransportRule | Where-Object { $_.State -eq "Enabled" }
    
    $hasExternalForwardingBlock = $false
    $hasExecutableBlock = $false
    
    foreach ($rule in $transportRules) {
        # Check for external forwarding blocking
        if ($rule.MessageTypeMatches -contains "AutoForward" -and $rule.SentToScope -eq "NotInOrganization") {
            $hasExternalForwardingBlock = $true
        }
        
        # Check for executable blocking
        if ($rule.AttachmentNameMatchesPatterns -or $rule.AttachmentExtensionMatchesWords) {
            $hasExecutableBlock = $true
        }
    }
    
    $maxScore += 10
    if ($hasExternalForwardingBlock) {
        $securityScore += 10
        $assessmentResults += [PSCustomObject]@{
            Category = "Transport Rules"
            Setting = "External Forwarding Block"
            CurrentValue = "Configured"
            Status = "SECURE"
            Risk = "None"
            Recommendation = "Transport rule blocking external forwarding is in place"
        }
    }
    else {
        $assessmentResults += [PSCustomObject]@{
            Category = "Transport Rules"
            Setting = "External Forwarding Block"
            CurrentValue = "Not Configured"
            Status = "VULNERABLE"
            Risk = "High"
            Recommendation = "Create transport rule to block automatic external forwarding"
        }
    }
    
    $maxScore += 5
    if ($hasExecutableBlock) {
        $securityScore += 5
        $assessmentResults += [PSCustomObject]@{
            Category = "Transport Rules"
            Setting = "Executable Attachment Block"
            CurrentValue = "Configured"
            Status = "SECURE"
            Risk = "None"
            Recommendation = "Executable file types are being blocked"
        }
    }
    else {
        $assessmentResults += [PSCustomObject]@{
            Category = "Transport Rules"
            Setting = "Executable Attachment Block"
            CurrentValue = "Not Configured"
            Status = "WARNING"
            Risk = "Medium"
            Recommendation = "Create transport rule to block dangerous file types (.exe, .bat, .js, etc.)"
        }
    }

    # 5. Authentication Policies
    Write-Host "Checking authentication policies..." -ForegroundColor Yellow
    $authPolicies = Get-AuthenticationPolicy
    
    $maxScore += 5
    if ($authPolicies.Count -gt 0) {
        $basicAuthBlocked = $false
        foreach ($policy in $authPolicies) {
            if ($policy.AllowBasicAuthPop -eq $false -and 
                $policy.AllowBasicAuthImap -eq $false -and 
                $policy.AllowBasicAuthSmtp -eq $false) {
                $basicAuthBlocked = $true
                break
            }
        }
        
        if ($basicAuthBlocked) {
            $securityScore += 5
            $assessmentResults += [PSCustomObject]@{
                Category = "Authentication"
                Setting = "Basic Auth Protocols"
                CurrentValue = "Blocked"
                Status = "SECURE"
                Risk = "None"
                Recommendation = "Basic authentication for legacy protocols is disabled"
            }
        }
        else {
            $assessmentResults += [PSCustomObject]@{
                Category = "Authentication"
                Setting = "Basic Auth Protocols"
                CurrentValue = "Allowed"
                Status = "VULNERABLE"
                Risk = "High"
                Recommendation = "Disable basic authentication for POP, IMAP, and SMTP"
            }
        }
    }

    # 6. DKIM Configuration
    Write-Host "Checking DKIM configuration..." -ForegroundColor Yellow
    $dkimConfigs = Get-DkimSigningConfig
    
    $maxScore += 5
    $dkimEnabled = ($dkimConfigs | Where-Object { $_.Enabled -eq $true }).Count
    
    if ($dkimEnabled -gt 0) {
        $securityScore += 5
        $assessmentResults += [PSCustomObject]@{
            Category = "Email Authentication"
            Setting = "DKIM"
            CurrentValue = "Enabled ($dkimEnabled domains)"
            Status = "SECURE"
            Risk = "None"
            Recommendation = "DKIM signing is enabled"
        }
    }
    else {
        $assessmentResults += [PSCustomObject]@{
            Category = "Email Authentication"
            Setting = "DKIM"
            CurrentValue = "Not Enabled"
            Status = "WARNING"
            Risk = "Medium"
            Recommendation = "Enable DKIM signing for all domains"
        }
    }

    # 7. External Sender Warnings
    $maxScore += 5
    $externalSenderTag = Get-ExternalInOutlook -ErrorAction SilentlyContinue
    
    if ($externalSenderTag -and $externalSenderTag.Enabled -eq $true) {
        $securityScore += 5
        $assessmentResults += [PSCustomObject]@{
            Category = "User Protection"
            Setting = "External Sender Warning"
            CurrentValue = "Enabled"
            Status = "SECURE"
            Risk = "None"
            Recommendation = "External sender warnings are enabled"
        }
    }
    else {
        $assessmentResults += [PSCustomObject]@{
            Category = "User Protection"
            Setting = "External Sender Warning"
            CurrentValue = "Not Enabled"
            Status = "WARNING"
            Risk = "Medium"
            Recommendation = "Enable external sender warnings in Outlook"
        }
    }

    # Calculate final score
    $finalScore = [math]::Round(($securityScore / $maxScore) * 100, 2)

    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Exchange Security Assessment Results" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    Write-Host "Security Score: $securityScore / $maxScore " -ForegroundColor White -NoNewline
    if ($finalScore -ge 80) {
        Write-Host "($finalScore%) - EXCELLENT" -ForegroundColor Green
    }
    elseif ($finalScore -ge 60) {
        Write-Host "($finalScore%) - GOOD" -ForegroundColor Yellow
    }
    else {
        Write-Host "($finalScore%) - NEEDS IMPROVEMENT" -ForegroundColor Red
    }

    # Vulnerabilities
    $vulnerabilities = $assessmentResults | Where-Object { $_.Status -eq "VULNERABLE" }
    $warnings = $assessmentResults | Where-Object { $_.Status -eq "WARNING" }
    
    Write-Host "`nFindings:" -ForegroundColor Cyan
    Write-Host "  - Critical Vulnerabilities:    $($vulnerabilities.Count)" -ForegroundColor Red
    Write-Host "  - Warnings:                    $($warnings.Count)" -ForegroundColor Yellow
    Write-Host "  - Secure Settings:             $(($assessmentResults | Where-Object { $_.Status -eq 'SECURE' }).Count)" -ForegroundColor Green

    # Critical vulnerabilities
    if ($vulnerabilities.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  CRITICAL: Security Vulnerabilities" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Red
        
        $vulnerabilities | Select-Object Category, Setting, CurrentValue, Risk, Recommendation |
            Format-Table -AutoSize -Wrap
    }

    # Warnings
    if ($warnings.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Yellow
        Write-Host "  Warnings and Recommendations" -ForegroundColor Yellow
        Write-Host "========================================`n" -ForegroundColor Yellow
        
        $warnings | Select-Object Category, Setting, CurrentValue, Recommendation |
            Format-Table -AutoSize -Wrap
    }

    # All findings
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Complete Assessment" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    $assessmentResults | Select-Object Category, Setting, Status, Risk |
        Format-Table -AutoSize

    # Export
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPath = Join-Path $ExportPath "ExchangeSecurity_Report_$timestamp.csv"
    $assessmentResults | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Report saved to: $reportPath" -ForegroundColor Green
    Write-Host "Security Score: $finalScore%" -ForegroundColor $(if ($finalScore -ge 80) { "Green" } elseif ($finalScore -ge 60) { "Yellow" } else { "Red" })
    Write-Host "========================================`n" -ForegroundColor Green

    # Priority recommendations
    Write-Host "Priority Actions:" -ForegroundColor Cyan
    if ($vulnerabilities.Count -gt 0) {
        Write-Host "  1. [CRITICAL] Address $($vulnerabilities.Count) security vulnerabilities" -ForegroundColor Red
    }
    if ($warnings.Count -gt 0) {
        Write-Host "  2. [HIGH] Review $($warnings.Count) security warnings" -ForegroundColor Yellow
    }
    Write-Host "  3. Enable Advanced Threat Protection (ATP/Defender for Office 365)" -ForegroundColor White
    Write-Host "  4. Implement DLP policies for sensitive data" -ForegroundColor White
    Write-Host "  5. Regular security audits and monitoring" -ForegroundColor White
    Write-Host "  6. User security awareness training`n" -ForegroundColor White

    Disconnect-ExchangeOnline -Confirm:$false | Out-Null
}
catch {
    Write-Host "`nError: $_" -ForegroundColor Red
    try { Disconnect-ExchangeOnline -Confirm:$false | Out-Null } catch { }
    exit 1
}
