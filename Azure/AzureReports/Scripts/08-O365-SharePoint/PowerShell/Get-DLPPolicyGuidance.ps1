<#
.SYNOPSIS
    Provides Data Loss Prevention (DLP) policy guidance and current state analysis.

.DESCRIPTION
    This script analyzes current DLP policies, identifies gaps, and provides
    recommendations for implementing comprehensive data protection.

.PARAMETER ExportPath
    Optional. The path where the CSV report will be saved. Defaults to current directory.

.EXAMPLE
    .\Get-DLPPolicyGuidance.ps1

.EXAMPLE
    .\Get-DLPPolicyGuidance.ps1 -ExportPath "C:\Reports"

.NOTES
    Author: Azure Security Audit Team
    Requirements:
    - ExchangeOnlineManagement PowerShell module (for Security & Compliance)
    - Permissions: Compliance Administrator or Global Administrator
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
    Write-Host "  DLP Policy Guidance & Analysis" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    # Ensure required modules are available
    Test-RequiredModule -ModuleName "ExchangeOnlineManagement"

    # Connect to Security & Compliance Center
    Write-Host "Connecting to Security & Compliance Center..." -ForegroundColor Yellow
    Connect-IPPSSession -ErrorAction Stop
    Write-Host "Connected successfully.`n" -ForegroundColor Green

    # Get DLP policies
    Write-Host "Fetching DLP policies..." -ForegroundColor Yellow
    $dlpPolicies = Get-DlpCompliancePolicy
    $dlpRules = Get-DlpComplianceRule

    Write-Host "Found $($dlpPolicies.Count) DLP policies with $($dlpRules.Count) rules.`n" -ForegroundColor Green

    # Analyze policies
    $policyAnalysis = @()
    $assessmentResults = @()
    $securityScore = 0
    $maxScore = 0

    # Check for essential policy types
    $essentialPolicies = @{
        "Credit Card" = $false
        "Social Security" = $false
        "Banking" = $false
        "Health Records" = $false
        "PII" = $false
        "Confidential" = $false
    }

    foreach ($policy in $dlpPolicies) {
        $rules = $dlpRules | Where-Object { $_.Policy -eq $policy.Name }
        
        # Analyze policy configuration
        $locations = @()
        if ($policy.ExchangeLocation) { $locations += "Exchange" }
        if ($policy.SharePointLocation) { $locations += "SharePoint" }
        if ($policy.OneDriveLocation) { $locations += "OneDrive" }
        if ($policy.TeamsLocation) { $locations += "Teams" }
        
        $locationsStr = if ($locations.Count -gt 0) { $locations -join ', ' } else { "None" }
        
        # Check for sensitive info types
        $sensitiveTypes = @()
        foreach ($rule in $rules) {
            if ($rule.ContentContainsSensitiveInformation) {
                $sensitiveInfo = $rule.ContentContainsSensitiveInformation | ConvertFrom-Json -ErrorAction SilentlyContinue
                if ($sensitiveInfo) {
                    foreach ($info in $sensitiveInfo) {
                        if ($info.name) {
                            $sensitiveTypes += $info.name
                            
                            # Mark essential policies as found
                            if ($info.name -like "*credit card*") { $essentialPolicies["Credit Card"] = $true }
                            if ($info.name -like "*social security*" -or $info.name -like "*SSN*") { $essentialPolicies["Social Security"] = $true }
                            if ($info.name -like "*bank*" -or $info.name -like "*ABA*") { $essentialPolicies["Banking"] = $true }
                            if ($info.name -like "*health*" -or $info.name -like "*medical*") { $essentialPolicies["Health Records"] = $true }
                        }
                    }
                }
            }
        }
        
        # Risk assessment
        $riskLevel = "Low"
        $issues = @()
        
        if (-not $policy.Enabled) {
            $riskLevel = "High"
            $issues += "Policy disabled"
        }
        
        if ($locations.Count -eq 0) {
            $riskLevel = "High"
            $issues += "No locations configured"
        }
        
        if ($rules.Count -eq 0) {
            $riskLevel = "High"
            $issues += "No rules configured"
        }
        
        if ($policy.Mode -eq "TestWithNotifications" -or $policy.Mode -eq "TestWithoutNotifications") {
            $riskLevel = "Medium"
            $issues += "Test mode - not enforcing"
        }
        
        $policyAnalysis += [PSCustomObject]@{
            PolicyName = $policy.Name
            Enabled = $policy.Enabled
            Mode = $policy.Mode
            Priority = $policy.Priority
            Locations = $locationsStr
            LocationsCount = $locations.Count
            RulesCount = $rules.Count
            SensitiveTypesCount = ($sensitiveTypes | Select-Object -Unique).Count
            SensitiveTypes = (($sensitiveTypes | Select-Object -Unique) -join '; ')
            CreatedBy = $policy.CreatedBy
            LastModified = if ($policy.WhenChanged) { $policy.WhenChanged.ToString("yyyy-MM-dd") } else { "Unknown" }
            RiskLevel = $riskLevel
            Issues = if ($issues.Count -gt 0) { ($issues -join '; ') } else { "None" }
        }
    }

    # Assess coverage
    $maxScore += 60  # 10 points per essential policy
    $maxScore += 20  # Location coverage
    $maxScore += 20  # Active policies

    # Essential policy coverage
    foreach ($key in $essentialPolicies.Keys) {
        if ($essentialPolicies[$key]) {
            $securityScore += 10
            $assessmentResults += [PSCustomObject]@{
                Category = "Policy Coverage"
                Item = $key
                Status = "COVERED"
                Recommendation = "$key protection is configured"
            }
        }
        else {
            $assessmentResults += [PSCustomObject]@{
                Category = "Policy Coverage"
                Item = $key
                Status = "MISSING"
                Recommendation = "Implement DLP policy for $key"
            }
        }
    }

    # Location coverage
    $allLocations = @("Exchange", "SharePoint", "OneDrive", "Teams")
    $coveredLocations = @()
    foreach ($policy in $dlpPolicies | Where-Object { $_.Enabled }) {
        if ($policy.ExchangeLocation -and "Exchange" -notin $coveredLocations) { $coveredLocations += "Exchange" }
        if ($policy.SharePointLocation -and "SharePoint" -notin $coveredLocations) { $coveredLocations += "SharePoint" }
        if ($policy.OneDriveLocation -and "OneDrive" -notin $coveredLocations) { $coveredLocations += "OneDrive" }
        if ($policy.TeamsLocation -and "Teams" -notin $coveredLocations) { $coveredLocations += "Teams" }
    }
    
    $locationScore = ($coveredLocations.Count / $allLocations.Count) * 20
    $securityScore += $locationScore

    foreach ($location in $allLocations) {
        if ($location -in $coveredLocations) {
            $assessmentResults += [PSCustomObject]@{
                Category = "Location Coverage"
                Item = $location
                Status = "COVERED"
                Recommendation = "$location is protected by DLP"
            }
        }
        else {
            $assessmentResults += [PSCustomObject]@{
                Category = "Location Coverage"
                Item = $location
                Status = "NOT COVERED"
                Recommendation = "Extend DLP policies to $location"
            }
        }
    }

    # Active policies
    $activePolicies = $dlpPolicies | Where-Object { $_.Enabled -and $_.Mode -eq "Enable" }
    if ($activePolicies.Count -gt 0) {
        $securityScore += 20
        $assessmentResults += [PSCustomObject]@{
            Category = "Policy Status"
            Item = "Active Enforcement"
            Status = "ACTIVE"
            Recommendation = "$($activePolicies.Count) policies actively enforcing"
        }
    }
    else {
        $assessmentResults += [PSCustomObject]@{
            Category = "Policy Status"
            Item = "Active Enforcement"
            Status = "NONE"
            Recommendation = "Enable DLP policies in enforcement mode"
        }
    }

    # Calculate final score
    $finalScore = if ($maxScore -gt 0) { [math]::Round(($securityScore / $maxScore) * 100, 2) } else { 0 }

    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  DLP Policy Assessment" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    Write-Host "DLP Protection Score: $securityScore / $maxScore " -ForegroundColor White -NoNewline
    if ($finalScore -ge 80) {
        Write-Host "($finalScore%) - EXCELLENT" -ForegroundColor Green
    }
    elseif ($finalScore -ge 60) {
        Write-Host "($finalScore%) - GOOD" -ForegroundColor Yellow
    }
    else {
        Write-Host "($finalScore%) - NEEDS IMPROVEMENT" -ForegroundColor Red
    }

    Write-Host "`nPolicy Overview:" -ForegroundColor Cyan
    Write-Host "  - Total Policies:              $($dlpPolicies.Count)" -ForegroundColor White
    Write-Host "  - Active Policies:             $($activePolicies.Count)" -ForegroundColor Green
    Write-Host "  - Test Mode Policies:          $(($dlpPolicies | Where-Object { $_.Mode -like 'Test*' }).Count)" -ForegroundColor Yellow
    Write-Host "  - Disabled Policies:           $(($dlpPolicies | Where-Object { -not $_.Enabled }).Count)" -ForegroundColor Red
    Write-Host "  - Total Rules:                 $($dlpRules.Count)" -ForegroundColor White

    # Coverage gaps
    $missingPolicies = $assessmentResults | Where-Object { $_.Status -eq "MISSING" }
    if ($missingPolicies.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  CRITICAL: Policy Coverage Gaps" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Red
        
        $missingPolicies | Select-Object Item, Recommendation |
            Format-Table -AutoSize
    }

    # Location gaps
    $missingLocations = $assessmentResults | Where-Object { $_.Category -eq "Location Coverage" -and $_.Status -eq "NOT COVERED" }
    if ($missingLocations.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Yellow
        Write-Host "  WARNING: Unprotected Locations" -ForegroundColor Yellow
        Write-Host "========================================`n" -ForegroundColor Yellow
        
        $missingLocations | Select-Object Item, Recommendation |
            Format-Table -AutoSize
    }

    # Policy details
    if ($policyAnalysis.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "  Current DLP Policies" -ForegroundColor Cyan
        Write-Host "========================================`n" -ForegroundColor Cyan
        
        $policyAnalysis | Select-Object PolicyName, Enabled, Mode, Locations, RulesCount, RiskLevel |
            Format-Table -AutoSize
    }
    else {
        Write-Host "`nNo DLP policies configured.`n" -ForegroundColor Red
    }

    # Best practices guidance
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  DLP Best Practices Guidance" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $bestPractices = @"
ESSENTIAL SENSITIVE INFORMATION TYPES:
  1. Credit Card Numbers - Protect payment card data (PCI-DSS)
  2. Social Security Numbers - Protect personal identifiers
  3. Bank Account Numbers - Protect financial information
  4. Health Records (PHI) - HIPAA compliance
  5. Personally Identifiable Information (PII) - GDPR/CCPA

RECOMMENDED POLICY CONFIGURATION:
  - Start in Test mode, monitor for 2-4 weeks
  - Review incidents and tune rules to reduce false positives
  - Move to Enforcement mode after validation
  - Apply to all locations: Exchange, SharePoint, OneDrive, Teams

POLICY ACTIONS:
  - Block sharing with external users
  - Require business justification
  - Send notifications to users and admins
  - Generate incident reports

ADVANCED FEATURES:
  - Use sensitivity labels for classification
  - Configure advanced rules with confidence levels
  - Implement exceptions for approved scenarios
  - Enable policy tips for user education
"@

    Write-Host $bestPractices -ForegroundColor White

    # Export
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    $assessmentPath = Join-Path $ExportPath "DLPAssessment_Report_$timestamp.csv"
    $assessmentResults | Export-Csv -Path $assessmentPath -NoTypeInformation -Encoding UTF8
    
    if ($policyAnalysis.Count -gt 0) {
        $policiesPath = Join-Path $ExportPath "DLPPolicies_Report_$timestamp.csv"
        $policyAnalysis | Export-Csv -Path $policiesPath -NoTypeInformation -Encoding UTF8
    }

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Reports saved:" -ForegroundColor Green
    Write-Host "  - Assessment:  $assessmentPath" -ForegroundColor White
    if ($policyAnalysis.Count -gt 0) {
        Write-Host "  - Policies:    $policiesPath" -ForegroundColor White
    }
    Write-Host "Protection Score: $finalScore%" -ForegroundColor $(if ($finalScore -ge 80) { "Green" } elseif ($finalScore -ge 60) { "Yellow" } else { "Red" })
    Write-Host "========================================`n" -ForegroundColor Green

    # Priority actions
    Write-Host "Priority Actions:" -ForegroundColor Cyan
    if ($missingPolicies.Count -gt 0) {
        Write-Host "  1. [CRITICAL] Implement $($missingPolicies.Count) missing essential policies" -ForegroundColor Red
    }
    if ($missingLocations.Count -gt 0) {
        Write-Host "  2. [HIGH] Extend DLP to $($missingLocations.Count) unprotected locations" -ForegroundColor Yellow
    }
    if ($activePolicies.Count -eq 0) {
        Write-Host "  3. [CRITICAL] Enable DLP policies in enforcement mode" -ForegroundColor Red
    }
    Write-Host "  4. Regular review and tuning of DLP policies" -ForegroundColor White
    Write-Host "  5. User training on data classification and handling" -ForegroundColor White
    Write-Host "  6. Implement sensitivity labels" -ForegroundColor White
    Write-Host "  7. Monitor DLP incidents and reports`n" -ForegroundColor White

    Disconnect-ExchangeOnline -Confirm:$false | Out-Null
}
catch {
    Write-Host "`nError: $_" -ForegroundColor Red
    try { Disconnect-ExchangeOnline -Confirm:$false | Out-Null } catch { }
    exit 1
}
