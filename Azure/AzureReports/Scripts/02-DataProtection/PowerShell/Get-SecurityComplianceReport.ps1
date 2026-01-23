<#
.SYNOPSIS
    Generates a comprehensive security compliance report for Azure resources.

.DESCRIPTION
    This script performs a comprehensive security compliance check across Azure resources
    including VMs, storage accounts, networks, and security settings. It provides an
    overall security score and identifies compliance gaps.

.PARAMETER ExportPath
    Optional. The path where the reports will be saved. Defaults to current directory.

.PARAMETER SubscriptionId
    Optional. Specific subscription ID to query. If not provided, queries all accessible subscriptions.

.EXAMPLE
    .\Get-SecurityComplianceReport.ps1
    Runs the script for all accessible subscriptions.

.EXAMPLE
    .\Get-SecurityComplianceReport.ps1 -ExportPath "C:\Reports"
    Runs the script and saves the report to C:\Reports folder.

.NOTES
    Author: Azure Security Audit Team
    Requirements:
    - Az.Security PowerShell module
    - Az.Resources PowerShell module
    - Az.Compute PowerShell module
    - Permissions: Security Reader, Reader access to Azure subscriptions
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ExportPath = ".",
    
    [Parameter(Mandatory=$false)]
    [string]$SubscriptionId
)

# Function to check and install required modules
function Test-RequiredModules {
    $requiredModules = @('Az.Security', 'Az.Resources', 'Az.Compute', 'Az.Accounts')
    
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-Host "Module $module not found. Installing..." -ForegroundColor Yellow
            try {
                Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
                Write-Host "Module $module installed successfully." -ForegroundColor Green
            }
            catch {
                Write-Host "Failed to install module $module. Error: $_" -ForegroundColor Red
                return $false
            }
        }
    }
    return $true
}

# Main script execution
try {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Security Compliance Report" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    # Check for required modules
    Write-Host "Checking required modules..." -ForegroundColor Yellow
    if (-not (Test-RequiredModules)) {
        throw "Required modules are not available. Please install them manually."
    }

    # Import required modules
    Import-Module Az.Security -ErrorAction Stop
    Import-Module Az.Resources -ErrorAction Stop
    Import-Module Az.Compute -ErrorAction Stop

    # Connect to Azure
    Write-Host "Connecting to Azure..." -ForegroundColor Yellow
    try {
        $context = Get-AzContext
        if (-not $context) {
            Connect-AzAccount -ErrorAction Stop
        }
        Write-Host "Successfully connected to Azure.`n" -ForegroundColor Green
    }
    catch {
        throw "Failed to connect to Azure. Error: $_"
    }

    # Set subscription context if specified
    if ($SubscriptionId) {
        Write-Host "Setting subscription context to: $SubscriptionId" -ForegroundColor Cyan
        Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
        $subscriptions = @(Get-AzSubscription -SubscriptionId $SubscriptionId)
    }
    else {
        $subscriptions = Get-AzSubscription
        Write-Host "Found $($subscriptions.Count) accessible subscriptions.`n" -ForegroundColor Cyan
    }

    # Initialize compliance tracking
    $complianceResults = @()
    $overallScore = 0
    $totalChecks = 0

    foreach ($subscription in $subscriptions) {
        Write-Host "`nProcessing Subscription: $($subscription.Name)" -ForegroundColor Cyan
        Write-Host "Subscription ID: $($subscription.Id)`n" -ForegroundColor Gray
        
        Set-AzContext -SubscriptionId $subscription.Id | Out-Null

        # 1. Check Azure Security Center Secure Score
        Write-Host "  [1/7] Checking Azure Security Center..." -ForegroundColor Yellow
        try {
            $secureScore = Get-AzSecuritySecureScore -ErrorAction SilentlyContinue
            $secureScoreValue = if ($secureScore) { 
                [math]::Round(($secureScore[0].Score.Current / $secureScore[0].Score.Max) * 100, 2)
            } else { 
                "Not Available" 
            }
        }
        catch {
            $secureScoreValue = "Error retrieving"
        }

        # 2. Check for Security Contacts
        Write-Host "  [2/7] Checking Security Contacts..." -ForegroundColor Yellow
        try {
            $securityContacts = Get-AzSecurityContact -ErrorAction SilentlyContinue
            $hasSecurityContacts = ($securityContacts.Count -gt 0)
        }
        catch {
            $hasSecurityContacts = $false
        }

        # 3. Check Azure Defender Status
        Write-Host "  [3/7] Checking Azure Defender..." -ForegroundColor Yellow
        try {
            $defenderPlans = Get-AzSecurityPricing -ErrorAction SilentlyContinue
            $enabledDefenderPlans = ($defenderPlans | Where-Object { $_.PricingTier -eq 'Standard' }).Count
            $totalDefenderPlans = $defenderPlans.Count
        }
        catch {
            $enabledDefenderPlans = 0
            $totalDefenderPlans = 0
        }

        # 4. Check Virtual Machine Security
        Write-Host "  [4/7] Checking Virtual Machines..." -ForegroundColor Yellow
        try {
            $vms = Get-AzVM
            $vmsWithMonitoring = 0
            $vmsWithEncryption = 0
            
            foreach ($vm in $vms) {
                # Check for monitoring agent
                $vmDetail = Get-AzVM -ResourceGroupName $vm.ResourceGroupName -Name $vm.Name
                if ($vmDetail.Extensions | Where-Object { $_.Publisher -match "Microsoft.EnterpriseCloud.Monitoring" }) {
                    $vmsWithMonitoring++
                }
                
                # Check for disk encryption
                if ($vmDetail.StorageProfile.OsDisk.EncryptionSettings.Enabled) {
                    $vmsWithEncryption++
                }
            }
            
            $vmMonitoringPercent = if ($vms.Count -gt 0) { [math]::Round(($vmsWithMonitoring / $vms.Count) * 100, 2) } else { 100 }
            $vmEncryptionPercent = if ($vms.Count -gt 0) { [math]::Round(($vmsWithEncryption / $vms.Count) * 100, 2) } else { 100 }
        }
        catch {
            $vms = @()
            $vmMonitoringPercent = 0
            $vmEncryptionPercent = 0
        }

        # 5. Check Network Security Groups
        Write-Host "  [5/7] Checking Network Security..." -ForegroundColor Yellow
        try {
            $nsgs = Get-AzNetworkSecurityGroup
            $nsgsWithDangerousRules = 0
            
            foreach ($nsg in $nsgs) {
                # Check for overly permissive rules (allow any source)
                $dangerousRules = $nsg.SecurityRules | Where-Object {
                    $_.Access -eq 'Allow' -and 
                    $_.Direction -eq 'Inbound' -and 
                    ($_.SourceAddressPrefix -eq '*' -or $_.SourceAddressPrefix -eq 'Internet')
                }
                
                if ($dangerousRules) {
                    $nsgsWithDangerousRules++
                }
            }
            
            $nsgCompliancePercent = if ($nsgs.Count -gt 0) { 
                [math]::Round((($nsgs.Count - $nsgsWithDangerousRules) / $nsgs.Count) * 100, 2) 
            } else { 100 }
        }
        catch {
            $nsgs = @()
            $nsgCompliancePercent = 0
        }

        # 6. Check Storage Account Security
        Write-Host "  [6/7] Checking Storage Accounts..." -ForegroundColor Yellow
        try {
            $storageAccounts = Get-AzStorageAccount
            $secureStorageAccounts = 0
            
            foreach ($sa in $storageAccounts) {
                $isSecure = $true
                
                # Check HTTPS only
                if (-not $sa.EnableHttpsTrafficOnly) { $isSecure = $false }
                
                # Check TLS version
                if ($sa.MinimumTlsVersion -in @('TLS1_0', 'TLS1_1')) { $isSecure = $false }
                
                # Check public blob access
                if ($sa.AllowBlobPublicAccess) { $isSecure = $false }
                
                if ($isSecure) { $secureStorageAccounts++ }
            }
            
            $storageCompliancePercent = if ($storageAccounts.Count -gt 0) { 
                [math]::Round(($secureStorageAccounts / $storageAccounts.Count) * 100, 2) 
            } else { 100 }
        }
        catch {
            $storageAccounts = @()
            $storageCompliancePercent = 0
        }

        # 7. Check for Security Policies
        Write-Host "  [7/7] Checking Security Policies..." -ForegroundColor Yellow
        try {
            $policies = Get-AzPolicyAssignment -Scope "/subscriptions/$($subscription.Id)" -ErrorAction SilentlyContinue
            $securityPolicies = ($policies | Where-Object { 
                $_.Properties.DisplayName -match 'Security|Compliance|Audit' 
            }).Count
        }
        catch {
            $securityPolicies = 0
        }

        # Calculate subscription compliance score
        $subscriptionScore = 0
        $checksCount = 0
        
        # Secure Score (20 points)
        if ($secureScoreValue -ne "Not Available" -and $secureScoreValue -ne "Error retrieving") {
            $subscriptionScore += ($secureScoreValue / 100) * 20
        }
        $checksCount++
        
        # Security Contacts (10 points)
        if ($hasSecurityContacts) { $subscriptionScore += 10 }
        $checksCount++
        
        # Azure Defender (20 points)
        if ($totalDefenderPlans -gt 0) {
            $subscriptionScore += ($enabledDefenderPlans / $totalDefenderPlans) * 20
        }
        $checksCount++
        
        # VM Security (20 points)
        $subscriptionScore += (($vmMonitoringPercent + $vmEncryptionPercent) / 200) * 20
        $checksCount++
        
        # Network Security (15 points)
        $subscriptionScore += ($nsgCompliancePercent / 100) * 15
        $checksCount++
        
        # Storage Security (10 points)
        $subscriptionScore += ($storageCompliancePercent / 100) * 10
        $checksCount++
        
        # Security Policies (5 points)
        if ($securityPolicies -gt 0) { $subscriptionScore += 5 }
        $checksCount++

        # Store results
        $complianceResults += [PSCustomObject]@{
            SubscriptionName = $subscription.Name
            SubscriptionId = $subscription.Id
            SecureScore = $secureScoreValue
            HasSecurityContacts = $hasSecurityContacts
            DefenderPlansEnabled = "$enabledDefenderPlans / $totalDefenderPlans"
            TotalVMs = $vms.Count
            VMsWithMonitoring = "$vmsWithMonitoring ($vmMonitoringPercent%)"
            VMsWithEncryption = "$vmsWithEncryption ($vmEncryptionPercent%)"
            TotalNSGs = $nsgs.Count
            NSGCompliance = "$nsgCompliancePercent%"
            TotalStorageAccounts = $storageAccounts.Count
            StorageCompliance = "$storageCompliancePercent%"
            SecurityPolicies = $securityPolicies
            ComplianceScore = [math]::Round($subscriptionScore, 2)
            ComplianceGrade = if ($subscriptionScore -ge 90) { "A" } 
                             elseif ($subscriptionScore -ge 80) { "B" }
                             elseif ($subscriptionScore -ge 70) { "C" }
                             elseif ($subscriptionScore -ge 60) { "D" }
                             else { "F" }
        }

        $overallScore += $subscriptionScore
        $totalChecks += $checksCount
    }

    # Calculate overall compliance score
    $overallComplianceScore = if ($subscriptions.Count -gt 0) { 
        [math]::Round($overallScore / $subscriptions.Count, 2) 
    } else { 0 }

    # Display summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Overall Compliance Summary" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    Write-Host "Subscriptions Analyzed: $($subscriptions.Count)" -ForegroundColor White
    Write-Host "Overall Compliance Score: $overallComplianceScore / 100" -ForegroundColor White
    
    $overallGrade = if ($overallComplianceScore -ge 90) { "A" } 
                    elseif ($overallComplianceScore -ge 80) { "B" }
                    elseif ($overallComplianceScore -ge 70) { "C" }
                    elseif ($overallComplianceScore -ge 60) { "D" }
                    else { "F" }
    
    $gradeColor = if ($overallGrade -in @("A", "B")) { "Green" }
                  elseif ($overallGrade -eq "C") { "Yellow" }
                  else { "Red" }
    
    Write-Host "Compliance Grade: " -NoNewline
    Write-Host $overallGrade -ForegroundColor $gradeColor

    # Display detailed results
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Subscription Compliance Details" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $complianceResults | Format-Table SubscriptionName, ComplianceScore, ComplianceGrade, SecureScore, DefenderPlansEnabled -AutoSize

    # Export to CSV
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPath = Join-Path $ExportPath "SecurityCompliance_Report_$timestamp.csv"
    
    $complianceResults | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Report saved to: $reportPath" -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Green

    # Security recommendations
    Write-Host "Compliance Recommendations:" -ForegroundColor Cyan
    
    $failingSubscriptions = $complianceResults | Where-Object { $_.ComplianceScore -lt 70 }
    if ($failingSubscriptions.Count -gt 0) {
        Write-Host "`n  [CRITICAL] $($failingSubscriptions.Count) subscription(s) below 70% compliance" -ForegroundColor Red
    }
    
    $noContacts = ($complianceResults | Where-Object { -not $_.HasSecurityContacts }).Count
    if ($noContacts -gt 0) {
        Write-Host "  [HIGH] $noContacts subscription(s) without security contacts configured" -ForegroundColor Yellow
    }
    
    Write-Host "`nBest Practices:" -ForegroundColor Cyan
    Write-Host "  1. Enable Azure Defender (now Microsoft Defender for Cloud) on all subscriptions" -ForegroundColor White
    Write-Host "  2. Configure security contacts for alert notifications" -ForegroundColor White
    Write-Host "  3. Enable monitoring agents on all VMs" -ForegroundColor White
    Write-Host "  4. Encrypt all VM disks using Azure Disk Encryption" -ForegroundColor White
    Write-Host "  5. Review and restrict Network Security Group rules" -ForegroundColor White
    Write-Host "  6. Enable HTTPS-only and TLS 1.2+ for storage accounts" -ForegroundColor White
    Write-Host "  7. Implement Azure Policy for continuous compliance" -ForegroundColor White
    Write-Host "  8. Regularly review Azure Security Center recommendations`n" -ForegroundColor White

    Write-Host "For more information:" -ForegroundColor Cyan
    Write-Host "  https://docs.microsoft.com/azure/security-center/`n" -ForegroundColor White

}
catch {
    Write-Host "`nError: $_" -ForegroundColor Red
    Write-Host "Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor Red
    exit 1
}
