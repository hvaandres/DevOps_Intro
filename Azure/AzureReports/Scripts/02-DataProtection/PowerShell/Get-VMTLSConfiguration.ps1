<#
.SYNOPSIS
    Analyzes TLS configuration for Azure Virtual Machines using Azure Resource Graph.

.DESCRIPTION
    This script queries Azure Resource Graph to retrieve TLS configuration settings
    for all Virtual Machines. It identifies VMs with weak TLS versions and provides
    recommendations for secure TLS implementation.

.PARAMETER ExportPath
    Optional. The path where the CSV report will be saved. Defaults to current directory.

.PARAMETER SubscriptionId
    Optional. Specific subscription ID to query. If not provided, queries all accessible subscriptions.

.EXAMPLE
    .\Get-VMTLSConfiguration.ps1
    Runs the script for all accessible subscriptions.

.EXAMPLE
    .\Get-VMTLSConfiguration.ps1 -ExportPath "C:\Reports"
    Runs the script and saves the report to C:\Reports folder.

.EXAMPLE
    .\Get-VMTLSConfiguration.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789012"
    Runs the script for a specific subscription.

.NOTES
    Author: Azure Security Audit Team
    Requirements:
    - Az.ResourceGraph PowerShell module
    - Az.Compute PowerShell module
    - Permissions: Reader access to Azure subscriptions
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
    $requiredModules = @('Az.ResourceGraph', 'Az.Compute', 'Az.Accounts')
    
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
    Write-Host "  Azure VM TLS Configuration Analysis" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    # Check for required modules
    Write-Host "Checking required modules..." -ForegroundColor Yellow
    if (-not (Test-RequiredModules)) {
        throw "Required modules are not available. Please install them manually."
    }

    # Import required modules
    Import-Module Az.ResourceGraph -ErrorAction Stop
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
    }

    # Query all VMs using Azure Resource Graph
    Write-Host "Querying Virtual Machines using Azure Resource Graph..." -ForegroundColor Yellow
    
    $query = @"
Resources
| where type =~ 'microsoft.compute/virtualmachines'
| extend vmSize = tostring(properties.hardwareProfile.vmSize)
| extend osType = tostring(properties.storageProfile.osDisk.osType)
| extend publisher = tostring(properties.storageProfile.imageReference.publisher)
| extend offer = tostring(properties.storageProfile.imageReference.offer)
| extend sku = tostring(properties.storageProfile.imageReference.sku)
| project id, name, location, resourceGroup, subscriptionId, vmSize, osType, publisher, offer, sku, tags
"@

    $vms = Search-AzGraph -Query $query -First 1000

    if ($vms.Count -eq 0) {
        Write-Host "No Virtual Machines found.`n" -ForegroundColor Yellow
        exit 0
    }

    Write-Host "Found $($vms.Count) Virtual Machines. Analyzing TLS configuration...`n" -ForegroundColor Green

    # Analyze each VM
    $reportData = @()
    $counter = 0

    foreach ($vm in $vms) {
        $counter++
        Write-Progress -Activity "Analyzing VM TLS Configuration" -Status "Processing $($vm.name)" -PercentComplete (($counter / $vms.Count) * 100)
        
        try {
            # Get detailed VM information
            $vmDetail = Get-AzVM -ResourceGroupName $vm.resourceGroup -Name $vm.name -Status -ErrorAction SilentlyContinue
            
            if (-not $vmDetail) {
                Write-Host "  Warning: Could not retrieve details for VM: $($vm.name)" -ForegroundColor Yellow
                continue
            }

            # Determine TLS configuration based on OS and extensions
            $tlsVersion = "Unknown"
            $tlsStatus = "Not Configured"
            $hasExtensions = $false
            $securityExtensions = @()
            
            # Check for security-related extensions
            if ($vmDetail.Extensions) {
                $hasExtensions = $true
                foreach ($ext in $vmDetail.Extensions) {
                    if ($ext.Publisher -match "Microsoft.Azure.Security" -or 
                        $ext.Publisher -match "Microsoft.EnterpriseCloud.Monitoring" -or
                        $ext.VirtualMachineExtensionType -match "IaaS") {
                        $securityExtensions += $ext.VirtualMachineExtensionType
                    }
                }
            }

            # Check OS-specific TLS configuration
            if ($vm.osType -eq "Windows") {
                # Windows VMs - Check for TLS registry settings (requires run command or custom script)
                $tlsStatus = "Requires Manual Verification"
                $tlsVersion = "Check Windows Registry"
                $recommendation = "Run script to check HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
            }
            elseif ($vm.osType -eq "Linux") {
                # Linux VMs - TLS depends on OpenSSL version and configuration
                $tlsStatus = "Requires Manual Verification"
                $tlsVersion = "Check OpenSSL Configuration"
                $recommendation = "Verify /etc/ssl/openssl.cnf and OpenSSL version"
            }
            else {
                $tlsStatus = "Unknown OS Type"
                $tlsVersion = "N/A"
                $recommendation = "Unable to determine OS type"
            }

            # Power state
            $powerState = ($vmDetail.Statuses | Where-Object { $_.Code -match 'PowerState' }).DisplayStatus
            
            # Determine security score
            $securityScore = 0
            if ($securityExtensions.Count -gt 0) { $securityScore += 20 }
            if ($vmDetail.OSProfile.WindowsConfiguration.EnableAutomaticUpdates -eq $true) { $securityScore += 20 }
            if ($vm.tags -and $vm.tags.Environment) { $securityScore += 10 }
            
            # Default recommendation
            if (-not $recommendation) {
                $recommendation = "Enable TLS 1.2 or higher; Disable TLS 1.0 and 1.1"
            }

            $reportData += [PSCustomObject]@{
                VMName = $vm.name
                ResourceGroup = $vm.resourceGroup
                Location = $vm.location
                SubscriptionId = $vm.subscriptionId
                OSType = $vm.osType
                VMSize = $vm.vmSize
                Publisher = $vm.publisher
                Offer = $vm.offer
                SKU = $vm.sku
                PowerState = $powerState
                TLSVersion = $tlsVersion
                TLSStatus = $tlsStatus
                HasSecurityExtensions = ($securityExtensions.Count -gt 0)
                SecurityExtensions = ($securityExtensions -join ', ')
                SecurityScore = $securityScore
                Recommendation = $recommendation
                Tags = if ($vm.tags) { ($vm.tags | ConvertTo-Json -Compress) } else { "None" }
            }
        }
        catch {
            Write-Host "  Warning: Error processing VM $($vm.name): $_" -ForegroundColor Yellow
        }
    }

    Write-Progress -Activity "Analyzing VM TLS Configuration" -Completed

    # Display summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  VM TLS Configuration Summary" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $totalVMs = $reportData.Count
    $windowsVMs = ($reportData | Where-Object { $_.OSType -eq 'Windows' }).Count
    $linuxVMs = ($reportData | Where-Object { $_.OSType -eq 'Linux' }).Count
    $vmsWithSecurity = ($reportData | Where-Object { $_.HasSecurityExtensions }).Count
    $runningVMs = ($reportData | Where-Object { $_.PowerState -match 'running' }).Count

    Write-Host "Total Virtual Machines:      $totalVMs" -ForegroundColor White
    Write-Host "Windows VMs:                 $windowsVMs" -ForegroundColor White
    Write-Host "Linux VMs:                   $linuxVMs" -ForegroundColor White
    Write-Host "Running VMs:                 $runningVMs" -ForegroundColor Green
    Write-Host "VMs with Security Extensions: $vmsWithSecurity " -ForegroundColor Cyan -NoNewline
    Write-Host "($([math]::Round(($vmsWithSecurity / $totalVMs) * 100, 2))%)" -ForegroundColor Cyan

    # Display VMs by location
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  VMs by Location" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $reportData | Group-Object -Property Location | 
        Select-Object @{N='Location';E={$_.Name}}, Count | 
        Sort-Object -Property Count -Descending | 
        Format-Table -AutoSize

    # Display VMs without security extensions
    $vmsWithoutSecurity = $reportData | Where-Object { -not $_.HasSecurityExtensions }
    if ($vmsWithoutSecurity.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Yellow
        Write-Host "  VMs Without Security Extensions (First 15)" -ForegroundColor Yellow
        Write-Host "========================================`n" -ForegroundColor Yellow
        
        $vmsWithoutSecurity | 
            Select-Object VMName, ResourceGroup, OSType, PowerState -First 15 | 
            Format-Table -AutoSize
    }

    # Display OS distribution
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  OS Distribution" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $reportData | Group-Object -Property Offer | 
        Select-Object @{N='OS Offer';E={$_.Name}}, Count | 
        Sort-Object -Property Count -Descending | 
        Select-Object -First 10 |
        Format-Table -AutoSize

    # Export to CSV
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPath = Join-Path $ExportPath "VMTLSConfiguration_Report_$timestamp.csv"
    
    $reportData | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Report saved to: $reportPath" -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Green

    # Security recommendations
    Write-Host "TLS Security Recommendations:" -ForegroundColor Cyan
    Write-Host "1. Disable TLS 1.0 and TLS 1.1 on all VMs" -ForegroundColor White
    Write-Host "2. Enable TLS 1.2 or TLS 1.3 as minimum supported version" -ForegroundColor White
    Write-Host "3. Install Azure Security Center agent on all VMs" -ForegroundColor White
    Write-Host "4. Regularly update SSL/TLS certificates" -ForegroundColor White
    Write-Host "5. Use Azure Policy to enforce TLS configuration" -ForegroundColor White
    Write-Host "`nWindows VMs:" -ForegroundColor Yellow
    Write-Host "  - Use Group Policy or Registry to configure TLS" -ForegroundColor White
    Write-Host "  - Path: HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" -ForegroundColor White
    Write-Host "`nLinux VMs:" -ForegroundColor Yellow
    Write-Host "  - Update OpenSSL to latest version" -ForegroundColor White
    Write-Host "  - Configure /etc/ssl/openssl.cnf appropriately" -ForegroundColor White
    Write-Host "  - Use 'openssl version' to verify version`n" -ForegroundColor White

    # Note about manual verification
    Write-Host "NOTE: TLS configuration requires manual verification or Azure Run Command." -ForegroundColor Cyan
    Write-Host "Consider using Azure Policy Guest Configuration for automated compliance checks.`n" -ForegroundColor Cyan

}
catch {
    Write-Host "`nError: $_" -ForegroundColor Red
    Write-Host "Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor Red
    exit 1
}
