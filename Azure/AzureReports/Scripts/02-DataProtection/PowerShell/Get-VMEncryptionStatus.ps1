<#
.SYNOPSIS
    Checks disk encryption status for Azure Virtual Machines.

.DESCRIPTION
    This script queries all Azure Virtual Machines and checks their disk encryption status.
    It identifies VMs with unencrypted disks and provides recommendations for implementing
    Azure Disk Encryption (ADE) or encryption at host.

.PARAMETER ExportPath
    Optional. The path where the CSV report will be saved. Defaults to current directory.

.PARAMETER SubscriptionId
    Optional. Specific subscription ID to query. If not provided, queries all accessible subscriptions.

.EXAMPLE
    .\Get-VMEncryptionStatus.ps1
    Runs the script for all accessible subscriptions.

.EXAMPLE
    .\Get-VMEncryptionStatus.ps1 -ExportPath "C:\Reports"
    Runs the script and saves the report to C:\Reports folder.

.NOTES
    Author: Azure Security Audit Team
    Requirements:
    - Az.Compute PowerShell module
    - Az.ResourceGraph PowerShell module
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
    $requiredModules = @('Az.Compute', 'Az.ResourceGraph', 'Az.Accounts')
    
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
    Write-Host "  VM Disk Encryption Status Check" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    # Check for required modules
    Write-Host "Checking required modules..." -ForegroundColor Yellow
    if (-not (Test-RequiredModules)) {
        throw "Required modules are not available. Please install them manually."
    }

    # Import required modules
    Import-Module Az.Compute -ErrorAction Stop
    Import-Module Az.ResourceGraph -ErrorAction Stop

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
    Write-Host "Querying Virtual Machines..." -ForegroundColor Yellow
    
    $query = @"
Resources
| where type =~ 'microsoft.compute/virtualmachines'
| extend osType = tostring(properties.storageProfile.osDisk.osType)
| extend osDiskEncryption = tostring(properties.storageProfile.osDisk.encryptionSettings.enabled)
| extend managedDisk = tostring(properties.storageProfile.osDisk.managedDisk.id)
| project id, name, location, resourceGroup, subscriptionId, osType, osDiskEncryption, managedDisk, tags
"@

    $vms = Search-AzGraph -Query $query -First 1000

    if ($vms.Count -eq 0) {
        Write-Host "No Virtual Machines found.`n" -ForegroundColor Yellow
        exit 0
    }

    Write-Host "Found $($vms.Count) Virtual Machines. Checking encryption status...`n" -ForegroundColor Green

    # Analyze each VM
    $reportData = @()
    $counter = 0

    foreach ($vm in $vms) {
        $counter++
        Write-Progress -Activity "Checking VM Encryption Status" -Status "Processing $($vm.name)" -PercentComplete (($counter / $vms.Count) * 100)
        
        try {
            # Get detailed VM information
            $vmDetail = Get-AzVM -ResourceGroupName $vm.resourceGroup -Name $vm.name -Status -ErrorAction SilentlyContinue
            
            if (-not $vmDetail) {
                Write-Host "  Warning: Could not retrieve details for VM: $($vm.name)" -ForegroundColor Yellow
                continue
            }

            # Check OS Disk encryption
            $osDiskEncrypted = $false
            $osDiskEncryptionType = "None"
            
            if ($vmDetail.StorageProfile.OsDisk.EncryptionSettings.Enabled -eq $true) {
                $osDiskEncrypted = $true
                $osDiskEncryptionType = "Azure Disk Encryption (ADE)"
            }
            elseif ($vmDetail.StorageProfile.OsDisk.ManagedDisk) {
                # Check for encryption at rest (SSE)
                $diskId = $vmDetail.StorageProfile.OsDisk.ManagedDisk.Id
                $disk = Get-AzDisk -ResourceGroupName $vm.resourceGroup -DiskName $vmDetail.StorageProfile.OsDisk.Name -ErrorAction SilentlyContinue
                
                if ($disk) {
                    if ($disk.Encryption.Type -eq "EncryptionAtRestWithPlatformKey") {
                        $osDiskEncrypted = $true
                        $osDiskEncryptionType = "SSE with Platform-Managed Keys"
                    }
                    elseif ($disk.Encryption.Type -eq "EncryptionAtRestWithCustomerKey") {
                        $osDiskEncrypted = $true
                        $osDiskEncryptionType = "SSE with Customer-Managed Keys"
                    }
                    elseif ($disk.EncryptionSettingsCollection) {
                        $osDiskEncrypted = $true
                        $osDiskEncryptionType = "Azure Disk Encryption (ADE)"
                    }
                }
            }

            # Check Data Disks encryption
            $dataDisksCount = $vmDetail.StorageProfile.DataDisks.Count
            $encryptedDataDisks = 0
            $dataDiskEncryptionTypes = @()

            foreach ($dataDisk in $vmDetail.StorageProfile.DataDisks) {
                if ($dataDisk.ManagedDisk) {
                    $disk = Get-AzDisk -ResourceGroupName $vm.resourceGroup -DiskName $dataDisk.Name -ErrorAction SilentlyContinue
                    
                    if ($disk) {
                        if ($disk.Encryption.Type -match "EncryptionAtRest" -or $disk.EncryptionSettingsCollection) {
                            $encryptedDataDisks++
                            $dataDiskEncryptionTypes += $disk.Encryption.Type
                        }
                    }
                }
            }

            $allDataDisksEncrypted = if ($dataDisksCount -eq 0) { "N/A" } 
                                     elseif ($encryptedDataDisks -eq $dataDisksCount) { $true } 
                                     else { $false }

            # Check for Encryption at Host
            $encryptionAtHost = $vmDetail.SecurityProfile.EncryptionAtHost
            
            # Overall encryption status
            $encryptionStatus = "Not Encrypted"
            if ($osDiskEncrypted -and ($allDataDisksEncrypted -eq $true -or $allDataDisksEncrypted -eq "N/A")) {
                if ($encryptionAtHost) {
                    $encryptionStatus = "Fully Encrypted (with Encryption at Host)"
                } else {
                    $encryptionStatus = "Encrypted"
                }
            }
            elseif ($osDiskEncrypted) {
                $encryptionStatus = "Partially Encrypted (OS Disk Only)"
            }
            elseif ($encryptedDataDisks -gt 0) {
                $encryptionStatus = "Partially Encrypted (Some Data Disks)"
            }

            # Security score
            $securityScore = 0
            if ($osDiskEncrypted) { $securityScore += 50 }
            if ($allDataDisksEncrypted -eq $true) { $securityScore += 30 }
            if ($encryptionAtHost) { $securityScore += 20 }

            # Recommendations
            $recommendations = @()
            if (-not $osDiskEncrypted) {
                $recommendations += "Enable encryption for OS disk"
            }
            if ($allDataDisksEncrypted -eq $false) {
                $recommendations += "Enable encryption for all data disks"
            }
            if (-not $encryptionAtHost) {
                $recommendations += "Consider enabling Encryption at Host for additional security"
            }
            if ($osDiskEncryptionType -eq "SSE with Platform-Managed Keys") {
                $recommendations += "Consider using Customer-Managed Keys for enhanced control"
            }

            $reportData += [PSCustomObject]@{
                VMName = $vm.name
                ResourceGroup = $vm.resourceGroup
                Location = $vm.location
                SubscriptionId = $vm.subscriptionId
                OSType = $vm.osType
                OSDiskEncrypted = $osDiskEncrypted
                OSDiskEncryptionType = $osDiskEncryptionType
                DataDisksCount = $dataDisksCount
                EncryptedDataDisks = $encryptedDataDisks
                AllDataDisksEncrypted = $allDataDisksEncrypted
                EncryptionAtHost = if ($encryptionAtHost) { "Enabled" } else { "Disabled" }
                EncryptionStatus = $encryptionStatus
                SecurityScore = $securityScore
                Recommendations = ($recommendations -join '; ')
            }
        }
        catch {
            Write-Host "  Warning: Error processing VM $($vm.name): $_" -ForegroundColor Yellow
        }
    }

    Write-Progress -Activity "Checking VM Encryption Status" -Completed

    # Display summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  VM Encryption Summary" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $totalVMs = $reportData.Count
    $fullyEncrypted = ($reportData | Where-Object { $_.EncryptionStatus -match "Fully Encrypted" }).Count
    $encrypted = ($reportData | Where-Object { $_.EncryptionStatus -eq "Encrypted" }).Count
    $partiallyEncrypted = ($reportData | Where-Object { $_.EncryptionStatus -match "Partially" }).Count
    $notEncrypted = ($reportData | Where-Object { $_.EncryptionStatus -eq "Not Encrypted" }).Count
    $withEncryptionAtHost = ($reportData | Where-Object { $_.EncryptionAtHost -eq "Enabled" }).Count

    Write-Host "Total Virtual Machines:      $totalVMs" -ForegroundColor White
    Write-Host "Fully Encrypted:             $fullyEncrypted " -ForegroundColor Green -NoNewline
    Write-Host "($([math]::Round(($fullyEncrypted / $totalVMs) * 100, 2))%)" -ForegroundColor Green
    Write-Host "Encrypted (Standard):        $encrypted " -ForegroundColor Green -NoNewline
    Write-Host "($([math]::Round(($encrypted / $totalVMs) * 100, 2))%)" -ForegroundColor Green
    Write-Host "Partially Encrypted:         $partiallyEncrypted" -ForegroundColor Yellow
    Write-Host "Not Encrypted:               $notEncrypted " -ForegroundColor Red -NoNewline
    Write-Host "(SECURITY RISK!)" -ForegroundColor Red
    Write-Host "With Encryption at Host:     $withEncryptionAtHost" -ForegroundColor Cyan

    # Display encryption types
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Encryption Types Distribution" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $reportData | Group-Object -Property OSDiskEncryptionType | 
        Select-Object @{N='Encryption Type';E={$_.Name}}, Count | 
        Sort-Object -Property Count -Descending | 
        Format-Table -AutoSize

    # Display unencrypted or partially encrypted VMs
    $atRiskVMs = $reportData | Where-Object { 
        $_.EncryptionStatus -eq "Not Encrypted" -or 
        $_.EncryptionStatus -match "Partially" 
    }

    if ($atRiskVMs.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  VMs At Risk (Not Fully Encrypted)" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Red
        
        $atRiskVMs | 
            Select-Object VMName, ResourceGroup, EncryptionStatus, OSDiskEncryptionType, DataDisksCount | 
            Format-Table -AutoSize -Wrap
    }

    # Display VMs with best security posture
    $secureVMs = $reportData | Where-Object { $_.SecurityScore -eq 100 }
    if ($secureVMs.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Green
        Write-Host "  VMs with Best Security Posture (First 10)" -ForegroundColor Green
        Write-Host "========================================`n" -ForegroundColor Green
        
        $secureVMs | 
            Select-Object VMName, ResourceGroup, OSDiskEncryptionType, EncryptionAtHost -First 10 | 
            Format-Table -AutoSize
    }

    # Export to CSV
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPath = Join-Path $ExportPath "VMEncryptionStatus_Report_$timestamp.csv"
    
    $reportData | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Report saved to: $reportPath" -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Green

    # Security recommendations
    Write-Host "Encryption Recommendations:" -ForegroundColor Cyan
    if ($notEncrypted -gt 0) {
        Write-Host "  [CRITICAL] $notEncrypted VMs are not encrypted - immediate action required" -ForegroundColor Red
    }
    if ($partiallyEncrypted -gt 0) {
        Write-Host "  [HIGH] $partiallyEncrypted VMs are partially encrypted - ensure all disks are encrypted" -ForegroundColor Yellow
    }
    Write-Host "`nBest Practices:" -ForegroundColor Cyan
    Write-Host "  1. Enable Azure Disk Encryption (ADE) for OS and data disks" -ForegroundColor White
    Write-Host "  2. Use Customer-Managed Keys (CMK) for enhanced control" -ForegroundColor White
    Write-Host "  3. Enable Encryption at Host for additional layer of security" -ForegroundColor White
    Write-Host "  4. Store encryption keys in Azure Key Vault" -ForegroundColor White
    Write-Host "  5. Regularly rotate encryption keys" -ForegroundColor White
    Write-Host "  6. Use Azure Policy to enforce encryption requirements`n" -ForegroundColor White

    Write-Host "For more information:" -ForegroundColor Cyan
    Write-Host "  https://docs.microsoft.com/azure/security/fundamentals/azure-disk-encryption-vms-vmss`n" -ForegroundColor White

}
catch {
    Write-Host "`nError: $_" -ForegroundColor Red
    Write-Host "Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor Red
    exit 1
}
