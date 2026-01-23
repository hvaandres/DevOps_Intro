<#
.SYNOPSIS
    Evaluates Conditional Access policies in Azure AD.

.DESCRIPTION
    This script connects to Microsoft Graph and retrieves all Conditional Access policies.
    It analyzes policy configurations, identifies potential security gaps, and provides
    a comprehensive report on access controls and requirements.

.PARAMETER ExportPath
    Optional. The path where the CSV report will be saved. Defaults to current directory.

.PARAMETER IncludeDisabled
    Optional. Include disabled policies in the report. Default is false (enabled policies only).

.EXAMPLE
    .\Get-ConditionalAccessReport.ps1
    Runs the script for enabled policies only and saves the report in the current directory.

.EXAMPLE
    .\Get-ConditionalAccessReport.ps1 -IncludeDisabled
    Runs the script including disabled policies.

.EXAMPLE
    .\Get-ConditionalAccessReport.ps1 -ExportPath "C:\Reports" -IncludeDisabled
    Runs the script with custom export path and includes disabled policies.

.NOTES
    Author: Azure Security Audit Team
    Requirements:
    - Microsoft.Graph PowerShell module
    - Permissions: Policy.Read.All, Directory.Read.All, Application.Read.All
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ExportPath = ".",
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeDisabled
)

# Function to check and install required modules
function Test-RequiredModules {
    $requiredModules = @('Microsoft.Graph.Identity.SignIns', 'Microsoft.Graph.Users')
    
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-Host "Module $module not found. Installing..." -ForegroundColor Yellow
            try {
                Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber
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

# Function to format included/excluded items
function Format-ConditionalAccessItems {
    param($Items, $Type)
    
    if (-not $Items) { return "None" }
    
    $result = @()
    
    switch ($Type) {
        'Users' {
            if ($Items.IncludeUsers -contains 'All') { $result += "All Users" }
            elseif ($Items.IncludeUsers) { $result += "Users: $($Items.IncludeUsers.Count)" }
            if ($Items.IncludeGroups) { $result += "Groups: $($Items.IncludeGroups.Count)" }
            if ($Items.IncludeRoles) { $result += "Roles: $($Items.IncludeRoles.Count)" }
            if ($Items.ExcludeUsers) { $result += "Excluded Users: $($Items.ExcludeUsers.Count)" }
            if ($Items.ExcludeGroups) { $result += "Excluded Groups: $($Items.ExcludeGroups.Count)" }
        }
        'Applications' {
            if ($Items.IncludeApplications -contains 'All') { $result += "All Applications" }
            elseif ($Items.IncludeApplications) { $result += "Apps: $($Items.IncludeApplications.Count)" }
            if ($Items.ExcludeApplications) { $result += "Excluded Apps: $($Items.ExcludeApplications.Count)" }
        }
    }
    
    return ($result -join ', ')
}

# Main script execution
try {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Conditional Access Policy Evaluation" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    # Check for required modules
    Write-Host "Checking required modules..." -ForegroundColor Yellow
    if (-not (Test-RequiredModules)) {
        throw "Required modules are not available. Please install them manually."
    }

    # Connect to Microsoft Graph
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
    try {
        Connect-MgGraph -Scopes "Policy.Read.All", "Directory.Read.All", "Application.Read.All" -ErrorAction Stop
        Write-Host "Successfully connected to Microsoft Graph.`n" -ForegroundColor Green
    }
    catch {
        throw "Failed to connect to Microsoft Graph. Error: $_"
    }

    # Get all Conditional Access policies
    Write-Host "Retrieving Conditional Access policies..." -ForegroundColor Yellow
    $policies = Get-MgIdentityConditionalAccessPolicy -All

    if ($policies.Count -eq 0) {
        Write-Host "No Conditional Access policies found.`n" -ForegroundColor Yellow
        Disconnect-MgGraph | Out-Null
        exit 0
    }

    Write-Host "Found $($policies.Count) policies.`n" -ForegroundColor Green

    # Filter policies if needed
    if (-not $IncludeDisabled) {
        $policies = $policies | Where-Object { $_.State -eq 'enabled' }
        Write-Host "Analyzing $($policies.Count) enabled policies...`n" -ForegroundColor Cyan
    }
    else {
        Write-Host "Analyzing all policies (including disabled)...`n" -ForegroundColor Cyan
    }

    # Analyze each policy
    $reportData = @()
    $counter = 0

    foreach ($policy in $policies) {
        $counter++
        Write-Progress -Activity "Analyzing Conditional Access Policies" -Status "Processing $($policy.DisplayName)" -PercentComplete (($counter / $policies.Count) * 100)
        
        # Parse conditions
        $conditions = $policy.Conditions
        
        # User conditions
        $userScope = Format-ConditionalAccessItems -Items $conditions.Users -Type 'Users'
        
        # Application conditions
        $appScope = Format-ConditionalAccessItems -Items $conditions.Applications -Type 'Applications'
        
        # Platform conditions
        $platforms = if ($conditions.Platforms.IncludePlatforms) {
            if ($conditions.Platforms.IncludePlatforms -contains 'all') {
                "All Platforms"
            } else {
                $conditions.Platforms.IncludePlatforms -join ', '
            }
        } else { "Not Specified" }
        
        # Location conditions
        $locations = if ($conditions.Locations.IncludeLocations) {
            if ($conditions.Locations.IncludeLocations -contains 'All') {
                "All Locations"
            } elseif ($conditions.Locations.IncludeLocations -contains 'AllTrusted') {
                "All Trusted Locations"
            } else {
                "$($conditions.Locations.IncludeLocations.Count) Locations"
            }
        } else { "Not Specified" }
        
        # Client app types
        $clientApps = if ($conditions.ClientAppTypes) {
            $conditions.ClientAppTypes -join ', '
        } else { "Not Specified" }
        
        # Sign-in risk
        $signInRisk = if ($conditions.SignInRiskLevels) {
            $conditions.SignInRiskLevels -join ', '
        } else { "Not Specified" }
        
        # User risk
        $userRisk = if ($conditions.UserRiskLevels) {
            $conditions.UserRiskLevels -join ', '
        } else { "Not Specified" }
        
        # Grant controls
        $grantControls = @()
        if ($policy.GrantControls) {
            if ($policy.GrantControls.BuiltInControls) {
                $grantControls += $policy.GrantControls.BuiltInControls
            }
            if ($policy.GrantControls.CustomAuthenticationFactors) {
                $grantControls += "Custom: $($policy.GrantControls.CustomAuthenticationFactors.Count)"
            }
            $grantOperator = if ($policy.GrantControls.Operator) { $policy.GrantControls.Operator } else { "AND" }
            $grantControl = "($grantOperator) " + ($grantControls -join ', ')
        }
        else {
            $grantControl = "Block Access"
        }
        
        # Session controls
        $sessionControls = @()
        if ($policy.SessionControls) {
            if ($policy.SessionControls.ApplicationEnforcedRestrictions) { $sessionControls += "App Enforced Restrictions" }
            if ($policy.SessionControls.CloudAppSecurity) { $sessionControls += "Cloud App Security" }
            if ($policy.SessionControls.SignInFrequency) { $sessionControls += "Sign-in Frequency: $($policy.SessionControls.SignInFrequency.Value) $($policy.SessionControls.SignInFrequency.Type)" }
            if ($policy.SessionControls.PersistentBrowser) { $sessionControls += "Persistent Browser: $($policy.SessionControls.PersistentBrowser.Mode)" }
        }
        $sessionControl = if ($sessionControls.Count -gt 0) { $sessionControls -join '; ' } else { "None" }
        
        # Check for MFA requirement
        $requiresMFA = $policy.GrantControls.BuiltInControls -contains 'mfa'
        
        # Check for compliant device requirement
        $requiresCompliantDevice = $policy.GrantControls.BuiltInControls -contains 'compliantDevice' -or 
                                   $policy.GrantControls.BuiltInControls -contains 'domainJoinedDevice'
        
        # Risk-based policy
        $isRiskBased = ($signInRisk -ne "Not Specified") -or ($userRisk -ne "Not Specified")
        
        $reportData += [PSCustomObject]@{
            PolicyName = $policy.DisplayName
            State = $policy.State
            CreatedDateTime = if ($policy.CreatedDateTime) { $policy.CreatedDateTime.ToString("yyyy-MM-dd") } else { "N/A" }
            ModifiedDateTime = if ($policy.ModifiedDateTime) { $policy.ModifiedDateTime.ToString("yyyy-MM-dd") } else { "N/A" }
            UserScope = $userScope
            ApplicationScope = $appScope
            Platforms = $platforms
            Locations = $locations
            ClientAppTypes = $clientApps
            SignInRiskLevels = $signInRisk
            UserRiskLevels = $userRisk
            GrantControls = $grantControl
            SessionControls = $sessionControl
            RequiresMFA = $requiresMFA
            RequiresCompliantDevice = $requiresCompliantDevice
            IsRiskBased = $isRiskBased
        }
    }

    Write-Progress -Activity "Analyzing Conditional Access Policies" -Completed

    # Display summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Conditional Access Policy Summary" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $totalPolicies = $policies.Count
    $enabledPolicies = ($policies | Where-Object { $_.State -eq 'enabled' }).Count
    $disabledPolicies = ($policies | Where-Object { $_.State -eq 'disabled' }).Count
    $reportOnlyPolicies = ($policies | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' }).Count
    $mfaPolicies = ($reportData | Where-Object { $_.RequiresMFA }).Count
    $devicePolicies = ($reportData | Where-Object { $_.RequiresCompliantDevice }).Count
    $riskBasedPolicies = ($reportData | Where-Object { $_.IsRiskBased }).Count

    Write-Host "Total Policies:              $totalPolicies" -ForegroundColor White
    Write-Host "Enabled Policies:            $enabledPolicies" -ForegroundColor Green
    Write-Host "Disabled Policies:           $disabledPolicies" -ForegroundColor Yellow
    Write-Host "Report-Only Policies:        $reportOnlyPolicies" -ForegroundColor Cyan
    Write-Host "`nPolicy Types:" -ForegroundColor Cyan
    Write-Host "  MFA-Enforcing Policies:    $mfaPolicies" -ForegroundColor White
    Write-Host "  Device Compliance Policies: $devicePolicies" -ForegroundColor White
    Write-Host "  Risk-Based Policies:       $riskBasedPolicies" -ForegroundColor White

    # Display enabled policies
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "  Enabled Conditional Access Policies" -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Green
    
    $reportData | Where-Object { $_.State -eq 'enabled' } | 
        Select-Object PolicyName, UserScope, GrantControls, RequiresMFA, RequiresCompliantDevice | 
        Format-Table -AutoSize -Wrap

    # Check for security gaps
    Write-Host "`n========================================" -ForegroundColor Yellow
    Write-Host "  Security Analysis" -ForegroundColor Yellow
    Write-Host "========================================`n" -ForegroundColor Yellow

    $hasAllUsersMFA = $reportData | Where-Object { 
        $_.State -eq 'enabled' -and 
        $_.RequiresMFA -and 
        $_.UserScope -like "*All Users*" 
    }

    $hasAdminMFA = $reportData | Where-Object { 
        $_.State -eq 'enabled' -and 
        $_.RequiresMFA -and 
        $_.UserScope -like "*Roles*" 
    }

    if (-not $hasAllUsersMFA) {
        Write-Host "[WARNING] No policy requires MFA for all users" -ForegroundColor Red
    } else {
        Write-Host "[OK] MFA policy for all users is configured" -ForegroundColor Green
    }

    if (-not $hasAdminMFA) {
        Write-Host "[WARNING] Consider a dedicated MFA policy for administrator roles" -ForegroundColor Yellow
    } else {
        Write-Host "[OK] MFA policy for administrator roles is configured" -ForegroundColor Green
    }

    if ($riskBasedPolicies -eq 0) {
        Write-Host "[INFO] Consider implementing risk-based Conditional Access policies" -ForegroundColor Cyan
    } else {
        Write-Host "[OK] Risk-based policies are configured ($riskBasedPolicies policies)" -ForegroundColor Green
    }

    if ($devicePolicies -eq 0) {
        Write-Host "[INFO] Consider requiring compliant or domain-joined devices" -ForegroundColor Cyan
    } else {
        Write-Host "[OK] Device compliance policies are configured ($devicePolicies policies)" -ForegroundColor Green
    }

    # Export to CSV
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPath = Join-Path $ExportPath "ConditionalAccess_Report_$timestamp.csv"
    
    $reportData | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

    # Export detailed policy info to JSON for advanced analysis
    $jsonPath = Join-Path $ExportPath "ConditionalAccess_Detailed_$timestamp.json"
    $policies | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "CSV Report saved to: $reportPath" -ForegroundColor Green
    Write-Host "JSON Report saved to: $jsonPath" -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Green

    # Recommendations
    Write-Host "Best Practice Recommendations:" -ForegroundColor Cyan
    Write-Host "1. Ensure MFA is required for all users and especially for administrators" -ForegroundColor White
    Write-Host "2. Implement risk-based Conditional Access for adaptive security" -ForegroundColor White
    Write-Host "3. Require compliant devices for accessing corporate resources" -ForegroundColor White
    Write-Host "4. Use named locations to restrict access from trusted networks only" -ForegroundColor White
    Write-Host "5. Regularly review and update policies to match security requirements" -ForegroundColor White
    Write-Host "6. Use Report-Only mode to test new policies before enforcement" -ForegroundColor White
    Write-Host "7. Always exclude emergency access accounts from all CA policies`n" -ForegroundColor White

    # Disconnect from Microsoft Graph
    Disconnect-MgGraph | Out-Null
    Write-Host "Disconnected from Microsoft Graph.`n" -ForegroundColor Green

}
catch {
    Write-Host "`nError: $_" -ForegroundColor Red
    Write-Host "Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor Red
    
    # Attempt to disconnect even on error
    try { Disconnect-MgGraph | Out-Null } catch { }
    
    exit 1
}
