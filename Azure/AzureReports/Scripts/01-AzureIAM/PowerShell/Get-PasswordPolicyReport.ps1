<#
.SYNOPSIS
    Assesses password expiry policies across Azure AD.

.DESCRIPTION
    This script connects to Microsoft Graph and retrieves password policy settings
    for the organization and individual users. It identifies password policy configurations,
    expiration settings, and users with passwords that never expire.

.PARAMETER ExportPath
    Optional. The path where the CSV report will be saved. Defaults to current directory.

.EXAMPLE
    .\Get-PasswordPolicyReport.ps1
    Runs the script and saves the report in the current directory.

.EXAMPLE
    .\Get-PasswordPolicyReport.ps1 -ExportPath "C:\Reports"
    Runs the script and saves the report to C:\Reports folder.

.NOTES
    Author: Azure Security Audit Team
    Requirements:
    - Microsoft.Graph PowerShell module
    - Permissions: User.Read.All, Domain.Read.All, Policy.Read.All
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ExportPath = "."
)

# Function to check and install required modules
function Test-RequiredModules {
    $requiredModules = @('Microsoft.Graph.Users', 'Microsoft.Graph.Identity.DirectoryManagement')
    
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

# Main script execution
try {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Password Policy Assessment Script" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    # Check for required modules
    Write-Host "Checking required modules..." -ForegroundColor Yellow
    if (-not (Test-RequiredModules)) {
        throw "Required modules are not available. Please install them manually."
    }

    # Connect to Microsoft Graph
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
    try {
        Connect-MgGraph -Scopes "User.Read.All", "Domain.Read.All", "Policy.Read.All" -ErrorAction Stop
        Write-Host "Successfully connected to Microsoft Graph.`n" -ForegroundColor Green
    }
    catch {
        throw "Failed to connect to Microsoft Graph. Error: $_"
    }

    # Get organization password policies
    Write-Host "Retrieving organization password policies..." -ForegroundColor Yellow
    
    $domains = Get-MgDomain
    $orgPasswordPolicy = @{
        PasswordValidityPeriodInDays = 90  # Default Azure AD value
        PasswordNotificationWindowInDays = 14
    }

    # Get domain password settings
    foreach ($domain in $domains) {
        if ($domain.IsDefault) {
            Write-Host "Default Domain: $($domain.Id)" -ForegroundColor Cyan
            $orgPasswordPolicy.DefaultDomain = $domain.Id
            
            if ($domain.PasswordValidityPeriodInDays) {
                $orgPasswordPolicy.PasswordValidityPeriodInDays = $domain.PasswordValidityPeriodInDays
            }
            if ($domain.PasswordNotificationWindowInDays) {
                $orgPasswordPolicy.PasswordNotificationWindowInDays = $domain.PasswordNotificationWindowInDays
            }
        }
    }

    Write-Host "`nOrganization Password Policy:" -ForegroundColor Cyan
    Write-Host "  Password Validity Period: $($orgPasswordPolicy.PasswordValidityPeriodInDays) days" -ForegroundColor White
    Write-Host "  Password Notification Window: $($orgPasswordPolicy.PasswordNotificationWindowInDays) days`n" -ForegroundColor White

    # Get all users
    Write-Host "Fetching all users..." -ForegroundColor Yellow
    $users = Get-MgUser -All -Property Id, UserPrincipalName, DisplayName, AccountEnabled, PasswordPolicies, LastPasswordChangeDateTime, UserType

    Write-Host "Found $($users.Count) users. Analyzing password policies...`n" -ForegroundColor Green

    # Analyze each user
    $reportData = @()
    $counter = 0

    foreach ($user in $users) {
        $counter++
        Write-Progress -Activity "Analyzing Password Policies" -Status "Processing $($user.UserPrincipalName)" -PercentComplete (($counter / $users.Count) * 100)
        
        $passwordNeverExpires = $false
        $disablePasswordExpiration = $false
        $disableStrongPassword = $false
        
        # Check password policies
        if ($user.PasswordPolicies) {
            $policies = $user.PasswordPolicies.Split(',').Trim()
            $passwordNeverExpires = $policies -contains 'DisablePasswordExpiration'
            $disablePasswordExpiration = $policies -contains 'DisablePasswordExpiration'
            $disableStrongPassword = $policies -contains 'DisableStrongPassword'
        }
        
        # Calculate password age and expiration
        $passwordAge = $null
        $daysUntilExpiration = $null
        $passwordStatus = "Unknown"
        
        if ($user.LastPasswordChangeDateTime) {
            $passwordAge = (New-TimeSpan -Start $user.LastPasswordChangeDateTime -End (Get-Date)).Days
            
            if ($passwordNeverExpires) {
                $daysUntilExpiration = "Never"
                $passwordStatus = "Never Expires"
            }
            else {
                $daysUntilExpiration = $orgPasswordPolicy.PasswordValidityPeriodInDays - $passwordAge
                
                if ($daysUntilExpiration -le 0) {
                    $passwordStatus = "Expired"
                }
                elseif ($daysUntilExpiration -le $orgPasswordPolicy.PasswordNotificationWindowInDays) {
                    $passwordStatus = "Expiring Soon"
                }
                else {
                    $passwordStatus = "Valid"
                }
            }
        }
        else {
            $passwordAge = "Never Changed"
            $daysUntilExpiration = "N/A"
            $passwordStatus = "Never Changed"
        }
        
        $reportData += [PSCustomObject]@{
            UserPrincipalName = $user.UserPrincipalName
            DisplayName = $user.DisplayName
            UserType = $user.UserType
            AccountEnabled = $user.AccountEnabled
            PasswordNeverExpires = $passwordNeverExpires
            DisableStrongPassword = $disableStrongPassword
            LastPasswordChange = if ($user.LastPasswordChangeDateTime) { $user.LastPasswordChangeDateTime.ToString("yyyy-MM-dd") } else { "Never" }
            PasswordAgeDays = $passwordAge
            DaysUntilExpiration = $daysUntilExpiration
            PasswordStatus = $passwordStatus
            PasswordPolicies = $user.PasswordPolicies
        }
    }

    Write-Progress -Activity "Analyzing Password Policies" -Completed

    # Display summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Password Policy Summary" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $totalUsers = ($reportData | Where-Object { $_.UserType -eq 'Member' }).Count
    $neverExpires = ($reportData | Where-Object { $_.PasswordNeverExpires -and $_.UserType -eq 'Member' }).Count
    $expiringSoon = ($reportData | Where-Object { $_.PasswordStatus -eq 'Expiring Soon' -and $_.UserType -eq 'Member' }).Count
    $expired = ($reportData | Where-Object { $_.PasswordStatus -eq 'Expired' -and $_.UserType -eq 'Member' }).Count
    $weakPassword = ($reportData | Where-Object { $_.DisableStrongPassword -and $_.UserType -eq 'Member' }).Count
    $neverChanged = ($reportData | Where-Object { $_.PasswordStatus -eq 'Never Changed' -and $_.UserType -eq 'Member' }).Count

    Write-Host "Total Member Users:              $totalUsers" -ForegroundColor White
    Write-Host "Passwords Never Expire:          $neverExpires " -ForegroundColor Red -NoNewline
    Write-Host "($([math]::Round(($neverExpires / $totalUsers) * 100, 2))%)" -ForegroundColor Red
    Write-Host "Passwords Expiring Soon:         $expiringSoon" -ForegroundColor Yellow
    Write-Host "Expired Passwords:               $expired" -ForegroundColor Red
    Write-Host "Weak Password Policy:            $weakPassword" -ForegroundColor Red
    Write-Host "Never Changed Password:          $neverChanged" -ForegroundColor Yellow

    # Display users with passwords that never expire
    if ($neverExpires -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  Passwords Set to NEVER EXPIRE (First 15)" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Red
        
        $reportData | Where-Object { $_.PasswordNeverExpires -and $_.UserType -eq 'Member' -and $_.AccountEnabled } | 
            Select-Object UserPrincipalName, DisplayName, LastPasswordChange, PasswordAgeDays -First 15 | 
            Format-Table -AutoSize
    }

    # Display passwords expiring soon
    if ($expiringSoon -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Yellow
        Write-Host "  Passwords Expiring Soon (Next $($orgPasswordPolicy.PasswordNotificationWindowInDays) Days)" -ForegroundColor Yellow
        Write-Host "========================================`n" -ForegroundColor Yellow
        
        $reportData | Where-Object { $_.PasswordStatus -eq 'Expiring Soon' -and $_.AccountEnabled } | 
            Select-Object UserPrincipalName, DisplayName, DaysUntilExpiration | 
            Sort-Object { [int]$_.DaysUntilExpiration } | 
            Format-Table -AutoSize
    }

    # Display expired passwords
    if ($expired -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  EXPIRED Passwords" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Red
        
        $reportData | Where-Object { $_.PasswordStatus -eq 'Expired' -and $_.AccountEnabled } | 
            Select-Object UserPrincipalName, DisplayName, LastPasswordChange, PasswordAgeDays -First 15 | 
            Format-Table -AutoSize
    }

    # Display password age statistics
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Password Age Distribution" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $ageRanges = @{
        '0-30 days' = ($reportData | Where-Object { $_.PasswordAgeDays -is [int] -and $_.PasswordAgeDays -le 30 -and $_.UserType -eq 'Member' }).Count
        '31-60 days' = ($reportData | Where-Object { $_.PasswordAgeDays -is [int] -and $_.PasswordAgeDays -gt 30 -and $_.PasswordAgeDays -le 60 -and $_.UserType -eq 'Member' }).Count
        '61-90 days' = ($reportData | Where-Object { $_.PasswordAgeDays -is [int] -and $_.PasswordAgeDays -gt 60 -and $_.PasswordAgeDays -le 90 -and $_.UserType -eq 'Member' }).Count
        '91-180 days' = ($reportData | Where-Object { $_.PasswordAgeDays -is [int] -and $_.PasswordAgeDays -gt 90 -and $_.PasswordAgeDays -le 180 -and $_.UserType -eq 'Member' }).Count
        '181+ days' = ($reportData | Where-Object { $_.PasswordAgeDays -is [int] -and $_.PasswordAgeDays -gt 180 -and $_.UserType -eq 'Member' }).Count
    }

    $ageRanges.GetEnumerator() | Sort-Object Name | ForEach-Object {
        Write-Host "$($_.Key): $($_.Value) users" -ForegroundColor White
    }

    # Export to CSV
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPath = Join-Path $ExportPath "PasswordPolicy_Report_$timestamp.csv"
    
    $reportData | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Report saved to: $reportPath" -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Green

    # Security recommendations
    Write-Host "Security Recommendations:" -ForegroundColor Cyan
    if ($neverExpires -gt 0) {
        Write-Host "  [HIGH] $neverExpires users have passwords set to never expire - consider enforcing expiration" -ForegroundColor Red
    }
    if ($weakPassword -gt 0) {
        Write-Host "  [HIGH] $weakPassword users have weak password policies - enable strong password requirements" -ForegroundColor Red
    }
    if ($expired -gt 0) {
        Write-Host "  [MEDIUM] $expired users have expired passwords - require password change" -ForegroundColor Yellow
    }
    if ($neverChanged -gt 0) {
        Write-Host "  [MEDIUM] $neverChanged users have never changed their password - investigate" -ForegroundColor Yellow
    }
    Write-Host "  [INFO] Consider implementing Azure AD Password Protection for enhanced security" -ForegroundColor Cyan
    Write-Host "  [INFO] Review and update password policies regularly`n" -ForegroundColor Cyan

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
