<#
.SYNOPSIS
    Analyzes Multi-Factor Authentication (MFA) status across all Azure AD users.

.DESCRIPTION
    This script connects to Microsoft Graph and retrieves MFA registration status for all users.
    It identifies users without MFA enabled for security risk assessment and generates a detailed CSV report.

.PARAMETER ExportPath
    Optional. The path where the CSV report will be saved. Defaults to current directory.

.EXAMPLE
    .\Get-MFAStatus.ps1
    Runs the script and saves the report in the current directory.

.EXAMPLE
    .\Get-MFAStatus.ps1 -ExportPath "C:\Reports"
    Runs the script and saves the report to C:\Reports folder.

.NOTES
    Author: Azure Security Audit Team
    Requirements:
    - Microsoft.Graph PowerShell module
    - Permissions: User.Read.All, UserAuthenticationMethod.Read.All, AuditLog.Read.All
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ExportPath = "."
)

# Function to check and install required modules
function Test-RequiredModules {
    $requiredModules = @('Microsoft.Graph.Users', 'Microsoft.Graph.Identity.SignIns')
    
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
    Write-Host "  MFA Status Analysis Script" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    # Check for required modules
    Write-Host "Checking required modules..." -ForegroundColor Yellow
    if (-not (Test-RequiredModules)) {
        throw "Required modules are not available. Please install them manually."
    }

    # Connect to Microsoft Graph
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
    try {
        Connect-MgGraph -Scopes "User.Read.All", "UserAuthenticationMethod.Read.All", "AuditLog.Read.All" -ErrorAction Stop
        Write-Host "Successfully connected to Microsoft Graph.`n" -ForegroundColor Green
    }
    catch {
        throw "Failed to connect to Microsoft Graph. Error: $_"
    }

    # Get all users
    Write-Host "Fetching all users from Azure AD..." -ForegroundColor Yellow
    $users = Get-MgUser -All -Property Id, UserPrincipalName, DisplayName, AccountEnabled

    Write-Host "Found $($users.Count) users. Analyzing MFA status...`n" -ForegroundColor Green

    # Analyze MFA status for each user
    $mfaData = @()
    $counter = 0

    foreach ($user in $users) {
        $counter++
        Write-Progress -Activity "Analyzing MFA Status" -Status "Processing $($user.UserPrincipalName)" -PercentComplete (($counter / $users.Count) * 100)
        
        try {
            $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue
            
            $hasMFA = $false
            $mfaMethods = @()
            
            foreach ($method in $authMethods) {
                $methodType = $method.AdditionalProperties.'@odata.type'
                
                # Check for MFA methods
                if ($methodType -match 'phoneAuthenticationMethod' -or
                    $methodType -match 'microsoftAuthenticatorAuthenticationMethod' -or
                    $methodType -match 'fido2AuthenticationMethod' -or
                    $methodType -match 'softwareOathAuthenticationMethod' -or
                    $methodType -match 'emailAuthenticationMethod') {
                    $hasMFA = $true
                    $mfaMethods += $methodType.Split('.')[-1] -replace 'AuthenticationMethod', ''
                }
            }
            
            $mfaData += [PSCustomObject]@{
                UserPrincipalName = $user.UserPrincipalName
                DisplayName = $user.DisplayName
                MFAEnabled = $hasMFA
                MFAMethods = ($mfaMethods -join ', ')
                AccountEnabled = $user.AccountEnabled
                MFAMethodCount = $mfaMethods.Count
            }
        }
        catch {
            Write-Host "  Warning: Error processing user $($user.UserPrincipalName): $_" -ForegroundColor Yellow
        }
    }

    Write-Progress -Activity "Analyzing MFA Status" -Completed

    # Display summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  MFA Status Summary" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $totalUsers = $mfaData.Count
    $mfaEnabled = ($mfaData | Where-Object { $_.MFAEnabled }).Count
    $mfaDisabled = ($mfaData | Where-Object { -not $_.MFAEnabled }).Count
    $enabledNoMFA = ($mfaData | Where-Object { $_.AccountEnabled -and -not $_.MFAEnabled }).Count

    Write-Host "Total Users:                 $totalUsers" -ForegroundColor White
    Write-Host "Users with MFA Enabled:      $mfaEnabled " -ForegroundColor Green -NoNewline
    Write-Host "($([math]::Round(($mfaEnabled / $totalUsers) * 100, 2))%)" -ForegroundColor Green
    Write-Host "Users without MFA:           $mfaDisabled " -ForegroundColor Red -NoNewline
    Write-Host "($([math]::Round(($mfaDisabled / $totalUsers) * 100, 2))%)" -ForegroundColor Red
    Write-Host "Enabled Accounts without MFA: $enabledNoMFA " -ForegroundColor Yellow -NoNewline
    Write-Host "(SECURITY RISK!)" -ForegroundColor Red

    # Display top users without MFA
    Write-Host "`n========================================" -ForegroundColor Yellow
    Write-Host "  Users WITHOUT MFA (First 10)" -ForegroundColor Yellow
    Write-Host "========================================`n" -ForegroundColor Yellow
    
    $mfaData | Where-Object { -not $_.MFAEnabled -and $_.AccountEnabled } | 
        Select-Object UserPrincipalName, DisplayName, AccountEnabled -First 10 | 
        Format-Table -AutoSize

    # Export to CSV
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPath = Join-Path $ExportPath "MFAStatus_Report_$timestamp.csv"
    
    $mfaData | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Report saved to: $reportPath" -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Green

    # Display detailed statistics
    Write-Host "Detailed MFA Method Statistics:" -ForegroundColor Cyan
    $methodStats = $mfaData | Where-Object { $_.MFAEnabled } | Group-Object -Property MFAMethods | 
        Select-Object @{N='Method';E={$_.Name}}, Count | 
        Sort-Object -Property Count -Descending
    
    $methodStats | Format-Table -AutoSize

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
