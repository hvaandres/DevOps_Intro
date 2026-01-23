<#
.SYNOPSIS
    Reviews and reports on all guest users in Azure AD.

.DESCRIPTION
    This script connects to Microsoft Graph and retrieves all guest users.
    It helps maintain security by identifying external access and providing
    detailed information about each guest user.

.PARAMETER ExportPath
    Optional. The path where the CSV report will be saved. Defaults to current directory.

.EXAMPLE
    .\Get-GuestUserReport.ps1
    Runs the script and saves the report in the current directory.

.EXAMPLE
    .\Get-GuestUserReport.ps1 -ExportPath "C:\Reports"
    Runs the script and saves the report to C:\Reports folder.

.NOTES
    Author: Azure Security Audit Team
    Requirements:
    - Microsoft.Graph PowerShell module
    - Permissions: User.Read.All, Directory.Read.All
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ExportPath = "."
)

# Function to check and install required modules
function Test-RequiredModules {
    $requiredModules = @('Microsoft.Graph.Users')
    
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
    Write-Host "  Guest User Access Review Script" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    # Check for required modules
    Write-Host "Checking required modules..." -ForegroundColor Yellow
    if (-not (Test-RequiredModules)) {
        throw "Required modules are not available. Please install them manually."
    }

    # Connect to Microsoft Graph
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
    try {
        Connect-MgGraph -Scopes "User.Read.All", "Directory.Read.All" -ErrorAction Stop
        Write-Host "Successfully connected to Microsoft Graph.`n" -ForegroundColor Green
    }
    catch {
        throw "Failed to connect to Microsoft Graph. Error: $_"
    }

    # Get all guest users
    Write-Host "Fetching guest users from Azure AD..." -ForegroundColor Yellow
    $guestUsers = Get-MgUser -Filter "userType eq 'Guest'" -All `
        -Property Id, UserPrincipalName, DisplayName, CreatedDateTime, AccountEnabled, ExternalUserState, ExternalUserStateChangeDateTime, Mail, UserType

    Write-Host "Found $($guestUsers.Count) guest users.`n" -ForegroundColor Green

    # Process guest user data
    $reportData = @()
    $counter = 0

    foreach ($guest in $guestUsers) {
        $counter++
        Write-Progress -Activity "Processing Guest Users" -Status "Processing $($guest.DisplayName)" -PercentComplete (($counter / $guestUsers.Count) * 100)
        
        # Calculate days since creation
        $daysSinceCreated = if ($guest.CreatedDateTime) {
            (New-TimeSpan -Start $guest.CreatedDateTime -End (Get-Date)).Days
        } else {
            "N/A"
        }
        
        # Extract domain from email/UPN
        $guestDomain = if ($guest.Mail) {
            $guest.Mail.Split('@')[-1]
        } elseif ($guest.UserPrincipalName -match '@') {
            ($guest.UserPrincipalName.Split('@')[0]).Split('#')[-1]
        } else {
            "Unknown"
        }
        
        $reportData += [PSCustomObject]@{
            DisplayName = $guest.DisplayName
            UserPrincipalName = $guest.UserPrincipalName
            Email = $guest.Mail
            GuestDomain = $guestDomain
            AccountEnabled = $guest.AccountEnabled
            CreatedDate = if ($guest.CreatedDateTime) { $guest.CreatedDateTime.ToString("yyyy-MM-dd") } else { "N/A" }
            DaysSinceCreated = $daysSinceCreated
            ExternalUserState = $guest.ExternalUserState
            StateChangeDate = if ($guest.ExternalUserStateChangeDateTime) { $guest.ExternalUserStateChangeDateTime.ToString("yyyy-MM-dd") } else { "N/A" }
        }
    }

    Write-Progress -Activity "Processing Guest Users" -Completed

    # Display summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Guest User Summary" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $totalGuests = $reportData.Count
    $enabledGuests = ($reportData | Where-Object { $_.AccountEnabled }).Count
    $disabledGuests = ($reportData | Where-Object { -not $_.AccountEnabled }).Count
    $acceptedInvites = ($reportData | Where-Object { $_.ExternalUserState -eq 'Accepted' }).Count
    $pendingInvites = ($reportData | Where-Object { $_.ExternalUserState -eq 'PendingAcceptance' }).Count

    Write-Host "Total Guest Users:           $totalGuests" -ForegroundColor White
    Write-Host "Enabled Guest Accounts:      $enabledGuests" -ForegroundColor Green
    Write-Host "Disabled Guest Accounts:     $disabledGuests" -ForegroundColor Yellow
    Write-Host "Accepted Invitations:        $acceptedInvites" -ForegroundColor Green
    Write-Host "Pending Invitations:         $pendingInvites" -ForegroundColor Yellow

    # Domain statistics
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Guest Users by Domain" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $domainStats = $reportData | Group-Object -Property GuestDomain | 
        Select-Object @{N='Domain';E={$_.Name}}, Count | 
        Sort-Object -Property Count -Descending

    $domainStats | Format-Table -AutoSize

    # Display recent guest additions
    Write-Host "`n========================================" -ForegroundColor Yellow
    Write-Host "  Recently Added Guests (Last 30 Days)" -ForegroundColor Yellow
    Write-Host "========================================`n" -ForegroundColor Yellow
    
    $recentGuests = $reportData | Where-Object { 
        $_.DaysSinceCreated -ne "N/A" -and [int]$_.DaysSinceCreated -le 30 
    } | Sort-Object -Property DaysSinceCreated | Select-Object -First 10
    
    if ($recentGuests) {
        $recentGuests | Select-Object DisplayName, Email, GuestDomain, CreatedDate, AccountEnabled | 
            Format-Table -AutoSize
    } else {
        Write-Host "No guest users added in the last 30 days.`n" -ForegroundColor Gray
    }

    # Display pending invitations
    if ($pendingInvites -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Yellow
        Write-Host "  Pending Guest Invitations" -ForegroundColor Yellow
        Write-Host "========================================`n" -ForegroundColor Yellow
        
        $reportData | Where-Object { $_.ExternalUserState -eq 'PendingAcceptance' } | 
            Select-Object DisplayName, Email, CreatedDate, DaysSinceCreated | 
            Format-Table -AutoSize
    }

    # Export to CSV
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPath = Join-Path $ExportPath "GuestUsers_Report_$timestamp.csv"
    
    $reportData | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Report saved to: $reportPath" -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Green

    # Recommendations
    Write-Host "Recommendations:" -ForegroundColor Cyan
    Write-Host "1. Review guest users from unknown or untrusted domains" -ForegroundColor White
    Write-Host "2. Disable or remove guest accounts that are no longer needed" -ForegroundColor White
    Write-Host "3. Follow up on pending invitations that are more than 7 days old" -ForegroundColor White
    Write-Host "4. Implement guest access policies and expiration dates`n" -ForegroundColor White

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
