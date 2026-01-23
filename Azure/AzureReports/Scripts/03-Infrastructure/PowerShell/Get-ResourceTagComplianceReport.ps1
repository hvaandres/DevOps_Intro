<#
.SYNOPSIS
    Audits Azure resources for required tag compliance.

.DESCRIPTION
    This script checks all Azure resources against required tag policies
    and identifies resources missing mandatory tags.

.PARAMETER ExportPath
    Optional. The path where the CSV report will be saved. Defaults to current directory.

.PARAMETER RequiredTags
    Optional. Array of required tag names. Defaults to common tags: Environment, Owner, CostCenter, Project.

.EXAMPLE
    .\Get-ResourceTagComplianceReport.ps1

.EXAMPLE
    .\Get-ResourceTagComplianceReport.ps1 -RequiredTags "Environment","Owner","Department"

.NOTES
    Author: Azure Security Audit Team
    Requirements:
    - Az.Resources PowerShell module
    - Permissions: Reader
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ExportPath = ".",
    
    [Parameter(Mandatory=$false)]
    [string[]]$RequiredTags = @("Environment", "Owner", "CostCenter", "Project")
)

try {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Resource Tag Compliance Audit" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    Write-Host "Required Tags: $($RequiredTags -join ', ')`n" -ForegroundColor Yellow

    $context = Get-AzContext
    if (-not $context) { Connect-AzAccount }

    Write-Host "Fetching all resources..." -ForegroundColor Yellow
    $resources = Get-AzResource

    Write-Host "Found $($resources.Count) resources. Analyzing tags...`n" -ForegroundColor Green

    $reportData = @()
    $compliantCount = 0
    $nonCompliantCount = 0
    $counter = 0

    foreach ($resource in $resources) {
        $counter++
        Write-Progress -Activity "Analyzing Resource Tags" -Status $resource.Name -PercentComplete (($counter / $resources.Count) * 100)
        
        $missingTags = @()
        $presentTags = @()
        
        foreach ($requiredTag in $RequiredTags) {
            if ($resource.Tags -and $resource.Tags.ContainsKey($requiredTag)) {
                $presentTags += "$requiredTag=$($resource.Tags[$requiredTag])"
            }
            else {
                $missingTags += $requiredTag
            }
        }
        
        $compliancePercent = if ($RequiredTags.Count -gt 0) {
            [math]::Round((($RequiredTags.Count - $missingTags.Count) / $RequiredTags.Count) * 100, 2)
        } else { 100 }
        
        $isCompliant = ($missingTags.Count -eq 0)
        if ($isCompliant) { $compliantCount++ } else { $nonCompliantCount++ }
        
        $reportData += [PSCustomObject]@{
            ResourceName = $resource.Name
            ResourceType = $resource.ResourceType
            ResourceGroup = $resource.ResourceGroupName
            Location = $resource.Location
            MissingTags = ($missingTags -join ', ')
            PresentTags = ($presentTags -join ', ')
            TotalTags = if ($resource.Tags) { $resource.Tags.Count } else { 0 }
            CompliancePercent = $compliancePercent
            IsCompliant = $isCompliant
            Status = if ($isCompliant) { "Compliant" } 
                     elseif ($missingTags.Count -eq $RequiredTags.Count) { "No Tags" }
                     else { "Partial" }
        }
    }

    Write-Progress -Activity "Analyzing Resource Tags" -Completed

    # Summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Compliance Summary" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $overallCompliance = [math]::Round(($compliantCount / $resources.Count) * 100, 2)

    Write-Host "Total Resources: $($resources.Count)" -ForegroundColor White
    Write-Host "Compliant: $compliantCount " -ForegroundColor Green -NoNewline
    Write-Host "($overallCompliance%)" -ForegroundColor Green
    Write-Host "Non-Compliant: $nonCompliantCount " -ForegroundColor Red -NoNewline
    Write-Host "($([math]::Round(100 - $overallCompliance, 2))%)" -ForegroundColor Red

    # Compliance by resource type
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Compliance by Resource Type" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    $reportData | Group-Object ResourceType | 
        Select-Object @{N='ResourceType';E={$_.Name}}, 
                      Count,
                      @{N='Compliant';E={($_.Group | Where-Object { $_.IsCompliant }).Count}},
                      @{N='ComplianceRate';E={[math]::Round((($_.Group | Where-Object { $_.IsCompliant }).Count / $_.Count) * 100, 2)}} |
        Sort-Object ComplianceRate |
        Format-Table -AutoSize

    # Non-compliant resources
    $noTags = ($reportData | Where-Object { $_.Status -eq "No Tags" }).Count
    if ($noTags -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Red
        Write-Host "  Resources with NO Tags (First 20)" -ForegroundColor Red
        Write-Host "========================================`n" -ForegroundColor Red
        
        $reportData | Where-Object { $_.Status -eq "No Tags" } |
            Select-Object ResourceName, ResourceType, ResourceGroup -First 20 |
            Format-Table -AutoSize
    }

    # Missing tag statistics
    Write-Host "`n========================================" -ForegroundColor Yellow
    Write-Host "  Most Commonly Missing Tags" -ForegroundColor Yellow
    Write-Host "========================================`n" -ForegroundColor Yellow

    $allMissingTags = $reportData | Where-Object { $_.MissingTags } | 
        ForEach-Object { $_.MissingTags.Split(',').Trim() } |
        Group-Object |
        Select-Object @{N='Tag';E={$_.Name}}, Count |
        Sort-Object Count -Descending

    $allMissingTags | Format-Table -AutoSize

    # Export
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportPath = Join-Path $ExportPath "ResourceTagCompliance_Report_$timestamp.csv"
    $reportData | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

    Write-Host "`nReport saved to: $reportPath" -ForegroundColor Green

    Write-Host "`nRecommendations:" -ForegroundColor Cyan
    Write-Host "  1. Implement Azure Policy to enforce required tags" -ForegroundColor White
    Write-Host "  2. Use Azure Blueprints for standardized deployments" -ForegroundColor White
    Write-Host "  3. Tag resources at creation time" -ForegroundColor White
    Write-Host "  4. Regularly audit and update tags" -ForegroundColor White
    Write-Host "  5. Use tag inheritance from Resource Groups`n" -ForegroundColor White

    Write-Host "To remediate missing tags, use:" -ForegroundColor Cyan
    Write-Host "  Set-AzResource -ResourceId <ResourceId> -Tag @{TagName='TagValue'} -Force`n" -ForegroundColor Gray
}
catch {
    Write-Host "`nError: $_" -ForegroundColor Red
    exit 1
}
