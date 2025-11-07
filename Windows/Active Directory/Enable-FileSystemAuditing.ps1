<#
.SYNOPSIS
    Enable file system auditing on all directories under a specified path with permission verification
.DESCRIPTION
    Applies SACL (System Access Control List) audit rules to directories without modifying DACL permissions.
    Automatically enables required audit policies if not already configured.
    Includes verification to ensure no permissions are changed during the process.
.PARAMETER RootPath
    The root path where auditing should be applied (e.g., "D:\", "E:\Shares")
.PARAMETER AuditUser
    The user or group to audit. Default is "Everyone" for comprehensive auditing.
.PARAMETER AuditRights
    File system rights to audit. Default is "Modify". 
    Options: Read, Write, Modify, Delete, ReadAndExecute, ChangePermissions, TakeOwnership, FullControl
.PARAMETER AuditType
    What to audit. Default is "Success,Failure" (both).
    Options: Success, Failure, or Success,Failure
.PARAMETER SkipVerification
    Skip permission verification checks for faster execution (not recommended for first run)
.PARAMETER NoAutoEnablePolicies
    Do not automatically enable audit policies - fail if they're not configured
.EXAMPLE
    .\Enable-FileSystemAuditing.ps1 -RootPath "D:\"
    Apply auditing to all directories under D:\ with default settings
.EXAMPLE
    .\Enable-FileSystemAuditing.ps1 -RootPath "E:\Shares" -AuditUser "Domain Users" -AuditRights "Read,Write,Delete"
    Apply custom auditing to E:\Shares for Domain Users group
.EXAMPLE
    .\Enable-FileSystemAuditing.ps1 -RootPath "D:\" -SkipVerification
    Apply auditing without permission verification (faster, but less safe)
.NOTES
    Requires: Run as Administrator with SeSecurityPrivilege
    Version: 2.0
    Script should be run from: C:\Scripts
    Logs are saved to: C:\Scripts\Logs
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false, HelpMessage="Root path to apply auditing (e.g., D:\, E:\Shares)")]
    [ValidateScript({
        if (Test-Path $_) { $true }
        else { throw "Path '$_' does not exist" }
    })]
    [string]$RootPath,
    
    [Parameter(Mandatory=$false)]
    [string]$AuditUser = "Everyone",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet('Read', 'Write', 'Modify', 'Delete', 'ReadAndExecute', 'ChangePermissions', 'TakeOwnership', 'FullControl')]
    [string]$AuditRights = "Modify",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet('Success', 'Failure', 'Success,Failure')]
    [string]$AuditType = "Success,Failure",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipVerification,
    
    [Parameter(Mandatory=$false)]
    [switch]$NoAutoEnablePolicies
)

# ============================================
# CONFIGURATION
# ============================================

# Logging
$LogPath = "C:\Scripts\Logs"
$LogFile = Join-Path $LogPath "AuditConfig_$(Get-Date -Format 'MMddyyyy_HHmmss').log"
$PermissionChangeLog = Join-Path $LogPath "PermissionChanges_$(Get-Date -Format 'MMddyyyy_HHmmss').csv"

# Verification enabled by default, disabled with switch
$VerifyEachDirectory = -not $SkipVerification

# Auto-enable audit policies by default, disabled with switch
$AutoEnableAuditPolicies = -not $NoAutoEnablePolicies

# ============================================
# INTERNAL VARIABLES
# ============================================

# Convert string parameters to proper flags
$AuditRightsFlag = [System.Security.AccessControl.FileSystemRights]$AuditRights

if ($AuditType -eq "Success,Failure") {
    $AuditTypeFlag = [System.Security.AccessControl.AuditFlags]::Success -bor [System.Security.AccessControl.AuditFlags]::Failure
}
elseif ($AuditType -eq "Success") {
    $AuditTypeFlag = [System.Security.AccessControl.AuditFlags]::Success
}
else {
    $AuditTypeFlag = [System.Security.AccessControl.AuditFlags]::Failure
}

# Inheritance and Propagation flags
$InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
$PropagationFlags = [System.Security.AccessControl.PropagationFlags]::None

# Initialize counters
$Script:SuccessCount = 0
$Script:ErrorCount = 0
$Script:PermissionChangeCount = 0
$Script:SkippedCount = 0

# Create log directory
if (!(Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

# ============================================
# FUNCTIONS
# ============================================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'SUCCESS', 'WARNING', 'ERROR')]
        [string]$Level = 'INFO'
    )
    
    $Timestamp = Get-Date -Format 'MM/dd/yyyy HH:mm:ss'
    $LogMessage = "[$Timestamp] [$Level] $Message"
    
    # Color coding for console output
    $Color = switch ($Level) {
        'SUCCESS' { 'Green' }
        'WARNING' { 'Yellow' }
        'ERROR'   { 'Red' }
        default   { 'White' }
    }
    
    Write-Host $LogMessage -ForegroundColor $Color
    Add-Content -Path $LogFile -Value $LogMessage
}

function Enable-AuditPolicies {
    Write-Log "Audit policies are not properly configured" -Level WARNING
    
    if ($AutoEnableAuditPolicies) {
        Write-Log "Attempting to enable required audit policies..." -Level INFO
        
        try {
            # Enable File System auditing
            $Result1 = auditpol /set /subcategory:"File System" /success:enable /failure:enable 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Enabled File System auditing" -Level SUCCESS
            }
            else {
                Write-Log "Failed to enable File System auditing: $Result1" -Level ERROR
                return $false
            }
            
            # Enable File Share auditing
            $Result2 = auditpol /set /subcategory:"File Share" /success:enable /failure:enable 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Enabled File Share auditing" -Level SUCCESS
            }
            else {
                Write-Log "Failed to enable File Share auditing: $Result2" -Level ERROR
                return $false
            }
            
            Write-Log "Audit policies successfully enabled" -Level SUCCESS
            return $true
        }
        catch {
            Write-Log "Failed to enable audit policies: $($_.Exception.Message)" -Level ERROR
            return $false
        }
    }
    else {
        Write-Log "Auto-enable is disabled. Please enable audit policies manually:" -Level WARNING
        Write-Log "  auditpol /set /subcategory:`"File System`" /success:enable /failure:enable" -Level INFO
        Write-Log "  auditpol /set /subcategory:`"File Share`" /success:enable /failure:enable" -Level INFO
        return $false
    }
}

function Get-PermissionSnapshot {
    param([string]$Path)
    
    try {
        $Acl = Get-Acl -Path $Path -ErrorAction Stop
        
        # Create snapshot of current permissions (DACL only)
        $Snapshot = $Acl.Access | Select-Object `
            IdentityReference,
            FileSystemRights,
            AccessControlType,
            IsInherited,
            InheritanceFlags,
            PropagationFlags | 
            ConvertTo-Json -Compress
        
        return $Snapshot
    }
    catch {
        Write-Log "Failed to get permission snapshot for $Path - $($_.Exception.Message)" -Level ERROR
        return $null
    }
}

function Compare-Permissions {
    param(
        [string]$Path,
        [string]$BeforeSnapshot,
        [string]$AfterSnapshot
    )
    
    if ($BeforeSnapshot -eq $AfterSnapshot) {
        return $true
    }
    else {
        Write-Log "PERMISSION CHANGE DETECTED on $Path" -Level ERROR
        
        # Log to CSV for detailed analysis
        [PSCustomObject]@{
            Timestamp = Get-Date -Format 'MM/dd/yyyy HH:mm:ss'
            Path = $Path
            BeforePermissions = $BeforeSnapshot
            AfterPermissions = $AfterSnapshot
        } | Export-Csv -Path $PermissionChangeLog -Append -NoTypeInformation
        
        $Script:PermissionChangeCount++
        return $false
    }
}

function Set-DirectoryAuditing {
    param([string]$DirectoryPath)
    
    try {
        # Take permission snapshot BEFORE
        if ($VerifyEachDirectory) {
            $PermissionsBefore = Get-PermissionSnapshot -Path $DirectoryPath
            if ($null -eq $PermissionsBefore) {
                $Script:SkippedCount++
                return $false
            }
        }
        
        # Get current ACL
        $Acl = Get-Acl -Path $DirectoryPath -ErrorAction Stop
        
        # Check if audit rule already exists
        $ExistingRule = $Acl.Audit | Where-Object {
            $_.IdentityReference -eq $AuditUser -and
            $_.FileSystemRights -eq $AuditRightsFlag -and
            $_.AuditFlags -eq $AuditTypeFlag
        }
        
        if ($ExistingRule) {
            Write-Log "Audit rule already exists on $DirectoryPath" -Level INFO
            $Script:SkippedCount++
            return $true
        }
        
        # Create and add audit rule (SACL)
        $AuditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            $AuditUser,
            $AuditRightsFlag,
            $InheritanceFlags,
            $PropagationFlags,
            $AuditTypeFlag
        )
        
        $Acl.AddAuditRule($AuditRule)
        Set-Acl -Path $DirectoryPath -AclObject $Acl -ErrorAction Stop
        
        # Verify permissions AFTER
        if ($VerifyEachDirectory) {
            $PermissionsAfter = Get-PermissionSnapshot -Path $DirectoryPath
            
            if (-not (Compare-Permissions -Path $DirectoryPath -BeforeSnapshot $PermissionsBefore -AfterSnapshot $PermissionsAfter)) {
                Write-Log "Attempting to revert changes on $DirectoryPath" -Level WARNING
                return $false
            }
        }
        
        Write-Log "Successfully applied audit rule to $DirectoryPath" -Level SUCCESS
        $Script:SuccessCount++
        return $true
    }
    catch {
        Write-Log "Failed to apply audit rule to $DirectoryPath - $($_.Exception.Message)" -Level ERROR
        $Script:ErrorCount++
        return $false
    }
}

function Test-Prerequisites {
    Write-Log "Checking prerequisites..." -Level INFO
    
    # Check if running as Administrator
    $CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log "Script must be run as Administrator" -Level ERROR
        return $false
    }
    
    # Check if root path exists
    if (-not (Test-Path $RootPath)) {
        Write-Log "Root path $RootPath does not exist" -Level ERROR
        return $false
    }
    
    # Check if Advanced Audit Policy is configured
    Write-Log "Checking audit policy configuration..." -Level INFO
    $AuditPol = auditpol /get /category:"Object Access" /r | ConvertFrom-Csv
    
    $FileSystemPolicy = $AuditPol | Where-Object { $_.Subcategory -eq "File System" }
    $FileSharePolicy = $AuditPol | Where-Object { $_.Subcategory -eq "File Share" }
    
    $FileSystemConfigured = $FileSystemPolicy.'Inclusion Setting' -match 'Success|Failure'
    $FileShareConfigured = $FileSharePolicy.'Inclusion Setting' -match 'Success|Failure'
    
    if (-not $FileSystemConfigured -or -not $FileShareConfigured) {
        Write-Log "Current audit policy status:" -Level INFO
        Write-Log "  File System Auditing: $($FileSystemPolicy.'Inclusion Setting')" -Level INFO
        Write-Log "  File Share Auditing: $($FileSharePolicy.'Inclusion Setting')" -Level INFO
        
        # Attempt to enable policies
        if (-not (Enable-AuditPolicies)) {
            Write-Log "Failed to enable audit policies. Cannot proceed." -Level ERROR
            Write-Log "SACLs without audit policies enabled will not generate events." -Level ERROR
            return $false
        }
        
        # Verify they're now enabled
        Start-Sleep -Seconds 2
        $AuditPol = auditpol /get /category:"Object Access" /r | ConvertFrom-Csv
        $FileSystemPolicy = $AuditPol | Where-Object { $_.Subcategory -eq "File System" }
        $FileSharePolicy = $AuditPol | Where-Object { $_.Subcategory -eq "File Share" }
        
        Write-Log "Verified audit policy status:" -Level INFO
        Write-Log "  File System Auditing: $($FileSystemPolicy.'Inclusion Setting')" -Level SUCCESS
        Write-Log "  File Share Auditing: $($FileSharePolicy.'Inclusion Setting')" -Level SUCCESS
    }
    else {
        Write-Log "Audit policies are properly configured:" -Level SUCCESS
        Write-Log "  File System Auditing: $($FileSystemPolicy.'Inclusion Setting')" -Level SUCCESS
        Write-Log "  File Share Auditing: $($FileSharePolicy.'Inclusion Setting')" -Level SUCCESS
    }
    
    return $true
}

function Get-RootPathInteractive {
    Write-Host "`n============================================" -ForegroundColor Cyan
    Write-Host "File System Auditing Configuration" -ForegroundColor Cyan
    Write-Host "============================================`n" -ForegroundColor Cyan
    
    Write-Host "Enter the root path where auditing should be applied" -ForegroundColor Yellow
    Write-Host "Examples: D:\, E:\Shares, C:\Data`n" -ForegroundColor Gray
    
    do {
        $Path = Read-Host "Root Path"
        
        if ([string]::IsNullOrWhiteSpace($Path)) {
            Write-Host "Path cannot be empty. Please try again.`n" -ForegroundColor Red
            continue
        }
        
        if (-not (Test-Path $Path)) {
            Write-Host "Path '$Path' does not exist. Please try again.`n" -ForegroundColor Red
            continue
        }
        
        return $Path
        
    } while ($true)
}

# ============================================
# MAIN EXECUTION
# ============================================

# If RootPath not provided, prompt for it
if ([string]::IsNullOrWhiteSpace($RootPath)) {
    $RootPath = Get-RootPathInteractive
}

Write-Log "========================================" -Level INFO
Write-Log "File System Auditing Configuration Script" -Level INFO
Write-Log "========================================" -Level INFO
Write-Log "Root Path: $RootPath" -Level INFO
Write-Log "Audit User: $AuditUser" -Level INFO
Write-Log "Audit Rights: $AuditRights" -Level INFO
Write-Log "Audit Type: $AuditType" -Level INFO
Write-Log "Verification Enabled: $VerifyEachDirectory" -Level INFO
Write-Log "Auto-Enable Policies: $AutoEnableAuditPolicies" -Level INFO
Write-Log "Log File: $LogFile" -Level INFO
Write-Log "========================================" -Level INFO

# Run prerequisite checks (will auto-enable policies if needed)
if (-not (Test-Prerequisites)) {
    Write-Log "Prerequisite checks failed. Exiting." -Level ERROR
    Write-Host "`nScript cannot proceed. Please review the errors above." -ForegroundColor Red
    exit 1
}

# Confirm before proceeding
Write-Host "`nThis script will apply audit rules to all directories under $RootPath" -ForegroundColor Yellow
Write-Host "Permissions will NOT be modified - only auditing (SACL) will be configured" -ForegroundColor Yellow
$Confirm = Read-Host "`nDo you want to proceed? (Y/N)"

if ($Confirm -ne 'Y') {
    Write-Log "Operation cancelled by user" -Level WARNING
    exit 0
}

Write-Log "Starting audit configuration process..." -Level INFO
$StartTime = Get-Date

# Get all directories
Write-Log "Enumerating directories under $RootPath..." -Level INFO
try {
    $Directories = @(Get-ChildItem -Path $RootPath -Directory -Recurse -ErrorAction SilentlyContinue)
    Write-Log "Found $($Directories.Count) subdirectories to process (plus root)" -Level INFO
}
catch {
    Write-Log "Failed to enumerate directories - $($_.Exception.Message)" -Level ERROR
    exit 1
}

# Process root directory first
Write-Log "Processing root directory: $RootPath" -Level INFO
$null = Set-DirectoryAuditing -DirectoryPath $RootPath

# Process subdirectories with progress
$ProcessedCount = 0
$TotalCount = $Directories.Count

foreach ($Dir in $Directories) {
    $ProcessedCount++
    
    # Update progress every 10 directories
    if ($ProcessedCount % 10 -eq 0) {
        $PercentComplete = [math]::Round(($ProcessedCount / $TotalCount) * 100, 2)
        Write-Progress -Activity "Applying Audit Rules" `
            -Status "Processing $ProcessedCount of $TotalCount directories ($PercentComplete%)" `
            -PercentComplete $PercentComplete
    }
    
    $null = Set-DirectoryAuditing -DirectoryPath $Dir.FullName
}

Write-Progress -Activity "Applying Audit Rules" -Completed

# Calculate execution time
$EndTime = Get-Date
$Duration = $EndTime - $StartTime

# ============================================
# SUMMARY REPORT
# ============================================

Write-Log "========================================" -Level INFO
Write-Log "AUDIT CONFIGURATION SUMMARY" -Level INFO
Write-Log "========================================" -Level INFO
Write-Log "Total Directories Processed: $($TotalCount + 1)" -Level INFO
Write-Log "Successfully Configured: $Script:SuccessCount" -Level SUCCESS
Write-Log "Skipped (Already Configured): $Script:SkippedCount" -Level INFO
Write-Log "Errors Encountered: $Script:ErrorCount" -Level $(if ($Script:ErrorCount -gt 0) { 'WARNING' } else { 'INFO' })
Write-Log "Permission Changes Detected: $Script:PermissionChangeCount" -Level $(if ($Script:PermissionChangeCount -gt 0) { 'ERROR' } else { 'SUCCESS' })
Write-Log "Execution Time: $($Duration.ToString('hh\:mm\:ss'))" -Level INFO
Write-Log "========================================" -Level INFO

if ($Script:PermissionChangeCount -gt 0) {
    Write-Log "CRITICAL: Permission changes were detected!" -Level ERROR
    Write-Log "Review the permission change log: $PermissionChangeLog" -Level ERROR
}
else {
    Write-Log "No permission changes detected - all DACLs remained unchanged" -Level SUCCESS
}

Write-Log "Full log available at: $LogFile" -Level INFO

# Validation instructions
Write-Log "========================================" -Level INFO
Write-Log "NEXT STEPS - VALIDATION" -Level INFO
Write-Log "========================================" -Level INFO
Write-Log "1. Test audit functionality:" -Level INFO
Write-Log "   - Access a file on $RootPath and check Event Viewer > Security" -Level INFO
Write-Log "   - Look for Event IDs: 4663 (File access), 5140/5145 (Share access)" -Level INFO
Write-Log "" -Level INFO
Write-Log "2. Verify a specific folder:" -Level INFO
Write-Log "   `$acl = Get-Acl '<path>' -Audit" -Level INFO
Write-Log "   `$acl.Audit | Format-Table" -Level INFO
Write-Log "" -Level INFO
Write-Log "3. Check permissions haven't changed:" -Level INFO
Write-Log "   `$acl = Get-Acl '<path>'" -Level INFO
Write-Log "   `$acl.Access | Format-Table IdentityReference, FileSystemRights, AccessControlType" -Level INFO
Write-Log "========================================" -Level INFO

# Final confirmation
if ($Script:ErrorCount -eq 0 -and $Script:PermissionChangeCount -eq 0) {
    Write-Host "`nAudit configuration completed successfully!" -ForegroundColor Green
    exit 0
}
elseif ($Script:PermissionChangeCount -gt 0) {
    Write-Host "`nWARNING: Audit configuration completed but permission changes were detected!" -ForegroundColor Red
    Write-Host "Review the logs immediately: $PermissionChangeLog" -ForegroundColor Red
    exit 2
}
else {
    Write-Host "`nAudit configuration completed with some errors. Review the log file." -ForegroundColor Yellow
    exit 1
}
