<#
=============================================================================================
Name:        O365AdminReport.ps1
Description: Exports Microsoft 365 admin role assignments to CSV using Microsoft Graph.
             Supports all admins, role-based, or per-user reporting modes.
Version:     2.0
             All Graph data retrieval uses Invoke-MgGraphRequest (direct REST) to avoid
             AggregateException bugs present in Get-MgBeta* cmdlets for bulk enumeration.
=============================================================================================

USAGE:
  .\O365AdminReport.ps1                                       # All admins (default)
  .\O365AdminReport.ps1 -RoleBasedAdminReport                 # All roles with their members
  .\O365AdminReport.ps1 -ExcludeGroups                        # Exclude group objects from results
  .\O365AdminReport.ps1 -AdminName "user@domain.com"          # Roles for specific user(s), comma-separated
  .\O365AdminReport.ps1 -RoleName "Global Administrator"      # Members of specific role(s), comma-separated
  .\O365AdminReport.ps1 -TenantId "" -ClientId "" -CertificateThumbprint ""   # Certificate-based / unattended

=============================================================================================
#>

param (
    [switch] $RoleBasedAdminReport,
    [switch] $ExcludeGroups,
    [string] $AdminName = "",
    [string] $RoleName  = "",
    [string] $TenantId,
    [string] $ClientId,
    [string] $CertificateThumbprint
)

# ── Logging ────────────────────────────────────────────────────────────────────
$LogDir  = "C:\Scripts\Logs"
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$LogFile = Join-Path $LogDir "O365AdminReport_$(Get-Date -Format 'MM-dd-yyyy').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "MM/dd/yyyy HH:mm:ss"
    Add-Content -Path $LogFile -Value "$Timestamp [$Level] $Message"
    switch ($Level) {
        "ERROR" { Write-Host $Message -ForegroundColor Red }
        "WARN"  { Write-Host $Message -ForegroundColor Yellow }
        default { Write-Host $Message }
    }
}

# ── Module check ───────────────────────────────────────────────────────────────
Write-Log "Script started."

if (-not (Get-Module Microsoft.Graph.Beta -ListAvailable)) {
    Write-Log "Microsoft Graph Beta module not found." "WARN"
    $Confirm = Read-Host "Install Microsoft Graph Beta module now? [Y] Yes [N] No"
    if ($Confirm -match "[yY]") {
        Write-Log "Installing Microsoft Graph Beta module..."
        Install-Module Microsoft.Graph.Beta -Scope CurrentUser -AllowClobber -Force
        Write-Log "Microsoft Graph Beta module installed."
    }
    else {
        Write-Log "Exiting - Microsoft Graph Beta module is required." "ERROR"
        Exit
    }
}

# ── Connect to Graph ───────────────────────────────────────────────────────────
if ($TenantId -and $ClientId -and $CertificateThumbprint) {
    Connect-MgGraph -TenantId $TenantId -AppId $ClientId `
        -CertificateThumbprint $CertificateThumbprint `
        -ErrorAction SilentlyContinue -ErrorVariable ConnectError | Out-Null
}
else {
    Connect-MgGraph -Scopes "Directory.Read.All","User.Read.All" `
        -ErrorAction SilentlyContinue -ErrorVariable ConnectError | Out-Null
}

if ($ConnectError) {
    Write-Log "Failed to connect to Microsoft Graph: $ConnectError" "ERROR"
    Exit
}
Write-Log "Connected to Microsoft Graph."

# ── Output path ────────────────────────────────────────────────────────────────
$OutputCsv = "C:\Scripts\AdminReport_$(Get-Date -Format 'MM-dd-yyyy_HH-mm').csv"

# ══════════════════════════════════════════════════════════════════════════════
# Graph REST helpers — all using Invoke-MgGraphRequest to avoid Beta SDK bugs
# ══════════════════════════════════════════════════════════════════════════════

# Page through any Graph endpoint that returns a value array + @odata.nextLink
function Invoke-GraphGetAll {
    param([string]$Uri)
    $Results = [System.Collections.Generic.List[object]]::new()
    do {
        try {
            $Response = Invoke-MgGraphRequest -Uri $Uri -Method GET -ErrorAction Stop
        }
        catch {
            Write-Log "Graph request failed [$Uri]: $_" "ERROR"
            return $Results
        }
        foreach ($Item in $Response.value) { $Results.Add($Item) }
        $Uri = $Response.'@odata.nextLink'
    } while ($Uri)
    return $Results
}

# Get all users with only the fields we need
function Get-AllUsers {
    $Select = "id,displayName,mail,accountEnabled,assignedLicenses"
    return Invoke-GraphGetAll "https://graph.microsoft.com/beta/users?`$select=$Select&`$top=999"
}

# Get all directory roles (only active/instantiated roles are returned)
function Get-AllDirectoryRoles {
    return Invoke-GraphGetAll "https://graph.microsoft.com/beta/directoryRoles?`$select=id,displayName"
}

# Get members of a directory role by role ID
function Get-RoleMembers {
    param([string]$RoleId)
    return Invoke-GraphGetAll "https://graph.microsoft.com/beta/directoryRoles/$RoleId/members?`$select=id,displayName,mail,`@odata.type"
}

# Get directory roles assigned to a user (transitive) — filtered to roles only
function Get-UserAdminRoles {
    param([string]$UserId)
    $Select  = "`$select=id,displayName"
    $Filter  = "`$filter=isof('microsoft.graph.directoryRole')"
    $Members = Invoke-GraphGetAll "https://graph.microsoft.com/beta/users/$UserId/transitiveMemberOf/microsoft.graph.directoryRole?$Select"
    return $Members
}

# Get a single user by UPN or ID
function Get-UserByUPN {
    param([string]$UPN)
    $Select = "id,displayName,mail,accountEnabled,assignedLicenses"
    try {
        $Response = Invoke-MgGraphRequest `
            -Uri "https://graph.microsoft.com/beta/users/$([System.Uri]::EscapeDataString($UPN))?`$select=$Select" `
            -Method GET -ErrorAction Stop
        return $Response
    }
    catch {
        return $null
    }
}

# ── Utility helpers ────────────────────────────────────────────────────────────
function Get-LicenseStatus($AssignedLicenses) {
    if ($AssignedLicenses -and $AssignedLicenses.Count -gt 0) { return "Licensed" }
    return "Unlicensed"
}

function Get-SignInStatus($AccountEnabled) {
    if ($AccountEnabled -eq $true) { return "Allowed" }
    return "Blocked"
}

# ══════════════════════════════════════════════════════════════════════════════
# MODE 1: Role-based report — each role with its member list
# ══════════════════════════════════════════════════════════════════════════════
if ($RoleBasedAdminReport) {
    Write-Log "Mode: Role-Based Admin Report"

    $Roles      = Get-AllDirectoryRoles
    $RoleCount  = $Roles.Count
    $Index      = 0

    foreach ($Role in $Roles) {
        $Index++
        Write-Progress -Activity "Processing roles" `
                       -Status "$($Role.displayName) ($Index of $RoleCount)" `
                       -PercentComplete (($Index / $RoleCount) * 100)

        $Members = Get-RoleMembers -RoleId $Role.id

        if ($ExcludeGroups) {
            $Members = $Members | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.user' }
        }

        if (-not $Members -or $Members.Count -eq 0) { continue }

        $Names = @($Members | ForEach-Object { $_.displayName })
        $Mails = @($Members | ForEach-Object { $_.mail })

        [PSCustomObject]@{
            'Role Name'          = $Role.displayName
            'Admin Name'         = ($Names -join ', ')
            'Admin EmailAddress' = ($Mails -join ', ')
            'Admin Count'        = $Names.Count
        } | Export-Csv -Path $OutputCsv -NoTypeInformation -Append

        Write-Log "Role '$($Role.displayName)' - $($Names.Count) member(s)."
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# MODE 2: Report for specific user(s)
# ══════════════════════════════════════════════════════════════════════════════
elseif ($AdminName -ne "") {
    Write-Log "Mode: Specific User(s) - $AdminName"

    foreach ($UPN in ($AdminName -split ",")) {
        $UPN  = $UPN.Trim()
        $User = Get-UserByUPN -UPN $UPN

        if (-not $User) {
            Write-Log "User not found: $UPN" "WARN"
            continue
        }

        $Roles = Get-UserAdminRoles -UserId $User.id

        if (-not $Roles -or $Roles.Count -eq 0) {
            Write-Log "User '$UPN' has no admin roles - skipping."
            continue
        }

        Write-Progress -Activity "Processing user: $($User.displayName)" -Status "Writing to CSV"

        [PSCustomObject]@{
            'Admin Name'         = $User.displayName
            'Admin EmailAddress' = $User.mail
            'Assigned Roles'     = (($Roles | ForEach-Object { $_.displayName }) -join ', ')
            'License Status'     = Get-LicenseStatus $User.assignedLicenses
            'SignIn Status'      = Get-SignInStatus   $User.accountEnabled
        } | Export-Csv -Path $OutputCsv -NoTypeInformation -Append

        Write-Log "Processed: $($User.displayName) - Roles: $(($Roles | ForEach-Object { $_.displayName }) -join ', ')"
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# MODE 3: All members of a specific role
# ══════════════════════════════════════════════════════════════════════════════
elseif ($RoleName -ne "") {
    Write-Log "Mode: Specific Role(s) - $RoleName"

    foreach ($Name in ($RoleName -split ",")) {
        $Name = $Name.Trim()

        # directoryRoles uses filter by displayName
        $RoleResult = Invoke-GraphGetAll `
            "https://graph.microsoft.com/beta/directoryRoles?`$filter=displayName eq '$([System.Uri]::EscapeDataString($Name))'&`$select=id,displayName"

        if (-not $RoleResult -or $RoleResult.Count -eq 0) {
            Write-Log "Role not found: $Name" "WARN"
            continue
        }

        $Role    = $RoleResult[0]
        $Members = Get-RoleMembers -RoleId $Role.id

        if ($ExcludeGroups) {
            $Members = $Members | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.user' }
        }

        if (-not $Members -or $Members.Count -eq 0) {
            Write-Log "Role '$Name' has no members - skipping."
            continue
        }

        $Names = @($Members | ForEach-Object { $_.displayName })
        $Mails = @($Members | ForEach-Object { $_.mail })

        Write-Progress -Activity "Processing role: $Name" -Status "Writing to CSV"

        [PSCustomObject]@{
            'Role Name'          = $Name
            'Admin Name'         = ($Names -join ', ')
            'Admin EmailAddress' = ($Mails -join ', ')
            'Admin Count'        = $Names.Count
        } | Export-Csv -Path $OutputCsv -NoTypeInformation -Append

        Write-Log "Role '$Name' - $($Names.Count) member(s)."
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# MODE 4 (Default): All admins — scan every user for admin role membership
# ══════════════════════════════════════════════════════════════════════════════
else {
    Write-Log "Mode: All Admins Report"
    Write-Host "Retrieving all users - this may take a moment on large tenants..." -ForegroundColor Cyan

    $AllUsers    = Get-AllUsers
    $Total       = $AllUsers.Count
    $Processed   = 0
    $AdminsFound = 0

    Write-Log "Retrieved $Total users. Checking role assignments..."

    foreach ($UserObj in $AllUsers) {
        $Processed++
        Write-Progress -Activity "Scanning for admin role assignments" `
                       -Status "$($UserObj.displayName) ($Processed of $Total)" `
                       -PercentComplete (($Processed / $Total) * 100)

        $Roles = Get-UserAdminRoles -UserId $UserObj.id

        if (-not $Roles -or $Roles.Count -eq 0) { continue }

        [PSCustomObject]@{
            'Admin Name'         = $UserObj.displayName
            'Admin EmailAddress' = $UserObj.mail
            'Assigned Roles'     = (($Roles | ForEach-Object { $_.displayName }) -join ', ')
            'License Status'     = Get-LicenseStatus $UserObj.assignedLicenses
            'SignIn Status'      = Get-SignInStatus   $UserObj.accountEnabled
        } | Export-Csv -Path $OutputCsv -NoTypeInformation -Append

        Write-Log "Admin found: $($UserObj.displayName) - $(($Roles | ForEach-Object { $_.displayName }) -join ', ')"
        $AdminsFound++
    }

    Write-Log "Scan complete. $AdminsFound admin(s) found out of $Total user(s)."
}

# ── Wrap up ────────────────────────────────────────────────────────────────────
Write-Progress -Activity "Done" -Completed

if (Test-Path $OutputCsv) {
    Write-Log "Report saved: $OutputCsv"
    Write-Host "`nReport saved to: $OutputCsv" -ForegroundColor Green
    $Shell     = New-Object -ComObject wscript.shell
    $UserInput = $Shell.popup("Do you want to open the report now?", 0, "Open Report", 4)
    if ($UserInput -eq 6) { Invoke-Item $OutputCsv }
}
else {
    Write-Log "No admin data found. CSV was not created." "WARN"
    Write-Host "No admin data found." -ForegroundColor Yellow
}

Write-Log "Script finished."
Disconnect-MgGraph | Out-Null
