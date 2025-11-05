<#
.SYNOPSIS
    Exports Active Directory user information to a CSV file.

.DESCRIPTION
    This script exports all AD users from a specified Organizational Unit (OU) or 
    the entire domain to a CSV file. The export includes user properties such as 
    name, logon information, contact details, account status, and last logon date.
    
    The script creates timestamped CSV files and maintains a log of all operations.

.NOTES
    File Name      : Export-ADUsers.ps1
    Author         : Jeremy Miller
    Version        : 3.0
    Last Modified  : November 05, 2025
    Prerequisite   : Active Directory PowerShell Module
    
.EXAMPLE
    .\Export-ADUsers.ps1
    Prompts for an OU or exports all domain users if no OU is specified.

.LINK
    https://github.com/wpbjmiller/Powershell
#>

# Import Active Directory module
Import-Module ActiveDirectory

# Determine the log file path
if ($MyInvocation.MyCommand.Path) {
    $ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
    $LogFile = Join-Path -Path $ScriptDirectory -ChildPath "ExportADUsersLog.txt"
} else {
    $LogFile = "C:\Scripts\ExportADUsersLog.txt"
}

# Logging function
function Write-Log {
    param (
        [string]$Message
    )
    $timestamp = Get-Date -Format "MM-dd-yyyy HH:mm:ss"
    $logEntry = "$timestamp - $Message"
    Add-Content -Path $LogFile -Value $logEntry
}

# Get the root distinguished name of the domain
$RootDN = (Get-ADDomain).DistinguishedName

# Prompt for an optional OU filter
$OU = Read-Host "Enter the OU Distinguished Name (or press Enter to use the domain root)"
$SearchBase = if ($OU -match "^OU=") { $OU } else { $RootDN }

# Extract domain name from the distinguished name
$DomainName = ($RootDN -split ',')[0] -replace "DC=", ""

# Define CSV file location variable with domain name and timestamp
$LogDate = Get-Date -f MMddyyyyhhmm
$Csvfile = "C:\Scripts\${DomainName}_AllADUsers_$LogDate.csv"

# Log script start
Write-Log -Message "Script started: Exporting AD users from $SearchBase"

# Get all users from the specified OU or domain root
$Users = Get-ADUser -SearchBase $SearchBase -Filter * -Properties *

# Export user data
$Users | Sort-Object Name | Select-Object `
    @{Label = "First name"; Expression = { $_.GivenName } },
    @{Label = "Last name"; Expression = { $_.Surname } },
    @{Label = "Display name"; Expression = { $_.DisplayName } },
    @{Label = "User logon name"; Expression = { $_.SamAccountName } },
    @{Label = "User principal name"; Expression = { $_.UserPrincipalName } },
    @{Label = "Job Title"; Expression = { $_.Title } },
    @{Label = "Description"; Expression = { $_.Description } },
    @{Label = "E-mail"; Expression = { $_.Mail } },
    @{Label = "Mobile"; Expression = { $_.mobile } },
    @{Label = "Account status"; Expression = { if ($_.Enabled -eq 'TRUE') { 'Enabled' } Else { 'Disabled' } } },
    @{Label = "Last logon date"; Expression = { $_.lastlogondate } },
    @{Label = "OU"; Expression = { ($_.DistinguishedName -split ',', 2)[1] } },
    @{Label = "Home Drive"; Expression = { $_.HomeDrive } },
    @{Label = "Home Directory"; Expression = { $_.HomeDirectory } },
    @{Label = "Logon Script"; Expression = { $_.scriptPath } } |
    Export-Csv -Encoding UTF8 -Path $Csvfile -NoTypeInformation

# Log script completion
Write-Log -Message "Script completed: Exported AD users to $Csvfile"
