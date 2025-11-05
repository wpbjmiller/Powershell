# Export-ADUsers.ps1

## Overview
PowerShell script that exports Active Directory user accounts to a timestamped CSV file with comprehensive user details.

## Requirements
- Windows PowerShell 5.1 or later
- Active Directory PowerShell Module
- Domain user permissions (read access to AD)

## Usage
```powershell
.\Export-ADUsers.ps1
```

When prompted, either:
- Enter an OU Distinguished Name (e.g., `OU=Users,OU=Corporate,DC=domain,DC=com`)
- Press Enter to export all domain users

## How It Works
1. **Import Module**: Loads the Active Directory PowerShell module
2. **User Prompt**: Asks for an optional OU filter or defaults to domain root
3. **Query AD**: Retrieves all user objects with full properties from the specified scope
4. **Export Data**: Sorts users by name and exports to CSV with formatted columns
5. **Logging**: Creates a log file tracking script execution in the script directory

## Output Files
- **CSV File**: `C:\Scripts\{DomainName}_AllADUsers_{MMddyyyyhhmm}.csv`
- **Log File**: `ExportADUsersLog.txt` (in script directory or `C:\Scripts\`)

## Exported User Information
The script captures the following attributes for each user:

| Field | Source Property |
|-------|----------------|
| First name | GivenName |
| Last name | Surname |
| Display name | DisplayName |
| User logon name | SamAccountName |
| User principal name | UserPrincipalName |
| Job Title | Title |
| Description | Description |
| E-mail | Mail |
| Mobile | Mobile |
| Account status | Enabled (Enabled/Disabled) |
| Last logon date | LastLogonDate |
| OU | DistinguishedName (parsed) |
| Home Drive | HomeDrive |
| Home Directory | HomeDirectory |
| Logon Script | ScriptPath |

## Example Output
```
DomainName_AllADUsers_11052025T1430.csv
```

## Notes
- All users are sorted alphabetically by name
- CSV uses UTF-8 encoding
- Timestamps use MM-dd-yyyy HH:mm:ss format
- Requires appropriate AD permissions to read user properties

## Author
Jeremy Miller

## Repository
https://github.com/wpbjmiller/Powershell
