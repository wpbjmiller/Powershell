# M365 PowerShell Scripts

PowerShell scripts for Microsoft 365 administration using Microsoft Graph.

---

## O365AdminReport.ps1

Exports Microsoft 365 admin role assignments to a CSV report. Scans all users and their directory role memberships via the Microsoft Graph REST API.

### Requirements

- Windows PowerShell 5.1 or later
- Microsoft Graph Beta PowerShell module (`Microsoft.Graph.Beta`)
  - The script will prompt to install it automatically if not present
- Microsoft 365 account with one of the following:
  - `Directory.Read.All` and `User.Read.All` permissions (interactive)
  - App registration with certificate for unattended runs

### Output

| File | Location |
|---|---|
| CSV Report | `C:\Scripts\AdminReport_MM-dd-yyyy_HH-mm.csv` |
| Log | `C:\Scripts\Logs\O365AdminReport_MM-dd-yyyy.log` |

### Usage

```powershell
# All admins in the tenant (default)
.\O365AdminReport.ps1

# All directory roles with their assigned members
.\O365AdminReport.ps1 -RoleBasedAdminReport

# All admins, excluding group objects
.\O365AdminReport.ps1 -ExcludeGroups

# Admin roles assigned to a specific user (comma-separate multiple UPNs)
.\O365AdminReport.ps1 -AdminName "user@domain.com"
.\O365AdminReport.ps1 -AdminName "user1@domain.com,user2@domain.com"

# All members assigned to a specific role (comma-separate multiple roles)
.\O365AdminReport.ps1 -RoleName "Global Administrator"
.\O365AdminReport.ps1 -RoleName "Global Administrator,Exchange Administrator"

# Certificate-based authentication for unattended / scheduled runs
.\O365AdminReport.ps1 -TenantId "<TenantId>" -ClientId "<AppId>" -CertificateThumbprint "<Thumbprint>"
```

### Report Columns

**All Admins / Specific User modes:**

| Column | Description |
|---|---|
| Admin Name | Display name of the admin user |
| Admin EmailAddress | Primary email address |
| Assigned Roles | Comma-separated list of assigned admin roles |
| License Status | Licensed or Unlicensed |
| SignIn Status | Allowed or Blocked |

**Role-Based / Specific Role modes:**

| Column | Description |
|---|---|
| Role Name | Directory role name |
| Admin Name | Comma-separated list of members |
| Admin EmailAddress | Comma-separated list of member emails |
| Admin Count | Total number of members in the role |

### Notes

- All Graph data retrieval uses `Invoke-MgGraphRequest` (direct REST API) rather than `Get-MgBeta*` cmdlets. This avoids a known `AggregateException` bug in the Microsoft Graph Beta PowerShell module when enumerating large result sets.
- A user appearing more than once in the log is expected behavior when they hold multiple role assignments across separate directory role objects.
- Compatible with Windows PowerShell 5.1 — does not require PowerShell 7+.
