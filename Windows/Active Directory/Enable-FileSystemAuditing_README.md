# Enable-FileSystemAuditing

A comprehensive PowerShell script for configuring Windows file system auditing across entire directory structures with built-in safety checks and automatic audit policy configuration.

## Overview

This script applies System Access Control Lists (SACLs) to directories for auditing purposes while **never modifying permissions (DACLs)**. It automatically enables required Windows audit policies, includes permission verification to ensure no security changes occur, and provides detailed logging of all operations.

Perfect for compliance requirements, security monitoring, and forensic readiness on Windows file servers.

## Features

- ✅ **Automatic Audit Policy Configuration** - Detects and enables required Windows audit policies
- ✅ **Permission Protection** - Verifies that no permissions are changed during execution
- ✅ **Recursive Directory Processing** - Applies auditing to all subdirectories automatically
- ✅ **Duplicate Detection** - Skips directories that already have the correct audit configuration
- ✅ **Comprehensive Logging** - Color-coded console output and detailed log files
- ✅ **Progress Tracking** - Real-time progress display for large directory structures
- ✅ **Flexible Parameters** - Customize audit scope, rights, and behavior
- ✅ **Interactive Mode** - Can prompt for input or run completely unattended
- ✅ **Client-Agnostic** - No hardcoded values, ready for any environment

## Requirements

- Windows Server 2012 R2 or later (or Windows 8.1/10/11)
- PowerShell 5.1 or later
- Administrator privileges
- SeSecurityPrivilege (Manage auditing and security log)

## Installation

1. Create the script directory structure:
```powershell
New-Item -ItemType Directory -Path "C:\Scripts" -Force
New-Item -ItemType Directory -Path "C:\Scripts\Logs" -Force
```

2. Download the script:
```powershell
# Save Enable-FileSystemAuditing.ps1 to C:\Scripts
```

3. Verify execution policy allows running scripts:
```powershell
Get-ExecutionPolicy
# If Restricted, run: Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## Usage

### Basic Usage (Interactive Mode)

Run the script without parameters - it will prompt for the root path:

```powershell
cd C:\Scripts
.\Enable-FileSystemAuditing.ps1
```

### Command-Line Usage

Specify the path to audit:

```powershell
.\Enable-FileSystemAuditing.ps1 -RootPath "D:\"
```

### Advanced Examples

**Audit specific security group:**
```powershell
.\Enable-FileSystemAuditing.ps1 -RootPath "E:\Shares" -AuditUser "DOMAIN\File Share Users"
```

**Custom audit rights:**
```powershell
.\Enable-FileSystemAuditing.ps1 -RootPath "D:\Finance" -AuditRights "Read,Write,Delete,ChangePermissions"
```

**Audit only successful access:**
```powershell
.\Enable-FileSystemAuditing.ps1 -RootPath "D:\" -AuditType "Success"
```

**Fast mode (skip verification after first successful run):**
```powershell
.\Enable-FileSystemAuditing.ps1 -RootPath "D:\" -SkipVerification
```

**Manual audit policy mode:**
```powershell
.\Enable-FileSystemAuditing.ps1 -RootPath "D:\" -NoAutoEnablePolicies
```

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `RootPath` | String | *(prompted)* | Root path where auditing should be applied (e.g., "D:\", "E:\Shares") |
| `AuditUser` | String | "Everyone" | User or group to audit. "Everyone" captures all access attempts. |
| `AuditRights` | String | "Modify" | File system rights to audit. Options: Read, Write, Modify, Delete, ReadAndExecute, ChangePermissions, TakeOwnership, FullControl |
| `AuditType` | String | "Success,Failure" | What to audit. Options: Success, Failure, or Success,Failure |
| `SkipVerification` | Switch | False | Skip permission verification checks for faster execution |
| `NoAutoEnablePolicies` | Switch | False | Do not automatically enable audit policies |

## How It Works

### 1. Audit Policies vs SACLs

The script configures **two separate components** required for Windows auditing:

- **Audit Policies (GPO/auditpol)**: System-wide settings that enable the audit subsystem
  - File System auditing
  - File Share auditing
  
- **SACLs (System Access Control Lists)**: Directory-specific audit rules that define what to log

Both are required - policies enable the "cameras" and SACLs point them at specific locations.

### 2. Permission Safety

The script uses a snapshot-and-compare mechanism:
1. Takes a snapshot of current permissions (DACL) before applying audit rules
2. Applies the audit rule (SACL only)
3. Takes another snapshot and compares
4. Logs any discrepancies (which should never occur)

**SACL operations never modify permissions** - this verification is an abundance of caution.

### 3. Process Flow

```
1. Check prerequisites (admin rights, path exists)
2. Check/enable audit policies
3. Enumerate all directories
4. For each directory:
   - Check if audit rule already exists (skip if so)
   - Snapshot permissions
   - Apply audit rule
   - Verify permissions unchanged
5. Generate summary report
```

## Event IDs to Monitor

After running this script, you'll see these Event IDs in the Security log:

| Event ID | Description | When It Occurs |
|----------|-------------|----------------|
| 4663 | An attempt was made to access an object | File/folder access, modification, deletion |
| 5140 | A network share object was accessed | Share-level access |
| 5145 | A network share object was checked | Detailed file operations on shares |
| 4656 | A handle to an object was requested | Object handle operations |

## Validation

### Check if auditing is configured on a folder:

```powershell
$acl = Get-Acl "D:\SomeFolder" -Audit
$acl.Audit | Format-Table -AutoSize
```

### Verify permissions haven't changed:

```powershell
$acl = Get-Acl "D:\SomeFolder"
$acl.Access | Format-Table IdentityReference, FileSystemRights, AccessControlType
```

### Test audit functionality:

1. Access a file on the audited path
2. Open Event Viewer > Windows Logs > Security
3. Look for Event IDs 4663, 5140, or 5145

### Check current audit policy status:

```powershell
auditpol /get /category:"Object Access"
```

## Log Files

All logs are stored in `C:\Scripts\Logs`:

- `AuditConfig_MMddyyyy_HHmmss.log` - Detailed execution log
- `PermissionChanges_MMddyyyy_HHmmss.csv` - Permission change alerts (should be empty)

## Troubleshooting

### "Script must be run as Administrator"
Right-click PowerShell and select "Run as Administrator"

### "Audit policies may not be properly configured"
The script should automatically fix this. If you used `-NoAutoEnablePolicies`, run:
```powershell
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
```

### No events appearing in Event Viewer
1. Verify audit policies are enabled: `auditpol /get /category:"Object Access"`
2. Check that SACLs are configured: `(Get-Acl "D:\SomeFolder" -Audit).Audit`
3. Increase Security log size: Event Viewer > Security > Properties > Maximum log size

### "Access Denied" errors
- Ensure you have SeSecurityPrivilege
- Verify you're running as Administrator
- Check that you have permissions to the target directories

### Script runs slowly
Use `-SkipVerification` switch after the first successful run (reduces safety checks)

## Security Considerations

### Using "Everyone" for Auditing

**This is safe and recommended.** The `AuditUser` parameter specifies **who to audit**, not **who can access**. Using "Everyone" means:
- ✅ Captures all access attempts (authorized and unauthorized)
- ✅ Includes service accounts and administrative access
- ✅ Logs failed access attempts (critical for security)
- ✅ **Does NOT grant any permissions**

### DACL vs SACL

- **DACL (Discretionary Access Control List)** = Permissions (who can access)
- **SACL (System Access Control List)** = Auditing (what gets logged)

This script **only modifies SACLs** and includes verification to ensure DACLs remain unchanged.

### Event Log Management

Enabling comprehensive auditing increases Security log size. Recommendations:
- Increase Security log to at least 1GB (more for busy file servers)
- Implement log forwarding/SIEM integration
- Set appropriate retention policies
- Monitor for disk space

## Best Practices

1. **Test in non-production first** - Run on a test server to gauge log volume
2. **Start with Success-only auditing** - Add Failure auditing after confirming log volume is manageable
3. **Use Group Policy for audit policies** - In domain environments, configure via GPO rather than local auditpol
4. **Implement centralized logging** - Use Windows Event Forwarding or a SIEM
5. **Monitor disk space** - Auditing can generate significant log data
6. **Document your configuration** - Save the parameters used for each environment
7. **Regular validation** - Periodically verify auditing is still working

## Performance Impact

- **Minimal CPU/Memory impact** - Audit configuration is a one-time operation
- **Log storage** - Primary consideration; plan for increased Security log size
- **Network impact** - None for local file systems; minimal for SMB shares
- **Disk I/O** - Audit events are written asynchronously; minimal impact

## Group Policy Alternative

For domain environments, you can configure audit policies via Group Policy instead of using this script's auto-enable feature:

**Path:** Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies > Object Access

**Enable:**
- Audit File System (Success and Failure)
- Audit File Share (Success and Failure)

Then run the script with `-NoAutoEnablePolicies` to only configure SACLs.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

This script is provided as-is under the MIT License. See LICENSE file for details.

## Author

Created for IT professionals managing Windows file server security and compliance requirements.

## Version History

- **2.0** - Added automatic audit policy configuration, improved parameter handling, interactive mode
- **1.0** - Initial release with SACL configuration and permission verification

## Additional Resources

- [Microsoft: Basic security audit policies](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-security-audit-policies)
- [Microsoft: Advanced security audit policy settings](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings)
- [Windows Event IDs for file auditing](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)

---

**Questions or Issues?** Please open an issue in this repository.
