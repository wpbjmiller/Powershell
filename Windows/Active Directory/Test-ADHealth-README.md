# Test-ADHealth.ps1

## Overview
Comprehensive health check script for all domain controllers in an Active Directory domain. Generates both console output and detailed HTML reports.

## Requirements
- **Must run on a Domain Controller**
- Windows PowerShell 3.0 or later
- Active Directory PowerShell Module
- Domain Administrator or equivalent permissions

## Usage
```powershell
.\Test-ADHealth.ps1
```

The script will:
1. Automatically detect the local domain controller for optimized performance
2. Test connectivity to all other domain controllers
3. Run comprehensive health checks on each DC
4. Generate console output and HTML report

### Custom Report Location
```powershell
# Modify the $reportPath variable in the script
$reportPath = "D:\Reports"
```

## How It Works
1. **Initialization**: Validates script is running on a DC and identifies local computer
2. **Domain-Wide Checks**: Tests DNS zones and trust relationships once
3. **Per-DC Checks**: 
   - Tests PowerShell remoting connectivity
   - Runs local queries on the local DC for better performance
   - Runs remote queries on other DCs (gracefully degrades if remoting unavailable)
4. **Reporting**: Outputs results to console with color-coding and generates HTML report

## Output Files
- **HTML Report**: `C:\Scripts\DCHealthCheck-{dd-MM-yyyy}.html`
- Console output with color-coded status indicators

## Health Checks Performed

### Network & Connectivity
- **Ping Test**: Latency to each DC
- **DNS Configuration**: Validates DNS server settings
- **Remote Access**: Tests PowerShell remoting availability

### Services
- **ADWS** (Active Directory Web Services)
- **KDC** (Kerberos Key Distribution Center)
- **Netlogon** (Net Logon)
- **NTDS** (Active Directory Domain Services)
- **DNS** (Domain Name System)
- **DFSR** (Distributed File System Replication)

### Storage & Database
- **Disk Space**: C: drive free space (warns if <20%, fails if <10%)
- **AD Database Size**: NTDS.dit file size in GB
- **SYSVOL Status**: DFSR service health

### Replication
- **AD Replication**: Checks replication partner metadata for failures
- **SYSVOL Replication**: DFSR service status

### Security & Certificates
- **Certificate Status**: Checks for certificates expiring within 30 days
- **Trust Relationships**: Validates domain trust status

### System Health
- **Uptime**: Days and hours since last boot
- **Critical Events**: Scans last 24 hours for critical errors in System/Application logs
- **Last Backup**: System State backup age (warns if >7 days)

### Active Directory Roles
- **FSMO Roles**: Identifies which DC holds which FSMO roles
  - PDC Emulator
  - RID Master
  - Infrastructure Master
  - Schema Master
  - Domain Naming Master
- **Global Catalog**: Verifies GC status

### Diagnostic Tests
- **DCDiag**: Runs key tests
  - Connectivity
  - Replications
  - Services
  - Advertising
- **Time Synchronization**: Checks time offset between DCs (warns if >60s, fails if >300s)

### Domain-Wide Checks
- **DNS Zones**: Checks for paused, shutdown, or non-integrated zones
- **Trust Relationships**: Validates all domain trusts

## Status Indicators

### Console Output
- 🟢 **Green (Success)**: Check passed, no issues
- 🟡 **Yellow (Warning)**: Minor issue detected, review recommended
- 🔴 **Red (Failed)**: Critical issue, immediate attention required
- ⚪ **Gray (N/A)**: Check skipped due to unavailable remote access

### Result Values
- **Success**: Check passed
- **Failed**: Check failed, issue detected
- **Warning**: Potential issue, monitor closely
- **N/A**: Check unavailable (typically due to missing remote access)

## Graceful Degradation
When PowerShell remoting is unavailable to a remote DC, the script automatically runs only checks that can be performed from the local DC:
- Ping tests
- DNS resolution
- AD replication metadata
- DCDiag tests
- Backup status

## HTML Report
The HTML report includes:
- Generation date and time
- All health check results in table format
- Color-coded status indicators
- Detailed reason messages for failures/warnings

## Example Output
```
========================================
ULTIMATE AD HEALTH CHECK
========================================

Checking domain-wide settings...

Testing remote access to: DC02.domain.com... Success
Checking: DC02.domain.com [REMOTE - full remote access available]

HostName : DC02.domain.com
Remote Access : Success
Ping : Success - 2 ms
DNS Config : Success
Services : Success
Uptime : 45d 12h
Free Space : Success - 120.5 GB (65%)
AD DB Size : 2.3 Gb
FSMO Roles : PDC, RID
DCDIAG : All tests passed
Time offset : Success - 1s
AD Replication : Success
SYSVOL Status : Success
Critical Events : Success
Last Backup : Success - 2 days ago
Global Catalog : Yes - GC enabled
Certificate : Success

Summary: No Errors Detected
Summary: No Warnings Detected
```

## Troubleshooting

### Script requires Domain Controller
**Error**: "The script needs to be run on a domain controller"
- **Solution**: Run the script directly on a DC, not from a member server or workstation

### Remote Access Failures
**Warning**: "PSRemoting unavailable"
- **Causes**: 
  - WinRM service not running
  - Firewall blocking WinRM ports (5985/5986)
  - Insufficient permissions
- **Solution**: Enable PowerShell remoting on remote DCs or run script locally on each DC

### Permission Errors
- **Solution**: Run as Domain Admin or account with appropriate AD read permissions

## Notes
- Script intelligently uses local queries when possible for better performance
- Remote checks are optional - basic checks still run without remoting
- HTML report saved to `C:\Scripts` by default (auto-creates directory if needed)
- All timestamps use the format: dd-MM-yyyy HH:mm:ss

## Author
Jeremy Miller

## Repository
https://github.com/wpbjmiller/Powershell
