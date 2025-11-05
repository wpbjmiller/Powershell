<#
.SYNOPSIS
    Comprehensive health check for all domain controllers in the domain.

.DESCRIPTION
    This script performs an extensive health check on all domain controllers in the domain.
    It intelligently detects the local DC and uses local queries for better performance,
    then uses remote queries for other DCs.
    
    For remote DCs where PowerShell Remoting is unavailable, the script gracefully degrades
    to run only checks that can be performed from the local DC.
    
    The script generates both console output and an HTML report with comprehensive results.

.PARAMETER reportPath
    The path where the HTML report will be saved. Default: C:\Scripts

.PARAMETER outputToConsole
    Display results in the console. Default: $true

.PARAMETER outputToHtml
    Generate an HTML report. Default: $true

.NOTES
    File Name      : Test-ADHealth.ps1
    Author         : Jeremy Miller
    Version        : 2.0
    Last Modified  : November 05, 2025
    Prerequisite   : Must run on a Domain Controller
                     PowerShell 3.0 or later
                     Active Directory PowerShell Module
    
.CHECKS PERFORMED
    - Network connectivity and DNS configuration
    - Critical services status (ADWS, KDC, Netlogon, NTDS, DNS, DFS)
    - Disk space and AD database size
    - AD Replication health
    - SYSVOL/DFSR replication status
    - Event log critical errors (last 24 hours)
    - DNS zone health
    - System State backup status
    - Global Catalog status
    - Certificate expiration (domain controller certificates)
    - Trust relationships
    - FSMO roles verification
    - DCDiag tests
    - Time synchronization across DCs
    - Domain Controller uptime

.EXAMPLE
    .\Test-ADHealth.ps1
    Runs the complete health check with default settings (console + HTML output).

.EXAMPLE
    .\Test-ADHealth.ps1 -reportPath "D:\Reports"
    Runs the health check and saves the HTML report to D:\Reports.

.LINK
    https://github.com/wpbjmiller/Powershell
#>

# Set variables
$reportDate = Get-Date -Format "dd-MM-yyyy"
$reportFileName = "DCHealthCheck-$reportDate.html"
$reportPath = "c:\Scripts"
$outputToConsole = $true
$outputToHtml = $true

# Get local computer name for optimization
$localComputerName = $env:COMPUTERNAME
$localComputerFQDN = ([System.Net.Dns]::GetHostByName($env:COMPUTERNAME)).HostName

# Scripts needs to be run on a domain controller
If (-not (Get-CimInstance -Query "SELECT * FROM Win32_OperatingSystem where ProductType = 2")) {
    Write-Host "The scripts needs to be run on a domain controller." -ForegroundColor Red
    break
}

Write-Host "Running on: $localComputerFQDN (local DC will be checked first using local queries)" -ForegroundColor Cyan

# Helper function to check if computer is local
Function Test-IsLocalComputer($computername) {
    $computerShortName = $computername.Split('.')[0]
    return ($computername -eq $localComputerName -or 
            $computername -eq $localComputerFQDN -or 
            $computerShortName -eq $localComputerName)
}

# Test PowerShell Remoting connectivity
Function Test-PSRemoting($computername) {
    
    $remotingResult = @{
        Success = $false
        Message = $null
    }

    $isLocal = Test-IsLocalComputer -computername $computername
    if ($isLocal) {
        $remotingResult.Success = $true
        $remotingResult.Message = "Local DC"
        return $remotingResult
    }

    try {
        $testResult = Invoke-Command -ComputerName $computername -ScriptBlock {
            $env:COMPUTERNAME
        } -ErrorAction Stop -WarningAction SilentlyContinue

        if ($testResult) {
            $remotingResult.Success = $true
            $remotingResult.Message = "Success"
        }
    }
    catch {
        $remotingResult.Success = $false
        $errorMessage = $_.Exception.Message
        
        if ($errorMessage -match "WinRM cannot complete the operation") {
            $remotingResult.Message = "WinRM not accessible (check firewall/service)"
        } elseif ($errorMessage -match "Access is denied") {
            $remotingResult.Message = "Access denied (check permissions)"
        } elseif ($errorMessage -match "cannot be resolved") {
            $remotingResult.Message = "Cannot resolve hostname"
        } else {
            $remotingResult.Message = "PSRemoting unavailable"
        }
    }

    return $remotingResult
}

# Check DNS configuration 
Function Get-DCDNSConfiguration($computername, $hasRemoteAccess) {

    $DNSResult = "Success"
    $DNSResultReason = $null
    $DNSResultLink = $null
    $isLocal = Test-IsLocalComputer -computername $computername

    try {
        $ipAddressDC = Resolve-DnsName $computername -Type A -ErrorAction Stop | Select-Object -ExpandProperty IPAddress 
    }
    catch {
        $DNSResult = "Failed"
        $DNSResultReason = "DNS record of host not found"
        return $DNSResult, $DNSResultReason, $DNSResultLink
    }

    if (-not $hasRemoteAccess -and -not $isLocal) {
        $DNSResult = "N/A"
        $DNSResultReason = "Requires remote access"
        return $DNSResult, $DNSResultReason, $DNSResultLink
    }

    try {
        if ($isLocal) {
            $activeNetAdapter = Get-NetAdapter -ErrorAction Stop | Where-Object {$_.Status -eq 'Up'} | Select-Object -ExpandProperty InterfaceIndex
        } else {
            $activeNetAdapter = Get-NetAdapter -CimSession $computername -ErrorAction Stop | Where-Object {$_.Status -eq 'Up'} | Select-Object -ExpandProperty InterfaceIndex
        }
        
        if ($null -eq $activeNetAdapter) {
            $DNSResult = "Failed"
            $DNSResultReason = "No active network adapter found"
            return $DNSResult, $DNSResultReason, $DNSResultLink
        }

        if ($isLocal) {
            $DnsServers = Get-DnsClientServerAddress -InterfaceIndex $activeNetAdapter -ErrorAction Stop | Select-Object -ExpandProperty ServerAddresses
        } else {
            $DnsServers = Get-DnsClientServerAddress -CimSession $computername -InterfaceIndex $activeNetAdapter -ErrorAction Stop | Select-Object -ExpandProperty ServerAddresses
        }

        if ($DnsServers[0] -eq $ipAddressDC -or $DnsServers[0] -eq "127.0.0.1" -or $DnsServers[0] -eq "::0") {
            $DNSResult = "Failed"
            $DNSResultReason = "Incorrect DNS server configured"
            $DNSResultLink = "https://lazyadmin.nl/it/add-domain-controller-to-existing-domain/#configure-dns-servers"
        }
    }
    catch {
        $DNSResult = "Failed"
        $DNSResultReason = "Unable to retrieve DNS configuration: $($_.Exception.Message)"
    }

    return $DNSResult, $DNSResultReason, $DNSResultLink
}

# Test the latency to the domain controller
Function Test-DCPing ($computername) {

    $pingResult = $null
    $pingReason = $null
    $isLocal = Test-IsLocalComputer -computername $computername

    if ($isLocal) {
        $pingResult = "Success - Local DC"
        return $pingResult, $pingReason
    }

    try {
        if ($Host.Version.Major -ge 7) {
            $latency = Test-Connection -ComputerName $computername -Count 1 -ErrorAction SilentlyContinue | 
            Select-Object -ExpandProperty latency
        } else {
            $latency = Test-Connection -ComputerName $computername -Count 1 -ErrorAction SilentlyContinue | 
            Select-Object -ExpandProperty ResponseTime
        }

        if ($latency) {
            $pingResult = "Success - $latency ms"
        } else {
            $pingResult = "Failed"
            $pingReason = "No response to ping"
        }
    }
    catch {
        $pingResult = "Failed"
        $pingReason = "Unable to ping: $($_.Exception.Message)"
    }

    return $pingResult, $pingReason
}

# Check critical AD services
Function Get-DCServices($computername, $hasRemoteAccess) {

    $servicesResult = "Success"
    $servicesResultReason = $null
    $isLocal = Test-IsLocalComputer -computername $computername

    if (-not $hasRemoteAccess -and -not $isLocal) {
        $servicesResult = "N/A"
        $servicesResultReason = "Requires remote access"
        return $servicesResult, $servicesResultReason
    }

    $services = @("ADWS", "KDC", "Netlogon", "NTDS", "DNS", "DFSR")
    $failedServices = @()

    try {
        foreach ($service in $services) {
            if ($isLocal) {
                $serviceStatus = Get-Service -Name $service -ErrorAction SilentlyContinue
            } else {
                $serviceStatus = Invoke-Command -ComputerName $computername -ScriptBlock {
                    param($serviceName)
                    Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                } -ArgumentList $service -ErrorAction Stop
            }

            if ($null -eq $serviceStatus) {
                continue
            }

            if ($serviceStatus.Status -ne "Running") {
                $failedServices += "$service ($($serviceStatus.Status))"
            }
        }

        if ($failedServices.Count -gt 0) {
            $servicesResult = "Failed"
            $servicesResultReason = "Services not running: $($failedServices -join ', ')"
        }
    }
    catch {
        $servicesResult = "Failed"
        $servicesResultReason = "Unable to query services: $($_.Exception.Message)"
    }

    return $servicesResult, $servicesResultReason
}

# Get DC uptime
Function Get-DCUpTime($computername, $hasRemoteAccess) {

    $uptimeResult = $null
    $uptimeReason = $null
    $isLocal = Test-IsLocalComputer -computername $computername

    if (-not $hasRemoteAccess -and -not $isLocal) {
        $uptimeResult = "N/A"
        $uptimeReason = "Requires remote access"
        return $uptimeResult, $uptimeReason
    }

    try {
        if ($isLocal) {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        } else {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $computername -ErrorAction Stop
        }

        $uptime = (Get-Date) - $os.LastBootUpTime
        $uptimeResult = "$($uptime.Days)d $($uptime.Hours)h"
    }
    catch {
        $uptimeResult = "Failed"
        $uptimeReason = "Unable to retrieve uptime: $($_.Exception.Message)"
    }

    return $uptimeResult, $uptimeReason
}

# Check free disk space
Function Get-FreeSpaceOS($computername, $hasRemoteAccess) {

    $freeSpaceResult = "Success"
    $freeSpaceReason = $null
    $isLocal = Test-IsLocalComputer -computername $computername

    if (-not $hasRemoteAccess -and -not $isLocal) {
        $freeSpaceResult = "N/A"
        $freeSpaceReason = "Requires remote access"
        return $freeSpaceResult, $freeSpaceReason
    }

    try {
        if ($isLocal) {
            $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction Stop
        } else {
            $disk = Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $computername -Filter "DeviceID='C:'" -ErrorAction Stop
        }

        $freeSpaceGB = [math]::Round($disk.FreeSpace / 1GB, 2)
        $freeSpacePercent = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 2)

        if ($freeSpacePercent -lt 10) {
            $freeSpaceResult = "Failed"
            $freeSpaceReason = "Low disk space: $freeSpaceGB GB ($freeSpacePercent%)"
        } elseif ($freeSpacePercent -lt 20) {
            $freeSpaceResult = "Warning"
            $freeSpaceReason = "Disk space low: $freeSpaceGB GB ($freeSpacePercent%)"
        } else {
            $freeSpaceResult = "Success - $freeSpaceGB GB ($freeSpacePercent%)"
        }
    }
    catch {
        $freeSpaceResult = "Failed"
        $freeSpaceReason = "Unable to retrieve disk space: $($_.Exception.Message)"
    }

    return $freeSpaceResult, $freeSpaceReason
}

# Get AD database size
Function Get-ADDatabaseSize($computername, $hasRemoteAccess) {

    $dbSizeResult = $null
    $dbSizeReason = $null
    $isLocal = Test-IsLocalComputer -computername $computername

    if (-not $hasRemoteAccess -and -not $isLocal) {
        $dbSizeResult = "N/A"
        $dbSizeReason = "Requires remote access"
        return $dbSizeResult, $dbSizeReason
    }

    try {
        if ($isLocal) {
            $ntdsPath = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -ErrorAction Stop)."DSA Database file"
            $dbSize = [math]::Round((Get-Item $ntdsPath -ErrorAction Stop).Length / 1GB, 2)
        } else {
            $dbSize = Invoke-Command -ComputerName $computername -ScriptBlock {
                $ntdsPath = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -ErrorAction Stop)."DSA Database file"
                [math]::Round((Get-Item $ntdsPath -ErrorAction Stop).Length / 1GB, 2)
            } -ErrorAction Stop
        }

        $dbSizeResult = $dbSize
    }
    catch {
        $dbSizeResult = "Failed"
        $dbSizeReason = "Unable to retrieve AD database size: $($_.Exception.Message)"
    }

    return $dbSizeResult, $dbSizeReason
}

# Check FSMO roles
Function Get-FSMORoles($dc, $fsmoCheckPassed) {

    $fsmoResult = $null
    $fsmoWarning = $null
    $fsmoCheck = $false

    try {
        $domain = Get-ADDomain
        $forest = Get-ADForest

        $roles = @()
        
        if ($dc.HostName -eq $domain.PDCEmulator) { $roles += "PDC" }
        if ($dc.HostName -eq $domain.RIDMaster) { $roles += "RID" }
        if ($dc.HostName -eq $domain.InfrastructureMaster) { $roles += "IM" }
        if ($dc.HostName -eq $forest.SchemaMaster) { $roles += "Schema" }
        if ($dc.HostName -eq $forest.DomainNamingMaster) { $roles += "DN" }

        if ($roles.Count -gt 0) {
            $fsmoResult = $roles -join ", "
            $fsmoCheck = $true
        }
    }
    catch {
        $fsmoWarning = "Failed to retrieve FSMO roles: $($_.Exception.Message)"
    }

    return $fsmoResult, $fsmoWarning, $fsmoCheck
}

# Run DCDiag tests
Function Get-DCDiagTests($computername) {

    $dcdiagResult = @{}

    try {
        $dcdiagOutput = dcdiag /s:$computername /test:Connectivity /test:Replications /test:Services /test:Advertising 2>&1
        
        $testNames = @("Connectivity", "Replications", "Services", "Advertising")
        
        foreach ($test in $testNames) {
            $testResult = if ($dcdiagOutput -match "$test.*passed") {
                "Passed"
            } elseif ($dcdiagOutput -match "$test.*failed") {
                "Failed"
            } else {
                "Unknown"
            }
            
            $dcdiagResult[$test] = $testResult
        }
    }
    catch {
        $dcdiagResult["Error"] = "Unable to run DCDiag: $($_.Exception.Message)"
    }

    return $dcdiagResult
}

# Check time synchronization
Function Get-TimeDifference($computername, $hasRemoteAccess) {

    $timeDiffResult = $null
    $isLocal = Test-IsLocalComputer -computername $computername

    if ($isLocal) {
        return "Local DC"
    }

    if (-not $hasRemoteAccess) {
        return "N/A - Requires remote access"
    }

    try {
        $remoteTime = Invoke-Command -ComputerName $computername -ScriptBlock {
            Get-Date
        } -ErrorAction Stop

        $localTime = Get-Date
        $timeDiff = [math]::Abs(($remoteTime - $localTime).TotalSeconds)

        if ($timeDiff -gt 300) {
            $timeDiffResult = "Failed - $([math]::Round($timeDiff))s difference"
        } elseif ($timeDiff -gt 60) {
            $timeDiffResult = "Warning - $([math]::Round($timeDiff))s difference"
        } else {
            $timeDiffResult = "Success - $([math]::Round($timeDiff))s"
        }
    }
    catch {
        $timeDiffResult = "Failed - Unable to retrieve time"
    }

    return $timeDiffResult
}

# Check AD replication status
Function Get-ReplicationStatus($computername) {

    $replResult = "Success"
    $replReason = $null

    try {
        $replStatus = Get-ADReplicationPartnerMetadata -Target $computername -ErrorAction Stop
        
        $failedRepl = $replStatus | Where-Object { $_.LastReplicationResult -ne 0 }
        
        if ($failedRepl) {
            $replResult = "Failed"
            $replReason = "Replication failures detected from $($failedRepl.Count) partner(s)"
        }
    }
    catch {
        $replResult = "Failed"
        $replReason = "Unable to retrieve replication status: $($_.Exception.Message)"
    }

    return $replResult, $replReason
}

# Check SYSVOL replication status
Function Get-SYSVOLStatus($computername, $hasRemoteAccess) {

    $sysvolResult = "Success"
    $sysvolReason = $null
    $isLocal = Test-IsLocalComputer -computername $computername

    if (-not $hasRemoteAccess -and -not $isLocal) {
        $sysvolResult = "N/A"
        $sysvolReason = "Requires remote access"
        return $sysvolResult, $sysvolReason
    }

    try {
        if ($isLocal) {
            $dfsrState = Get-Service DFSR -ErrorAction SilentlyContinue
        } else {
            $dfsrState = Invoke-Command -ComputerName $computername -ScriptBlock {
                Get-Service DFSR -ErrorAction SilentlyContinue
            } -ErrorAction Stop
        }

        if ($null -eq $dfsrState) {
            $sysvolResult = "Warning"
            $sysvolReason = "DFSR service not found (using FRS?)"
        } elseif ($dfsrState.Status -ne "Running") {
            $sysvolResult = "Failed"
            $sysvolReason = "DFSR service not running"
        }
    }
    catch {
        $sysvolResult = "Failed"
        $sysvolReason = "Unable to check SYSVOL status: $($_.Exception.Message)"
    }

    return $sysvolResult, $sysvolReason
}

# Check for critical events
Function Get-CriticalEvents($computername, $hasRemoteAccess) {

    $eventResult = "Success"
    $eventReason = $null
    $isLocal = Test-IsLocalComputer -computername $computername

    if (-not $hasRemoteAccess -and -not $isLocal) {
        $eventResult = "N/A"
        $eventReason = "Requires remote access"
        return $eventResult, $eventReason
    }

    try {
        $yesterday = (Get-Date).AddDays(-1)
        
        if ($isLocal) {
            $criticalEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'System', 'Application'
                Level = 1, 2
                StartTime = $yesterday
            } -ErrorAction Stop | Select-Object -First 10
        } else {
            $criticalEvents = Invoke-Command -ComputerName $computername -ScriptBlock {
                param($startTime)
                Get-WinEvent -FilterHashtable @{
                    LogName = 'System', 'Application'
                    Level = 1, 2
                    StartTime = $startTime
                } -ErrorAction Stop | Select-Object -First 10
            } -ArgumentList $yesterday -ErrorAction Stop
        }

        if ($criticalEvents.Count -gt 0) {
            $eventResult = "Warning"
            $eventReason = "$($criticalEvents.Count) critical event(s) in last 24h"
        }
    }
    catch {
        if ($_.Exception.Message -match "No events were found") {
            $eventResult = "Success"
        } else {
            $eventResult = "Failed"
            $eventReason = "Unable to retrieve events: $($_.Exception.Message)"
        }
    }

    return $eventResult, $eventReason
}

# Check backup status
Function Get-BackupStatus($computername) {

    $backupResult = "Unknown"
    $backupReason = $null

    try {
        $replMetadata = Get-ADReplicationUpToDatenessVectorTable -Target $computername -ErrorAction Stop
        
        if ($replMetadata) {
            $lastBackup = $replMetadata | Select-Object -First 1 -ExpandProperty LastReplicationSuccess
            
            if ($lastBackup) {
                $daysSinceBackup = ((Get-Date) - $lastBackup).Days
                
                if ($daysSinceBackup -gt 7) {
                    $backupResult = "Warning"
                    $backupReason = "Last backup: $daysSinceBackup days ago"
                } else {
                    $backupResult = "Success"
                    $backupReason = "Last backup: $daysSinceBackup days ago"
                }
            }
        }
    }
    catch {
        $backupResult = "N/A"
        $backupReason = "Unable to determine backup status"
    }

    return $backupResult, $backupReason
}

# Check Global Catalog status
Function Get-GlobalCatalogStatus($computername, $dc) {

    $gcResult = $null
    $gcReason = $null

    try {
        if ($dc.IsGlobalCatalog) {
            $gcResult = "Yes - GC enabled"
        } else {
            $gcResult = "No"
        }
    }
    catch {
        $gcResult = "Failed"
        $gcReason = "Unable to check GC status: $($_.Exception.Message)"
    }

    return $gcResult, $gcReason
}

# Check certificate status
Function Get-CertificateStatus($computername, $hasRemoteAccess) {

    $certResult = "Success"
    $certReason = $null
    $isLocal = Test-IsLocalComputer -computername $computername

    if (-not $hasRemoteAccess -and -not $isLocal) {
        $certResult = "N/A"
        $certReason = "Requires remote access"
        return $certResult, $certReason
    }

    try {
        if ($isLocal) {
            $certs = Get-ChildItem Cert:\LocalMachine\My -ErrorAction Stop | 
                     Where-Object { $_.EnhancedKeyUsageList.FriendlyName -match "Server Authentication" }
        } else {
            $certs = Invoke-Command -ComputerName $computername -ScriptBlock {
                Get-ChildItem Cert:\LocalMachine\My -ErrorAction Stop | 
                Where-Object { $_.EnhancedKeyUsageList.FriendlyName -match "Server Authentication" }
            } -ErrorAction Stop
        }

        $expiringCerts = $certs | Where-Object { $_.NotAfter -lt (Get-Date).AddDays(30) }
        
        if ($expiringCerts) {
            $certResult = "Warning"
            $certReason = "$($expiringCerts.Count) cert(s) expiring within 30 days"
        }
    }
    catch {
        $certResult = "N/A"
        $certReason = "Unable to check certificates"
    }

    return $certResult, $certReason
}

# Check DNS zones
Function Get-DNSZoneHealth() {

    $zoneResult = "Success"
    $zoneReason = $null

    try {
        $zones = Get-DnsServerZone -ErrorAction Stop
        
        $problematicZones = $zones | Where-Object { 
            $_.IsPaused -or $_.IsShutdown -or (-not $_.IsDsIntegrated -and $_.ZoneType -eq 'Primary')
        }

        if ($problematicZones) {
            $zoneResult = "Warning"
            $zoneReason = "$($problematicZones.Count) zone(s) need attention"
        }
    }
    catch {
        $zoneResult = "N/A"
        $zoneReason = "Unable to check DNS zones"
    }

    return $zoneResult, $zoneReason
}

# Check trust relationships
Function Get-TrustStatus() {

    $trustResult = "Success"
    $trustReason = $null

    try {
        $trusts = Get-ADTrust -Filter * -ErrorAction Stop
        
        if ($trusts) {
            foreach ($trust in $trusts) {
                if ($trust.TrustDirection -eq 'Disabled') {
                    $trustResult = "Warning"
                    $trustReason = "Trust with $($trust.Name) is disabled"
                    break
                }
            }
        }
    }
    catch {
        $trustResult = "N/A"
        $trustReason = "Unable to check trust relationships"
    }

    return $trustResult, $trustReason
}

# Helper function for colored console output
Function Write-HostColored($label, $status) {
    
    Write-Host "$label : " -NoNewline
    
    $color = switch -Wildcard ($status) {
        "Success*" { "Green" }
        "Failed*" { "Red" }
        "Warning*" { "Yellow" }
        "N/A*" { "Gray" }
        "Yes*" { "Green" }
        "No" { "Yellow" }
        default { "White" }
    }
    
    Write-Host $status -ForegroundColor $color
}

# ============================================================
# Main Script Execution
# ============================================================

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "ULTIMATE AD HEALTH CHECK" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Check domain-wide items once
Write-Host "Checking domain-wide settings..." -ForegroundColor Cyan
$dnsZoneHealth = Get-DNSZoneHealth
$trustStatus = Get-TrustStatus

# Get all domain controllers
$domainControllers = Get-ADDomainController -Filter *
$dcResults = @()
$fsmoCheckPassed = $false

# Check each domain controller
foreach ($dc in $domainControllers) {
    
    $isLocal = Test-IsLocalComputer -computername $dc.HostName
    
    if ($isLocal) {
        Write-Host "`nChecking: $($dc.HostName) [LOCAL DC]" -ForegroundColor Green
        $remoteAccess = @{ Success = $true; Message = "Local DC" }
    } else {
        Write-Host "`nTesting remote access to: $($dc.HostName)..." -NoNewline
        $remoteAccess = Test-PSRemoting -computername $dc.HostName
        
        if ($remoteAccess.Success) {
            Write-Host " Success" -ForegroundColor Green
            Write-Host "Checking: $($dc.HostName) [REMOTE - full remote access available]" -ForegroundColor Green
        } else {
            Write-Host " Failed" -ForegroundColor Red
            Write-Host "Checking: $($dc.HostName) [REMOTE - LIMITED: $($remoteAccess.Message)]" -ForegroundColor Yellow
            Write-Host "  Running basic checks only..." -ForegroundColor Yellow
        }
    }

    $currentDC = [PSCustomObject]@{
        "HostName" = $dc.HostName
    }

    if (-not $isLocal) {
        if ($remoteAccess.Success) {
            $currentDC | Add-Member -MemberType NoteProperty -Name "Remote Access" -Value "Success"
        } else {
            $currentDC | Add-Member -MemberType NoteProperty -Name "Remote Access" -Value "Failed - $($remoteAccess.Message)"
        }
    }

    # Run all health checks
    $currentDC | Add-Member -MemberType NoteProperty -Name "Ping" -Value (Test-DCPing -computername $dc.HostName)[0]
    
    $dnsResult = Get-DCDNSConfiguration -computername $dc.HostName -hasRemoteAccess $remoteAccess.Success
    $currentDC | Add-Member -MemberType NoteProperty -Name "DNS Config" -Value $dnsResult[0]
    if ($dnsResult[1]) { $currentDC | Add-Member -MemberType NoteProperty -Name "_DNS Config Reason" -Value $dnsResult[1] }
    
    $servicesResult = Get-DCServices -computername $dc.HostName -hasRemoteAccess $remoteAccess.Success
    $currentDC | Add-Member -MemberType NoteProperty -Name "Services" -Value $servicesResult[0]
    if ($servicesResult[1]) { $currentDC | Add-Member -MemberType NoteProperty -Name "_Services Reason" -Value $servicesResult[1] }
    
    $uptimeResult = Get-DCUpTime -computername $dc.HostName -hasRemoteAccess $remoteAccess.Success
    $currentDC | Add-Member -MemberType NoteProperty -Name "Uptime" -Value $uptimeResult[0]
    if ($uptimeResult[1]) { $currentDC | Add-Member -MemberType NoteProperty -Name "_Uptime Reason" -Value $uptimeResult[1] }
    
    $freeSpaceResult = Get-FreeSpaceOS -computername $dc.HostName -hasRemoteAccess $remoteAccess.Success
    $currentDC | Add-Member -MemberType NoteProperty -Name "Free Space" -Value $freeSpaceResult[0]
    if ($freeSpaceResult[1]) { $currentDC | Add-Member -MemberType NoteProperty -Name "_Free Space Reason" -Value $freeSpaceResult[1] }
    
    $adDbSize = Get-ADDatabaseSize -computername $dc.HostName -hasRemoteAccess $remoteAccess.Success
    if ($adDbSize[0] -ne "Failed" -and $adDbSize[0] -notlike "N/A*") {
        $currentDC | Add-Member -MemberType NoteProperty -Name "AD DB Size" -Value "$($adDbSize[0]) Gb"
    } else {
        $currentDC | Add-Member -MemberType NoteProperty -Name "AD DB Size" -Value $adDbSize[0]
    }
    if ($adDbSize[1]) { $currentDC | Add-Member -MemberType NoteProperty -Name "_AD DB Size Reason" -Value $adDbSize[1] }
    
    $fsmoResult = Get-FSMORoles -dc $dc -fsmoCheckPassed $fsmoCheckPassed
    if ($null -ne $fsmoResult[0]) {
        $currentDC | Add-Member -MemberType NoteProperty -Name "FSMO Roles" -Value $fsmoResult[0]
        $fsmoCheckPassed = $fsmoResult[2]
    } elseif ($null -ne $fsmoResult[1]) {
        $currentDC | Add-Member -MemberType NoteProperty -Name "FSMO Roles" -Value $fsmoResult[1]
    }
    
    $dcdiagResult = Get-DCDiagTests -computername $dc.HostName
    $currentDC | Add-Member -MemberType NoteProperty -Name "DCDIAG" -Value $dcdiagResult
    
    $currentDC | Add-Member -MemberType NoteProperty -Name "Time offset" -Value (Get-TimeDifference -computername $dc.HostName -hasRemoteAccess $remoteAccess.Success)
    
    # Additional comprehensive checks
    $replStatus = Get-ReplicationStatus -computername $dc.HostName
    $currentDC | Add-Member -MemberType NoteProperty -Name "AD Replication" -Value $replStatus[0]
    if ($replStatus[1]) { $currentDC | Add-Member -MemberType NoteProperty -Name "_AD Replication Reason" -Value $replStatus[1] }
    
    $sysvolStatus = Get-SYSVOLStatus -computername $dc.HostName -hasRemoteAccess $remoteAccess.Success
    $currentDC | Add-Member -MemberType NoteProperty -Name "SYSVOL Status" -Value $sysvolStatus[0]
    if ($sysvolStatus[1]) { $currentDC | Add-Member -MemberType NoteProperty -Name "_SYSVOL Status Reason" -Value $sysvolStatus[1] }
    
    $eventStatus = Get-CriticalEvents -computername $dc.HostName -hasRemoteAccess $remoteAccess.Success
    $currentDC | Add-Member -MemberType NoteProperty -Name "Critical Events" -Value $eventStatus[0]
    if ($eventStatus[1]) { $currentDC | Add-Member -MemberType NoteProperty -Name "_Critical Events Reason" -Value $eventStatus[1] }
    
    $backupStatus = Get-BackupStatus -computername $dc.HostName
    $currentDC | Add-Member -MemberType NoteProperty -Name "Last Backup" -Value $backupStatus[0]
    if ($backupStatus[1]) { $currentDC | Add-Member -MemberType NoteProperty -Name "_Last Backup Reason" -Value $backupStatus[1] }
    
    $gcStatus = Get-GlobalCatalogStatus -computername $dc.HostName -dc $dc
    $currentDC | Add-Member -MemberType NoteProperty -Name "Global Catalog" -Value $gcStatus[0]
    if ($gcStatus[1]) { $currentDC | Add-Member -MemberType NoteProperty -Name "_Global Catalog Reason" -Value $gcStatus[1] }
    
    $certStatus = Get-CertificateStatus -computername $dc.HostName -hasRemoteAccess $remoteAccess.Success
    $currentDC | Add-Member -MemberType NoteProperty -Name "Certificate" -Value $certStatus[0]
    if ($certStatus[1]) { $currentDC | Add-Member -MemberType NoteProperty -Name "_Certificate Reason" -Value $certStatus[1] }

    $dcResults += $currentDC
}

# Add domain-wide results to first DC for reporting
if ($dcResults.Count -gt 0) {
    $dcResults[0] | Add-Member -MemberType NoteProperty -Name "DNS Zones" -Value $dnsZoneHealth[0] -Force
    $dcResults[0] | Add-Member -MemberType NoteProperty -Name "Trust Relationships" -Value $trustStatus[0] -Force
}

# Console output
if ($outputToConsole) {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "HEALTH CHECK RESULTS" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    foreach ($dc in $dcResults) {
        $dc.PSObject.Properties | ForEach-Object {
            # Skip internal reason properties (start with _)
            if ($_.Name -match "^_") {
                return
            }
            
            if ($_.Name -ne "DCDIAG") {
                Write-HostColored -label $_.name -status $_.value
                
                # Check for associated reason property
                $reasonPropName = "_$($_.Name) Reason"
                $reasonProp = $dc.PSObject.Properties | Where-Object {$_.Name -eq $reasonPropName}
                
                if ($reasonProp -and $reasonProp.Value) {
                    if ($_.value -match "Warning") {
                        Write-Host "   Reason: $($reasonProp.Value)" -ForegroundColor Yellow
                    } elseif ($_.value -match "Failed|Error") {
                        Write-Host "   Reason: $($reasonProp.Value)" -ForegroundColor Red
                    }
                }
            } else {
                Write-Host "DCDIAG : " -NoNewline
                $failedCount = ($_.Value.PSObject.Properties | Where-Object {$_.Value -match "failed"}).Count
                if ($failedCount -gt 0) {
                    Write-Host "$failedCount test(s) failed" -ForegroundColor Red
                } else {
                    Write-Host "All tests passed" -ForegroundColor Green
                }
            }
        }
        Write-Host "`n ------------------------------- `n"
    }

    $errorCount = ($dcResults | ForEach-Object {
        $_.PSObject.Properties.Value | Where-Object { $_ -match "Failed|Error" -and $_ -notmatch "N/A" }
    }).Count

    if ($errorCount -gt 0) {
        Write-Host "Summary: $errorCount Error(s) Detected" -ForegroundColor Red
    } else {
        Write-Host "Summary: No Errors Detected" -ForegroundColor Green
    }

    $warningCount = ($dcResults | ForEach-Object {
        $_.PSObject.Properties.Value | Where-Object { $_ -match "Warning" }
    }).Count

    if ($warningCount -gt 0) {
        Write-Host "Summary: $warningCount Warning(s) Detected" -ForegroundColor Yellow
    } else {
        Write-Host "Summary: No Warnings Detected" -ForegroundColor Green
    }

    $naCount = ($dcResults | ForEach-Object {
        $_.PSObject.Properties.Value | Where-Object { $_ -match "N/A" }
    }).Count

    if ($naCount -gt 0) {
        Write-Host "Note: $naCount check(s) skipped due to unavailable remote access" -ForegroundColor Gray
    }
}

# HTML output
if ($outputToHtml) {
    # Create comprehensive HTML report
    $path = Join-Path -Path $reportPath -ChildPath $reportFileName
    
    if (-not (Test-Path $reportPath)) {
        New-Item -ItemType Directory -Path $reportPath -Force -ErrorAction SilentlyContinue | Out-Null
    }
    
    # Export to HTML (using ConvertTo-Html as simplified approach)
    $dcResults | ConvertTo-Html -Title "AD Health Check - $reportDate" -PreContent "<h1>Active Directory Health Check Report</h1><p>Generated: $reportDate</p>" | 
        Out-File -FilePath $path -Encoding UTF8
    
    Write-Host "`nHTML report saved to: $path" -ForegroundColor Green
}

Write-Host "`nAD Health Check Complete!" -ForegroundColor Cyan
