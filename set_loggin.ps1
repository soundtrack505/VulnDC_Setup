# set_logging_elastic_onebank.ps1
# OneBank lab logging preparation for Elastic SIEM
# Run as Administrator on every Windows machine.
# This script enables Windows logging/auditing only. It does not install Elastic Agent.
# Recommended roles: DC, WORKSTATION, IIS, MSSQL, FILESERVER

param(
    [ValidateSet("DC", "WORKSTATION", "IIS", "MSSQL", "FILESERVER")]
    [string]$Role = "WORKSTATION",

    [string[]]$AuditPaths = @(
        "C:\Exercise_Data",
        "C:\ProgramData\OneBank",
        "C:\OneBank",
        "C:\Shares\IT_Backups",
        "C:\Shares\AdminScripts",
        "D:\Shares\IT_Backups",
        "D:\Shares\AdminScripts"
    ),

    [switch]$ConfigureDomainObjectSacl,

    [string[]]$ADAuditObjects = @(
        "Domain Admins",
        "svc_backup",
        "morean.tal"
    ),

    [switch]$EnableWindowsFirewallLog,

    [string]$FirewallLogPath = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
)

function Assert-Admin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)

    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script as Administrator."
    }
}

function Enable-EventChannel {
    param([string]$Channel)

    try {
        wevtutil sl $Channel /e:true 2>$null
        Write-Host "[OK] Enabled channel: $Channel"
    }
    catch {
        Write-Warning "Could not enable channel: $Channel"
    }
}

function Set-LogSize {
    param(
        [string]$Channel,
        [int64]$SizeBytes
    )

    try {
        wevtutil sl $Channel /ms:$SizeBytes 2>$null
        Write-Host "[OK] Set log size for $Channel"
    }
    catch {
        Write-Warning "Could not set log size for $Channel"
    }
}

function Set-AuditPolicy {
    # These subcategories cover the OneBank story:
    # AD credentials for aturner, Kerberos TGS requests for svc_backup, SMB/share access with svc_backup,
    # password spraying, RDP, account/group changes, GenericAll abuse evidence, process creation, and local privesc.
    $auditSubcategories = @(
        "Logon",
        "Logoff",
        "Account Lockout",
        "Special Logon",
        "Other Logon/Logoff Events",
        "Process Creation",
        "Credential Validation",
        "Kerberos Authentication Service",
        "Kerberos Service Ticket Operations",
        "User Account Management",
        "Security Group Management",
        "Computer Account Management",
        "Directory Service Access",
        "Directory Service Changes",
        "Directory Service Replication",
        "Detailed Directory Service Replication",
        "File Share",
        "Detailed File Share",
        "File System",
        "Handle Manipulation",
        "Filtering Platform Connection",
        "Filtering Platform Packet Drop",
        "Removable Storage",
        "Other Object Access Events",
        "Audit Policy Change",
        "Authentication Policy Change",
        "Authorization Policy Change",
        "Sensitive Privilege Use",
        "Other Privilege Use Events",
        "Security System Extension",
        "System Integrity"
    )

    foreach ($subcategory in $auditSubcategories) {
        try {
            auditpol /set /subcategory:"$subcategory" /success:enable /failure:enable | Out-Null
            Write-Host "[OK] Audit enabled: $subcategory"
        }
        catch {
            Write-Warning "Could not set audit policy: $subcategory"
        }
    }

    try {
        # Include command line in Event ID 4688.
        New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null
        New-ItemProperty `
            -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
            -Name "ProcessCreationIncludeCmdLine_Enabled" `
            -Value 1 `
            -PropertyType DWord `
            -Force | Out-Null

        Write-Host "[OK] Enabled command line logging for Event ID 4688."
    }
    catch {
        Write-Warning "Could not enable command line logging for Event ID 4688."
    }
}

function Enable-PowerShellLogging {
    try {
        $base = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"

        New-Item -Path "$base\ScriptBlockLogging" -Force | Out-Null
        New-ItemProperty -Path "$base\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWord -Force | Out-Null

        New-Item -Path "$base\ModuleLogging\ModuleNames" -Force | Out-Null
        New-ItemProperty -Path "$base\ModuleLogging" -Name "EnableModuleLogging" -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path "$base\ModuleLogging\ModuleNames" -Name "*" -Value "*" -PropertyType String -Force | Out-Null

        New-Item -Path "$base\Transcription" -Force | Out-Null
        New-ItemProperty -Path "$base\Transcription" -Name "EnableTranscripting" -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path "$base\Transcription" -Name "OutputDirectory" -Value "C:\ProgramData\OneBank\PowerShellTranscripts" -PropertyType String -Force | Out-Null

        New-Item -Path "C:\ProgramData\OneBank\PowerShellTranscripts" -ItemType Directory -Force | Out-Null

        Write-Host "[OK] Enabled PowerShell ScriptBlock, Module, and Transcript logging."
    }
    catch {
        Write-Warning "Could not enable PowerShell logging."
    }
}

function Enable-FileAndShareAuditing {
    param([string[]]$Paths)

    foreach ($path in $Paths) {
        try {
            if (-not (Test-Path $path)) {
                New-Item -Path $path -ItemType Directory -Force | Out-Null
                Write-Host "[OK] Created audit path: $path"
            }

            $acl = Get-Acl $path

            $rights = [System.Security.AccessControl.FileSystemRights]::ReadData -bor `
                      [System.Security.AccessControl.FileSystemRights]::WriteData -bor `
                      [System.Security.AccessControl.FileSystemRights]::AppendData -bor `
                      [System.Security.AccessControl.FileSystemRights]::CreateFiles -bor `
                      [System.Security.AccessControl.FileSystemRights]::CreateDirectories -bor `
                      [System.Security.AccessControl.FileSystemRights]::Delete -bor `
                      [System.Security.AccessControl.FileSystemRights]::ReadAttributes -bor `
                      [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor `
                      [System.Security.AccessControl.FileSystemRights]::ReadPermissions -bor `
                      [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor `
                      [System.Security.AccessControl.FileSystemRights]::TakeOwnership

            $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
                "Everyone",
                $rights,
                "ContainerInherit,ObjectInherit",
                "None",
                "Success,Failure"
            )

            $acl.AddAuditRule($rule)
            Set-Acl -Path $path -AclObject $acl

            Write-Host "[OK] Enabled NTFS SACL auditing on $path"
        }
        catch {
            Write-Warning "Could not enable NTFS SACL auditing on $path"
            Write-Warning $_.Exception.Message
        }
    }
}

function Enable-ADObjectAuditing {
    param([string[]]$Objects)

    if ($Role -ne "DC") {
        return
    }

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        Write-Warning "ActiveDirectory module not available. Skipping AD object SACL configuration."
        return
    }

    foreach ($objectName in $Objects) {
        try {
            $adObject = Get-ADObject -LDAPFilter "(|(cn=$objectName)(sAMAccountName=$objectName))" -Properties DistinguishedName -ErrorAction Stop | Select-Object -First 1

            if (-not $adObject) {
                Write-Warning "AD object not found: $objectName"
                continue
            }

            $adPath = "AD:\$($adObject.DistinguishedName)"
            $acl = Get-Acl $adPath

            $identity = New-Object System.Security.Principal.NTAccount("Everyone")
            $rights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll -bor `
                      [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl -bor `
                      [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner -bor `
                      [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty -bor `
                      [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight

            $auditFlags = [System.Security.AccessControl.AuditFlags]::Success -bor [System.Security.AccessControl.AuditFlags]::Failure
            $inheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None

            $rule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
                $identity,
                $rights,
                $auditFlags,
                $inheritance
            )

            $acl.AddAuditRule($rule)
            Set-Acl -Path $adPath -AclObject $acl

            Write-Host "[OK] Enabled AD object SACL auditing on: $($adObject.DistinguishedName)"
        }
        catch {
            Write-Warning "Could not configure AD object SACL for: $objectName"
            Write-Warning $_.Exception.Message
        }
    }
}

function Configure-IISLogging {
    if ($Role -ne "IIS") {
        return
    }

    try {
        Import-Module WebAdministration -ErrorAction SilentlyContinue

        if (-not (Get-Module WebAdministration)) {
            Write-Warning "WebAdministration module not available. Is IIS installed?"
            return
        }

        $sites = Get-ChildItem IIS:\Sites -ErrorAction SilentlyContinue

        foreach ($site in $sites) {
            Set-ItemProperty "IIS:\Sites\$($site.Name)" -Name logFile.logFormat -Value "W3C"
            Set-ItemProperty "IIS:\Sites\$($site.Name)" -Name logFile.directory -Value "%SystemDrive%\inetpub\logs\LogFiles"
            Set-ItemProperty "IIS:\Sites\$($site.Name)" -Name logFile.period -Value "Daily"
            Set-ItemProperty "IIS:\Sites\$($site.Name)" -Name logFile.logExtFileFlags -Value `
                "Date,Time,ClientIP,UserName,SiteName,ComputerName,ServerIP,Method,UriStem,UriQuery,HttpStatus,Win32Status,BytesSent,BytesRecv,TimeTaken,ServerPort,UserAgent,Referer,ProtocolVersion,Host,HttpSubStatus"

            Write-Host "[OK] IIS W3C logging configured for site: $($site.Name)"
        }
    }
    catch {
        Write-Warning "Could not configure IIS logging."
        Write-Warning $_.Exception.Message
    }
}

function Configure-WindowsFirewallLogging {
    if (-not $EnableWindowsFirewallLog) {
        return
    }

    try {
        $firewallLogFolder = Split-Path $FirewallLogPath -Parent
        New-Item -Path $firewallLogFolder -ItemType Directory -Force | Out-Null

        Set-NetFirewallProfile -Profile Domain,Private,Public `
            -LogAllowed True `
            -LogBlocked True `
            -LogFileName $FirewallLogPath `
            -LogMaxSizeKilobytes 32767

        Write-Host "[OK] Enabled Windows Firewall text log: $FirewallLogPath"
    }
    catch {
        Write-Warning "Could not enable Windows Firewall text log."
        Write-Warning $_.Exception.Message
    }
}

Assert-Admin

Write-Host "=============================================="
Write-Host "Configuring OneBank logging for Elastic SIEM"
Write-Host "Role: $Role"
Write-Host "Sysmon: not configured by this script"
Write-Host "Splunk: not configured by this script"
Write-Host "=============================================="

# Common Windows channels
Enable-EventChannel "Windows PowerShell"
Enable-EventChannel "Microsoft-Windows-PowerShell/Operational"
Enable-EventChannel "Microsoft-Windows-TaskScheduler/Operational"
Enable-EventChannel "Microsoft-Windows-Windows Defender/Operational"
Enable-EventChannel "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
Enable-EventChannel "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
Enable-EventChannel "Microsoft-Windows-SMBServer/Audit"
Enable-EventChannel "Microsoft-Windows-SMBServer/Operational"
Enable-EventChannel "Microsoft-Windows-SmbClient/Security"
Enable-EventChannel "Microsoft-Windows-SmbClient/Connectivity"

# DC-specific channels
if ($Role -eq "DC") {
    Enable-EventChannel "Directory Service"
    Enable-EventChannel "DNS Server"
    Enable-EventChannel "Microsoft-Windows-NTLM/Operational"
}

# Useful log sizes
Set-LogSize "Security" 1073741824
Set-LogSize "System" 268435456
Set-LogSize "Application" 268435456
Set-LogSize "Windows PowerShell" 268435456
Set-LogSize "Microsoft-Windows-PowerShell/Operational" 536870912
Set-LogSize "Microsoft-Windows-TaskScheduler/Operational" 268435456
Set-LogSize "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" 134217728
Set-LogSize "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" 134217728
Set-LogSize "Microsoft-Windows-SMBServer/Audit" 268435456
Set-LogSize "Microsoft-Windows-SMBServer/Operational" 268435456

Set-AuditPolicy
Enable-PowerShellLogging
Enable-FileAndShareAuditing -Paths $AuditPaths
Enable-ADObjectAuditing -Objects $ADAuditObjects
Configure-IISLogging
Configure-WindowsFirewallLogging

Write-Host "=============================================="
Write-Host "Done. Windows logging/auditing is configured."
Write-Host "Next step: make sure Elastic Agent policy collects Security, System, Application, PowerShell, TaskScheduler, RDP, SMB, Defender, Directory Service, DNS, IIS logs, and Windows Firewall log if enabled."
Write-Host "=============================================="
