# Configure-OneBank-Windows-Logging.ps1
# Run as Administrator
#
# Examples:
#
# Enable local logging only:
# .\Configure-OneBank-Windows-Logging.ps1 -Role DC
#
# Enable local logging and configure Splunk UF:
# .\Configure-OneBank-Windows-Logging.ps1 -Role DC -ConfigureSplunk -SplunkIndexer 192.168.60.10 -SplunkPort 9997
#
# Roles:
# DC, WORKSTATION, IIS, MSSQL

param(
    [ValidateSet("DC", "WORKSTATION", "IIS", "MSSQL")]
    [string]$Role = "WORKSTATION",

    [switch]$ConfigureSplunk,

    [string]$SplunkIndexer = "",

    [int]$SplunkPort = 9997,

    [string]$Index = "onebank",

    [string]$SysmonFolder = "C:\Install\Sysmon",

    [string]$SysmonConfig = "C:\Install\Sysmon\sysmonconfig.xml"
)

function Assert-Admin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)

    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script as Administrator."
    }
}

function Enable-EventChannel {
    param(
        [string]$Channel
    )

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
        "Directory Service Changes",
        "File Share",
        "Detailed File Share",
        "File System",
        "Filtering Platform Connection",
        "Removable Storage",
        "Other Object Access Events"
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

    # Include command line in Event ID 4688
    try {
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
        Write-Warning "Could not enable command line logging for process creation."
    }
}

function Enable-PowerShellLogging {
    try {
        $base = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"

        New-Item -Path "$base\ScriptBlockLogging" -Force | Out-Null
        New-ItemProperty `
            -Path "$base\ScriptBlockLogging" `
            -Name "EnableScriptBlockLogging" `
            -Value 1 `
            -PropertyType DWord `
            -Force | Out-Null

        New-Item -Path "$base\ModuleLogging\ModuleNames" -Force | Out-Null
        New-ItemProperty `
            -Path "$base\ModuleLogging" `
            -Name "EnableModuleLogging" `
            -Value 1 `
            -PropertyType DWord `
            -Force | Out-Null

        New-ItemProperty `
            -Path "$base\ModuleLogging\ModuleNames" `
            -Name "*" `
            -Value "*" `
            -PropertyType String `
            -Force | Out-Null

        New-Item -Path "$base\Transcription" -Force | Out-Null
        New-ItemProperty `
            -Path "$base\Transcription" `
            -Name "EnableTranscripting" `
            -Value 1 `
            -PropertyType DWord `
            -Force | Out-Null

        New-ItemProperty `
            -Path "$base\Transcription" `
            -Name "OutputDirectory" `
            -Value "C:\ProgramData\OneBank\PowerShellTranscripts" `
            -PropertyType String `
            -Force | Out-Null

        New-Item -Path "C:\ProgramData\OneBank\PowerShellTranscripts" -ItemType Directory -Force | Out-Null

        Write-Host "[OK] Enabled PowerShell logging."
    }
    catch {
        Write-Warning "Could not enable PowerShell logging."
    }
}

function Configure-ExerciseFileAuditing {
    $path = "C:\Exercise_Data"

    try {
        if (-not (Test-Path $path)) {
            New-Item -Path $path -ItemType Directory -Force | Out-Null
        }

        $acl = Get-Acl $path

        $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            "Everyone",
            "ReadData,WriteData,AppendData,Delete,ReadAttributes,WriteAttributes,CreateFiles,CreateDirectories",
            "ContainerInherit,ObjectInherit",
            "None",
            "Success,Failure"
        )

        $acl.AddAuditRule($rule)
        Set-Acl -Path $path -AclObject $acl

        Write-Host "[OK] Enabled file auditing on $path"
    }
    catch {
        Write-Warning "Could not enable file auditing on $path"
    }
}

function Install-Or-Update-Sysmon {
    $sysmonExe = Join-Path $SysmonFolder "Sysmon64.exe"
    $sysmonZip = Join-Path $SysmonFolder "Sysmon.zip"
    $sysmonDownloadUrl = "https://download.sysinternals.com/files/Sysmon.zip"

    try {
        if (-not (Test-Path $SysmonFolder)) {
            New-Item -Path $SysmonFolder -ItemType Directory -Force | Out-Null
            Write-Host "[OK] Created Sysmon folder: $SysmonFolder"
        }

        if (-not (Test-Path $sysmonExe)) {
            Write-Host "[INFO] Sysmon64.exe not found. Downloading Sysmon from Microsoft Sysinternals..."

            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

                Invoke-WebRequest `
                    -Uri $sysmonDownloadUrl `
                    -OutFile $sysmonZip `
                    -UseBasicParsing

                Write-Host "[OK] Downloaded Sysmon ZIP to: $sysmonZip"
            }
            catch {
                Write-Warning "Could not download Sysmon. Check internet connectivity from this machine."
                Write-Warning "You can manually place Sysmon64.exe in $SysmonFolder and rerun the script."
                return
            }

            try {
                Expand-Archive `
                    -Path $sysmonZip `
                    -DestinationPath $SysmonFolder `
                    -Force

                Write-Host "[OK] Extracted Sysmon to: $SysmonFolder"
            }
            catch {
                Write-Warning "Could not extract Sysmon ZIP."
                return
            }
        }

        if (-not (Test-Path $sysmonExe)) {
            Write-Warning "Sysmon64.exe still not found after download/extract. Skipping Sysmon install."
            return
        }

        $service = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue

        if ($service) {
            if (Test-Path $SysmonConfig) {
                & $sysmonExe -c $SysmonConfig
                Write-Host "[OK] Sysmon already installed. Updated Sysmon config: $SysmonConfig"
            }
            else {
                & $sysmonExe -c
                Write-Host "[OK] Sysmon already installed. No config file found, current config was displayed."
            }
        }
        else {
            if (Test-Path $SysmonConfig) {
                & $sysmonExe -accepteula -i $SysmonConfig
                Write-Host "[OK] Installed Sysmon with config: $SysmonConfig"
            }
            else {
                & $sysmonExe -accepteula -i
                Write-Host "[OK] Installed Sysmon with default configuration."
                Write-Warning "Default Sysmon config is limited. Recommended to add sysmonconfig.xml later."
            }
        }

        Enable-EventChannel "Microsoft-Windows-Sysmon/Operational"
    }
    catch {
        Write-Warning "Could not install or update Sysmon."
        Write-Warning $_.Exception.Message
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
    }
}

function Configure-SplunkForwarder {
    if (-not $ConfigureSplunk) {
        Write-Host "[INFO] Splunk configuration skipped. ConfigureSplunk switch was not used."
        return
    }

    if ([string]::IsNullOrWhiteSpace($SplunkIndexer)) {
        Write-Warning "ConfigureSplunk was used, but SplunkIndexer is empty. Skipping Splunk configuration."
        return
    }

    $ufHomeCandidates = @(
        "$env:ProgramFiles\SplunkUniversalForwarder",
        "${env:ProgramFiles(x86)}\SplunkUniversalForwarder"
    )

    $ufHome = $ufHomeCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

    if (-not $ufHome) {
        Write-Warning "Splunk Universal Forwarder not found. Install UF first, then rerun this script with -ConfigureSplunk."
        return
    }

    try {
        $appLocal = Join-Path $ufHome "etc\apps\TA-onebank-logs\local"
        New-Item -Path $appLocal -ItemType Directory -Force | Out-Null

        $inputsPath = Join-Path $appLocal "inputs.conf"

        $commonInputs = @"
[WinEventLog://Security]
disabled = 0
index = $Index
renderXml = true

[WinEventLog://System]
disabled = 0
index = $Index

[WinEventLog://Application]
disabled = 0
index = $Index

[WinEventLog://Windows PowerShell]
disabled = 0
index = $Index

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
index = $Index
renderXml = true

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = $Index
renderXml = true

[WinEventLog://Microsoft-Windows-Windows Defender/Operational]
disabled = 0
index = $Index

[WinEventLog://Microsoft-Windows-TaskScheduler/Operational]
disabled = 0
index = $Index

[WinEventLog://Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational]
disabled = 0
index = $Index

[WinEventLog://Microsoft-Windows-TerminalServices-LocalSessionManager/Operational]
disabled = 0
index = $Index

[monitor://C:\ProgramData\OneBank\PowerShellTranscripts\*.txt]
disabled = 0
index = $Index
sourcetype = powershell_transcript

[monitor://C:\Exercise_Data\*.log]
disabled = 0
index = $Index
sourcetype = onebank_exercise_file
"@

        $roleInputs = ""

        if ($Role -eq "DC") {
            $roleInputs += @"

[WinEventLog://Directory Service]
disabled = 0
index = $Index
renderXml = true

[WinEventLog://DNS Server]
disabled = 0
index = $Index
"@
        }

        if ($Role -eq "IIS") {
            $roleInputs += @"

[monitor://C:\inetpub\logs\LogFiles\*\*.log]
disabled = 0
index = $Index
sourcetype = ms:iis:auto
crcSalt = <SOURCE>
"@
        }

        if ($Role -eq "MSSQL") {
            $roleInputs += @"

[monitor://C:\Program Files\Microsoft SQL Server\*\MSSQL\Log\ERRORLOG*]
disabled = 0
index = $Index
sourcetype = mssql:errorlog
crcSalt = <SOURCE>

[monitor://D:\SQLAuditExport\*.csv]
disabled = 0
index = $Index
sourcetype = mssql:audit:csv
crcSalt = <SOURCE>
"@
        }

        Set-Content -Path $inputsPath -Value ($commonInputs + $roleInputs) -Encoding ASCII

        $systemLocal = Join-Path $ufHome "etc\system\local"
        New-Item -Path $systemLocal -ItemType Directory -Force | Out-Null

        $outputsPath = Join-Path $systemLocal "outputs.conf"

        $outputs = @"
[tcpout]
defaultGroup = onebank_indexers

[tcpout:onebank_indexers]
server = $SplunkIndexer`:$SplunkPort
"@

        Set-Content -Path $outputsPath -Value $outputs -Encoding ASCII

        $splunkService = Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue

        if ($splunkService) {
            Restart-Service SplunkForwarder
            Write-Host "[OK] Splunk UF configured and restarted. Role: $Role"
        }
        else {
            Write-Warning "SplunkForwarder service not found. Config files were created, but service was not restarted."
        }
    }
    catch {
        Write-Warning "Could not configure Splunk Forwarder."
    }
}

Assert-Admin

Write-Host "=============================================="
Write-Host "Configuring OneBank Windows logging"
Write-Host "Role: $Role"
Write-Host "Configure Splunk: $ConfigureSplunk"
Write-Host "=============================================="

# Common Windows channels
Enable-EventChannel "Microsoft-Windows-PowerShell/Operational"
Enable-EventChannel "Microsoft-Windows-TaskScheduler/Operational"
Enable-EventChannel "Microsoft-Windows-Windows Defender/Operational"
Enable-EventChannel "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
Enable-EventChannel "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
Enable-EventChannel "Microsoft-Windows-Sysmon/Operational"

# DC-specific channels
if ($Role -eq "DC") {
    Enable-EventChannel "Directory Service"
    Enable-EventChannel "DNS Server"
}

# Increase useful log sizes
Set-LogSize "Security" 1073741824
Set-LogSize "System" 268435456
Set-LogSize "Application" 268435456
Set-LogSize "Microsoft-Windows-PowerShell/Operational" 268435456
Set-LogSize "Microsoft-Windows-Sysmon/Operational" 536870912
Set-LogSize "Microsoft-Windows-TaskScheduler/Operational" 134217728
Set-LogSize "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" 134217728
Set-LogSize "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" 134217728

# Main configuration
Set-AuditPolicy
Enable-PowerShellLogging
Configure-ExerciseFileAuditing
Install-Or-Update-Sysmon
Configure-IISLogging
Configure-SplunkForwarder

Write-Host "=============================================="
Write-Host "Done."
Write-Host "Local logging was configured."
if ($ConfigureSplunk -and $SplunkIndexer) {
    Write-Host "Splunk configuration was attempted for indexer: $SplunkIndexer`:$SplunkPort"
}
else {
    Write-Host "Splunk configuration was skipped."
}
Write-Host "=============================================="
