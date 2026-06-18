#requires -Version 5.1
<#
.SYNOPSIS
    BlueTeam-CTF-Lab :: Script 1 of 3 :: Build Lab Foundation.

.DESCRIPTION
    Creates a realistic but SAFE enterprise-like Active Directory foundation for a
    Blue Team / Incident Response CTF investigation lab.

    THIS SCRIPT INTENTIONALLY DOES **NOT**:
        - perform or simulate any attack
        - create any intentionally vulnerable configuration
        - plant attacker artifacts, weak credentials or persistence
        - dump credentials, disable security tools, or do anything destructive
    Those belong to 02-Create-Attack-Scenarios.ps1.

    This script ONLY builds a clean organization: OU tree, users, admin/service/
    disabled accounts, groups, baseline (clean) memberships, pre-staged computer
    objects, file-share folders with safe ACLs, and benign email artifacts.

    Every object created is:
        - placed under a single 'OU=Lab' containment boundary (and under the lab
          root folder on disk),
        - tagged with a '[LAB-CTF]' marker in its Description,
        - recorded in a JSON manifest so 99-Cleanup-Lab.ps1 can remove it precisely.

.NOTES
    LAB / ISOLATED ENVIRONMENT USE ONLY.
    Run on the lab Domain Controller with Domain Admin privileges.
    Requires the ActiveDirectory PowerShell module.

    Re-runnable (idempotent): existing objects are detected and skipped.
#>

[CmdletBinding()]
param(
    # Optional override for the email/UPN suffix. If empty, the DC's DNS root is used.
    [string]$DomainDnsName = '',

    # Root folder on disk for ALL lab files (shares, artifacts, output, logs).
    [string]$LabRootPath = 'C:\BlueTeam-CTF-Lab',

    # Optional path to lab-config.json. Defaults to .\Config\lab-config.json next to the script.
    [string]$ConfigPath = '',

    # Default lab-only password for all created accounts. CHANGE for your lab if desired.
    [string]$DefaultUserPassword = 'LabP@ssw0rd!2026',

    # Pre-stage WS01/WS02/SIEM01/MAILSIM01 computer accounts (disabled). DC01 is never touched.
    [bool]$CreateComputerObjects = $true,

    # Also publish real SMB shares for the lab folders (NTFS ACLs are always set).
    [bool]$CreateSmbShares = $false
)

# ============================================================================
#  CONFIGURATION SECTION
# ============================================================================
$ErrorActionPreference = 'Stop'
$LabTag      = 'BlueTeam-CTF-Lab'
$LabDescTag  = '[LAB-CTF] BlueTeam-CTF-Lab foundation object - safe to remove via 99-Cleanup-Lab.ps1'

# Derived paths
$Script:LabRootPath  = $LabRootPath
$OutputPath          = Join-Path $LabRootPath 'Output'
$LogPath             = Join-Path $OutputPath 'Logs'
$ArtifactsPath       = Join-Path $LabRootPath 'Artifacts'
$SharesPath          = Join-Path $LabRootPath 'Shares'
$ConfigDir           = Join-Path $LabRootPath 'Config'
$EmailsPath          = Join-Path $ArtifactsPath 'Emails'

if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = Join-Path $PSScriptRoot 'Config\lab-config.json'
}

# Host / IP plan (documentation + computer pre-staging). FAKE LAB IPs ONLY.
$HostPlan = @(
    [pscustomobject]@{ Host='DC01';      Role='Domain Controller'; IP='10.10.10.10'; Create=$false; OU='Servers'      }
    [pscustomobject]@{ Host='WS01';      Role='Workstation';       IP='10.10.10.21'; Create=$true;  OU='Workstations' }
    [pscustomobject]@{ Host='WS02';      Role='Workstation';       IP='10.10.10.22'; Create=$true;  OU='Workstations' }
    [pscustomobject]@{ Host='SIEM01';    Role='SIEM Collector';    IP='10.10.10.50'; Create=$true;  OU='Servers'      }
    [pscustomobject]@{ Host='MAILSIM01'; Role='Mail Simulation';   IP='10.10.10.60'; Create=$true;  OU='Servers'      }
    [pscustomobject]@{ Host='FW01';      Role='Firewall';          IP='10.10.10.1';  Create=$false; OU='-'            }
)

# ---- Tracking collections (drive exports + manifest) ----
$Script:Manifest      = New-Object System.Collections.Generic.List[object]
$Script:CreatedUsers  = New-Object System.Collections.Generic.List[object]
$Script:CreatedGroups = New-Object System.Collections.Generic.List[object]
$Script:CreatedMember = New-Object System.Collections.Generic.List[object]
$Script:Counters      = [ordered]@{
    OUs=0; Users=0; Groups=0; Memberships=0; Computers=0; Folders=0; Shares=0; Emails=0; Skipped=0; Errors=0
}

# ============================================================================
#  CORE FUNCTIONS
# ============================================================================

function Write-LabLog {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','OK','WARN','ERROR','STEP')][string]$Level = 'INFO'
    )
    $ts   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[{0}] [{1,-5}] {2}" -f $ts, $Level, $Message
    $color = switch ($Level) {
        'OK'    {'Green'}; 'WARN' {'Yellow'}; 'ERROR' {'Red'}; 'STEP' {'Cyan'}; default {'Gray'}
    }
    Write-Host $line -ForegroundColor $color
    try { Add-Content -Path $Script:LogFile -Value $line -ErrorAction SilentlyContinue } catch {}
}

function Add-Manifest {
    param(
        [Parameter(Mandatory)][ValidateSet('OU','User','Group','Membership','Computer','Folder','Share','Email','ACL')]
        [string]$Type,
        [Parameter(Mandatory)][string]$Identity,
        [string]$Location = '',
        [string]$Detail   = ''
    )
    $Script:Manifest.Add([pscustomobject]@{
        Type      = $Type
        Identity  = $Identity
        Location  = $Location
        Detail    = $Detail
        Tag       = $LabTag
        Created   = (Get-Date).ToString('o')
    })
}

function Initialize-LabPaths {
    foreach ($p in @($LabRootPath,$OutputPath,$LogPath,$ArtifactsPath,$SharesPath,$ConfigDir,$EmailsPath)) {
        if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
    }
    $Script:LogFile = Join-Path $LogPath ("01-Build-Lab-Foundation_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
}

function Import-LabConfig {
    # Optional JSON config; param values already supplied on the command line win.
    if (Test-Path $ConfigPath) {
        try {
            $cfg = Get-Content $ConfigPath -Raw | ConvertFrom-Json
            if (-not $PSBoundParameters.ContainsKey('DomainDnsName')   -and $cfg.DomainDnsName)        { $script:DomainDnsName        = $cfg.DomainDnsName }
            if (-not $PSBoundParameters.ContainsKey('DefaultUserPassword') -and $cfg.DefaultUserPassword) { $script:DefaultUserPassword = $cfg.DefaultUserPassword }
            if (-not $PSBoundParameters.ContainsKey('CreateComputerObjects') -and $null -ne $cfg.CreateComputerObjects) { $script:CreateComputerObjects = [bool]$cfg.CreateComputerObjects }
            if (-not $PSBoundParameters.ContainsKey('CreateSmbShares') -and $null -ne $cfg.CreateSmbShares) { $script:CreateSmbShares = [bool]$cfg.CreateSmbShares }
            Write-LabLog "Loaded configuration from $ConfigPath" 'OK'
        } catch {
            Write-LabLog "Could not parse $ConfigPath ($($_.Exception.Message)); using defaults." 'WARN'
        }
    } else {
        Write-LabLog "No lab-config.json found at $ConfigPath; using built-in defaults." 'INFO'
    }
}

function Test-Prerequisites {
    Write-LabLog 'Validating prerequisites...' 'STEP'
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw 'ActiveDirectory module not found. Install RSAT-AD-PowerShell on the DC.'
    }
    Import-Module ActiveDirectory -ErrorAction Stop
    $Script:Domain   = Get-ADDomain -ErrorAction Stop
    $Script:DomainDN = $Script:Domain.DistinguishedName
    $Script:Netbios  = $Script:Domain.NetBIOSName
    $Script:DnsRoot  = if ([string]::IsNullOrWhiteSpace($script:DomainDnsName)) { $Script:Domain.DNSRoot } else { $script:DomainDnsName }
    Write-LabLog ("Target domain: {0}  (NetBIOS: {1}, DN: {2})" -f $Script:DnsRoot,$Script:Netbios,$Script:DomainDN) 'OK'
    $Script:SecurePassword = ConvertTo-SecureString -String $DefaultUserPassword -AsPlainText -Force
}

# ---- Active Directory builders (all idempotent) ----

function New-LabOU {
    param([Parameter(Mandatory)][string]$Name,[Parameter(Mandatory)][string]$ParentDN)
    $dn = "OU=$Name,$ParentDN"
    try { $exists = Get-ADOrganizationalUnit -Identity $dn -ErrorAction Stop } catch { $exists = $null }
    if ($exists) {
        Write-LabLog "OU already exists: $dn" 'INFO'; $Script:Counters.Skipped++
    } else {
        New-ADOrganizationalUnit -Name $Name -Path $ParentDN -Description $LabDescTag `
            -ProtectedFromAccidentalDeletion:$false -ErrorAction Stop
        Write-LabLog "Created OU: $dn" 'OK'
        $Script:Counters.OUs++
        Add-Manifest -Type 'OU' -Identity $Name -Location $dn
    }
    return $dn
}

function New-LabUser {
    param(
        [Parameter(Mandatory)][string]$Sam,
        [Parameter(Mandatory)][string]$Display,
        [Parameter(Mandatory)][string]$TargetOU,
        [string]$Department = '',
        [string]$Title      = '',
        [bool]  $Enabled    = $true,
        [string]$Note       = ''
    )
    $existing = Get-ADUser -Filter "SamAccountName -eq '$Sam'" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-LabLog "User already exists: $Sam" 'INFO'; $Script:Counters.Skipped++
    } else {
        $parts   = $Display.Trim() -split '\s+',2
        $given   = $parts[0]
        $surname = if ($parts.Count -gt 1) { $parts[1] } else { '' }
        $upn     = "$Sam@$($Script:DnsRoot)"
        $email   = $upn
        $desc    = ("$LabDescTag" + $(if ($Note) { " | $Note" } else { '' }))
        New-ADUser -Name $Display -SamAccountName $Sam -UserPrincipalName $upn -DisplayName $Display `
            -GivenName $given -Surname $surname -Department $Department -Title $Title -EmailAddress $email `
            -Description $desc -AccountPassword $Script:SecurePassword -Enabled $Enabled `
            -PasswordNeverExpires $true -ChangePasswordAtLogon $false -Path $TargetOU -ErrorAction Stop
        Write-LabLog "Created user: $Sam ($Department/$Title) Enabled=$Enabled" 'OK'
        $Script:Counters.Users++
        Add-Manifest -Type 'User' -Identity $Sam -Location $TargetOU -Detail $Title
    }
    $Script:CreatedUsers.Add([pscustomobject]@{
        SamAccountName=$Sam; UserPrincipalName="$Sam@$($Script:DnsRoot)"; DisplayName=$Display
        Department=$Department; Title=$Title; Email="$Sam@$($Script:DnsRoot)"; Enabled=$Enabled
        OU=$TargetOU; DefaultPassword=$DefaultUserPassword; Note=$Note
    })
}

function New-LabGroup {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$TargetOU,
        [ValidateSet('Global','DomainLocal','Universal')][string]$Scope='Global',
        [string]$Description=''
    )
    $existing = Get-ADGroup -Filter "Name -eq '$Name'" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-LabLog "Group already exists: $Name" 'INFO'; $Script:Counters.Skipped++
    } else {
        $desc = ("$LabDescTag" + $(if ($Description) { " | $Description" } else { '' }))
        New-ADGroup -Name $Name -SamAccountName $Name -GroupScope $Scope -GroupCategory Security `
            -Path $TargetOU -Description $desc -ErrorAction Stop
        Write-LabLog "Created group: $Name ($Scope)" 'OK'
        $Script:Counters.Groups++
        Add-Manifest -Type 'Group' -Identity $Name -Location $TargetOU -Detail $Scope
    }
    $Script:CreatedGroups.Add([pscustomobject]@{ Name=$Name; Scope=$Scope; OU=$TargetOU; Description=$Description })
}

function Add-LabGroupMember {
    param([Parameter(Mandatory)][string]$Group,[Parameter(Mandatory)][string]$Member)
    try {
        $current = Get-ADGroupMember -Identity $Group -ErrorAction Stop |
                   Where-Object { $_.SamAccountName -eq $Member }
        if ($current) {
            $Script:Counters.Skipped++
        } else {
            Add-ADGroupMember -Identity $Group -Members $Member -ErrorAction Stop
            Write-LabLog "Added '$Member' to group '$Group'" 'OK'
            $Script:Counters.Memberships++
            Add-Manifest -Type 'Membership' -Identity "$Group<=$Member" -Detail 'group member'
        }
        $Script:CreatedMember.Add([pscustomobject]@{ Group=$Group; Member=$Member })
    } catch {
        Write-LabLog "Failed adding '$Member' to '$Group': $($_.Exception.Message)" 'WARN'
        $Script:Counters.Errors++
    }
}

function New-LabComputer {
    param([Parameter(Mandatory)][string]$Name,[Parameter(Mandatory)][string]$TargetOU)
    $existing = Get-ADComputer -Filter "Name -eq '$Name'" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-LabLog "Computer object already exists: $Name" 'INFO'; $Script:Counters.Skipped++
    } else {
        New-ADComputer -Name $Name -SamAccountName "$Name`$" -Path $TargetOU -Enabled $false `
            -Description $LabDescTag -ErrorAction Stop
        Write-LabLog "Pre-staged computer object: $Name (disabled)" 'OK'
        $Script:Counters.Computers++
        Add-Manifest -Type 'Computer' -Identity $Name -Location $TargetOU
    }
}

# ---- File system builders ----

function New-LabFolder {
    param([Parameter(Mandatory)][string]$Path,[string]$Detail='')
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        Write-LabLog "Created folder: $Path" 'OK'
        $Script:Counters.Folders++
        Add-Manifest -Type 'Folder' -Identity $Path -Detail $Detail
    } else {
        $Script:Counters.Skipped++
    }
}

function Set-LabFolderAccess {
    # Safe baseline NTFS ACL. Adds (does not reset) an allow rule for a lab group.
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Identity,
        [ValidateSet('Read','Modify','Full')][string]$Level='Read'
    )
    try {
        $rights = switch ($Level) { 'Read'{'ReadAndExecute'} 'Modify'{'Modify'} 'Full'{'FullControl'} }
        $acl  = Get-Acl -Path $Path
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    "$($Script:Netbios)\$Identity", $rights,
                    'ContainerInherit,ObjectInherit','None','Allow')
        $acl.AddAccessRule($rule)
        Set-Acl -Path $Path -AclObject $acl
        Write-LabLog "ACL: $Identity = $Level on $Path" 'OK'
        Add-Manifest -Type 'ACL' -Identity "$Identity=$Level" -Location $Path
    } catch {
        Write-LabLog "ACL set failed ($Identity on $Path): $($_.Exception.Message)" 'WARN'
        $Script:Counters.Errors++
    }
}

function New-LabSmbShare {
    param([Parameter(Mandatory)][string]$Name,[Parameter(Mandatory)][string]$Path)
    if (-not $CreateSmbShares) { return }
    if (Get-SmbShare -Name $Name -ErrorAction SilentlyContinue) {
        Write-LabLog "SMB share already exists: $Name" 'INFO'; $Script:Counters.Skipped++; return
    }
    try {
        New-SmbShare -Name $Name -Path $Path -FullAccess "$($Script:Netbios)\Domain Admins" `
            -ReadAccess 'Authenticated Users' -Description "$LabTag share" -ErrorAction Stop | Out-Null
        Write-LabLog "Created SMB share: $Name -> $Path" 'OK'
        $Script:Counters.Shares++
        Add-Manifest -Type 'Share' -Identity $Name -Location $Path
    } catch {
        Write-LabLog "SMB share creation failed ($Name): $($_.Exception.Message)" 'WARN'
        $Script:Counters.Errors++
    }
}

function New-BenignEmailArtifact {
    param(
        [Parameter(Mandatory)][string]$Folder,
        [Parameter(Mandatory)][string]$FileName,
        [Parameter(Mandatory)][string]$From,
        [Parameter(Mandatory)][string]$To,
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][string]$Body,
        [string]$DateStr = (Get-Date).ToString('R')
    )
    $full = Join-Path $Folder $FileName
    if (Test-Path $full) { $Script:Counters.Skipped++; return }
    $eml = @"
From: $From
To: $To
Date: $DateStr
Subject: $Subject
Message-ID: <$([guid]::NewGuid().ToString())@$($Script:DnsRoot)>
X-Lab-Artifact: $LabTag (benign foundation email)
Content-Type: text/plain; charset="utf-8"

$Body
"@
    Set-Content -Path $full -Value $eml -Encoding UTF8
    Write-LabLog "Created benign email artifact: $FileName" 'OK'
    $Script:Counters.Emails++
    Add-Manifest -Type 'Email' -Identity $FileName -Location $Folder
}

# ============================================================================
#  BUILD STEPS
# ============================================================================

function Build-OUStructure {
    Write-LabLog 'Building OU structure...' 'STEP'
    $Script:OU = @{}
    $Script:OU.Root          = New-LabOU 'Lab' $Script:DomainDN
    $usersDN                 = New-LabOU 'Users'     $Script:OU.Root
    $Script:OU.UsersStd      = New-LabOU 'Standard Users'  $usersDN
    $Script:OU.UsersAdmin    = New-LabOU 'Admin Users'     $usersDN
    $Script:OU.UsersSvc      = New-LabOU 'Service Accounts'$usersDN
    $Script:OU.UsersDisabled = New-LabOU 'Disabled Users'  $usersDN
    $groupsDN                = New-LabOU 'Groups'    $Script:OU.Root
    $Script:OU.GroupsSec     = New-LabOU 'Security Groups'   $groupsDN
    $Script:OU.GroupsDept    = New-LabOU 'Department Groups' $groupsDN
    $Script:OU.GroupsAccess  = New-LabOU 'Access Groups'     $groupsDN
    $compDN                  = New-LabOU 'Computers' $Script:OU.Root
    $Script:OU.CompWs        = New-LabOU 'Workstations' $compDN
    $Script:OU.CompSrv       = New-LabOU 'Servers'      $compDN
    $resDN                   = New-LabOU 'Resources' $Script:OU.Root
    $Script:OU.ResShares     = New-LabOU 'File Shares' $resDN
    $Script:OU.ResMail       = New-LabOU 'Mail'        $resDN
}

function Build-Users {
    Write-LabLog 'Creating users...' 'STEP'

    # --- Standard users (24) ---
    $standard = @(
        @{Sam='alice.cohen'; Display='Alice Cohen';   Dept='IT';         Title='IT Systems Engineer'}
        @{Sam='amit.katz';   Display='Amit Katz';      Dept='IT';         Title='IT Support Engineer'}
        @{Sam='koby.shemesh';Display='Koby Shemesh';   Dept='IT';         Title='Network Administrator'}
        @{Sam='dan.levi';    Display='Dan Levi';       Dept='Helpdesk';   Title='Helpdesk Technician'}
        @{Sam='noam.peretz'; Display='Noam Peretz';    Dept='Helpdesk';   Title='Helpdesk Technician'}
        @{Sam='tal.shahar';  Display='Tal Shahar';     Dept='Helpdesk';   Title='Helpdesk Team Lead'}
        @{Sam='maya.bitton'; Display='Maya Bitton';    Dept='Finance';    Title='Financial Analyst'}
        @{Sam='yael.dahan';  Display='Yael Dahan';     Dept='Finance';    Title='Accountant'}
        @{Sam='gil.oren';    Display='Gil Oren';       Dept='Finance';    Title='Finance Manager'}
        @{Sam='efrat.naor';  Display='Efrat Naor';     Dept='Finance';    Title='Payroll Specialist'}
        @{Sam='shir.azulai'; Display='Shir Azulai';    Dept='HR';         Title='HR Specialist'}
        @{Sam='rina.mor';    Display='Rina Mor';       Dept='HR';         Title='HR Coordinator'}
        @{Sam='moran.tal';   Display='Moran Tal';      Dept='HR';         Title='Recruiter'}
        @{Sam='ron.mizrahi'; Display='Ron Mizrahi';    Dept='Operations'; Title='Operations Specialist'}
        @{Sam='eitan.gabay'; Display='Eitan Gabay';    Dept='Operations'; Title='Operations Analyst'}
        @{Sam='shai.levin';  Display='Shai Levin';     Dept='Operations'; Title='Logistics Coordinator'}
        @{Sam='lior.benami'; Display='Lior Ben-Ami';   Dept='Management'; Title='Department Manager'}
        @{Sam='sigal.barak'; Display='Sigal Barak';    Dept='Management'; Title='Director'}
        @{Sam='omer.shapir'; Display='Omer Shapir';    Dept='Security';   Title='SOC Analyst'}
        @{Sam='hadas.ilan';  Display='Hadas Ilan';     Dept='Security';   Title='Security Engineer'}
        @{Sam='nir.regev';   Display='Nir Regev';      Dept='Sales';      Title='Sales Representative'}
        @{Sam='dana.salem';  Display='Dana Salem';     Dept='Sales';      Title='Sales Representative'}
        @{Sam='tomer.azran'; Display='Tomer Azran';    Dept='Sales';      Title='Account Executive'}
        @{Sam='avi.bendavid';Display='Avi Ben-David';  Dept='Sales';      Title='Sales Manager'}
    )
    foreach ($u in $standard) {
        New-LabUser -Sam $u.Sam -Display $u.Display -TargetOU $Script:OU.UsersStd `
                    -Department $u.Dept -Title $u.Title -Enabled $true -Note 'Standard user'
    }

    # --- Admin-style users (NOT Domain Admins by design) ---
    $admins = @(
        @{Sam='adm.yossi';     Display='Yossi (Admin)';      Dept='IT'; Title='IT Administrator'}
        @{Sam='adm.dana';      Display='Dana (Admin)';       Dept='Helpdesk'; Title='Helpdesk Administrator'}
        @{Sam='adm.itmanager'; Display='IT Manager (Admin)'; Dept='IT'; Title='IT Manager'}
    )
    foreach ($u in $admins) {
        New-LabUser -Sam $u.Sam -Display $u.Display -TargetOU $Script:OU.UsersAdmin `
                    -Department $u.Dept -Title $u.Title -Enabled $true -Note 'Admin-style account (not Domain Admin)'
    }

    # --- Service accounts (NON-vulnerable in Script 1) ---
    $svc = @('svc_backup','svc_sql','svc_web','svc_iis','svc_monitoring','svc_deploy')
    foreach ($s in $svc) {
        New-LabUser -Sam $s -Display $s -TargetOU $Script:OU.UsersSvc `
                    -Department 'IT' -Title 'Service Account' -Enabled $true -Note 'Service account (no vulnerability in Script 1)'
    }

    # --- Disabled / legacy accounts ---
    $disabled = @('old.user1','old.user2','legacy.backup','former.admin')
    foreach ($d in $disabled) {
        New-LabUser -Sam $d -Display $d -TargetOU $Script:OU.UsersDisabled `
                    -Department 'Operations' -Title 'Legacy/Disabled' -Enabled $false -Note 'Disabled legacy account'
    }
}

function Build-Groups {
    Write-LabLog 'Creating groups...' 'STEP'

    $dept = 'IT','Helpdesk','Finance','HR','Operations','Management','Security','Sales'
    foreach ($d in $dept) {
        New-LabGroup -Name "GG_Department_$d" -TargetOU $Script:OU.GroupsDept -Description "Department group: $d"
    }

    $access = @(
        'GG_FileShare_Finance_RO','GG_FileShare_Finance_RW',
        'GG_FileShare_HR_RO','GG_FileShare_HR_RW',
        'GG_FileShare_IT_RO','GG_FileShare_IT_RW',
        'GG_FileShare_Public_RW','GG_VPN_Users','GG_Mail_Users'
    )
    foreach ($g in $access) { New-LabGroup -Name $g -TargetOU $Script:OU.GroupsAccess -Description 'Resource access group' }

    $sec = @(
        'GG_Helpdesk_Operators','GG_Workstation_Admins','GG_Server_Operators',
        'GG_IT_Admins','GG_SIEM_Analysts','GG_Security_Investigators'
    )
    foreach ($g in $sec) { New-LabGroup -Name $g -TargetOU $Script:OU.GroupsSec -Description 'Operations/admin group' }
}

function Build-Memberships {
    Write-LabLog 'Assigning baseline (clean) group memberships...' 'STEP'

    # Department membership (driven by created user records)
    foreach ($u in $Script:CreatedUsers | Where-Object { $_.Note -eq 'Standard user' }) {
        Add-LabGroupMember -Group "GG_Department_$($u.Department)" -Member $u.SamAccountName
        Add-LabGroupMember -Group 'GG_Mail_Users'        -Member $u.SamAccountName
        Add-LabGroupMember -Group 'GG_FileShare_Public_RW' -Member $u.SamAccountName
        if ($u.Department -in @('IT','Helpdesk','Management','Security')) {
            Add-LabGroupMember -Group 'GG_VPN_Users' -Member $u.SamAccountName
        }
    }
    foreach ($a in $Script:CreatedUsers | Where-Object { $_.Note -like 'Admin-style*' }) {
        Add-LabGroupMember -Group 'GG_Mail_Users' -Member $a.SamAccountName
    }

    # Functional groups (clean - NO risky nesting here; that is Script 2 / Module 5)
    foreach ($m in 'dan.levi','noam.peretz','tal.shahar') { Add-LabGroupMember 'GG_Helpdesk_Operators' $m }
    foreach ($m in 'alice.cohen','amit.katz','koby.shemesh','adm.yossi','adm.itmanager') { Add-LabGroupMember 'GG_IT_Admins' $m }
    foreach ($m in 'omer.shapir','hadas.ilan') { Add-LabGroupMember 'GG_SIEM_Analysts' $m; Add-LabGroupMember 'GG_Security_Investigators' $m }

    # File-share department access
    foreach ($u in $Script:CreatedUsers | Where-Object { $_.Department -eq 'IT'      -and $_.Note -eq 'Standard user' }) { Add-LabGroupMember 'GG_FileShare_IT_RW' $u.SamAccountName }
    foreach ($u in $Script:CreatedUsers | Where-Object { $_.Department -eq 'Finance' -and $_.Note -eq 'Standard user' }) { Add-LabGroupMember 'GG_FileShare_Finance_RW' $u.SamAccountName }
    foreach ($u in $Script:CreatedUsers | Where-Object { $_.Department -eq 'HR'      -and $_.Note -eq 'Standard user' }) { Add-LabGroupMember 'GG_FileShare_HR_RW' $u.SamAccountName }
}

function Build-Computers {
    Write-LabLog 'Pre-staging computer objects / documenting host plan...' 'STEP'
    if ($CreateComputerObjects) {
        foreach ($h in $HostPlan | Where-Object { $_.Create }) {
            $ou = if ($h.OU -eq 'Workstations') { $Script:OU.CompWs } else { $Script:OU.CompSrv }
            New-LabComputer -Name $h.Host -TargetOU $ou
        }
    } else {
        Write-LabLog 'CreateComputerObjects=$false -> host plan documented only (no AD computer objects).' 'INFO'
    }
    # Always export the host/IP plan as documentation
    $HostPlan | Export-Csv (Join-Path $OutputPath 'hostname-plan.csv') -NoTypeInformation -Encoding UTF8
}

function Build-FileShares {
    Write-LabLog 'Creating file-share folders with safe baseline ACLs...' 'STEP'
    $shares = @(
        @{Name='Finance'; RW='GG_FileShare_Finance_RW'; RO='GG_FileShare_Finance_RO'}
        @{Name='HR';      RW='GG_FileShare_HR_RW';      RO='GG_FileShare_HR_RO'}
        @{Name='IT';      RW='GG_FileShare_IT_RW';      RO='GG_FileShare_IT_RO'}
        @{Name='Public';  RW='GG_FileShare_Public_RW';  RO=$null}
        @{Name='Backup';  RW='GG_IT_Admins';            RO='GG_Server_Operators'}
    )
    foreach ($s in $shares) {
        $path = Join-Path $SharesPath $s.Name
        New-LabFolder -Path $path -Detail "File share: $($s.Name)"
        if ($s.RW) { Set-LabFolderAccess -Path $path -Identity $s.RW -Level 'Modify' }
        if ($s.RO) { Set-LabFolderAccess -Path $path -Identity $s.RO -Level 'Read' }
        New-LabSmbShare -Name "Lab_$($s.Name)" -Path $path
        # Benign readme so the (clean) share is non-empty and believable
        $readme = Join-Path $path 'README.txt'
        if (-not (Test-Path $readme)) {
            Set-Content -Path $readme -Encoding UTF8 -Value "Department file share ($($s.Name)). $LabTag - benign placeholder."
        }
    }
}

function Build-EmailArtifacts {
    Write-LabLog 'Creating benign foundation email artifacts...' 'STEP'
    foreach ($f in 'Inbox','Sent','Deleted','Quarantine') { New-LabFolder -Path (Join-Path $EmailsPath $f) -Detail "Email folder: $f" }
    $dom = $Script:DnsRoot
    New-BenignEmailArtifact -Folder (Join-Path $EmailsPath 'Inbox') -FileName 'welcome_001.eml' `
        -From "it.helpdesk@$dom" -To "alice.cohen@$dom" -Subject 'Welcome to the company' `
        -Body "Hi Alice,`nWelcome aboard. Your account is ready. Contact the Helpdesk for any access requests.`nRegards, IT Helpdesk"
    New-BenignEmailArtifact -Folder (Join-Path $EmailsPath 'Inbox') -FileName 'it_maintenance_002.eml' `
        -From "it.helpdesk@$dom" -To "all-staff@$dom" -Subject 'Scheduled maintenance window' `
        -Body "Dear all,`nRoutine maintenance is scheduled this weekend. No action required.`nIT Operations"
    New-BenignEmailArtifact -Folder (Join-Path $EmailsPath 'Inbox') -FileName 'hr_policy_003.eml' `
        -From "hr@$dom" -To "all-staff@$dom" -Subject 'Updated leave policy' `
        -Body "Team,`nThe leave policy has been updated on the HR share. Please review.`nHR Department"
    New-BenignEmailArtifact -Folder (Join-Path $EmailsPath 'Sent') -FileName 'newsletter_004.eml' `
        -From "marketing@$dom" -To "all-staff@$dom" -Subject 'Monthly newsletter' `
        -Body "Hello everyone,`nHere is the monthly company newsletter. Enjoy!`nMarketing"
}

# ============================================================================
#  DOCUMENTATION / EXPORTS
# ============================================================================

function Export-Documentation {
    Write-LabLog 'Exporting documentation and manifest...' 'STEP'

    $Script:CreatedUsers  | Export-Csv (Join-Path $OutputPath 'created-users.csv')  -NoTypeInformation -Encoding UTF8
    $Script:CreatedGroups | Export-Csv (Join-Path $OutputPath 'created-groups.csv') -NoTypeInformation -Encoding UTF8
    $Script:CreatedMember | Export-Csv (Join-Path $OutputPath 'created-memberships.csv') -NoTypeInformation -Encoding UTF8
    $Script:Manifest      | Export-Csv (Join-Path $OutputPath 'lab-foundation-summary.csv') -NoTypeInformation -Encoding UTF8

    # Machine-readable manifest for 99-Cleanup-Lab.ps1
    $manifestObj = [pscustomobject]@{
        Tag           = $LabTag
        Script        = '01-Build-Lab-Foundation.ps1'
        GeneratedUtc  = (Get-Date).ToUniversalTime().ToString('o')
        DomainDN      = $Script:DomainDN
        NetBIOS       = $Script:Netbios
        DnsRoot       = $Script:DnsRoot
        LabRootPath   = $LabRootPath
        LabOU         = $Script:OU.Root
        Counters      = $Script:Counters
        Objects       = $Script:Manifest
    }
    $manifestObj | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $OutputPath 'lab-foundation-manifest.json') -Encoding UTF8

    # Markdown summary
    $md = New-Object System.Text.StringBuilder
    [void]$md.AppendLine("# BlueTeam-CTF-Lab - Foundation Summary")
    [void]$md.AppendLine("")
    [void]$md.AppendLine("- Generated: $((Get-Date).ToString('u'))")
    [void]$md.AppendLine("- Domain: $($Script:DnsRoot)  (NetBIOS: $($Script:Netbios))")
    [void]$md.AppendLine("- Lab OU: ``$($Script:OU.Root)``")
    [void]$md.AppendLine("- Lab root folder: ``$LabRootPath``")
    [void]$md.AppendLine("- Default lab password (ALL accounts): ``$DefaultUserPassword``")
    [void]$md.AppendLine("")
    [void]$md.AppendLine("## What was created (counts)")
    foreach ($k in $Script:Counters.Keys) { [void]$md.AppendLine("- $k`: $($Script:Counters[$k])") }
    [void]$md.AppendLine("")
    [void]$md.AppendLine("## Hostname / IP plan (fake lab IPs)")
    [void]$md.AppendLine("| Host | Role | IP |")
    [void]$md.AppendLine("|---|---|---|")
    foreach ($h in $HostPlan) { [void]$md.AppendLine("| $($h.Host) | $($h.Role) | $($h.IP) |") }
    [void]$md.AppendLine("")
    [void]$md.AppendLine("## How to investigate this (operator notes)")
    [void]$md.AppendLine("- This foundation is a CLEAN org. No vulnerabilities or attacker traces exist yet.")
    [void]$md.AppendLine("- Run ``02-Create-Attack-Scenarios.ps1`` to layer vulnerable configs + evidence.")
    [void]$md.AppendLine("- All objects live under ``$($Script:OU.Root)`` and ``$LabRootPath`` and are tagged ``$LabTag``.")
    [void]$md.AppendLine("- Remove everything with ``99-Cleanup-Lab.ps1`` (uses lab-foundation-manifest.json).")
    [void]$md.AppendLine("")
    [void]$md.AppendLine("## Created users")
    [void]$md.AppendLine("| Sam | Display | Dept | Title | Enabled |")
    [void]$md.AppendLine("|---|---|---|---|---|")
    foreach ($u in $Script:CreatedUsers) { [void]$md.AppendLine("| $($u.SamAccountName) | $($u.DisplayName) | $($u.Department) | $($u.Title) | $($u.Enabled) |") }
    [void]$md.AppendLine("")
    [void]$md.AppendLine("## Created groups")
    [void]$md.AppendLine("| Group | Scope |")
    [void]$md.AppendLine("|---|---|")
    foreach ($g in ($Script:CreatedGroups | Sort-Object Name -Unique)) { [void]$md.AppendLine("| $($g.Name) | $($g.Scope) |") }

    $md.ToString() | Set-Content (Join-Path $OutputPath 'lab-foundation-summary.md') -Encoding UTF8
    Write-LabLog "Documentation written to $OutputPath" 'OK'
}

function Write-FinalSummary {
    Write-Host ''
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host ' BlueTeam-CTF-Lab :: Foundation build complete' -ForegroundColor Cyan
    Write-Host '============================================================' -ForegroundColor Cyan
    foreach ($k in $Script:Counters.Keys) { Write-Host (" {0,-12}: {1}" -f $k, $Script:Counters[$k]) -ForegroundColor White }
    Write-Host ''
    Write-Host " Lab OU       : $($Script:OU.Root)" -ForegroundColor Gray
    Write-Host " Lab folder   : $LabRootPath" -ForegroundColor Gray
    Write-Host " Default pass : $DefaultUserPassword  (LAB ONLY)" -ForegroundColor Yellow
    Write-Host " Output       : $OutputPath" -ForegroundColor Gray
    Write-Host " Manifest     : $(Join-Path $OutputPath 'lab-foundation-manifest.json')" -ForegroundColor Gray
    Write-Host ''
    Write-Host ' NEXT STEP    : Run 02-Create-Attack-Scenarios.ps1 to add vulnerabilities + evidence.' -ForegroundColor Green
    Write-Host ' This script created a CLEAN org only - no attack, no vulnerabilities, no artifacts of compromise.' -ForegroundColor Green
    Write-Host ''
}

# ============================================================================
#  MAIN
# ============================================================================
try {
    Initialize-LabPaths
    Write-LabLog '=== 01-Build-Lab-Foundation.ps1 started ===' 'STEP'
    Write-LabLog 'LAB / ISOLATED USE ONLY. Builds a clean org; no attack content.' 'WARN'
    Import-LabConfig
    Test-Prerequisites

    Build-OUStructure
    Build-Groups
    Build-Users
    Build-Memberships
    Build-Computers
    Build-FileShares
    Build-EmailArtifacts

    Export-Documentation
    Write-FinalSummary
    Write-LabLog '=== 01-Build-Lab-Foundation.ps1 completed successfully ===' 'OK'
}
catch {
    $Script:Counters.Errors++
    Write-LabLog "FATAL: $($_.Exception.Message)" 'ERROR'
    Write-LabLog $_.ScriptStackTrace 'ERROR'
    throw
}
