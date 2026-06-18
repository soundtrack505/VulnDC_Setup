#requires -Version 5.1
<#
.SYNOPSIS
    BlueTeam-CTF-Lab :: 02-Create-Attack-Scenarios.ps1
    STAGES intentionally-vulnerable configurations and pre-built investigation
    evidence on top of an EXISTING lab. It does NOT build the base lab and it does
    NOT perform any attack.

.DESCRIPTION
    CRITICAL SAFETY MODEL - this script only PREPARES conditions + evidence:
      * No malware / exploit code / weaponized documents.
      * No real credential access or dumping. All credentials are FAKE lab strings.
      * "Persistence" objects are INERT: the scheduled task action only Add-Content's
        to a local text file; the "backdoor user" is just an AD user with a suspicious
        description - the script creates it but never authenticates or uses it.
      * No security tooling is disabled; no destructive actions.
      * Operates only on configurable lab object names; validates before every change;
        never touches objects outside the configured Lab OU / lab root folder.
      * Every misconfiguration carries an inline "LAB ONLY" risk comment.
      * Fully idempotent; writes attack-scenario-state.json so 99-Cleanup-Attack-Scenarios.ps1
        can revert every created/modified object, ACL, file, task, GPO and log source.

.NOTES
    LAB / ISOLATED USE ONLY. Run on the lab DC with Domain Admin rights.
    Config: Config\attack-scenario-config.json (runtime) + Config\vulnerabilities.json (doc metadata).
#>

[CmdletBinding()]
param(
    [string]$ConfigPath   = '',
    [string]$VulnCatalog  = '',
    [string]$LabRootPath  = ''
)

$ErrorActionPreference = 'Stop'
$LabTag = 'BlueTeam-CTF-Lab'

# ----------------------------------------------------------------------------
#  Resolve config paths
# ----------------------------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($ConfigPath))  { $ConfigPath  = Join-Path $PSScriptRoot 'Config\attack-scenario-config.json' }
if ([string]::IsNullOrWhiteSpace($VulnCatalog)) { $VulnCatalog = Join-Path $PSScriptRoot 'Config\vulnerabilities.json' }

# ============================================================================
#  GLOBAL STATE / TRACKERS
# ============================================================================
$Script:State        = New-Object System.Collections.Generic.List[object]   # cleanup ledger
$Script:Artifacts    = New-Object System.Collections.Generic.List[object]
$Script:Permissions  = New-Object System.Collections.Generic.List[object]
$Script:Modified     = New-Object System.Collections.Generic.List[object]
$Script:Summary      = New-Object System.Collections.Generic.List[object]
$Script:Counters     = [ordered]@{ Modules=0; Configs=0; Artifacts=0; Skipped=0; Errors=0 }

# ============================================================================
#  CORE HELPERS
# ============================================================================
function Write-LabLog {
    param([Parameter(Mandatory)][string]$Message,[ValidateSet('INFO','OK','WARN','ERROR','STEP')][string]$Level='INFO')
    $ts=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); $line="[{0}] [{1,-5}] {2}" -f $ts,$Level,$Message
    $c=switch($Level){'OK'{'Green'}'WARN'{'Yellow'}'ERROR'{'Red'}'STEP'{'Cyan'}default{'Gray'}}
    Write-Host $line -ForegroundColor $c
    try { Add-Content -Path $Script:LogFile -Value $line -ErrorAction SilentlyContinue } catch {}
}

# Record a reversible action in the state ledger (consumed by the cleanup script).
function Add-State {
    param(
        [Parameter(Mandatory)][ValidateSet('UserCreated','GroupCreated','GroupMember','SPN','PreAuth',
            'DescriptionChanged','PasswordChanged','ADACE','GpoCreated','ScheduledTask','LocalAdmin',
            'Artifact','EventSource')][string]$Type,
        [Parameter(Mandatory)][string]$Identity,
        [string]$Target='', [hashtable]$Data=@{}, [string]$Module=''
    )
    $Script:State.Add([pscustomobject]@{
        Type=$Type; Identity=$Identity; Target=$Target; Module=$Module
        Data=$Data; Tag=$LabTag; Created=(Get-Date).ToString('o')
    })
}

function Add-Summary {
    param([string]$Module,[string]$Item,[string]$Risk,[string]$Evidence,[string]$Mitre='')
    $Script:Summary.Add([pscustomobject]@{ Module=$Module; Item=$Item; Risk=$Risk; Evidence=$Evidence; MITRE=$Mitre })
}

function New-ArtifactFile {
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$Content,[string]$Module='',[switch]$Force)
    $dir = Split-Path $Path -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if ((Test-Path $Path) -and -not $Force) { $Script:Counters.Skipped++; return }
    Set-Content -Path $Path -Value $Content -Encoding UTF8
    Write-LabLog "Artifact: $Path" 'OK'
    $Script:Counters.Artifacts++
    $Script:Artifacts.Add([pscustomobject]@{ Module=$Module; Path=$Path })
    Add-State -Type 'Artifact' -Identity (Split-Path $Path -Leaf) -Target $Path -Module $Module
}

function Test-InLabScope {
    param([string]$DistinguishedName)
    return ($DistinguishedName -like "*$($Script:LabOuDn)")
}

# Timeline timestamp helper: base time + N minutes, ISO 8601 (Zulu).
function T { param([int]$Minutes) ($Script:Base.AddMinutes($Minutes)).ToString('s') + 'Z' }

# ---- Multi-format SIEM/firewall export (CSV / JSON / CEF / LEEF) ----
function Convert-ToCef {
    param([object]$E)
    $ext="rt=$($E.TimeStamp) src=$($E.SrcIp) dst=$($E.DstIp) suser=$($E.Account) shost=$($E.SrcHost) dhost=$($E.DstHost) act=$($E.Action) cs1Label=Technique cs1=$($E.Technique) cs2Label=Module cs2=$($E.Module) msg=$($E.Detail)"
    "CEF:0|$LabTag|BlueTeamCTF|1.0|$($E.EventName)|$($E.EventName)|$($E.Severity)|$ext"
}
function Convert-ToLeef {
    param([object]$E)
    $t="`t"
    "LEEF:2.0|$LabTag|BlueTeamCTF|1.0|$($E.EventName)|devTime=$($E.TimeStamp)${t}src=$($E.SrcIp)${t}dst=$($E.DstIp)${t}usrName=$($E.Account)${t}srcHost=$($E.SrcHost)${t}dstHost=$($E.DstHost)${t}action=$($E.Action)${t}technique=$($E.Technique)${t}module=$($E.Module)${t}msg=$($E.Detail)"
}
function Export-MultiFormat {
    param([Parameter(Mandatory)][object[]]$Events,[Parameter(Mandatory)][string]$BasePath,[string]$Module='')
    $Events | Export-Csv "$BasePath.csv" -NoTypeInformation -Encoding UTF8
    $Events | ConvertTo-Json -Depth 4 | Set-Content "$BasePath.json" -Encoding UTF8
    ($Events | ForEach-Object { Convert-ToCef  $_ }) | Set-Content "$BasePath.cef"  -Encoding UTF8
    ($Events | ForEach-Object { Convert-ToLeef $_ }) | Set-Content "$BasePath.leef" -Encoding UTF8
    foreach ($ext in 'csv','json','cef','leef') {
        $p="$BasePath.$ext"
        $Script:Artifacts.Add([pscustomobject]@{ Module=$Module; Path=$p })
        Add-State -Type 'Artifact' -Identity (Split-Path $p -Leaf) -Target $p -Module $Module
    }
    Write-LabLog "Multi-format log: $BasePath.{csv,json,cef,leef}" 'OK'
    $Script:Counters.Artifacts += 4
}

# ============================================================================
#  BOOTSTRAP / VALIDATION
# ============================================================================
function Initialize-Scenario {
    # Load runtime config
    if (-not (Test-Path $ConfigPath)) { throw "Config not found: $ConfigPath" }
    $Script:Cfg  = Get-Content $ConfigPath -Raw | ConvertFrom-Json
    $Script:Mod  = $Script:Cfg.Modules
    $Script:P    = $Script:Cfg.Parameters
    $Script:Safe = $Script:Cfg.SafetyToggles
    $Script:Net  = $Script:Cfg.Network

    if ([string]::IsNullOrWhiteSpace($LabRootPath)) { $LabRootPath = $Script:Cfg.Paths.LabRoot }
    $Script:LabRoot   = $LabRootPath
    $Script:OutputPath= Join-Path $LabRootPath 'Output'
    $Script:LogPath   = Join-Path $Script:OutputPath 'Logs'
    $Script:Artif     = Join-Path $LabRootPath 'Artifacts'
    $Script:Shares    = Join-Path $LabRootPath 'Shares'
    $Script:Endpoint  = Join-Path $Script:Artif 'Endpoint'
    $Script:Emails    = Join-Path $Script:Artif 'Emails'
    $Script:Firewall  = Join-Path $Script:Artif 'Firewall'
    $Script:Siem      = Join-Path $Script:Artif 'SIEM'
    foreach ($p in @($Script:OutputPath,$Script:LogPath,$Script:Artif,$Script:Endpoint,$Script:Emails,$Script:Firewall,$Script:Siem)) {
        if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
    }
    $Script:LogFile = Join-Path $Script:LogPath ("02-Create-Attack-Scenarios_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

    Write-LabLog '=== 02-Create-Attack-Scenarios.ps1 started ===' 'STEP'
    Write-LabLog 'LAB / ISOLATED USE ONLY. Stages SAFE vulnerable configs + benign evidence. No attacks performed.' 'WARN'

    Import-Module ActiveDirectory -ErrorAction Stop
    $d = Get-ADDomain -ErrorAction Stop
    $Script:DnsRoot = if ($Script:Cfg.Domain.AutoDetect) { $d.DNSRoot }     else { $Script:Cfg.Domain.DnsRoot }
    $Script:Netbios = if ($Script:Cfg.Domain.AutoDetect) { $d.NetBIOSName } else { $Script:Cfg.Domain.NetBIOS }

    # Lab OU scope (every AD change is checked against this)
    $Script:LabOuDn = if ($Script:Cfg.Scope.AutoDetectFromFoundation) {
        $fm = Join-Path $Script:OutputPath 'lab-foundation-manifest.json'
        if (Test-Path $fm) { (Get-Content $fm -Raw | ConvertFrom-Json).LabOU } else { "OU=Lab,$($d.DistinguishedName)" }
    } else { $Script:Cfg.Scope.LabOuDn }

    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$($Script:LabOuDn)'" -ErrorAction SilentlyContinue)) {
        throw "Lab OU '$($Script:LabOuDn)' not found. The base lab must exist before staging scenarios."
    }
    Write-LabLog "Domain=$($Script:DnsRoot)  NetBIOS=$($Script:Netbios)  LabOU=$($Script:LabOuDn)" 'OK'

    $Script:Base = [datetime]$Script:P.TimelineBaseUtc
    if (Test-Path $VulnCatalog) { $Script:Catalog = Get-Content $VulnCatalog -Raw | ConvertFrom-Json } else { $Script:Catalog = $null }
}

# Validate an existing lab user is present AND inside lab scope before modifying it.
function Resolve-LabUser {
    param([Parameter(Mandatory)][string]$Sam)
    $u = Get-ADUser -Filter "SamAccountName -eq '$Sam'" -Properties Description,ServicePrincipalNames,DistinguishedName -ErrorAction SilentlyContinue
    if (-not $u)                       { Write-LabLog "User '$Sam' not found - skipping." 'WARN'; return $null }
    if (-not (Test-InLabScope $u.DistinguishedName)) { Write-LabLog "User '$Sam' is OUTSIDE lab scope - refusing to modify." 'WARN'; return $null }
    return $u
}

# ============================================================================
#  MODULE 1 :: Phishing Initial Access Artifacts        T1566.001 / T1204.002
# ============================================================================
function Invoke-M01-Phishing {
    if (-not $Script:Mod.EnablePhishingArtifacts) { return }
    Write-LabLog 'M01: Phishing initial-access artifacts...' 'STEP'; $Script:Counters.Modules++
    try {
        $u=$Script:P.PhishingTargetUser; $h=$Script:P.PhishingVictimHost
        $att=$Script:P.PhishingAttachmentName; $url=$Script:P.PhishingUrl
        $eml=@"
From: $($Script:P.PhishingSenderAddress)
To: $u@$($Script:DnsRoot)
Date: $(T 0)
Subject: $($Script:P.PhishingSubject)
Message-ID: <phish-001@$($Script:Net.SuspiciousDomain)>
X-Lab-Artifact: $LabTag (SIMULATED phishing - benign)
X-Originating-IP: [$($Script:Net.ExternalAttackerIP)]
Content-Type: text/plain; charset="utf-8"

Dear $u,

Please find attached your outstanding invoice for June 2026.
Open the attached document and enable content to view the secure invoice.

Attachment: $att
Secure link: $url

Regards,
Billing Department
"@
        New-ArtifactFile -Path (Join-Path $Script:Emails 'Inbox\phishing_email_001.eml') -Content $eml -Module 'M01-Phishing'
        # RISK: malicious attachment placeholder. This is NOT a real macro doc - benign text only.
        New-ArtifactFile -Path (Join-Path $Script:Endpoint "$h\Downloads\$att.txt") -Module 'M01-Phishing' -Content @"
[$LabTag] BENIGN PLACEHOLDER - not a real Office document, no macro/payload.
Represents the attachment '$att' the user downloaded from the phishing email.
SHA256 (fake/lab): 0000000000000000000000000000000000000000000000000000000000000000
"@
        New-ArtifactFile -Path (Join-Path $Script:Endpoint "$h\UserActivity\recent_files.txt") -Module 'M01-Phishing' -Content @"
$(T 2)  C:\Users\$u\Downloads\$att
$(T 3)  C:\Users\$u\AppData\Local\Temp\$att
$(T 4)  C:\Users\$u\Documents\notes.txt
"@
        $hist=@(
            [pscustomobject]@{ Visited=(T -5); Url='https://intranet.lab.local/home'; Title='Company Intranet' }
            [pscustomobject]@{ Visited=(T 0);  Url="http://$($Script:Net.SuspiciousDomain)/invoice/june"; Title='Invoice Portal' }
            [pscustomobject]@{ Visited=(T 1);  Url="http://$($Script:Net.SuspiciousDomain)/download"; Title='Download' }
        )
        $bp=Join-Path $Script:Endpoint "$h\BrowserHistory\history.csv"
        if (-not (Test-Path (Split-Path $bp -Parent))) { New-Item -ItemType Directory -Path (Split-Path $bp -Parent) -Force | Out-Null }
        $hist | Export-Csv $bp -NoTypeInformation -Encoding UTF8
        $Script:Artifacts.Add([pscustomobject]@{ Module='M01-Phishing'; Path=$bp }); Add-State -Type 'Artifact' -Identity 'history.csv' -Target $bp -Module 'M01-Phishing'
        Add-Summary 'M01 Phishing' "Email to $u, attachment '$att'" 'Initial access via spearphishing attachment' "Emails\Inbox\phishing_email_001.eml; Endpoint\$h\*" 'T1566.001'
        $Script:Counters.Configs++
    } catch { Write-LabLog "M01 failed: $($_.Exception.Message)" 'ERROR'; $Script:Counters.Errors++ }
}

# ============================================================================
#  MODULE 2 :: Kerberoastable Service Account                       T1558.003
# ============================================================================
function Invoke-M02-Kerberoast {
    if (-not $Script:Mod.EnableKerberoastingUser) { return }
    Write-LabLog 'M02: Kerberoastable service account...' 'STEP'; $Script:Counters.Modules++
    try {
        $acct=$Script:P.KerberoastAccount
        $u = Resolve-LabUser $acct; if (-not $u) { return }
        foreach ($spn in $Script:P.KerberoastSpns) {
            if ($u.ServicePrincipalNames -notcontains $spn) {
                Set-ADUser -Identity $acct -ServicePrincipalNames @{Add=$spn}
                Write-LabLog "Added SPN '$spn' to $acct" 'OK'
                Add-State -Type 'SPN' -Identity $acct -Target $spn -Module 'M02-Kerberoast'
            } else { $Script:Counters.Skipped++ }
        }
        # RISK: an SPN-bearing account's TGS is encrypted with its password hash. Any domain
        # user can request it and crack it offline (Kerberoasting). Weak password makes it trivial.
        $oldDesc=$u.Description
        Set-ADUser -Identity $acct -Description "LAB ONLY - Intentionally Kerberoastable Account [$LabTag]"
        Add-State -Type 'DescriptionChanged' -Identity $acct -Data @{ OldValue=$oldDesc } -Module 'M02-Kerberoast'
        try {
            Set-ADAccountPassword -Identity $acct -Reset -NewPassword (ConvertTo-SecureString $Script:P.KerberoastWeakPassword -AsPlainText -Force)
            Add-State -Type 'PasswordChanged' -Identity $acct -Data @{ Note='weak lab password set'; RestoreTo=$Script:P.RestoreDefaultPassword } -Module 'M02-Kerberoast'
        } catch { Write-LabLog "Weak pwd not set for $acct (policy): $($_.Exception.Message)" 'WARN' }
        Add-Summary 'M02 Kerberoast' "$acct SPNs: $($Script:P.KerberoastSpns -join ', ')" 'SPN + weak password = Kerberoastable' 'AD: servicePrincipalName attribute' 'T1558.003'
        $Script:Counters.Configs++
    } catch { Write-LabLog "M02 failed: $($_.Exception.Message)" 'ERROR'; $Script:Counters.Errors++ }
}

# ============================================================================
#  MODULE 3 :: AS-REP Roastable User                               T1558.004
# ============================================================================
function Invoke-M03-AsrepRoast {
    if (-not $Script:Mod.EnableASREPRoastingUser) { return }
    Write-LabLog 'M03: AS-REP roastable user...' 'STEP'; $Script:Counters.Modules++
    try {
        $acct=$Script:P.AsrepRoastAccount
        $u = Resolve-LabUser $acct; if (-not $u) { return }
        # RISK: disabling Kerberos pre-auth lets anyone request an AS-REP whose encrypted part
        # is derived from the user's hash -> offline cracking (AS-REP roasting).
        Set-ADAccountControl -Identity $acct -DoesNotRequirePreAuthentication $true
        Add-State -Type 'PreAuth' -Identity $acct -Data @{ Set=$true } -Module 'M03-AsrepRoast'
        $oldDesc=$u.Description
        Set-ADUser -Identity $acct -Description "LAB ONLY - Intentionally AS-REP Roastable Account [$LabTag]"
        Add-State -Type 'DescriptionChanged' -Identity $acct -Data @{ OldValue=$oldDesc } -Module 'M03-AsrepRoast'
        try {
            Set-ADAccountPassword -Identity $acct -Reset -NewPassword (ConvertTo-SecureString $Script:P.AsrepWeakPassword -AsPlainText -Force)
            Add-State -Type 'PasswordChanged' -Identity $acct -Data @{ Note='weak lab password set'; RestoreTo=$Script:P.RestoreDefaultPassword } -Module 'M03-AsrepRoast'
        } catch { Write-LabLog "Weak pwd not set for $acct (policy): $($_.Exception.Message)" 'WARN' }
        Write-LabLog "Disabled Kerberos pre-auth on $acct" 'OK'
        Add-Summary 'M03 AS-REP' $acct 'Pre-auth disabled -> AS-REP roastable' 'AD: userAccountControl DONT_REQ_PREAUTH' 'T1558.004'
        $Script:Counters.Configs++
    } catch { Write-LabLog "M03 failed: $($_.Exception.Message)" 'ERROR'; $Script:Counters.Errors++ }
}

# ============================================================================
#  MODULE 4 :: Vulnerable DACL (GenericAll / WriteDACL)                T1098
# ============================================================================
function Invoke-M04-VulnerableDacl {
    if (-not $Script:Mod.EnableVulnerableDACL) { return }
    Write-LabLog 'M04: Vulnerable DACL...' 'STEP'; $Script:Counters.Modules++
    try {
        $grp=$Script:P.DaclPrincipalGroup; $target=$Script:P.DaclTargetUser; $rightName=$Script:P.DaclRight
        if (-not (Get-ADGroup -Filter "Name -eq '$grp'" -ErrorAction SilentlyContinue)) {
            $secOu="OU=Security Groups,OU=Groups,$($Script:LabOuDn)"
            if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$secOu'" -ErrorAction SilentlyContinue)) { $secOu=$Script:LabOuDn }
            New-ADGroup -Name $grp -SamAccountName $grp -GroupScope Global -GroupCategory Security -Path $secOu `
                -Description "LAB ONLY - holds excessive AD rights [$LabTag]"
            Write-LabLog "Created DACL principal group: $grp" 'OK'
            Add-State -Type 'GroupCreated' -Identity $grp -Module 'M04-DACL'
        }
        if (Get-ADUser -Filter "SamAccountName -eq 'dan.levi'" -ErrorAction SilentlyContinue) {
            if (-not (Get-ADGroupMember $grp | Where-Object SamAccountName -eq 'dan.levi')) {
                Add-ADGroupMember -Identity $grp -Members 'dan.levi'
                Add-State -Type 'GroupMember' -Identity $grp -Target 'dan.levi' -Module 'M04-DACL'
            }
        }
        $tObj = Resolve-LabUser $target; if (-not $tObj) { return }
        $tDN  = $tObj.DistinguishedName
        $sid  = (Get-ADGroup -Identity $grp).SID
        $right = if ($rightName -eq 'WriteDacl') { [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl } else { [System.DirectoryServices.ActiveDirectoryRights]::GenericAll }
        # RISK: GenericAll/WriteDACL over a privileged service account allows password reset,
        # targeted SPN abuse, or full takeover of svc_backup.
        $acl = Get-Acl "AD:\$tDN"
        $already = $acl.Access | Where-Object {
            ($_.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) -and
            ($_.IdentityReference.Value -eq $sid.Value) -and ($_.ActiveDirectoryRights -match $rightName) }
        if (-not $already) {
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid,$right,[System.Security.AccessControl.AccessControlType]::Allow)
            $acl.AddAccessRule($ace); Set-Acl "AD:\$tDN" $acl
            Write-LabLog "Granted $rightName : $grp -> $target" 'OK'
            Add-State -Type 'ADACE' -Identity $grp -Target $tDN -Data @{ Sid=$sid.Value; Right=$rightName } -Module 'M04-DACL'
        } else { $Script:Counters.Skipped++ }
        $Script:Permissions.Add([pscustomobject]@{ Principal=$grp; Right=$rightName; TargetObject=$target; TargetDN=$tDN; Risk='Full control over svc_backup (reset pwd / targeted Kerberoast / takeover)' })
        Add-Summary 'M04 DACL' "$grp has $rightName over $target" 'Excessive AD rights -> object takeover' 'Output\created-permissions.csv; AD ACL on target' 'T1098'
        $Script:Counters.Configs++
    } catch { Write-LabLog "M04 failed: $($_.Exception.Message)" 'ERROR'; $Script:Counters.Errors++ }
}

# ============================================================================
#  MODULE 5 :: Excessive / Nested Group Membership                     T1098
# ============================================================================
function Invoke-M05-ExcessiveMembership {
    if (-not $Script:Mod.EnableExcessiveGroupMembership) { return }
    Write-LabLog 'M05: Excessive nested group membership...' 'STEP'; $Script:Counters.Modules++
    try {
        $child=$Script:P.ExcessiveMemberGroup; $parent=$Script:P.ExcessiveParentGroup
        foreach ($g in @($child,$parent)) { if (-not (Get-ADGroup -Filter "Name -eq '$g'" -ErrorAction SilentlyContinue)) { Write-LabLog "Group '$g' missing - skipping M05." 'WARN'; return } }
        # RISK: nesting Helpdesk_Operators INTO Workstation_Admins silently grants every helpdesk
        # technician workstation-admin rights -> lateral movement enabler.
        if (-not (Get-ADGroupMember $parent | Where-Object Name -eq $child)) {
            Add-ADGroupMember -Identity $parent -Members $child
            Write-LabLog "Nested '$child' into '$parent'" 'OK'
            Add-State -Type 'GroupMember' -Identity $parent -Target $child -Module 'M05-Nesting'
        } else { $Script:Counters.Skipped++ }
        if (Get-ADGroup -Filter "Name -eq 'GG_Server_Operators'" -ErrorAction SilentlyContinue) {
            if (-not (Get-ADGroupMember 'GG_Server_Operators' | Where-Object Name -eq $child)) {
                Add-ADGroupMember -Identity 'GG_Server_Operators' -Members $child
                Add-State -Type 'GroupMember' -Identity 'GG_Server_Operators' -Target $child -Module 'M05-Nesting'
            }
        }
        Add-Summary 'M05 Nesting' "$child nested into $parent" 'Helpdesk inherits workstation-admin rights' 'AD: group memberOf chain' 'T1098'
        $Script:Counters.Configs++
    } catch { Write-LabLog "M05 failed: $($_.Exception.Message)" 'ERROR'; $Script:Counters.Errors++ }
}

# ============================================================================
#  MODULE 6 :: Local Admin Misconfiguration                            T1078
# ============================================================================
function Invoke-M06-LocalAdmin {
    if (-not $Script:Mod.EnableLocalAdminMisconfiguration) { return }
    Write-LabLog 'M06: Local admin misconfiguration...' 'STEP'; $Script:Counters.Modules++
    try {
        $h=$Script:P.LocalAdminHost; $princ=$Script:P.LocalAdminPrincipal; $applied='Simulated (documented only)'
        if ($Script:Safe.ApplyLocalAdminRemotely -and (Test-Connection -ComputerName $h -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            try {
                Invoke-Command -ComputerName $h -ScriptBlock { param($p,$nb) Add-LocalGroupMember -Group 'Administrators' -Member "$nb\$p" -ErrorAction SilentlyContinue } -ArgumentList $princ,$Script:Netbios
                $applied="Applied on $h"
                Add-State -Type 'LocalAdmin' -Identity $princ -Target $h -Data @{ NetBIOS=$Script:Netbios } -Module 'M06-LocalAdmin'
                Write-LabLog $applied 'OK'
            } catch { Write-LabLog "Remote apply failed; using simulated artifact. $($_.Exception.Message)" 'WARN' }
        }
        # RISK: a domain group as local admin means (via M05 nesting) all Helpdesk Operators are
        # admin on $h -> lateral movement / token theft surface.
        New-ArtifactFile -Path (Join-Path $Script:Endpoint "$h\LocalGroups\local_administrators.txt") -Module 'M06-LocalAdmin' -Content @"
[$LabTag] Local Administrators of $h  ($applied)
$($Script:Netbios)\Domain Admins
$($Script:Netbios)\$princ      <-- RISK: domain group is local admin; nested Helpdesk Operators inherit it
BUILTIN\Administrators
"@
        Add-Summary 'M06 LocalAdmin' "$princ is local admin on $h" 'Local admin via group -> lateral movement' "Endpoint\$h\LocalGroups\local_administrators.txt" 'T1078'
        $Script:Counters.Configs++
    } catch { Write-LabLog "M06 failed: $($_.Exception.Message)" 'ERROR'; $Script:Counters.Errors++ }
}

# ============================================================================
#  MODULE 7 :: Fake Credentials in Share                            T1552.001
# ============================================================================
function Invoke-M07-WeakCredsShare {
    if (-not $Script:Mod.EnableWeakCredentialsShare) { return }
    Write-LabLog 'M07: Fake credentials in file share...' 'STEP'; $Script:Counters.Modules++
    try {
        $folder=Join-Path $Script:Shares $Script:P.WeakCredShareFolder
        if (-not (Test-Path $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
        $acct=$Script:P.WeakCredExposedAccount; $pwd=$Script:P.WeakCredExposedPassword
        # RISK: plaintext credentials in a readable share (unsecured credentials). FAKE lab values.
        New-ArtifactFile -Path (Join-Path $folder 'old_backup_credentials.txt') -Module 'M07-WeakCreds' -Content @"
[$LabTag] LAB-ONLY FAKE CREDENTIALS - not real, do not use.
domain   : $($Script:DnsRoot)
username : $($Script:Netbios)\$acct
password : $pwd
note     : used by nightly backup task on the file server
"@
        New-ArtifactFile -Path (Join-Path $folder 'service_account_notes.txt') -Module 'M07-WeakCreds' -Content @"
[$LabTag] LAB-ONLY notes (fake).
svc_sql    - SQL service, last pwd: $($Script:P.KerberoastWeakPassword)
svc_backup - see old_backup_credentials.txt
"@
        New-ArtifactFile -Path (Join-Path $folder 'deployment_config.xml') -Module 'M07-WeakCreds' -Content @"
<?xml version="1.0"?>
<!-- $LabTag LAB-ONLY fake deployment config -->
<deployment><serviceAccount user="$($Script:Netbios)\$acct" password="$pwd" /><target host="WS02" share="C$" /></deployment>
"@
        New-ArtifactFile -Path (Join-Path $folder 'passwords_archive.txt') -Module 'M07-WeakCreds' -Content @"
[$LabTag] LAB-ONLY fake archive.
wifi-guest : Guest2026
$acct : $pwd
"@
        Add-Summary 'M07 WeakCreds' "Exposed $acct password in $($Script:P.WeakCredShareFolder) share" 'Plaintext creds in readable share' "Shares\$($Script:P.WeakCredShareFolder)\old_backup_credentials.txt" 'T1552.001'
        $Script:Counters.Configs++
    } catch { Write-LabLog "M07 failed: $($_.Exception.Message)" 'ERROR'; $Script:Counters.Errors++ }
}

# ============================================================================
#  MODULE 8 :: Inert Suspicious Scheduled Task                      T1053.005
# ============================================================================
function Invoke-M08-ScheduledTask {
    if (-not $Script:Mod.EnableScheduledTaskPersistence) { return }
    Write-LabLog 'M08: Inert suspicious scheduled task...' 'STEP'; $Script:Counters.Modules++
    try {
        $name=$Script:P.ScheduledTaskName; $h=$Script:P.ScheduledTaskHost
        $heartbeat=Join-Path $Script:Endpoint "$h\persistence_heartbeat.txt"
        $hbDir=Split-Path $heartbeat -Parent; if (-not (Test-Path $hbDir)) { New-Item -ItemType Directory -Path $hbDir -Force | Out-Null }
        # RISK: a legit-sounding task launching powershell at startup is a classic persistence
        # pattern. The ACTION here is INERT - it only appends a heartbeat line to a local file.
        $cmd="-ExecutionPolicy Bypass -Command `"Add-Content '$heartbeat' ('Task executed ' + (Get-Date).ToString('o'))`""
        if ($Script:Safe.RegisterScheduledTaskLocally) {
            if (-not (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue)) {
                $action =New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $cmd
                $trigger=New-ScheduledTaskTrigger -AtStartup
                $set    =New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
                Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Settings $set `
                    -Description "$LabTag inert persistence simulation" -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
                Write-LabLog "Registered scheduled task '$name' (inert)" 'OK'
                Add-State -Type 'ScheduledTask' -Identity $name -Target 'localhost' -Module 'M08-SchedTask'
            } else { $Script:Counters.Skipped++ }
        } else { Write-LabLog 'RegisterScheduledTaskLocally=false -> documentation artifact only.' 'INFO' }
        New-ArtifactFile -Path (Join-Path $Script:Endpoint "$h\ScheduledTasks\$name.txt") -Module 'M08-SchedTask' -Content @"
[$LabTag] Scheduled task evidence (host $h)
TaskName : $name
Trigger  : At system startup
RunAs    : SYSTEM
Action   : powershell.exe $cmd
Created  : $(T 95)
Note     : INERT - action only writes a heartbeat line. Suspicious NAME + powershell startup = persistence pattern.
"@
        Add-Summary 'M08 SchedTask' "$name on $h" 'Inert scheduled-task persistence' "Endpoint\$h\ScheduledTasks\$name.txt; Event 4698" 'T1053.005'
        $Script:Counters.Configs++
    } catch { Write-LabLog "M08 failed: $($_.Exception.Message)" 'ERROR'; $Script:Counters.Errors++ }
}

# ============================================================================
#  MODULE 9 :: Inert Backdoor Domain User                           T1136.002
# ============================================================================
function Invoke-M09-BackdoorUser {
    if (-not $Script:Mod.EnableBackdoorDomainUser) { return }
    Write-LabLog 'M09: Inert backdoor domain user...' 'STEP'; $Script:Counters.Modules++
    try {
        $sam=$Script:P.BackdoorUser; $grp=$Script:P.BackdoorGroup
        $svcOu="OU=Service Accounts,OU=Users,$($Script:LabOuDn)"
        if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$svcOu'" -ErrorAction SilentlyContinue)) { $svcOu=$Script:LabOuDn }
        if (-not (Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue)) {
            # RISK: an unmanaged account with a service-like name + privileged group = stealth
            # persistence. INERT - the script never authenticates as this account.
            New-ADUser -Name $sam -SamAccountName $sam -UserPrincipalName "$sam@$($Script:DnsRoot)" -DisplayName $sam `
                -Description "LAB ONLY - Suspicious/backdoor account (created out-of-process) [$LabTag]" `
                -AccountPassword (ConvertTo-SecureString $Script:P.BackdoorPassword -AsPlainText -Force) `
                -Enabled $true -PasswordNeverExpires $true -Path $svcOu
            Write-LabLog "Created inert backdoor user: $sam" 'OK'
            Add-State -Type 'UserCreated' -Identity $sam -Target $svcOu -Module 'M09-Backdoor'
        } else { $Script:Counters.Skipped++ }
        if ($grp -and (Get-ADGroup -Filter "Name -eq '$grp'" -ErrorAction SilentlyContinue)) {
            if (-not (Get-ADGroupMember $grp | Where-Object SamAccountName -eq $sam)) {
                Add-ADGroupMember -Identity $grp -Members $sam
                Add-State -Type 'GroupMember' -Identity $grp -Target $sam -Module 'M09-Backdoor'
            }
        }
        New-ArtifactFile -Path (Join-Path $Script:Endpoint "DC01\Auth\account_creation_evidence.txt") -Module 'M09-Backdoor' -Content @"
[$LabTag] Suspicious account creation evidence (DC01)
$(T 130)  Event 4720 - User account created: $sam
$(T 131)  Event 4728/4732 - $sam added to $grp
Note: created outside normal IT provisioning workflow.
"@
        Add-Summary 'M09 Backdoor' "$sam (member of $grp)" 'Inert backdoor/persistence account' "Endpoint\DC01\Auth\account_creation_evidence.txt; Event 4720/4732" 'T1136.002'
        $Script:Counters.Configs++
    } catch { Write-LabLog "M09 failed: $($_.Exception.Message)" 'ERROR'; $Script:Counters.Errors++ }
}

# ============================================================================
#  MODULE 10 :: Suspicious GPO / Delegated ACL                      T1484.001
# ============================================================================
function Invoke-M10-GpoPersistence {
    if (-not $Script:Mod.EnableGPOOrACLPersistence) { return }
    Write-LabLog 'M10: Suspicious GPO / delegation...' 'STEP'; $Script:Counters.Modules++
    try {
        if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
            Write-LabLog 'GroupPolicy module unavailable -> writing documentation artifact only.' 'WARN'
        } else {
            Import-Module GroupPolicy -ErrorAction Stop
            $gpoName=$Script:P.GpoName; $deleg=$Script:P.GpoDelegateGroup
            if (-not (Get-GPO -Name $gpoName -ErrorAction SilentlyContinue)) {
                # RISK: a GPO is NOT linked (deploys nothing harmful), but a low-priv group is granted
                # edit rights -> they could later push a startup script to every linked machine.
                New-GPO -Name $gpoName -Comment "$LabTag - LAB ONLY suspicious GPO (unlinked, no settings)" | Out-Null
                Write-LabLog "Created GPO '$gpoName' (unlinked, empty)" 'OK'
                Add-State -Type 'GpoCreated' -Identity $gpoName -Module 'M10-GPO'
                if (Get-ADGroup -Filter "Name -eq '$deleg'" -ErrorAction SilentlyContinue) {
                    Set-GPPermission -Name $gpoName -TargetName $deleg -TargetType Group -PermissionLevel GpoEditDeleteModifySecurity -Replace | Out-Null
                    Write-LabLog "Delegated edit rights on '$gpoName' to '$deleg'" 'OK'
                }
            } else { $Script:Counters.Skipped++ }
        }
        New-ArtifactFile -Path (Join-Path $Script:Endpoint "DC01\GPO\suspicious_gpo.txt") -Module 'M10-GPO' -Content @"
[$LabTag] Suspicious GPO evidence
GPO       : $($Script:P.GpoName)  (UNLINKED, no settings deployed)
Delegation: $($Script:P.GpoDelegateGroup) has Edit/Modify-Security rights  <-- RISK
Note      : referenced startup script \\$($Script:Net.DC01)\SYSVOL\...\maintenance.ps1 (NOT deployed in lab)
"@
        Add-Summary 'M10 GPO' "$($Script:P.GpoName) editable by $($Script:P.GpoDelegateGroup)" 'GPO edit delegation -> future code push' "Endpoint\DC01\GPO\suspicious_gpo.txt" 'T1484.001'
        $Script:Counters.Configs++
    } catch { Write-LabLog "M10 failed: $($_.Exception.Message)" 'ERROR'; $Script:Counters.Errors++ }
}

# ============================================================================
#  MODULE 11 :: Static Lateral-Movement Evidence            T1021.002 / .001
# ============================================================================
function Invoke-M11-LateralEvidence {
    if (-not $Script:Mod.EnableLateralMovementArtifacts) { return }
    Write-LabLog 'M11: Lateral-movement evidence...' 'STEP'; $Script:Counters.Modules++
    try {
        $src=$Script:P.LateralSourceHost; $dst=$Script:P.LateralDestHost; $acct=$Script:P.LateralAccount
        New-ArtifactFile -Path (Join-Path $Script:Endpoint "$src\PowerShell\console_history.txt") -Module 'M11-Lateral' -Content @"
# $LabTag console history ($src) - benign reconstruction
whoami /groups
net group "Domain Admins" /domain
Get-ADUser -Filter * -Properties ServicePrincipalName | ? { `$_.ServicePrincipalName }
net use \\$dst\C`$ /user:$($Script:Netbios)\$acct ********
Copy-Item .\stage2_tool.txt \\$dst\C`$\Windows\Temp\
Invoke-Command -ComputerName $dst -ScriptBlock { hostname }
"@
        New-ArtifactFile -Path (Join-Path $Script:Endpoint "$dst\RemoteExecution\remote_commands.log") -Module 'M11-Lateral' -Content @"
$(T 60)  [$dst] Inbound session from $src as $($Script:Netbios)\$acct (SMB admin share C$)
$(T 61)  [$dst] File written: C:\Windows\Temp\stage2_tool.txt
$(T 63)  [$dst] WinRM/PSRemoting command: hostname
$(T 70)  [$dst] Outbound auth attempt to DC01 as $acct
"@
        New-ArtifactFile -Path (Join-Path $Script:Endpoint "$dst\Files\stage2_tool.txt") -Module 'M11-Lateral' -Content "[$LabTag] BENIGN placeholder representing a staged tool. No code/payload."
        $auth=@(
            [pscustomobject]@{ Time=(T 60); Src=$src; Dst=$dst; Account=$acct; Logon='Type 3 (Network/SMB)'; Result='Success' }
            [pscustomobject]@{ Time=(T 70); Src=$dst; Dst='DC01'; Account=$acct; Logon='Type 3'; Result='Success' }
            [pscustomobject]@{ Time=(T 72); Src=$dst; Dst='DC01'; Account='adm.itmanager'; Logon='Type 3'; Result='Failure' }
        )
        $ap=Join-Path $Script:Endpoint 'DC01\Auth\admin_logon_attempts.csv'
        if (-not (Test-Path (Split-Path $ap -Parent))) { New-Item -ItemType Directory -Path (Split-Path $ap -Parent) -Force | Out-Null }
        $auth | Export-Csv $ap -NoTypeInformation -Encoding UTF8
        $Script:Artifacts.Add([pscustomobject]@{ Module='M11-Lateral'; Path=$ap }); Add-State -Type 'Artifact' -Identity 'admin_logon_attempts.csv' -Target $ap -Module 'M11-Lateral'
        Add-Summary 'M11 Lateral' "$src -> $dst -> DC01 as $acct" 'Lateral movement via SMB/WinRM' "Endpoint\$dst\*; DC01\Auth\admin_logon_attempts.csv" 'T1021.002'
        $Script:Counters.Configs++
    } catch { Write-LabLog "M11 failed: $($_.Exception.Message)" 'ERROR'; $Script:Counters.Errors++ }
}

# ============================================================================
#  MODULE 12 :: SIEM-Ingestible Kill-Chain Events
# ============================================================================
function Invoke-M12-SiemEvents {
    if (-not $Script:Mod.EnableSIEMFriendlyEventGeneration) { return }
    Write-LabLog 'M12: SIEM-ingestible events...' 'STEP'; $Script:Counters.Modules++
    try {
        $n=$Script:Net
        $ev=@(
            [pscustomobject]@{ TimeStamp=(T 0);   EventName='PhishDelivered';  Tactic='Initial Access'; Technique='T1566.001'; SrcHost='MAILSIM01'; SrcIp=$n.MAILSIM01; DstHost='WS01'; DstIp=$n.WS01; Account=$Script:P.PhishingTargetUser; Action='deliver'; Severity=6; Module='M01'; Detail='Phishing email with attachment delivered' }
            [pscustomobject]@{ TimeStamp=(T 4);   EventName='UserExecution';   Tactic='Execution'; Technique='T1204.002'; SrcHost='WS01'; SrcIp=$n.WS01; DstHost='WS01'; DstIp=$n.WS01; Account=$Script:P.PhishingTargetUser; Action='open-attachment'; Severity=7; Module='M01'; Detail='Attachment opened on WS01' }
            [pscustomobject]@{ TimeStamp=(T 10);  EventName='Discovery';       Tactic='Discovery'; Technique='T1087.002'; SrcHost='WS01'; SrcIp=$n.WS01; DstHost='DC01'; DstIp=$n.DC01; Account=$Script:P.PhishingTargetUser; Action='ad-enum'; Severity=4; Module='M11'; Detail='Domain account/group enumeration' }
            [pscustomobject]@{ TimeStamp=(T 20);  EventName='Kerberoast';      Tactic='Credential Access'; Technique='T1558.003'; SrcHost='WS01'; SrcIp=$n.WS01; DstHost='DC01'; DstIp=$n.DC01; Account=$Script:P.PhishingTargetUser; Action='tgs-request'; Severity=7; Module='M02'; Detail="TGS requested for SPN of $($Script:P.KerberoastAccount)" }
            [pscustomobject]@{ TimeStamp=(T 25);  EventName='AsrepRoast';      Tactic='Credential Access'; Technique='T1558.004'; SrcHost='WS01'; SrcIp=$n.WS01; DstHost='DC01'; DstIp=$n.DC01; Account=$Script:P.PhishingTargetUser; Action='asrep-request'; Severity=7; Module='M03'; Detail="AS-REP requested for $($Script:P.AsrepRoastAccount)" }
            [pscustomobject]@{ TimeStamp=(T 40);  EventName='CredInFile';      Tactic='Credential Access'; Technique='T1552.001'; SrcHost='WS01'; SrcIp=$n.WS01; DstHost='FILE'; DstIp=$n.DC01; Account=$Script:P.PhishingTargetUser; Action='read-share'; Severity=6; Module='M07'; Detail='Read old_backup_credentials.txt from Backup share' }
            [pscustomobject]@{ TimeStamp=(T 60);  EventName='LateralSMB';      Tactic='Lateral Movement'; Technique='T1021.002'; SrcHost='WS01'; SrcIp=$n.WS01; DstHost='WS02'; DstIp=$n.WS02; Account=$Script:P.LateralAccount; Action='smb-admin-share'; Severity=8; Module='M11'; Detail='Connected to WS02 C$ via svc_backup' }
            [pscustomobject]@{ TimeStamp=(T 70);  EventName='LateralToDC';     Tactic='Lateral Movement'; Technique='T1021.001'; SrcHost='WS02'; SrcIp=$n.WS02; DstHost='DC01'; DstIp=$n.DC01; Account=$Script:P.LateralAccount; Action='auth'; Severity=8; Module='M11'; Detail='Authenticated toward DC01' }
            [pscustomobject]@{ TimeStamp=(T 95);  EventName='SchedTaskCreate'; Tactic='Persistence'; Technique='T1053.005'; SrcHost='WS02'; SrcIp=$n.WS02; DstHost='WS02'; DstIp=$n.WS02; Account='SYSTEM'; Action='task-register'; Severity=7; Module='M08'; Detail="Scheduled task $($Script:P.ScheduledTaskName) created (Event 4698)" }
            [pscustomobject]@{ TimeStamp=(T 130); EventName='AccountCreate';   Tactic='Persistence'; Technique='T1136.002'; SrcHost='DC01'; SrcIp=$n.DC01; DstHost='DC01'; DstIp=$n.DC01; Account='adm.itmanager'; Action='user-create'; Severity=9; Module='M09'; Detail="Backdoor user $($Script:P.BackdoorUser) created (Event 4720)" }
            [pscustomobject]@{ TimeStamp=(T 131); EventName='GroupAdd';        Tactic='Persistence'; Technique='T1098'; SrcHost='DC01'; SrcIp=$n.DC01; DstHost='DC01'; DstIp=$n.DC01; Account='adm.itmanager'; Action='group-add'; Severity=9; Module='M09'; Detail="$($Script:P.BackdoorUser) added to $($Script:P.BackdoorGroup) (Event 4728/4732)" }
        )
        Export-MultiFormat -Events $ev -BasePath (Join-Path $Script:Siem 'killchain_events') -Module 'M12-SIEM'

        # Optional: write REAL benign Windows events to a lab-only source for live SIEM ingestion.
        if ($Script:Safe.WriteRealWindowsEventLog) {
            $src='BlueTeamCTFLab'
            try {
                if (-not [System.Diagnostics.EventLog]::SourceExists($src)) {
                    New-EventLog -LogName Application -Source $src
                    Add-State -Type 'EventSource' -Identity $src -Module 'M12-SIEM'
                }
                $id=9000
                foreach ($e in $ev) { Write-EventLog -LogName Application -Source $src -EntryType Information -EventId $id -Message "[$LabTag] $($e.Technique) $($e.EventName): $($e.Detail)"; $id++ }
                Write-LabLog "Wrote $($ev.Count) benign lab events to Application/$src" 'OK'
            } catch { Write-LabLog "Real event-log write skipped: $($_.Exception.Message)" 'WARN' }
        }
        Add-Summary 'M12 SIEM' "$($ev.Count) kill-chain events" 'Investigable kill chain' 'Artifacts\SIEM\killchain_events.{csv,json,cef,leef}; Application/BlueTeamCTFLab' 'multiple'
        $Script:Counters.Configs++
    } catch { Write-LabLog "M12 failed: $($_.Exception.Message)" 'ERROR'; $Script:Counters.Errors++ }
}

# ============================================================================
#  MODULE 13 :: Simulated Firewall / Network Logs
# ============================================================================
function Invoke-M13-FirewallLogs {
    if (-not $Script:Mod.EnableFirewallLogs) { return }
    Write-LabLog 'M13: Simulated firewall/network logs...' 'STEP'; $Script:Counters.Modules++
    try {
        $n=$Script:Net
        $fw=@(
            [pscustomobject]@{ TimeStamp=(T 0);  SrcHost='EXT'; SrcIp=$n.ExternalAttackerIP; DstHost='WS01'; DstIp=$n.WS01; SrcPort=443;  DstPort=49180; Protocol='TCP'; Action='Allow'; Bytes=8421;  Technique='T1566'; Module='M01'; Detail='Inbound phishing payload fetch'; EventName='fw-flow'; Severity=6; Account='-' }
            [pscustomobject]@{ TimeStamp=(T 1);  SrcHost='WS01'; SrcIp=$n.WS01; DstHost='EXT'; DstIp=$n.ExternalAttackerIP; SrcPort=49182; DstPort=80; Protocol='TCP'; Action='Allow'; Bytes=2048; Technique='T1071'; Module='M01'; Detail="DNS/HTTP to $($n.SuspiciousDomain)"; EventName='fw-flow'; Severity=7; Account='-' }
            [pscustomobject]@{ TimeStamp=(T 5);  SrcHost='WS01'; SrcIp=$n.WS01; DstHost='DNS'; DstIp=$n.DC01; SrcPort=51000; DstPort=53; Protocol='UDP'; Action='Allow'; Bytes=120; Technique='T1071.004'; Module='M01'; Detail="DNS query $($n.SuspiciousDomain)"; EventName='dns-query'; Severity=7; Account='-' }
            [pscustomobject]@{ TimeStamp=(T 60); SrcHost='WS01'; SrcIp=$n.WS01; DstHost='WS02'; DstIp=$n.WS02; SrcPort=49500; DstPort=445; Protocol='TCP'; Action='Allow'; Bytes=15360; Technique='T1021.002'; Module='M11'; Detail='SMB WS01->WS02'; EventName='fw-flow'; Severity=8; Account=$Script:P.LateralAccount }
            [pscustomobject]@{ TimeStamp=(T 70); SrcHost='WS02'; SrcIp=$n.WS02; DstHost='DC01'; DstIp=$n.DC01; SrcPort=49600; DstPort=445; Protocol='TCP'; Action='Allow'; Bytes=20480; Technique='T1021.002'; Module='M11'; Detail='SMB WS02->DC01'; EventName='fw-flow'; Severity=8; Account=$Script:P.LateralAccount }
            [pscustomobject]@{ TimeStamp=(T 150);SrcHost='WS02'; SrcIp=$n.WS02; DstHost='EXT'; DstIp=$n.ExternalAttackerIP; SrcPort=49700; DstPort=443; Protocol='TCP'; Action='Allow'; Bytes=524288; Technique='T1041'; Module='M11'; Detail='Suspicious outbound (possible exfil) - large transfer'; EventName='fw-flow'; Severity=9; Account='-' }
        )
        Export-MultiFormat -Events $fw -BasePath (Join-Path $Script:Firewall 'firewall_flows') -Module 'M13-Firewall'
        Add-Summary 'M13 Firewall' "$($fw.Count) flows incl. $($n.ExternalAttackerIP) + $($n.SuspiciousDomain)" 'Network IOCs' 'Artifacts\Firewall\firewall_flows.{csv,json,cef,leef}' 'T1071'
        $Script:Counters.Configs++
    } catch { Write-LabLog "M13 failed: $($_.Exception.Message)" 'ERROR'; $Script:Counters.Errors++ }
}

# ============================================================================
#  MODULE 14 :: CTF Flags / Questions  (operator + participant)
# ============================================================================
function Invoke-M14-CtfFlags {
    if (-not $Script:Mod.EnableCTFFlags) { return }
    Write-LabLog 'M14: CTF flags/questions...' 'STEP'; $Script:Counters.Modules++
    try {
        $q=@(
            [pscustomobject]@{ ID='Q01'; Diff='Easy';   Q='What was the initial access vector?'; A='Spearphishing email with a malicious attachment'; Ev='Emails\Inbox\phishing_email_001.eml'; Hint='Check the Inbox artifacts'; M='T1566.001' }
            [pscustomobject]@{ ID='Q02'; Diff='Easy';   Q='Which user received the phishing email?'; A=$Script:P.PhishingTargetUser; Ev='phishing_email_001.eml (To:)'; Hint='Email header'; M='T1566.001' }
            [pscustomobject]@{ ID='Q03'; Diff='Easy';   Q='Which host was compromised first?'; A=$Script:P.PhishingVictimHost; Ev="Endpoint\$($Script:P.PhishingVictimHost)\*"; Hint='Where are the download artifacts?'; M='T1204.002' }
            [pscustomobject]@{ ID='Q04'; Diff='Easy';   Q='What was the suspicious attachment name?'; A=$Script:P.PhishingAttachmentName; Ev='Downloads artifact'; Hint='Downloads folder'; M='T1204.002' }
            [pscustomobject]@{ ID='Q05'; Diff='Medium'; Q='Which account is Kerberoastable?'; A=$Script:P.KerberoastAccount; Ev='AD servicePrincipalName'; Hint='Look for SPNs'; M='T1558.003' }
            [pscustomobject]@{ ID='Q06'; Diff='Medium'; Q='Which account is AS-REP roastable?'; A=$Script:P.AsrepRoastAccount; Ev='UAC DONT_REQ_PREAUTH'; Hint='Pre-auth flag'; M='T1558.004' }
            [pscustomobject]@{ ID='Q07'; Diff='Hard';   Q='Which object has a vulnerable DACL?'; A=$Script:P.DaclTargetUser; Ev='created-permissions.csv'; Hint='Who can fully control a service account?'; M='T1098' }
            [pscustomobject]@{ ID='Q08'; Diff='Hard';   Q='Which principal holds excessive permissions?'; A=$Script:P.DaclPrincipalGroup; Ev='created-permissions.csv'; Hint='GenericAll holder'; M='T1098' }
            [pscustomobject]@{ ID='Q09'; Diff='Medium'; Q='Which file exposed credentials?'; A='old_backup_credentials.txt'; Ev="Shares\$($Script:P.WeakCredShareFolder)\"; Hint='Backup share'; M='T1552.001' }
            [pscustomobject]@{ ID='Q10'; Diff='Medium'; Q='Which account was used for lateral movement?'; A=$Script:P.LateralAccount; Ev='admin_logon_attempts.csv'; Hint='Type 3 logons'; M='T1021.002' }
            [pscustomobject]@{ ID='Q11'; Diff='Medium'; Q='Which host was accessed laterally?'; A=$Script:P.LateralDestHost; Ev="Endpoint\$($Script:P.LateralDestHost)\*"; Hint='SMB target'; M='T1021.002' }
            [pscustomobject]@{ ID='Q12'; Diff='Medium'; Q='Which scheduled task was used for persistence?'; A=$Script:P.ScheduledTaskName; Ev='Event 4698; ScheduledTasks artifact'; Hint='Legit-sounding task'; M='T1053.005' }
            [pscustomobject]@{ ID='Q13'; Diff='Hard';   Q='Which domain user is the backdoor?'; A=$Script:P.BackdoorUser; Ev='Event 4720; account_creation_evidence.txt'; Hint='Out-of-process service account'; M='T1136.002' }
            [pscustomobject]@{ ID='Q14'; Diff='Hard';   Q='Which group membership change was suspicious?'; A="$($Script:P.ExcessiveMemberGroup) nested into $($Script:P.ExcessiveParentGroup)"; Ev='AD memberOf'; Hint='Nested admin path'; M='T1098' }
            [pscustomobject]@{ ID='Q15'; Diff='Hard';   Q='Reconstruct the full attack timeline.'; A='Phish(T0)->Exec(T4)->Disc(T10)->Cred(T20-40)->Lateral WS01->WS02->DC01(T60-72)->Persist(T95,T130)'; Ev='SIEM killchain_events'; Hint='Sort by time'; M='multiple' }
            [pscustomobject]@{ ID='Q16'; Diff='Medium'; Q='Which MITRE techniques are represented?'; A='See mitre-mapping.md'; Ev='mitre-mapping.md'; Hint='Map each module'; M='multiple' }
            [pscustomobject]@{ ID='Q17'; Diff='Open';   Q='What containment steps would you take?'; A='Disable backdoor user; remove SchedTask; reset svc_backup/svc_sql; revoke GenericAll; un-nest groups; block external IP/domain'; Ev='analyst judgement'; Hint='Per-module remediation'; M='-' }
            [pscustomobject]@{ ID='Q18'; Diff='Open';   Q='What detections would you recommend?'; A='SPN TGS requests (4769 RC4); AS-REP w/o preauth; 4720/4728 outside change window; 4698; DACL change auditing; SMB admin-share logons'; Ev='expected-logs.md'; Hint='Map to Event IDs'; M='-' }
        )
        $op=New-Object System.Text.StringBuilder
        [void]$op.AppendLine("# CTF Flags - OPERATOR (with answers) - $LabTag"); [void]$op.AppendLine("")
        [void]$op.AppendLine("| ID | Diff | Question | Answer | Evidence | Hint | MITRE |"); [void]$op.AppendLine("|---|---|---|---|---|---|---|")
        foreach ($x in $q) { [void]$op.AppendLine("| $($x.ID) | $($x.Diff) | $($x.Q) | $($x.A) | $($x.Ev) | $($x.Hint) | $($x.M) |") }
        $op.ToString() | Set-Content (Join-Path $Script:OutputPath 'ctf-flags-operator.md') -Encoding UTF8

        $pt=New-Object System.Text.StringBuilder
        [void]$pt.AppendLine("# CTF Flags - PARTICIPANT - $LabTag"); [void]$pt.AppendLine("")
        [void]$pt.AppendLine("Investigate the environment and answer each question. Cite your evidence.")
        [void]$pt.AppendLine(""); [void]$pt.AppendLine("| ID | Diff | Question | MITRE (optional) | Your Answer | Evidence |"); [void]$pt.AppendLine("|---|---|---|---|---|---|")
        foreach ($x in $q) { [void]$pt.AppendLine("| $($x.ID) | $($x.Diff) | $($x.Q) |  |  |  |") }
        $pt.ToString() | Set-Content (Join-Path $Script:OutputPath 'ctf-flags-participant.md') -Encoding UTF8

        foreach ($f in 'ctf-flags-operator.md','ctf-flags-participant.md') { Add-State -Type 'Artifact' -Identity $f -Target (Join-Path $Script:OutputPath $f) -Module 'M14-CTF' }
        Write-LabLog 'CTF flag files generated (operator + participant).' 'OK'
        Add-Summary 'M14 CTF' "$($q.Count) questions" 'Investigation tasks' 'Output\ctf-flags-*.md' '-'
        $Script:Counters.Configs++
    } catch { Write-LabLog "M14 failed: $($_.Exception.Message)" 'ERROR'; $Script:Counters.Errors++ }
}

# ============================================================================
#  MODULE 15 :: MITRE ATT&CK Mapping
# ============================================================================
function Invoke-M15-Mitre {
    if (-not $Script:Mod.EnableMITREMapping) { return }
    Write-LabLog 'M15: MITRE ATT&CK mapping...' 'STEP'; $Script:Counters.Modules++
    try {
        $rows=@(
            'Initial Access|T1566.001|Phishing: Spearphishing Attachment|M01|phishing_email_001.eml|Email + endpoint artifacts'
            'Execution|T1204.002|User Execution: Malicious File|M01|Downloads\<attachment>.txt|recent_files.txt'
            'Discovery|T1087.002|Account Discovery: Domain Account|M11|console_history.txt|PowerShell history'
            'Discovery|T1069.002|Permission Groups Discovery: Domain Groups|M11|console_history.txt|net group output'
            'Discovery|T1482|Domain Trust Discovery|M11/M12|killchain_events|verify MITRE ID for your scenario'
            'Credential Access|T1558.003|Kerberoasting|M02|AD servicePrincipalName|TGS request 4769 (RC4)'
            'Credential Access|T1558.004|AS-REP Roasting|M03|UAC DONT_REQ_PREAUTH|AS-REP request'
            'Credential Access|T1552.001|Unsecured Credentials: in Files|M07|old_backup_credentials.txt|Share read'
            'Privilege Escalation / Persistence|T1098|Account Manipulation (DACL/nesting)|M04/M05|created-permissions.csv|AD ACL + memberOf'
            'Defense Evasion / PrivEsc|T1078.002|Valid Accounts: Domain Accounts|M06|local_administrators.txt|Type 3 logons'
            'Lateral Movement|T1021.002|Remote Services: SMB/Windows Admin Shares|M11|remote_commands.log|4624 Type 3, 5140'
            'Lateral Movement|T1021.001|Remote Services: RDP|M11|admin_logon_attempts.csv|verify per scenario'
            'Persistence|T1053.005|Scheduled Task|M08|Event 4698|ScheduledTasks artifact'
            'Persistence|T1136.002|Create Account: Domain Account|M09|Event 4720|account_creation_evidence.txt'
            'Persistence|T1484.001|Domain Policy Modification: GPO|M10|suspicious_gpo.txt|GPO delegation'
            'Command & Control|T1071|Application Layer Protocol|M13|firewall_flows|External IP + suspicious domain'
            'Exfiltration|T1041|Exfiltration Over C2 Channel|M13|firewall_flows (large transfer)|verify per scenario'
        )
        $md=New-Object System.Text.StringBuilder
        [void]$md.AppendLine("# MITRE ATT&CK Mapping - $LabTag"); [void]$md.AppendLine("")
        [void]$md.AppendLine('> IDs marked "verify MITRE ID" should be confirmed against attack.mitre.org for your exact scenario.')
        [void]$md.AppendLine(""); [void]$md.AppendLine("| Tactic | Technique ID | Technique | Module | Artifact | Expected Evidence |"); [void]$md.AppendLine("|---|---|---|---|---|---|")
        foreach ($r in $rows) { $c=$r -split '\|'; [void]$md.AppendLine("| $($c[0]) | $($c[1]) | $($c[2]) | $($c[3]) | $($c[4]) | $($c[5]) |") }
        $md.ToString() | Set-Content (Join-Path $Script:OutputPath 'mitre-mapping.md') -Encoding UTF8
        Add-State -Type 'Artifact' -Identity 'mitre-mapping.md' -Target (Join-Path $Script:OutputPath 'mitre-mapping.md') -Module 'M15-MITRE'
        Write-LabLog 'mitre-mapping.md generated.' 'OK'
        Add-Summary 'M15 MITRE' "$($rows.Count) technique rows" 'Detection/mapping reference' 'Output\mitre-mapping.md' 'multiple'
        $Script:Counters.Configs++
    } catch { Write-LabLog "M15 failed: $($_.Exception.Message)" 'ERROR'; $Script:Counters.Errors++ }
}

# ============================================================================
#  DOCUMENTATION / STATE EXPORTS
# ============================================================================
function Export-Docs {
    Write-LabLog 'Exporting documentation + state...' 'STEP'
    $o=$Script:OutputPath

    $Script:Summary     | Export-Csv (Join-Path $o 'scenario-summary.csv')   -NoTypeInformation -Encoding UTF8
    $Script:Permissions | Export-Csv (Join-Path $o 'created-permissions.csv') -NoTypeInformation -Encoding UTF8
    $Script:Artifacts   | Export-Csv (Join-Path $o 'created-artifacts.csv')   -NoTypeInformation -Encoding UTF8

    # modified-objects.csv (AD objects whose attributes were changed in place)
    $Script:Modified.Clear()
    foreach ($s in $Script:State | Where-Object { $_.Type -in 'SPN','PreAuth','DescriptionChanged','PasswordChanged','ADACE','GroupMember','LocalAdmin' }) {
        $Script:Modified.Add([pscustomobject]@{ Type=$s.Type; Object=$s.Identity; Target=$s.Target; Module=$s.Module; When=$s.Created })
    }
    $Script:Modified | Export-Csv (Join-Path $o 'modified-objects.csv') -NoTypeInformation -Encoding UTF8

    # scenario-summary.md
    $md=New-Object System.Text.StringBuilder
    [void]$md.AppendLine("# Attack Scenario Summary - $LabTag"); [void]$md.AppendLine("")
    [void]$md.AppendLine("- Generated: $((Get-Date).ToString('u'))  | Domain: $($Script:DnsRoot)  | Lab OU: ``$($Script:LabOuDn)``")
    [void]$md.AppendLine("- Modules run: $($Script:Counters.Modules)  Configs: $($Script:Counters.Configs)  Artifacts: $($Script:Counters.Artifacts)  Errors: $($Script:Counters.Errors)")
    [void]$md.AppendLine(""); [void]$md.AppendLine("| Module | Item | Risk | Evidence | MITRE |"); [void]$md.AppendLine("|---|---|---|---|---|")
    foreach ($s in $Script:Summary) { [void]$md.AppendLine("| $($s.Module) | $($s.Item) | $($s.Risk) | $($s.Evidence) | $($s.MITRE) |") }
    $md.ToString() | Set-Content (Join-Path $o 'scenario-summary.md') -Encoding UTF8

    # expected-logs.md (Windows Event IDs + SIEM sources)
    $el=New-Object System.Text.StringBuilder
    [void]$el.AppendLine("# Expected Logs & Windows Event IDs - $LabTag"); [void]$el.AppendLine("")
    [void]$el.AppendLine("| Activity | Windows Event ID | Source | Notes |"); [void]$el.AppendLine("|---|---|---|---|")
    @(
        'Successful logon|4624|Security|Type 3 = network/SMB lateral movement',
        'Failed logon|4625|Security|Spray / failed admin auth',
        'Kerberos TGS request|4769|Security|RC4 (0x17) on SPN account = Kerberoast indicator',
        'Kerberos AS auth|4768|Security|Pre-auth-disabled account = AS-REP indicator',
        'User account created|4720|Security|Backdoor user creation',
        'Member added to global group|4728|Security|Backdoor/group nesting',
        'Member added to local group|4732|Security|Local admin / sensitive group change',
        'Scheduled task created|4698|Security|Persistence task',
        'Process creation|4688|Security|powershell.exe spawned by Office (phishing)',
        'PowerShell script block|4104|Microsoft-Windows-PowerShell/Operational|Discovery/lateral commands',
        'File share accessed|5140|Security|Backup share / admin share C$',
        'Directory service change|5136|Security|DACL / attribute modification'
    ) | ForEach-Object { $c=$_ -split '\|'; [void]$el.AppendLine("| $($c[0]) | $($c[1]) | $($c[2]) | $($c[3]) |") }
    [void]$el.AppendLine(""); [void]$el.AppendLine("SIEM-ready exports: ``Artifacts\SIEM\killchain_events.{csv,json,cef,leef}`` and ``Artifacts\Firewall\firewall_flows.{csv,json,cef,leef}``. Real lab events: Application log source ``BlueTeamCTFLab``.")
    $el.ToString() | Set-Content (Join-Path $o 'expected-logs.md') -Encoding UTF8

    # operator-guide.md
    $og=New-Object System.Text.StringBuilder
    [void]$og.AppendLine("# Operator Guide - $LabTag (Attack Scenarios)"); [void]$og.AppendLine("")
    [void]$og.AppendLine("## What this staged"); foreach ($s in $Script:Summary) { [void]$og.AppendLine("- **$($s.Module)**: $($s.Item) - _$($s.Risk)_ (evidence: $($s.Evidence))") }
    [void]$og.AppendLine(""); [void]$og.AppendLine("## Reset / cleanup")
    [void]$og.AppendLine("- Run ``99-Cleanup-Attack-Scenarios.ps1`` (prompts unless ``-Force``). It reads ``Output\attack-scenario-state.json`` and reverts only what this script created/modified.")
    [void]$og.AppendLine("- Base lab objects are never touched by cleanup.")
    [void]$og.AppendLine(""); [void]$og.AppendLine("## Key answers"); [void]$og.AppendLine("See ``ctf-flags-operator.md`` and ``mitre-mapping.md``.")
    $og.ToString() | Set-Content (Join-Path $o 'operator-guide.md') -Encoding UTF8

    # participant-guide-outline.md
    $pg=New-Object System.Text.StringBuilder
    [void]$pg.AppendLine("# Participant Guide (Outline) - $LabTag"); [void]$pg.AppendLine("")
    [void]$pg.AppendLine("1. Scenario brief: suspected compromise starting from a phishing email.")
    [void]$pg.AppendLine("2. Your toolkit: Event Viewer, SIEM (ingest Artifacts\\SIEM + Firewall), AD tools (Get-ADUser/Group, BloodHound-style review), file browsing.")
    [void]$pg.AppendLine("3. Tasks: answer ``ctf-flags-participant.md`` (Q01-Q18), citing evidence.")
    [void]$pg.AppendLine("4. Deliverable: incident timeline + MITRE mapping + containment/detection recommendations.")
    [void]$pg.AppendLine("5. Rules: investigate only; do not run offensive tooling against the range.")
    $pg.ToString() | Set-Content (Join-Path $o 'participant-guide-outline.md') -Encoding UTF8

    # State file (cleanup ledger)
    $stateObj=[pscustomobject]@{
        Tag=$LabTag; Script='02-Create-Attack-Scenarios.ps1'; GeneratedUtc=(Get-Date).ToUniversalTime().ToString('o')
        DnsRoot=$Script:DnsRoot; NetBIOS=$Script:Netbios; LabOuDn=$Script:LabOuDn; LabRoot=$Script:LabRoot
        Counters=$Script:Counters; Entries=$Script:State
    }
    $stateObj | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $o 'attack-scenario-state.json') -Encoding UTF8
    Write-LabLog "State ledger: $(Join-Path $o 'attack-scenario-state.json')" 'OK'
}

function Write-FinalSummary {
    Write-Host ''
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host ' Attack scenarios staged (SAFE). No attack was performed.'   -ForegroundColor Cyan
    Write-Host '============================================================' -ForegroundColor Cyan
    foreach ($k in $Script:Counters.Keys) { Write-Host (" {0,-10}: {1}" -f $k,$Script:Counters[$k]) -ForegroundColor White }
    Write-Host ''
    Write-Host " Lab OU   : $($Script:LabOuDn)"   -ForegroundColor Gray
    Write-Host " Output   : $($Script:OutputPath)" -ForegroundColor Gray
    Write-Host " State    : $(Join-Path $Script:OutputPath 'attack-scenario-state.json')" -ForegroundColor Gray
    Write-Host " Cleanup  : 99-Cleanup-Attack-Scenarios.ps1  (use -Force to skip prompts)" -ForegroundColor Yellow
    Write-Host ''
}

# ============================================================================
#  MAIN
# ============================================================================
try {
    Initialize-Scenario
    Invoke-M01-Phishing
    Invoke-M02-Kerberoast
    Invoke-M03-AsrepRoast
    Invoke-M04-VulnerableDacl
    Invoke-M05-ExcessiveMembership
    Invoke-M06-LocalAdmin
    Invoke-M07-WeakCredsShare
    Invoke-M08-ScheduledTask
    Invoke-M09-BackdoorUser
    Invoke-M10-GpoPersistence
    Invoke-M11-LateralEvidence
    Invoke-M12-SiemEvents
    Invoke-M13-FirewallLogs
    Invoke-M14-CtfFlags
    Invoke-M15-Mitre
    Export-Docs
    Write-FinalSummary
    Write-LabLog '=== 02-Create-Attack-Scenarios.ps1 completed ===' 'OK'
}
catch {
    Write-LabLog "FATAL: $($_.Exception.Message)" 'ERROR'
    Write-LabLog $_.ScriptStackTrace 'ERROR'
    throw
}
