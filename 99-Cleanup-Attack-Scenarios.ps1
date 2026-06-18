#requires -Version 5.1
<#
.SYNOPSIS
    BlueTeam-CTF-Lab :: 99-Cleanup-Attack-Scenarios.ps1
    Reverts ONLY the vulnerable configs + evidence created by 02-Create-Attack-Scenarios.ps1.

.DESCRIPTION
    Reads Output\attack-scenario-state.json (the ledger written by Script 2) and undoes
    each recorded change in reverse order. The BASE LAB is never touched.

    SAFETY:
      * Acts only on objects recorded in the state file.
      * Re-validates that every AD object is still inside the Lab OU and tagged before
        deleting/reverting it; anything outside scope is skipped and reported.
      * Prompts for confirmation per category unless -Force is supplied.
      * Writes Output\cleanup-report.txt.

.PARAMETER StatePath
    Path to attack-scenario-state.json. Defaults to <LabRoot>\Output\attack-scenario-state.json.

.PARAMETER Force
    Skip all confirmation prompts.

.PARAMETER RemoveArtifacts
    Also delete generated artifact/log files (default: $true). Set -RemoveArtifacts:$false to keep evidence files.

.EXAMPLE
    .\99-Cleanup-Attack-Scenarios.ps1
.EXAMPLE
    .\99-Cleanup-Attack-Scenarios.ps1 -Force
#>

[CmdletBinding()]
param(
    [string]$StatePath = '',
    [string]$LabRootPath = 'C:\BlueTeam-CTF-Lab',
    [switch]$Force,
    [bool]$RemoveArtifacts = $true
)

$ErrorActionPreference = 'Stop'
$LabTag = 'BlueTeam-CTF-Lab'
$Report = New-Object System.Collections.Generic.List[string]
$Counters = [ordered]@{ Reverted=0; Skipped=0; Errors=0 }

function Note { param([string]$m,[ValidateSet('INFO','OK','WARN','ERROR')][string]$lvl='INFO')
    $c=switch($lvl){'OK'{'Green'}'WARN'{'Yellow'}'ERROR'{'Red'}default{'Gray'}}
    $line="[{0}] [{1,-5}] {2}" -f (Get-Date).ToString('HH:mm:ss'),$lvl,$m
    Write-Host $line -ForegroundColor $c; $Report.Add($line)
}
function Confirm-Step { param([string]$Message)
    if ($Force) { return $true }
    $a = Read-Host "$Message  [y/N]"
    return ($a -match '^(y|yes)$')
}

# ----------------------------------------------------------------------------
#  Load state
# ----------------------------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($StatePath)) { $StatePath = Join-Path $LabRootPath 'Output\attack-scenario-state.json' }
if (-not (Test-Path $StatePath)) { throw "State file not found: $StatePath. Nothing to clean up (or run Script 2 first)." }

$state = Get-Content $StatePath -Raw | ConvertFrom-Json
$LabOuDn = $state.LabOuDn
$Netbios = $state.NetBIOS
$LabRoot = $state.LabRoot
Note "Loaded state: $($state.Entries.Count) ledger entries. Lab OU: $LabOuDn" 'OK'
Note "LAB cleanup - reverts scenario changes only. Base lab is preserved." 'WARN'

Import-Module ActiveDirectory -ErrorAction Stop

function Test-Scope { param([string]$dn) return ($dn -like "*$LabOuDn") }
function Test-PathInLab { param([string]$p) return ($p -and ($p -like "$LabRoot*")) }

# Reverse order so dependent changes undo cleanly (e.g. members before groups).
$entries = @($state.Entries) ; [array]::Reverse($entries)

# ----------------------------------------------------------------------------
#  Group entries by category for confirmation
# ----------------------------------------------------------------------------
$adChanges   = $entries | Where-Object { $_.Type -in 'SPN','PreAuth','DescriptionChanged','PasswordChanged','ADACE','GroupMember','UserCreated','GroupCreated' }
$gpoChanges  = $entries | Where-Object { $_.Type -eq 'GpoCreated' }
$taskChanges = $entries | Where-Object { $_.Type -eq 'ScheduledTask' }
$localAdmin  = $entries | Where-Object { $_.Type -eq 'LocalAdmin' }
$evtSources  = $entries | Where-Object { $_.Type -eq 'EventSource' }
$fileArtifacts = $entries | Where-Object { $_.Type -eq 'Artifact' }

# ============================================================================
#  1) AD object/attribute reverts
# ============================================================================
if ($adChanges -and (Confirm-Step "Revert $($adChanges.Count) AD changes (SPNs, pre-auth, ACEs, created users/groups, memberships)?")) {
    foreach ($e in $adChanges) {
        try {
            switch ($e.Type) {
                'GroupMember' {
                    if (Get-ADGroup -Filter "Name -eq '$($e.Identity)'" -ErrorAction SilentlyContinue) {
                        Remove-ADGroupMember -Identity $e.Identity -Members $e.Target -Confirm:$false -ErrorAction SilentlyContinue
                        Note "Removed '$($e.Target)' from group '$($e.Identity)'" 'OK'; $Counters.Reverted++
                    }
                }
                'SPN' {
                    $u = Get-ADUser -Filter "SamAccountName -eq '$($e.Identity)'" -Properties DistinguishedName -ErrorAction SilentlyContinue
                    if ($u -and (Test-Scope $u.DistinguishedName)) {
                        Set-ADUser -Identity $e.Identity -ServicePrincipalNames @{Remove=$e.Target} -ErrorAction SilentlyContinue
                        Note "Removed SPN '$($e.Target)' from $($e.Identity)" 'OK'; $Counters.Reverted++
                    } else { Note "SPN target out of scope/missing: $($e.Identity)" 'WARN'; $Counters.Skipped++ }
                }
                'PreAuth' {
                    $u = Get-ADUser -Filter "SamAccountName -eq '$($e.Identity)'" -Properties DistinguishedName -ErrorAction SilentlyContinue
                    if ($u -and (Test-Scope $u.DistinguishedName)) {
                        Set-ADAccountControl -Identity $e.Identity -DoesNotRequirePreAuthentication $false
                        Note "Re-enabled Kerberos pre-auth on $($e.Identity)" 'OK'; $Counters.Reverted++
                    } else { $Counters.Skipped++ }
                }
                'DescriptionChanged' {
                    $u = Get-ADUser -Filter "SamAccountName -eq '$($e.Identity)'" -Properties DistinguishedName,Description -ErrorAction SilentlyContinue
                    if ($u -and (Test-Scope $u.DistinguishedName)) {
                        $old = $e.Data.OldValue
                        if ([string]::IsNullOrEmpty($old)) { Set-ADUser -Identity $e.Identity -Clear description }
                        else { Set-ADUser -Identity $e.Identity -Description $old }
                        Note "Restored description on $($e.Identity)" 'OK'; $Counters.Reverted++
                    } else { $Counters.Skipped++ }
                }
                'PasswordChanged' {
                    $restore = $e.Data.RestoreTo
                    if ($restore) {
                        $u = Get-ADUser -Filter "SamAccountName -eq '$($e.Identity)'" -Properties DistinguishedName -ErrorAction SilentlyContinue
                        if ($u -and (Test-Scope $u.DistinguishedName)) {
                            Set-ADAccountPassword -Identity $e.Identity -Reset -NewPassword (ConvertTo-SecureString $restore -AsPlainText -Force) -ErrorAction SilentlyContinue
                            Note "Reset $($e.Identity) password to lab baseline" 'OK'; $Counters.Reverted++
                        }
                    } else { Note "No restore password recorded for $($e.Identity) - left as-is." 'WARN'; $Counters.Skipped++ }
                }
                'ADACE' {
                    $tdn = $e.Target
                    if (Test-Scope $tdn) {
                        $acl = Get-Acl "AD:\$tdn"
                        $sidVal = $e.Data.Sid; $rightName = $e.Data.Right
                        $toRemove = $acl.Access | Where-Object {
                            ($_.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) -and
                            ($_.IdentityReference.Value -eq $sidVal) -and ($_.ActiveDirectoryRights -match $rightName) }
                        foreach ($r in $toRemove) { [void]$acl.RemoveAccessRule($r) }
                        if ($toRemove) { Set-Acl "AD:\$tdn" $acl; Note "Removed $rightName ACE ($sidVal) from $tdn" 'OK'; $Counters.Reverted++ } else { $Counters.Skipped++ }
                    } else { Note "ACE target out of scope: $tdn" 'WARN'; $Counters.Skipped++ }
                }
                'UserCreated' {
                    $u = Get-ADUser -Filter "SamAccountName -eq '$($e.Identity)'" -Properties DistinguishedName,Description -ErrorAction SilentlyContinue
                    if ($u -and (Test-Scope $u.DistinguishedName) -and ($u.Description -like "*$LabTag*")) {
                        Remove-ADUser -Identity $e.Identity -Confirm:$false
                        Note "Removed backdoor user $($e.Identity)" 'OK'; $Counters.Reverted++
                    } else { Note "Refusing to remove user $($e.Identity) (out of scope or untagged)." 'WARN'; $Counters.Skipped++ }
                }
                'GroupCreated' {
                    $g = Get-ADGroup -Filter "Name -eq '$($e.Identity)'" -Properties DistinguishedName,Description -ErrorAction SilentlyContinue
                    if ($g -and (Test-Scope $g.DistinguishedName) -and ($g.Description -like "*$LabTag*")) {
                        Remove-ADGroup -Identity $e.Identity -Confirm:$false
                        Note "Removed group $($e.Identity)" 'OK'; $Counters.Reverted++
                    } else { Note "Refusing to remove group $($e.Identity) (out of scope or untagged)." 'WARN'; $Counters.Skipped++ }
                }
            }
        } catch { Note "Revert error ($($e.Type) $($e.Identity)): $($_.Exception.Message)" 'ERROR'; $Counters.Errors++ }
    }
} elseif ($adChanges) { Note 'Skipped AD reverts (declined).' 'WARN' }

# ============================================================================
#  2) Scheduled tasks
# ============================================================================
if ($taskChanges -and (Confirm-Step "Remove $($taskChanges.Count) scheduled task(s)?")) {
    foreach ($e in $taskChanges) {
        try {
            if (Get-ScheduledTask -TaskName $e.Identity -ErrorAction SilentlyContinue) {
                Unregister-ScheduledTask -TaskName $e.Identity -Confirm:$false
                Note "Unregistered scheduled task $($e.Identity)" 'OK'; $Counters.Reverted++
            } else { $Counters.Skipped++ }
        } catch { Note "Task removal error ($($e.Identity)): $($_.Exception.Message)" 'ERROR'; $Counters.Errors++ }
    }
}

# ============================================================================
#  3) GPOs
# ============================================================================
if ($gpoChanges -and (Confirm-Step "Remove $($gpoChanges.Count) lab GPO(s)?")) {
    if (Get-Module -ListAvailable -Name GroupPolicy) {
        Import-Module GroupPolicy -ErrorAction SilentlyContinue
        foreach ($e in $gpoChanges) {
            try {
                $g = Get-GPO -Name $e.Identity -ErrorAction SilentlyContinue
                if ($g -and ($g.Description -like "*$LabTag*")) {
                    Remove-GPO -Name $e.Identity -ErrorAction Stop
                    Note "Removed GPO $($e.Identity)" 'OK'; $Counters.Reverted++
                } else { Note "Refusing to remove GPO $($e.Identity) (untagged/missing)." 'WARN'; $Counters.Skipped++ }
            } catch { Note "GPO removal error ($($e.Identity)): $($_.Exception.Message)" 'ERROR'; $Counters.Errors++ }
        }
    } else { Note 'GroupPolicy module unavailable - skipping GPO removal.' 'WARN' }
}

# ============================================================================
#  4) Remote local-admin memberships
# ============================================================================
if ($localAdmin -and (Confirm-Step "Revert $($localAdmin.Count) remote local-admin change(s)?")) {
    foreach ($e in $localAdmin) {
        try {
            $h=$e.Target; $p=$e.Identity; $nb=$e.Data.NetBIOS
            if (Test-Connection -ComputerName $h -Count 1 -Quiet -ErrorAction SilentlyContinue) {
                Invoke-Command -ComputerName $h -ScriptBlock { param($p,$nb) Remove-LocalGroupMember -Group 'Administrators' -Member "$nb\$p" -ErrorAction SilentlyContinue } -ArgumentList $p,$nb
                Note "Removed $nb\$p from local Administrators on $h" 'OK'; $Counters.Reverted++
            } else { Note "$h unreachable - manual local-admin revert may be needed." 'WARN'; $Counters.Skipped++ }
        } catch { Note "Local-admin revert error: $($_.Exception.Message)" 'ERROR'; $Counters.Errors++ }
    }
}

# ============================================================================
#  5) Event log source
# ============================================================================
if ($evtSources -and (Confirm-Step "Remove $($evtSources.Count) lab event-log source(s)?")) {
    foreach ($e in $evtSources) {
        try {
            if ([System.Diagnostics.EventLog]::SourceExists($e.Identity)) {
                [System.Diagnostics.EventLog]::DeleteEventSource($e.Identity)
                Note "Deleted event source $($e.Identity)" 'OK'; $Counters.Reverted++
            } else { $Counters.Skipped++ }
        } catch { Note "Event source removal error ($($e.Identity)): $($_.Exception.Message)" 'ERROR'; $Counters.Errors++ }
    }
}

# ============================================================================
#  6) Artifact / log files
# ============================================================================
if ($RemoveArtifacts -and $fileArtifacts -and (Confirm-Step "Delete $($fileArtifacts.Count) generated artifact/log file(s) under $LabRoot?")) {
    foreach ($e in $fileArtifacts) {
        try {
            $p=$e.Target
            if (Test-PathInLab $p) {
                if (Test-Path $p) { Remove-Item -Path $p -Force -ErrorAction SilentlyContinue; Note "Removed file $p" 'OK'; $Counters.Reverted++ } else { $Counters.Skipped++ }
            } else { Note "Refusing to delete file outside lab root: $p" 'WARN'; $Counters.Skipped++ }
        } catch { Note "File removal error: $($_.Exception.Message)" 'ERROR'; $Counters.Errors++ }
    }
} elseif (-not $RemoveArtifacts) { Note 'Keeping artifact files (-RemoveArtifacts:$false).' 'INFO' }

# ============================================================================
#  Report
# ============================================================================
Note '' 'INFO'
Note "Cleanup complete. Reverted=$($Counters.Reverted)  Skipped=$($Counters.Skipped)  Errors=$($Counters.Errors)" 'OK'

$reportPath = Join-Path (Split-Path $StatePath -Parent) 'cleanup-report.txt'
$header = @(
    "BlueTeam-CTF-Lab :: Attack Scenario Cleanup Report",
    "Generated : $((Get-Date).ToString('u'))",
    "State file: $StatePath",
    "Lab OU    : $LabOuDn",
    "Reverted=$($Counters.Reverted)  Skipped=$($Counters.Skipped)  Errors=$($Counters.Errors)",
    "============================================================"
)
($header + $Report) | Set-Content -Path $reportPath -Encoding UTF8
Note "Report written: $reportPath" 'OK'

if ($Counters.Errors -eq 0 -and -not $Force) {
    if (Confirm-Step "Archive the consumed state file (rename to .done)?") {
        try { Rename-Item -Path $StatePath -NewName ("attack-scenario-state.{0}.done.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss')) ; Note 'State file archived.' 'OK' } catch { Note "Could not archive state file: $($_.Exception.Message)" 'WARN' }
    }
}
