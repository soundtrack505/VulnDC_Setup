# Extending the Framework

## Add a new vulnerability/evidence module
1. **Add a flag** in `Config\attack-scenario-config.json` under `Modules`, e.g. `EnableDcSyncRightsArtifact`.
2. **Add parameters** under `Parameters` (object names, hosts, values — keep them fake/lab-only).
3. **Write a function** `Invoke-Mxx-YourModule` in `02-Create-Attack-Scenarios.ps1` following the template below.
4. **Call it** in the `MAIN` block in kill-chain order.
5. **Document it** in `Config\vulnerabilities.json` (risk, MITRE, detection, CTF questions).
6. **Map cleanup**: record every change with `Add-State -Type ...`. If you introduce a *new* revert type, extend `99-Cleanup-Attack-Scenarios.ps1` with a matching `switch` branch.

### Module template
```powershell
function Invoke-Mxx-YourModule {
    if (-not $Script:Mod.EnableYourModule) { return }
    Write-LabLog 'Mxx: your module...' 'STEP'; $Script:Counters.Modules++
    try {
        # 1) Validate targets are IN scope (use Resolve-LabUser for users).
        # 2) Make the SAFE change (config only) with a "# RISK:" comment.
        # 3) Record it for cleanup:  Add-State -Type '...' -Identity '...' -Target '...' -Data @{...} -Module 'Mxx'
        # 4) Optionally drop a benign evidence artifact: New-ArtifactFile -Path ... -Content ... -Module 'Mxx'
        # 5) Add-Summary 'Mxx Name' 'item' 'risk' 'evidence' 'Txxxx'
        $Script:Counters.Configs++
    } catch { Write-LabLog "Mxx failed: $($_.Exception.Message)" 'ERROR'; $Script:Counters.Errors++ }
}
```

## Cleanup ledger contract
- Every reversible action **must** be recorded via `Add-State`.
- Supported types already handled by cleanup: `UserCreated, GroupCreated, GroupMember, SPN, PreAuth, DescriptionChanged, PasswordChanged, ADACE, GpoCreated, ScheduledTask, LocalAdmin, Artifact, EventSource`.
- For in-place attribute changes, store the **old value** in `Data.OldValue` so cleanup can restore it.
- Cleanup re-checks lab scope/tag before deleting — keep new AD objects inside the Lab OU and tagged with `[BlueTeam-CTF-Lab]`.

## Add new SIEM/firewall events
- Append `[pscustomobject]` rows to the arrays in `Invoke-M12-SiemEvents` / `Invoke-M13-FirewallLogs` using the same field names.
- `Export-MultiFormat` will emit CSV/JSON/CEF/LEEF automatically.

## Add new CTF questions / MITRE rows
- Add rows to the `$q` array in `Invoke-M14-CtfFlags` (operator + participant regenerate together).
- Add rows to `$rows` in `Invoke-M15-Mitre` (`Tactic|ID|Technique|Module|Artifact|Evidence`). Use `verify MITRE ID` if unsure.

## Safety guardrails to preserve
- No exploitation, no real credential access, no security-tool tampering, no destructive actions.
- All credentials/IPs/domains stay fake and lab-only.
- "Persistence" stays inert (benign action / unused account / unlinked GPO).
- Never touch objects outside the configured Lab OU or lab root folder.
