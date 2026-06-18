# Validation Checklist — Attack Scenarios

Run after `02-Create-Attack-Scenarios.ps1`. All commands assume the lab DC + ActiveDirectory module.

## AD configuration
- [ ] Kerberoastable account has SPNs
  `Get-ADUser svc_sql -Properties servicePrincipalName | Select -Expand servicePrincipalName`
- [ ] AS-REP account has pre-auth disabled
  `Get-ADUser tomer.azran -Properties userAccountControl,DoesNotRequirePreAuth | Select Name,DoesNotRequirePreAuth`
- [ ] Vulnerable DACL present (GenericAll over svc_backup)
  `(Get-Acl "AD:\$((Get-ADUser svc_backup).DistinguishedName)").Access | ? { $_.ActiveDirectoryRights -match 'GenericAll' }`
- [ ] Excessive nesting present
  `Get-ADGroupMember GG_Workstation_Admins | ? Name -eq 'GG_Helpdesk_Operators'`
- [ ] Backdoor user exists in a privileged group
  `Get-ADUser svc_update -Properties Description; Get-ADGroupMember GG_IT_Admins | ? SamAccountName -eq 'svc_update'`
- [ ] DACL principal group exists
  `Get-ADGroup GG_AD_Misconfigured_Operators`

## Endpoint / host configuration
- [ ] Scheduled task registered (inert)
  `Get-ScheduledTask -TaskName SystemHealthMonitor | Select TaskName,State`
  `(Get-ScheduledTask SystemHealthMonitor).Actions.Arguments  # must only Add-Content a heartbeat`
- [ ] GPO created + unlinked (if GroupPolicy module present)
  `Get-GPO -Name 'Workstation Maintenance Policy'`
- [ ] Event source present (if WriteRealWindowsEventLog=true)
  `[System.Diagnostics.EventLog]::SourceExists('BlueTeamCTFLab')`

## Artifacts / evidence files
- [ ] Phishing email — `Artifacts\Emails\Inbox\phishing_email_001.eml`
- [ ] Attachment placeholder — `Artifacts\Endpoint\WS01\Downloads\Invoice_June_2026.docm.txt`
- [ ] Browser history — `Artifacts\Endpoint\WS01\BrowserHistory\history.csv`
- [ ] Weak creds — `Shares\Backup\old_backup_credentials.txt`
- [ ] Lateral logs — `Artifacts\Endpoint\WS02\RemoteExecution\remote_commands.log`
- [ ] Admin logons — `Artifacts\Endpoint\DC01\Auth\admin_logon_attempts.csv`
- [ ] SIEM events — `Artifacts\SIEM\killchain_events.{csv,json,cef,leef}`
- [ ] Firewall logs — `Artifacts\Firewall\firewall_flows.{csv,json,cef,leef}`

## Documentation outputs (in `Output\`)
- [ ] scenario-summary.csv / scenario-summary.md
- [ ] created-permissions.csv
- [ ] created-artifacts.csv
- [ ] modified-objects.csv
- [ ] ctf-flags-operator.md / ctf-flags-participant.md
- [ ] mitre-mapping.md
- [ ] expected-logs.md
- [ ] operator-guide.md / participant-guide-outline.md
- [ ] **attack-scenario-state.json** (required for cleanup)

## Cleanup readiness
- [ ] State file lists all created/modified objects
  `(Get-Content Output\attack-scenario-state.json -Raw | ConvertFrom-Json).Entries.Count`
- [ ] Dry confidence: `99-Cleanup-Attack-Scenarios.ps1` (without -Force) lists each category before acting.

## Safety verification
- [ ] No real credentials anywhere (all marked `LAB-ONLY FAKE`)
- [ ] Scheduled task action only writes a heartbeat file
- [ ] Backdoor user is never authenticated by the scripts
- [ ] No Defender/security setting was modified (grep your logs — there are no such calls)
- [ ] Every AD change is inside the Lab OU (`modified-objects.csv` Target column)
