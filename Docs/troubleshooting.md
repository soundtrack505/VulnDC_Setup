# Troubleshooting — Attack Scenarios

| Symptom | Cause | Fix |
|---|---|---|
| `Lab OU '...' not found` | Base lab not built, or wrong scope | Confirm the base lab exists; set `Scope.AutoDetectFromFoundation:false` and a correct `Scope.LabOuDn` in `attack-scenario-config.json`. |
| `User '<svc>' not found - skipping` | Target account name differs from your lab | Edit the matching `Parameters.*Account` values to real lab accounts. |
| `... is OUTSIDE lab scope - refusing to modify` | Target object lives outside the Lab OU | Intentional safety guard. Move the object into the Lab OU or point the parameter at a lab object. |
| Weak password not set (`policy`) | Domain password policy rejects the lab password | Lower the lab fine-grained password policy, or set stronger values in `KerberoastWeakPassword`/`AsrepWeakPassword`. Module still proceeds. |
| `GroupPolicy module unavailable` | RSAT GPMC not installed | `Install-WindowsFeature GPMC` (or RSAT). Module falls back to a documentation artifact. |
| Scheduled task not created | `RegisterScheduledTaskLocally:false` or insufficient rights | Toggle it true and run elevated. An evidence artifact is written regardless. |
| Real events missing in SIEM | `WriteRealWindowsEventLog:false`, or source creation blocked | Toggle true + run elevated. The CSV/JSON/CEF/LEEF exports are always written. |
| Local admin change skipped | `ApplyLocalAdminRemotely:false` or host unreachable | Intentional default. Enable the toggle and ensure WinRM to the host; otherwise the documentation artifact represents it. |
| Set-Acl on `AD:\...` fails | Not running as Domain Admin, or replication lag | Run elevated on the DC as Domain Admin; re-run (idempotent). |
| Cleanup says `State file not found` | Script 2 didn't finish, or wrong path | Pass `-StatePath` explicitly; check `Output\attack-scenario-state.json`. |
| Cleanup left an object | Object was modified out-of-band / untagged | Cleanup refuses to delete untagged or out-of-scope objects by design; remove manually after verifying. |
| Re-run created duplicates | — | It shouldn't: every module checks existence first (idempotent). Report which module if it does. |

## General tips
- Always run on the **DC**, **elevated**, as **Domain Admin**.
- Logs: `Output\Logs\02-Create-Attack-Scenarios_*.log`.
- To stage a subset, set the unwanted `Modules.*` flags to `false` and re-run.
- To fully reset: `99-Cleanup-Attack-Scenarios.ps1` then re-run Script 2.
