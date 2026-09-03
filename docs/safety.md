# Safety & Volume

The settings that can genuinely hurt a Windows machine, how the kit avoids
every one of them, and which of the *safe* settings still cost real disk
and money.

## What the kit will never do

Windows auditing has settings that can hang, halt or lock out a server. The
kit never touches them, in any mode:

| Never touched | Why |
|---|---|
| `CrashOnAuditFail` ("Audit: Shut down system immediately if unable to log security audits") | A full Security log **halts the machine** with `STOP C0000244`; until reset, only Administrators can log on - IIS fails, AD replication fails. ([Microsoft KB832981](https://learn.microsoft.com/troubleshoot/developer/webapps/iis/health-diagnostic-performance/users-cannot-access-web-sites-when-log-full)) |
| "Do not overwrite events" retention | Logging silently stops when the log fills; with CrashOnAuditFail it crashes the host. The test **fails** this mode wherever found; the Intune pack repairs it to circular. |
| Global object access auditing | SACLs on every kernel/file/registry object - extreme volume, measurable performance degradation. |
| Blanket File System / Registry SACLs | A careless wildcard SACL can bury a file server. Scoping SACLs is a design decision, never a default. |
| Shrinking logs, rebooting, restarting services | Sizes are only raised; the one restart-requiring setting (AD CS AuditFilter) is set with a warning and left to your change window. |

## Volume-impact settings (the HighVolume tier and friends)

| Setting | Impact |
|---|---|
| Process Creation (4688) + command line | High volume, scales with process churn. Command lines can contain typed credentials - treat the Security log as sensitive downstream. Highest detection value of any single setting. |
| PowerShell module logging (4103) | The heaviest setting in the kit: one Mimikatz run = 2000+ events; measurable PowerShell overhead on script-heavy servers. Many teams take script block logging and skip this. |
| PowerShell script block logging (4104) | Moderate volume, logs de-obfuscated code; generally safe fleet-wide. |
| Filtering Platform Connection (5156/5157) | Microsoft rates volume High; can dominate the Security log on connection-heavy hosts. Pilot on one host per role. |
| Sensitive Privilege Use (4673/4674) | Floods with backup agents. Pilot per server role. |
| File Share / SAM / Removable Storage / RPC Events | Steady streams on file servers, DCs, USB-heavy or RPC-heavy hosts respectively - watch during the pilot week. |
| 1 GB Security + 1 GB PowerShell logs | Up to ~3 GB extra disk per host. |

Pilot guidance (from the Yamato README): run the full set on a test box
mirroring production for at least a week, then use event ID metrics (e.g.
Hayabusa's `eid-metrics`) to decide what to keep.
[`Export-AttackCoverage.ps1`](mapping.md) supplies the benefit side of that
decision.

## Known limits, stated plainly

- **English-language OS assumed for verification**: `auditpol` output text
  is localised; setting uses GUIDs and is locale-safe. Locale-neutral
  verification is a roadmap item.
- **Native gaps**: registry autoruns need SACLs (the optional
  [Autoruns add-on](addons.md) covers them); no file hashes or DLL
  loads without agents; no flow statistics. These are the recognised limits
  of agentless native logging - the docs say so instead of pretending.
- **Domain-joined hosts**: GPO reapplies audit policy at refresh; deliver
  fleet-wide via the [deployment artefacts](deployment.md).
