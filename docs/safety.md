# Safety & FAQ

The settings that can genuinely hurt a Windows machine, how the kit avoids
every one of them, and which of the *safe* settings still cost real disk
and money.

## What the kit will never do

Windows auditing has settings that can hang, halt or lock out a server. The
kit never touches them, in any mode:

| Never touched | Why |
|---|---|
| `CrashOnAuditFail` ("Audit: Shut down system immediately if unable to log security audits") | A full Security log **halts the machine** with `STOP C0000244`; until reset, only Administrators can log on - IIS fails, AD replication fails. ([Microsoft KB832981](https://learn.microsoft.com/troubleshoot/developer/webapps/iis/health-diagnostic-performance/users-cannot-access-web-sites-when-log-full)) The test **fails** if another policy has turned it on. |
| "Do not overwrite events" retention | Logging silently stops when the log fills; with CrashOnAuditFail it crashes the host. The test **fails** this mode on the kit's logs, and Enable sets them back to overwrite as needed, with a warning (`-Rollback` restores the original). When Group Policy forces it (Event Log Service > "Control Event Log behavior when the log file reaches its maximum size" = Enabled), Enable leaves it and both scripts say to change the policy instead. |
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

## Disk space

Raising a log's maximum size takes no disk straight away: the log grows
into it as events arrive, and then wraps. Event rates differ too much
between hosts (and from day to day on workstations) to forecast, but the
maximum sizes are fixed, so the kit checks against those. Enable (also
under `-WhatIf`) and Test add up, per drive, how much more the selected
logs can grow before they're full, and compare that with the free space:

```text
[STORAGE OK ] C:\ 23 kit log(s) can still grow by 2.4 GB until full (0.1 GB of it from raised maximum sizes); 424.2 GB of 930.4 GB free now, 421.8 GB once they are full.
```

`STORAGE LOW` in yellow means under 10% of the drive would be left free
once the logs are full; in red it means they wouldn't fit at all. Either
way, plan a disk upgrade (or free space, or apply a smaller selection)
before rolling out. The check only warns: nothing is blocked, and a low
disk never fails Test.

Pilot guidance (from the Yamato README): run the full set on a test box
mirroring production for at least a week, then use event ID metrics (e.g.
Hayabusa's `eid-metrics`) to decide what to keep.
[`Export-AttackCoverage.ps1`](mapping.md) supplies the benefit side of that
decision.

## Known limits, stated plainly

- **PowerShell 7 needs its event log registered**: PowerShell 7 (`pwsh.exe`)
  has its own Group Policy settings (per
  [about_Group_Policy_Settings](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_group_policy_settings)).
  The kit's PowerShell 7 items point them at the Windows PowerShell policy,
  so both engines log the same way. PowerShell 7 writes to
  `PowerShellCore/Operational`, which exists only once PowerShell 7's event
  manifest is registered (the MSI installer offers to; Store and zip installs
  don't); `Test-LoggingBaseline.ps1` fails that channel when
  PowerShell 7 is installed without it. Register it once, as admin, in
  PowerShell 7: `& "$PSHOME\RegisterManifest.ps1"`.
- **Native gaps**: registry autoruns (Run keys, IFEO) need SACLs for change
  auditing, which the kit doesn't set; no file hashes or DLL loads without
  agents; no flow statistics. These are the recognised limits
  of agentless native logging - the docs say so instead of pretending.
  For registry autostart entries specifically, Microsoft's Sysinternals
  [Autoruns](https://learn.microsoft.com/sysinternals/downloads/autoruns)
  inventories them, and Palantir's
  [AutorunsToWinEventLog](https://github.com/palantir/windows-event-forwarding/tree/master/AutorunsToWinEventLog)
  shows one way to write that inventory to an event log for collection.
  Both sit outside the kit.
- **Domain-joined hosts**: GPO reapplies audit policy at refresh; deliver
  fleet-wide via the [deployment artefacts](deployment.md).

## FAQ

### Does the kit send anything anywhere, or fetch live data?

No. The kit is a static snapshot: the Yamato baselines and the MITRE
ATT&CK mapping data are vendored with recorded provenance (source, commit,
date). Nothing is fetched at runtime, and nothing about your hosts,
results or baselines leaves them. The kit has no network action at all,
so air-gapped estates work unchanged.

### How is this different from just running Yamato's batch script?

Same settings, operationalised: idempotent apply with `-WhatIf` and
rollback, tiered volume decisions, read-only verification with evidence
CSVs, per-role baseline files, fleet delivery (Intune/WEF/GPO) compiled
from one settings table, and ATT&CK coverage numbers for the selection.
Plus a handful of documented fixes to upstream quirks, each listed with
its reason in the
[deviations table](baselines.md#deviations-from-the-yamato-sources): the
batch sizes PrintService/Operational but never enables it, and WELA's
`configure` sets `RestrictSendingNTLMTraffic` to 2 (Deny all) where the
kit sets 1 (Audit all), per
[Microsoft's values for that policy](https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-outgoing-ntlm-traffic-to-remote-servers).

### Why isn't Sysmon included?

The kit's core is native Windows configuration, for environments where
agents are unwelcome (change-restricted servers, OT-adjacent estates).
Sysmon is excellent; if you can run it, run it, and the coverage report
tells you which techniques are Sysmon-only. Since February 2026 Sysmon is
also a
[built-in optional feature](https://learn.microsoft.com/windows/security/operating-system-security/sysmon/overview)
of Windows 11 and Windows Server 2025, which removes the third-party-agent
objection on those versions; supporting it as a tier of the baseline is
proposed in [#52](https://github.com/spydisec/WinLogKit/issues/52). Earlier versions still need the standalone Sysinternals build,
which stays out of scope.

### Something broke / I want out. How do I undo everything?

```powershell
.\Enable-LoggingBaseline.ps1 -Rollback
```

restores the audit policy, channel sizes/state and registry values captured
on the first real run. Nothing in the kit requires a reboot.

Backups are automatic, and always taken **before** any change: the first
real apply captures the complete pre-kit state to `.\Baseline\` (that is
what `-Rollback` restores), and every later apply saves a timestamped
pre-change snapshot to `.\Baseline\snapshots\<timestamp>\` - so stepping
from, say, Minimal to Heavy leaves a point-in-time record. To return to an
intermediate state rather than the very beginning:
`auditpol /restore /file:<snapshot>\auditpol-backup.csv`, plus the channel,
registry and SMB audit values recorded in that snapshot's `State.json`
(restore each `SmbAudit` entry with `Set-SmbServerConfiguration` or
`Set-SmbClientConfiguration` per its `Side`).

### Can I run this on a domain controller?

Yes - DC-only items (Kerberos, Directory Service subcategories, and more)
activate automatically on DCs and report NOT APPLICABLE elsewhere. Mind the
volume notes for DCs (SAM, File Share, Kerberos are busy there) and pilot
on one DC first.

### Windows Home edition?

Works - the kit's mechanisms (`auditpol`, `wevtutil`, registry) do not
depend on Group Policy tooling, which Home lacks. The kit's own workstation
field testing was done on Windows 11 Home: full apply, verify (all 16
categories PASS) and rollback.

### What's special on Server 2025 and Windows 11 24H2?

Both can audit which SMB peers cannot do signing or encryption (events
3021 signing / 3022 encryption server-side, 31998 signing / 31999
encryption client-side) and insecure guest logons (31997 on the client,
3023 on the server);
availability per
Microsoft's
[SMB feature descriptions](https://learn.microsoft.com/windows-server/storage/file-server/smb-feature-descriptions)).
The kit enables these audit-only settings and sizes both Audit channels;
on earlier versions the properties do not exist and the items report
NOT APPLICABLE. Two related notes:

- **NTLM**: NTLMv1 is removed in Server 2025 and the SMB client supports
  NTLM blocking. The kit's NTLM values stay audit-only
  (`RestrictSendingNTLMTraffic = 1`, the documented "Audit all" value),
  a logging-only change on every supported version, and
  feed the evidence you need before turning any blocking on.
- **Alignment**: Microsoft's own Server 2025 security baseline
  ([OSConfig security baselines](https://learn.microsoft.com/windows-server/security/osconfig/osconfig-how-to-configure-security-baselines))
  audits Success and Failure on nearly all subcategories, captures 4688
  command lines, and requires the Security log at 192 MB minimum. The
  kit's 1 GB Security log exceeds that minimum; 4688 with command line is
  the HighVolume tier (`-IncludeHighVolume`), and every role preset
  includes it.

On workstations generally, volume calibration differs from servers: far
fewer logons and connections make the HighVolume tier more affordable per
host, while the 1 GB Security log matters more on small SSDs.

### Does a "PASS" mean I'm detecting attacks?

No - it means the configured events are being generated and retained.
Detection needs rules on top (Sigma, SIEM analytics). The
[coverage mapping](mapping.md) tells you what your events *support*.

### How do I update the kit without losing my baselines?

Your selection CSVs and per-host output folders are separate from the kit
scripts. Read the release notes in the
[CHANGELOG](https://github.com/spydisec/WinLogKit/blob/main/CHANGELOG.md)
(releases that change how you work have an "Upgrading" table), pull the new release, keep your CSVs, rerun
`Test-LoggingBaseline.ps1 -BaselineFile <yours>` - the settings table may
have new items, which show as unlisted/excluded until you re-run the
builder and re-select.
