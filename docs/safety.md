# Safety & FAQ

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
  verification is planned.
- **Native gaps**: registry autoruns need SACLs for change auditing (the
  optional [Autoruns add-on](addons.md) adds a daily inventory of them,
  which is a partial mitigation, not SACL coverage); no file hashes or DLL
  loads without agents; no flow statistics. These are the recognised limits
  of agentless native logging - the docs say so instead of pretending.
- **Domain-joined hosts**: GPO reapplies audit policy at refresh; deliver
  fleet-wide via the [deployment artefacts](deployment.md).

## FAQ

### Does the kit send anything anywhere, or fetch live data?

No. The kit is a static snapshot: the Yamato baselines and the MITRE
ATT&CK mapping data are vendored with recorded provenance (source, commit,
date). Nothing is fetched at runtime, and nothing about your hosts,
results or baselines leaves them. The baseline has one optional network
action, `Invoke-WELACheck.ps1 -Download`, which fetches WELA from GitHub
when you explicitly ask; the optional [Autoruns add-on](addons.md) adds a
second, `Install-AutorunsToWinEventLog.ps1 -Download`, which fetches
`autorunsc` from live.sysinternals.com. Both have an offline alternative
(bring the files yourself), so air-gapped estates need no network at all.

### How is this different from just running Yamato's batch script?

Same settings, operationalised: idempotent apply with `-WhatIf` and
rollback, tiered volume decisions, read-only verification with evidence
CSVs, per-role baseline files, fleet delivery (Intune/WEF/GPO) compiled
from one settings table, and ATT&CK coverage numbers for the selection.
Plus a handful of documented fixes to upstream quirks (e.g. the batch
sizes PrintService/Operational but never enables it; WELA's `configure`
sets an NTLM value that *blocks* rather than audits).

### Why isn't Sysmon included?

The kit's core is native Windows configuration, for environments where
agents are unwelcome (change-restricted servers, OT-adjacent estates).
Sysmon is excellent; if you can run it, run it, and the coverage report
tells you which techniques are Sysmon-only. Since February 2026 Sysmon is
also a
[built-in optional feature](https://learn.microsoft.com/windows/security/operating-system-security/sysmon/overview)
of Windows 11 and Windows Server 2025, which removes the third-party-agent
objection on those versions; supporting it as a tier of the baseline is
planned. Earlier versions still need the standalone Sysinternals build,
which stays out of scope.

The one deliberate exception today is the optional
[AutorunsToWinEventLog add-on](addons.md), which depends on Sysinternals
`autorunsc` (a command-line tool, not a resident agent) to add a daily
inventory over the registry-autorun Persistence gap - partial mitigation,
not SACL-grade change auditing. It lives in its own folder, is never
installed by the baseline scripts, and is documented as the exception it
is.

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
3021/3022 server-side, 31998/31999 client-side; availability per
Microsoft's
[SMB feature descriptions](https://learn.microsoft.com/windows-server/storage/file-server/smb-feature-descriptions)).
The kit enables these audit-only settings and sizes both Audit channels;
on earlier versions the properties do not exist and the items report
NOT APPLICABLE. Two related notes:

- **NTLM**: NTLMv1 is removed in Server 2025 and the SMB client supports
  NTLM blocking. The kit's NTLM values stay audit-only
  (`RestrictSendingNTLMTraffic = 1`), safe on all supported versions, and
  feed the evidence you need before turning any blocking on.
- **Alignment**: Microsoft's own Server 2025 security baseline
  ([OSConfig](https://learn.microsoft.com/windows-server/security/osconfig/osconfig-overview))
  audits Success and Failure on nearly all subcategories, captures 4688
  command lines, and requires the Security log at 192 MB minimum. This kit
  meets or exceeds all of that (Security at 1 GB).

On workstations generally, volume calibration differs from servers: far
fewer logons and connections make the HighVolume tier more affordable per
host, while the 1 GB Security log matters more on small SSDs.

### Does a "PASS" mean I'm detecting attacks?

No - it means the configured events are being generated and retained.
Detection needs rules on top (Sigma, SIEM analytics). WELA's rule counts
and the [coverage mapping](mapping.md) tell you what your events *support*.

### How do I update the kit without losing my baselines?

Your selection CSVs and per-host output folders are separate from the kit
scripts. Pull the new release, keep your CSVs, rerun
`Test-LoggingBaseline.ps1 -BaselineFile <yours>` - the settings table may
have new items, which show as unlisted/excluded until you re-run the
builder and re-select.
