# Commands

Every script, what it does, and the flags you'll actually use. They all
read the same settings table (`LoggingBaseline.Settings.ps1`), so - given
the same selection, and regenerating artefacts after any settings change -
what you apply, what you verify and what you deploy can't disagree.
All of the kit's scripts run on PowerShell 7 and on stock Windows
PowerShell 5.1 - use whichever your host has. (WELA is Yamato's tool
with its own requirements; `Invoke-WELACheck.ps1` drives it either way.)

## Enable-LoggingBaseline.ps1

Applies the baseline. Idempotent - already-correct items are reported and
left alone; log sizes are only ever raised.

```powershell
.\Enable-LoggingBaseline.ps1 [-IncludeHighVolume] [-IncludeOptional]
                             [-BaselineFile <csv>] [-WhatIf] [-Rollback]
```

- `-WhatIf` - full diff, nothing changes (the transcript is still written:
  the preview is worth keeping).
- First real run captures the rollback baseline; `-Rollback` restores it.
- Never reboots, never restarts services; the one setting needing a service
  restart (AD CS AuditFilter) is set with a warning and left to your change
  window.
- Requires elevation.

## Test-LoggingBaseline.ps1

Read-only verification: channels (enabled, sized, circular retention),
audit subcategories (superset-aware - more auditing than required passes),
registry values, SMB audit settings. Per-behaviour-category PASS/FAIL/NOT
APPLICABLE, detail + summary CSVs, non-zero exit on any failure.

```powershell
.\Test-LoggingBaseline.ps1 [-IncludeHighVolume] [-IncludeOptional]
                           [-BaselineFile <csv>] [-WefRole Source|Collector]
```

- `-WefRole Source` additionally checks the SubscriptionManager policy and
  WinRM; `-WefRole Collector` checks Wecsvc, ForwardedEvents sizing and
  that at least one subscription is loaded.
- Requires elevation (reading audit policy needs it).

## New-LoggingBaseline.ps1

Interactive baseline builder. Shows the kit recommendation and risk note per
item; `t` renders the baseline tree (include/exclude state + per-category
coverage); writes an Excel-editable selection CSV.

```powershell
.\New-LoggingBaseline.ps1 [-AcceptRecommended] [-OutFile <csv>]
.\New-LoggingBaseline.ps1 -Show [-BaselineFile <csv>]   # view-only tree
```

No elevation needed; changes nothing.

## Export-AttackCoverage.ps1

Joins a selection against the vendored OSSEM-DM snapshot and reports which
ATT&CK techniques it makes observable - and why the rest are not
(NotSelected / NotInKit / RequiresSysmon). See
[ATT&CK Coverage Mapping](mapping.md).

```powershell
.\Export-AttackCoverage.ps1 [-IncludeHighVolume] [-IncludeOptional] [-BaselineFile <csv>]
```

## Invoke-WELACheck.ps1

Runs Yamato's WELA (`audit-settings`, `audit-filesize`) as an independent
second opinion, parses deviations superset-aware, archives raw output as
timestamped evidence. Locates WELA in `.\WELA\` or an unzipped
`WELA-<version>\` folder; `-Download` fetches it from GitHub on request.

```powershell
.\Invoke-WELACheck.ps1 [-Download] [-WelaPath <path>] [-Baseline YamatoSecurity|ASD|Microsoft_Client|Microsoft_Server]
```

WELA's own commands, for reference (v2.1.0, verified against source; all
output is CSV, archived per run under `.\Evidence\`):

```text
.\WELA.ps1 audit-settings -Baseline <YamatoSecurity|ASD|Microsoft_Client|Microsoft_Server> [-OutType std|gui|table]
.\WELA.ps1 audit-filesize -Baseline YamatoSecurity
.\WELA.ps1 configure      -Baseline YamatoSecurity [-Auto]     # not used by this kit
.\WELA.ps1 update-rules
```

**Expected deviations in WELA output** (WELA disagreeing with the kit is not
always kit drift):

- *Process Termination, Group Membership, Kernel Object, Registry*: WELA's
  recommendation table asks for these, but Yamato's own
  EnableWindowsLogSettings batch leaves all four disabled (noise, and the
  Kernel Object / Registry subcategories log almost nothing without SACLs).
  The kit follows the batch, so these rows show as deviations permanently.
- *Computer Account Management* on non-DCs: WELA's table is role-blind;
  those events only generate on domain controllers, where the kit applies
  them.
- Rows where WELA recommends less than the kit (e.g. Account Lockout
  `Failure`, Process Creation `Success`): the kit's Success and Failure
  supersets them, and `Invoke-WELACheck.ps1` compares superset-aware, so
  these rows are not reported as deviations once the kit is applied.

## New-IntuneRemediationPack.ps1

Compiles the selection into a self-contained Intune detection + remediation
script pair. See [Fleet Deployment](deployment.md).

## New-WefSubscription.ps1

Generates a source-initiated WEF subscription XML (one query per selected
channel) plus collector/source setup guidance. See
[Fleet Deployment](deployment.md).

## New-GpoPack.ps1

Generates the advanced audit policy `audit.csv` and an LGPO-format
`registry.txt` from the selection. See [Fleet Deployment](deployment.md).

## tests\Invoke-KitChecks.ps1

The kit's self-checks (parse on both engines, settings consistency, builder
round-trip, generated artefact validation, preset drift). Safe anywhere, no
admin - run it before a PR; CI runs it on every push.
