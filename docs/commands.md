# Commands

Every script, what it does, and the flags you'll actually use. All of them
read the same settings table (`WinLogKit.Settings.ps1`) and share one helper file
(`WinLogKit.Common.ps1`), so - given
the same selection, and regenerating artefacts after any settings change -
what you apply, what you verify and what you deploy can't disagree.
All of the kit's scripts run on PowerShell 7 and on stock Windows
PowerShell 5.1 - use whichever your host has.

## Where the scripts live

| Folder | Scripts | Run from |
|---|---|---|
| kit root | `New-`, `Enable-`, `Test-LoggingBaseline.ps1`, the settings table `WinLogKit.Settings.ps1`, the shared helpers `WinLogKit.Common.ps1` | the host you are configuring |
| `fleet\` | `New-GpoPack.ps1`, `New-WefSubscription.ps1` | an admin workstation |
| `tools\` | regenerators for presets and the Reference page, and the ATT&CK coverage report | maintainers |

The root, `fleet\` and `tools\` scripts read the settings table and
helpers from the kit root and write their output (`GPO\`, `WEF\`,
`Results\`) there too, wherever they live. Intune is delivered through
the Settings catalog, with no generator: see [Deploy](deployment.md).

## Enable-LoggingBaseline.ps1

Applies the baseline. Idempotent - already-correct items are reported and
left alone; log sizes are only ever raised.

```powershell
.\Enable-LoggingBaseline.ps1 [-IncludeHighVolume]
                             [-BaselineFile <csv>] [-WhatIf] [-Rollback]
```

- `-WhatIf` - full diff, nothing changes (the transcript is still written:
  the preview is worth keeping).
- Checks disk space first: whether the selected logs, once full at their
  new maximum sizes, still leave enough free space on their drive (warns
  only; see [Disk space](safety.md#disk-space)).
- A kit log set to "do not overwrite" (logging stops when it fills) is
  switched to overwrite as needed, with a warning; "archive when full" is
  left alone.
- First real run captures the rollback baseline; `-Rollback` restores it,
  including a log's original "do not overwrite" setting.
- Never reboots, never restarts services; the one setting needing a service
  restart (AD CS AuditFilter) is set with a warning and left to your change
  window.
- Requires elevation.

## Test-LoggingBaseline.ps1

Read-only verification: channels (enabled, sized, circular retention),
audit subcategories (superset-aware - more auditing than required passes),
registry values, SMB audit settings, and that `CrashOnAuditFail` is off
(the kit never sets it; the test fails if something else has). Per-behaviour-category PASS/FAIL/NOT
APPLICABLE, detail + summary CSVs, non-zero exit on any failure. Ends
with the same [disk space](safety.md#disk-space) check as Enable, for
information only.

```powershell
.\Test-LoggingBaseline.ps1 [-IncludeHighVolume]
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

## Cross-checking with WELA (optional)

The kit doesn't bundle or download a second-opinion tool: Test is the
verifier. If you want an independent view, run Yamato's
[WELA](https://github.com/Yamato-Security/WELA) yourself
(`.\WELA.ps1 audit-settings -Baseline YamatoSecurity`). Never use its
`configure` command alongside the kit (see
[Deviations](baselines.md#deviations-from-the-yamato-sources)).

Where WELA disagrees with the kit, it isn't always drift:

- *Process Termination, Group Membership, Kernel Object, Registry*: WELA's
  recommendation table asks for these, but Yamato's own
  EnableWindowsLogSettings batch leaves all four disabled (noise, and the
  Kernel Object / Registry subcategories log almost nothing without SACLs).
  The kit follows the batch, so these rows show as deviations permanently.
- *Computer Account Management* on non-DCs: WELA's table is role-blind;
  those events only generate on domain controllers, where the kit applies
  them.
- Rows where WELA recommends less than the kit (e.g. Account Lockout
  `Failure`, Process Creation `Success`): the kit applies Success and
  Failure, a superset.

## New-WefSubscription.ps1

Generates a source-initiated WEF subscription XML from a selection, plus
the collector and source setup steps. Each selected channel is forwarded
whole. `-Validate` parses every query in the local event engine first.
See [Collect](wec.md).

```powershell
.\fleet\New-WefSubscription.ps1 [-BaselineFile <csv>] [-Validate] [-SubscriptionId <name>] [-OutDir <dir>]
```

## New-GpoPack.ps1

Generates the advanced audit policy `audit.csv` and an LGPO-format
`registry.txt` from the selection. See [Deploy](deployment.md).

```powershell
.\fleet\New-GpoPack.ps1 [-BaselineFile <csv>] [-IncludeHighVolume] [-OutDir <dir>]
```

## Maintainer tools (`tools\`)

You don't need these to deploy logging. They regenerate the kit's derived
files, and CI fails if the committed copies drift.

- `New-PresetBaselines.ps1` - the four presets (run it under Windows
  PowerShell 5.1 so the CSVs keep their UTF-8 BOM).
- `Export-ReferenceTable.ps1` - the [Reference](reference.md) page.
- `Export-PolicyTables.ps1` - the [Settings catalog](intune-csp.md) and
  [Group Policy paths](gpo-paths.md) pages, from the settings table and
  the curated CSP names and Group Policy paths in `policy-map.psd1`.
- `Export-AttackCoverage.ps1` - joins a selection against the vendored
  MITRE ATT&CK snapshot and reports which techniques it makes observable,
  and why the rest are not (NotSelected, NotInKit, RequiresSysmon, NotNative
  or Unmapped). It produces the numbers on the [Coverage](mapping.md) page,
  and works on your own selection CSV too:

  ```powershell
  .\tools\Export-AttackCoverage.ps1 [-IncludeHighVolume] [-BaselineFile <csv>]
  ```

## tests\Invoke-KitChecks.ps1

The kit's self-checks, a Pester 5 suite in `tests\Kit.Tests.ps1` (parse on
both engines, settings consistency, builder round-trip, generated artefact
validation, preset drift, rollback and audit-reading checks). Safe anywhere,
no admin - run it before a PR; CI runs it on every push. It needs Pester 5
(`Install-Module Pester -RequiredVersion 5.9.1 -Scope CurrentUser -Force -SkipPublisherCheck`); the kit
itself needs no modules.
