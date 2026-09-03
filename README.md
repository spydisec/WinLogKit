# WinLogKit

[![CI](https://github.com/spydisec/WinLogKit/actions/workflows/ci.yml/badge.svg)](https://github.com/spydisec/WinLogKit/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/spydisec/WinLogKit?include_prereleases)](https://github.com/spydisec/WinLogKit/releases)
[![Docs](https://img.shields.io/badge/docs-spydisec.github.io%2FWinLogKit-1b3a4b)](https://spydisec.github.io/WinLogKit/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**An easy, auditable way to implement the
[Yamato Security](https://github.com/Yamato-Security) Windows event logging
baselines with native PowerShell.** Enable the right event channels, advanced
audit policy subcategories and registry settings; verify them repeatably; and
get an independent second opinion from
[WELA](https://github.com/Yamato-Security/WELA) - all with plain
PowerShell: PowerShell 7 or the built-in Windows PowerShell 5.1, no
modules, no agents, no Sysmon.

Targets **Windows Server 2019 / 2022 / 2025 and Windows 10 / 11**, standalone
or domain joined. Version-specific items (Server 2025 / Win11 24H2 SMB
auditing) and role-specific items (domain controller subcategories) are
detected at runtime and reported NOT APPLICABLE where they don't apply.
Fleet delivery via **Intune remediations**, **WEF/WEC subscriptions** and
**GPO artefacts** is built in, and the kit reports which **MITRE ATT&CK**
techniques a selection makes observable.

## 📖 Documentation

**<https://spydisec.github.io/WinLogKit/>** - getting started, baseline
guide, per-command reference, deployment (Intune / WEF / GPO), ATT&CK
coverage, the full [per-setting reference
table](https://spydisec.github.io/WinLogKit/reference/) (every event ID,
size, volume weight and baseline membership), safety notes and FAQ.

## Credits

The settings themselves come from Yamato Security's excellent work:

- [EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings) -
  the configuration guide and batch script this kit operationalises
- [WELA](https://github.com/Yamato-Security/WELA) - used here as an
  independent verification tool
- [EventLog-Baseline-Guide](https://github.com/Yamato-Security/EventLog-Baseline-Guide) -
  the source of the ASD / Microsoft Client / Microsoft Server reference
  baselines shipped as presets

This project is not affiliated with or endorsed by Yamato Security. A handful
of deliberate deviations from their scripts are
[documented with reasons](https://spydisec.github.io/WinLogKit/baselines/#deviations-from-the-yamato-sources).

## ⚠️ Warning

Same warning as the upstream guide: understand and **test every setting on a
non-production machine that mirrors your environment for at least a week**
before rolling out. Logging volume is real money and real disk. Use at your
own risk.

## Files

| File | What it does |
|---|---|
| `LoggingBaseline.Settings.ps1` | Single source of truth: every channel, subcategory and registry value with tier, scope, purpose and risk notes. Everything else derives from it. |
| `New-LoggingBaseline.ps1` | Interactive baseline builder: walk every setting, see the recommendation and risk, write selections to CSV. No admin, changes nothing. |
| `Enable-LoggingBaseline.ps1` | Applies a baseline. Idempotent, `-WhatIf` diff, `-Rollback` to first-run state, pre-change snapshots, never reboots or shrinks logs. |
| `Test-LoggingBaseline.ps1` | Verification only: PASS / FAIL / NOT APPLICABLE per category, CSVs to `.\Results\`, non-zero exit on failure for pipelines. |
| `Invoke-WELACheck.ps1` | Runs WELA as an independent second opinion, parses deviations, archives evidence per run. |
| `New-IntuneRemediationPack.ps1` | Compiles a selection into a self-contained Intune detect + remediate script pair. |
| `New-WefSubscription.ps1` | Generates a source-initiated WEF subscription XML plus collector/source setup steps. |
| `New-GpoPack.ps1` | Generates GPO delivery artefacts: `audit.csv` (GUID-driven) and LGPO-format `registry.txt`. |
| `Export-AttackCoverage.ps1` | Reports which ATT&CK techniques a selection makes observable, and why the rest are not. |
| `presets/` | Ready-made selection CSVs: ASD / Microsoft reference baselines, per-role starting points, and the blended **spydi** baselines (role x volume). |
| `addons/AutorunsToWinEventLog/` | **Optional add-on** (needs Sysinternals autorunsc): daily task writing every autostart entry to an `Autoruns` event log, a daily inventory over the native Persistence gap. Rewrite of Palantir's tool, MIT. |
| `tests/Invoke-KitChecks.ps1` | Self-checks CI runs on PowerShell 5.1 and 7; run locally before a PR. |

## Quick start

All commands from an elevated PowerShell prompt in the kit folder -
PowerShell 7 or the built-in Windows PowerShell 5.1 both work
(`New-LoggingBaseline.ps1` alone needs no elevation). If scripts are blocked,
`Set-ExecutionPolicy -Scope Process RemoteSigned` unblocks the current window
without persisting anything
([details](https://spydisec.github.io/WinLogKit/getting-started/#if-scripts-are-blocked-running-scripts-is-disabled-on-this-system)).

**Path A - tier switches** (fastest route to the recommended baseline):

```powershell
.\Enable-LoggingBaseline.ps1 -WhatIf         # 1. full diff, nothing changed
.\Enable-LoggingBaseline.ps1                 # 2. apply Core (first run captures rollback state)
.\Enable-LoggingBaseline.ps1 -IncludeHighVolume  # 3. after reviewing the volume notes
.\Test-LoggingBaseline.ps1   -IncludeHighVolume  # 4. verify what you applied
.\Invoke-WELACheck.ps1 -Download             # 5. independent second opinion
.\Enable-LoggingBaseline.ps1 -Rollback       # if needed: put everything back
```

**Path B - build your own baseline** (decide setting-by-setting, or start
from a preset):

```powershell
.\New-LoggingBaseline.ps1                    # interactive walk-through -> MyBaseline.csv
.\Enable-LoggingBaseline.ps1 -BaselineFile .\MyBaseline.csv -WhatIf
.\Enable-LoggingBaseline.ps1 -BaselineFile .\MyBaseline.csv
.\Test-LoggingBaseline.ps1   -BaselineFile .\MyBaseline.csv
```

Press `t` during the walk-through (or use `-Show`) for a tree view of the
selection with per-category coverage. The CSV is plain text: commit one per
server role and you get reviewable, versioned logging baselines for free.
Presets work anywhere a `-BaselineFile` is accepted:

```powershell
.\Enable-LoggingBaseline.ps1 -BaselineFile .\presets\spydi_Workstation_Minimal.csv -WhatIf
```

## Tiers

| Tier | Applied when | Contents |
|---|---|---|
| Core | always | Everything with low or justified volume |
| HighVolume | `-IncludeHighVolume` | Process Creation + command line, PowerShell script block + module logging, Filtering Platform Connection, Sensitive Privilege Use |
| Optional | `-IncludeOptional` | PowerShell transcription, Crypto-DPAPI debug channel, IPsec Driver auditing |

## Safety

The kit never touches the settings that can hang or lock out a host
(`CrashOnAuditFail`, "do not overwrite" retention, global object access
auditing, blanket SACLs) and never reboots, restarts services or shrinks
logs. Merely *heavy* settings carry a risk note the builder shows before you
select them. Full rationale, the volume-impact table and known limits:
[Safety](https://spydisec.github.io/WinLogKit/safety/).

## Where everything else lives

| Topic | Docs page |
|---|---|
| Install, first run, execution policy | [Getting Started](https://spydisec.github.io/WinLogKit/getting-started/) |
| Tiers, presets, spydi blended baselines | [Baselines](https://spydisec.github.io/WinLogKit/baselines/) |
| Every switch of every script, WELA reference | [Commands](https://spydisec.github.io/WinLogKit/commands/) |
| Intune, WEF/WEC, GPO rollout | [Deployment](https://spydisec.github.io/WinLogKit/deployment/) |
| ATT&CK technique coverage and method | [Coverage](https://spydisec.github.io/WinLogKit/mapping/) |
| Per-setting table: event IDs, sizes, volume, baseline membership | [Reference](https://spydisec.github.io/WinLogKit/reference/) |
| How the pieces fit, behaviour category mapping | [Architecture](https://spydisec.github.io/WinLogKit/architecture/) |
| Never-do list, volume impact, known limits | [Safety](https://spydisec.github.io/WinLogKit/safety/) |
| Workstations, Home edition, common questions | [FAQ](https://spydisec.github.io/WinLogKit/faq/) |

## Contributing

Issues and PRs welcome - especially field reports on real event volumes per
setting. See [CONTRIBUTING.md](CONTRIBUTING.md) for how changes land
(branch + PR, CI gates, release process), [SECURITY.md](SECURITY.md) for
reporting vulnerabilities, and [ROADMAP.md](ROADMAP.md) for what's planned.
Changes are tracked in [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE). The upstream Yamato Security projects are also MIT licensed.
