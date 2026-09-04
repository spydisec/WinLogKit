# WinLogKit

[![CI](https://github.com/spydisec/WinLogKit/actions/workflows/ci.yml/badge.svg)](https://github.com/spydisec/WinLogKit/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/spydisec/WinLogKit?include_prereleases)](https://github.com/spydisec/WinLogKit/releases)
[![Docs](https://img.shields.io/badge/docs-spydisec.github.io%2FWinLogKit-1b3a4b)](https://spydisec.github.io/WinLogKit/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/spydisec/WinLogKit/blob/main/LICENSE)

Turn on the Windows event logging that security monitoring needs, prove it
is being recorded, and roll it back if you change your mind. Plain
PowerShell (7 or the built-in 5.1), no modules, no agents.

The baselines are built from the [Yamato Security](https://github.com/Yamato-Security)
logging guides, the Australian Signals Directorate and Microsoft's own
recommendations, with every setting's purpose, volume risk and source
recorded in one table. Targets Windows Server 2019 / 2022 / 2025 and
Windows 10 / 11, standalone or domain-joined; version- and role-specific
items are detected at runtime and reported NOT APPLICABLE where they do not
apply.

## What it does

- **Enable** event channels, advanced audit policy subcategories and
  registry settings from one settings table. Idempotent, `-WhatIf` diff,
  `-Rollback` to first-run state.
- **Verify** the live state per behaviour category (PASS / FAIL / NOT
  APPLICABLE) with evidence CSVs, plus Yamato's WELA as an independent
  second opinion.
- **Collect** centrally: a Windows Event Forwarding subscription generated
  from the same selection. It forwards the selected channels whole by
  default, or narrows Security to the event IDs the baseline actually
  produces. The kit ends at the collector's ForwardedEvents log; any SIEM
  picks up from there.
- **Deploy** at fleet scale as an Intune remediation pack or GPO artefacts,
  compiled from the same table so deployed config cannot drift from the
  tested baseline.
- **Measure** which MITRE ATT&CK techniques a selection makes observable,
  offline, from data shipped in the kit.

## Quick start

From an elevated PowerShell prompt in the kit folder. Test on a
non-production machine that mirrors your environment for at least a week
before rolling out: logging volume is real disk and real money.

```powershell
.\Enable-LoggingBaseline.ps1 -WhatIf              # 1. full diff, nothing changes
.\Enable-LoggingBaseline.ps1                      # 2. apply Core (first run captures rollback state)
.\Test-LoggingBaseline.ps1                        # 3. verify
.\Enable-LoggingBaseline.ps1 -IncludeHighVolume   # 4. add the high-volume tier after reading its notes
.\Enable-LoggingBaseline.ps1 -Rollback            # undo everything captured at step 2
```

Want your own selection? `.\New-LoggingBaseline.ps1` walks every setting
and writes a CSV that Enable, Test, the coverage report and every fleet
generator accept through `-BaselineFile`; `presets\` ships ready-made
ones (ASD, Microsoft, and the kit's own `spydi_*` Minimal / Heavy pairs
per role).

The three host scripts are at the kit root; fleet generators (Intune, GPO,
WEF) are in `fleet\` and the coverage report and WELA check in `report\`.

If scripts are blocked, `Set-ExecutionPolicy -Scope Process RemoteSigned`
unblocks the current window without persisting anything; downloaded zips
also need `Unblock-File`, and a policy enforced by Group Policy cannot be
overridden locally (signing or a policy change is needed). Details in
[Getting Started](https://spydisec.github.io/WinLogKit/getting-started/#if-scripts-are-blocked-running-scripts-is-disabled-on-this-system).

## Documentation

Full documentation: <https://spydisec.github.io/WinLogKit/>

| Page | Covers |
|---|---|
| [Getting Started](https://spydisec.github.io/WinLogKit/getting-started/) | Install, first run, execution policy, where output lands |
| [Baselines](https://spydisec.github.io/WinLogKit/baselines/) | Tiers, presets, deviations from the sources |
| [Commands](https://spydisec.github.io/WinLogKit/commands/) | Every script and its switches |
| [Collect](https://spydisec.github.io/WinLogKit/wec/) | WEF / WEC: subscription, collector and source setup, XPath filtering |
| [Deploy](https://spydisec.github.io/WinLogKit/deployment/) | Intune and GPO rollout |
| [Coverage](https://spydisec.github.io/WinLogKit/mapping/) | How the pieces fit, behaviour categories, ATT&CK technique coverage |
| [Reference](https://spydisec.github.io/WinLogKit/reference/) | Every setting: event IDs, sizes, volume, preset membership |
| [Safety & FAQ](https://spydisec.github.io/WinLogKit/safety/) | Never-do list, volume impact, known limits, common questions |
| [Add-ons](https://spydisec.github.io/WinLogKit/addons/) | AutorunsToWinEventLog (optional, needs Sysinternals autorunsc) |

## Safety

The kit never touches the settings that can hang or lock out a host
(`CrashOnAuditFail`, "do not overwrite" retention, global object access
auditing, blanket SACLs) and never reboots, restarts services or shrinks
logs. Heavy settings carry a risk note the builder shows before you select
them. Use at your own risk.

## Contributing

Issues and PRs welcome, field reports on real event volumes per setting
especially. See
[CONTRIBUTING.md](https://github.com/spydisec/WinLogKit/blob/main/CONTRIBUTING.md)
for how changes land,
[SECURITY.md](https://github.com/spydisec/WinLogKit/blob/main/SECURITY.md)
for reporting vulnerabilities, and
[CHANGELOG.md](https://github.com/spydisec/WinLogKit/blob/main/CHANGELOG.md)
for what changed. Planned work is tracked in
[issues](https://github.com/spydisec/WinLogKit/issues).

## License

[MIT](https://github.com/spydisec/WinLogKit/blob/main/LICENSE). Not
affiliated with or endorsed by Yamato Security, the ASD or Microsoft; the
Yamato projects the settings derive from are also MIT licensed, and the
kit's deliberate deviations from them are
[documented with reasons](https://spydisec.github.io/WinLogKit/baselines/#deviations-from-the-yamato-sources).
