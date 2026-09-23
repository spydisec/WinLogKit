# WinLogKit

[![CI](https://github.com/spydisec/WinLogKit/actions/workflows/ci.yml/badge.svg)](https://github.com/spydisec/WinLogKit/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/spydisec/WinLogKit?include_prereleases)](https://github.com/spydisec/WinLogKit/releases)
[![Docs](https://img.shields.io/badge/docs-spydisec.github.io%2FWinLogKit-1b3a4b)](https://spydisec.github.io/WinLogKit/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/spydisec/WinLogKit/blob/main/LICENSE)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/spydisec/WinLogKit)

WinLogKit turns on the native Windows event logging that security
monitoring needs, proves it is recording, and can undo it, on Windows
servers and endpoints, from one sourced settings table. Plain PowerShell (7
or the built-in 5.1), no modules, no agents, no downloads.

The settings come from the [Yamato Security](https://github.com/Yamato-Security)
logging guides and Microsoft's documentation, with every setting's purpose,
volume risk and source recorded in one table. The ASD reference preset is
taken from Yamato's
[EventLog-Baseline-Guide](https://github.com/Yamato-Security/EventLog-Baseline-Guide)
scripts. Targets Windows Server 2019 / 2022 / 2025 and
Windows 10 / 11, standalone or domain-joined; version- and role-specific
items are detected at runtime and reported NOT APPLICABLE where they do not
apply.

## What it does

- **Enable** event channels, advanced audit policy subcategories and
  registry settings from one settings table. Idempotent, `-WhatIf` diff,
  `-Rollback` to first-run state.
- **Verify** the live state per behaviour category (PASS / FAIL / NOT
  APPLICABLE) with evidence CSVs.
- **Deploy** at fleet scale as an Intune remediation pack or GPO artefacts,
  compiled from the same table so deployed config cannot drift from the
  tested baseline.
- **Collect** centrally: a Windows Event Forwarding subscription generated
  from the same selection, forwarding the selected channels whole. The kit
  ends at the collector's ForwardedEvents log; any SIEM picks up from there.

## Quick start

From an elevated PowerShell prompt in the kit folder, pick the preset for
the host's role: `Workstation` (Windows 10/11), `MemberServer` or
`DomainController`. Test on a non-production machine that mirrors your
environment for at least a week before rolling out: logging volume is real
disk and real money.

```powershell
$preset = '.\presets\Workstation.csv'
.\Enable-LoggingBaseline.ps1 -BaselineFile $preset -WhatIf   # 1. full diff, nothing changes
.\Enable-LoggingBaseline.ps1 -BaselineFile $preset           # 2. apply (first run captures rollback state)
.\Test-LoggingBaseline.ps1   -BaselineFile $preset           # 3. verify
.\Enable-LoggingBaseline.ps1 -Rollback                       # undo everything captured at step 2
```

Want your own selection? Copy a preset and flip `Selected` in Excel, or run
`.\New-LoggingBaseline.ps1`, which walks every setting and writes a CSV that
Enable, Test and every fleet generator accept through `-BaselineFile`.

The three host scripts are at the kit root; fleet generators (Intune, GPO,
WEF) are in `fleet\`; `tools\` holds maintainer scripts.

## Not in scope

To keep the kit small and safe to run on any host, it deliberately doesn't:

- write files outside the event log (for example PowerShell transcripts)
- install agents, services, scheduled tasks or third-party binaries, or
  download anything
- filter events at the source, or ship SIEM content (parsers, queries,
  detections); the kit ends at the collector
- touch the [never-do list](https://spydisec.github.io/WinLogKit/safety/#what-the-kit-will-never-do)

The reasoning is in
[ADR-002](https://github.com/spydisec/WinLogKit/blob/main/docs/adr/0002-scope-and-simplification.md).
If scripts are blocked, `Set-ExecutionPolicy -Scope Process RemoteSigned`
unblocks the current window without persisting anything; downloaded zips
also need `Unblock-File`, and a policy enforced by Group Policy cannot be
overridden locally (signing or a policy change is needed). Details in
[Getting Started](https://spydisec.github.io/WinLogKit/getting-started/#if-scripts-are-blocked-running-scripts-is-disabled-on-this-system).

## Documentation

Full documentation: <https://spydisec.github.io/WinLogKit/>

| Page | Covers |
|---|---|
| [Get started](https://spydisec.github.io/WinLogKit/getting-started/) | Install, first run with a role preset, execution policy |
| [Baselines](https://spydisec.github.io/WinLogKit/baselines/) | The presets, the two tiers, building your own, deviations from the sources |
| [Deploy](https://spydisec.github.io/WinLogKit/deployment/) | Rolling out with Intune or Group Policy |
| [Collect](https://spydisec.github.io/WinLogKit/wec/) | Central collection with Windows Event Forwarding |
| [Reference](https://spydisec.github.io/WinLogKit/commands/) | Commands, every setting, ATT&CK coverage |
| [Safety & FAQ](https://spydisec.github.io/WinLogKit/safety/) | What the kit never does, volume impact, known limits |
| [Credits](https://spydisec.github.io/WinLogKit/credits/) | The projects WinLogKit is built from, and their licences |

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
affiliated with or endorsed by Yamato Security, the ASD, Microsoft or MITRE.
What the kit is built from, and each source's licence, is on the
[Credits](https://spydisec.github.io/WinLogKit/credits/) page; the kit's
deliberate deviations from the Yamato sources are
[documented with reasons](https://spydisec.github.io/WinLogKit/baselines/#deviations-from-the-yamato-sources).
