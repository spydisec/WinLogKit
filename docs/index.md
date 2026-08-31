# WinLogKit

**An easy, auditable way to implement the
[Yamato Security](https://github.com/Yamato-Security) Windows event logging
baselines with native PowerShell.** Enable the right event channels, advanced
audit policy subcategories and registry settings; verify them repeatably;
roll them back if needed; and deploy at fleet scale - all with plain Windows
PowerShell 5.1, **no modules, no agents, no Sysmon**.

[Get the latest release](https://github.com/spydisec/WinLogKit/releases){ .md-button .md-button--primary }
[View on GitHub](https://github.com/spydisec/WinLogKit){ .md-button }

## Why

Default Windows logging supports only 10-20% of Sigma detection rules, and
most logs are capped at 1-20 MB so evidence overwrites itself in hours. The
Yamato Security baselines fix that - this kit makes them **operational**:

- **Tiered enablement** - Core applies safely by default; high-volume
  settings (process creation, PowerShell logging, WFP connections) require
  an explicit human decision, with the volume/stability risk shown first.
- **Idempotent with an exit ramp** - `-WhatIf` previews everything, the
  first real run captures a rollback baseline, `-Rollback` restores it.
- **Verification is a first-class citizen** - a read-only test with
  per-category PASS/FAIL and CSV evidence, plus an independent second
  opinion from Yamato's [WELA](https://github.com/Yamato-Security/WELA).
- **Evidence-based selection** - the
  [ATT&CK coverage mapping](mapping.md) (built on
  [OSSEM-DM](https://github.com/OTRF/OSSEM-DM)) tells you which techniques a
  selection makes observable: the Core tier covers **282 of 362** mapped
  Windows techniques, and the HighVolume tier raises that to **320**.
- **Fleet delivery built in** - Intune remediation packs, WEF/WEC
  subscription generation, and GPO artefacts, all compiled from one
  settings table so nothing can drift.

## What it targets

Windows Server 2019 / 2022 / 2025 and Windows 10 / 11 workstations,
standalone or domain joined. Version- and role-specific items are detected
at runtime and reported NOT APPLICABLE where they don't apply.

## Privacy

The kit is a **static snapshot**: the Yamato baselines and the OSSEM-DM
mappings are vendored with recorded provenance. Nothing is fetched at
runtime, and nothing about your hosts, results or baselines ever leaves
them. The single optional network action is `Invoke-WELACheck.ps1 -Download`,
which fetches WELA from GitHub to your machine when you explicitly ask.

## Credits

Settings and baselines come from Yamato Security's
[EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings),
[WELA](https://github.com/Yamato-Security/WELA) and
[EventLog-Baseline-Guide](https://github.com/Yamato-Security/EventLog-Baseline-Guide);
ATT&CK mappings from OTRF's [OSSEM-DM](https://github.com/OTRF/OSSEM-DM).
This project is affiliated with neither. MIT licensed; deviations from
upstream are documented with reasons.

!!! warning
    Same warning as the upstream guide: test every setting on a
    non-production machine mirroring your environment for at least a week
    before rolling out. Logging volume is real money and real disk.
