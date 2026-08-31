# WinLogKit

**WinLogKit** turns the
[Yamato Security](https://github.com/Yamato-Security) logging baselines into
something you can actually deploy: enable the right Windows events, prove
they're being recorded, and roll back if you change your mind - plain
PowerShell, no agents.

[Get started in 10 minutes](getting-started.md){ .md-button .md-button--primary }
[See your ATT&CK coverage](mapping.md){ .md-button }
[View on GitHub](https://github.com/spydisec/WinLogKit){ .md-button }

Out of the box, Windows logs support only 10-20% of Sigma detection rules -
and overwrite the evidence within hours.

## Why WinLogKit

<div class="grid cards" markdown>

-   __Deploy with an exit ramp__

    ---

    Preview everything with `-WhatIf`; an automatic pre-change backup means
    one command rolls it all back.

-   __Prove it, don't assume it__

    ---

    Per-category PASS/FAIL with evidence CSVs, plus Yamato's
    [WELA](https://github.com/Yamato-Security/WELA) as an independent
    second opinion.

-   __Decide volume with numbers__

    ---

    The [ATT&CK coverage report](mapping.md) (current MITRE v19.2 data)
    measures each tier - Heavy buys 98% of the native ceiling.

-   __One table, every target__

    ---

    Intune packs, WEF subscriptions and GPO artefacts all compile from one
    settings table - deployed config can't drift from the tested baseline.

</div>

## What it targets

Windows Server 2019 / 2022 / 2025 and Windows 10 / 11 workstations,
standalone or domain-joined. Version- and role-specific items are detected
at runtime and reported NOT APPLICABLE where they don't apply. Baselines
ship as reviewable CSVs: reference sets (ASD, Microsoft), per-role starting
points, and the blended `spydi_*` Minimal/Heavy pairs -
[all documented with sources and event IDs](baselines.md).

## Privacy

The kit is a **static snapshot**: the Yamato baselines and the MITRE ATT&CK
mapping data are vendored with recorded provenance. Nothing is fetched at
runtime, and nothing about your hosts, results or baselines ever leaves
them. The single optional network action is `Invoke-WELACheck.ps1 -Download`,
which fetches WELA from GitHub to your machine when you explicitly ask.

## Credits

Settings and baselines come from Yamato Security's
[EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings),
[WELA](https://github.com/Yamato-Security/WELA) and
[EventLog-Baseline-Guide](https://github.com/Yamato-Security/EventLog-Baseline-Guide);
ATT&CK mapping data from [MITRE ATT&CK](https://github.com/mitre-attack/attack-stix-data)
with approach credit to OTRF's [OSSEM-DM](https://github.com/OTRF/OSSEM-DM).
This project is affiliated with none of them. MIT licensed; deviations from
upstream are documented with reasons.

!!! warning "Test before you trust"
    Logging volume costs disk and money. Run any baseline on a mirror of
    production for a week, then use the coverage and volume numbers to
    decide what stays.
