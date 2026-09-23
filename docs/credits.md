# Credits

WinLogKit is built on other people's published work. This page lists what
the kit is built from, what it points you to, and the tools used to make
it. Licences are as published by each project; check the project itself
for the current terms.

## Built from

These sources shaped the settings table, the presets and the coverage data.

| Source | What WinLogKit takes from it | Licence |
|---|---|---|
| [Yamato Security: EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings) | The core of the settings table: which event channels to enable and how large to make them, which audit subcategories to turn on, and the PowerShell logging policies. Setting values were taken in August 2026; the descriptions in the kit are its own wording. Deliberate differences are in the [deviations table](baselines.md#deviations-from-the-yamato-sources). | GPL-3.0 |
| [Yamato Security: WELA](https://github.com/Yamato-Security/WELA) | A second source for settings (the values its `configure` command uses, such as NTLM and AD CS auditing), and this site's stylesheet, adapted with WELA's MIT copyright and permission notice kept in `docs/stylesheets/extra.css`. | MIT |
| [Yamato Security: EventLog-Baseline-Guide](https://github.com/Yamato-Security/EventLog-Baseline-Guide) | The ASD, Microsoft client and Microsoft server baselines: the `ASD` preset and the **Refs** column on the [Reference](reference.md) page. | MIT |
| Australian Signals Directorate (ASD) | The ASD baseline, taken from Yamato's EventLog-Baseline-Guide scripts rather than ASD's own publication. | - |
| [Microsoft Learn](https://learn.microsoft.com/) | The documentation behind individual settings and their values: advanced audit policy, NTLM auditing, SMB signing and encryption auditing on Windows Server 2025, PowerShell logging, Windows Event Forwarding, Intune remediations. Linked where each setting is described. | Microsoft terms |
| [MITRE ATT&CK](https://attack.mitre.org/) ([attack-stix-data](https://github.com/mitre-attack/attack-stix-data)) | ATT&CK Enterprise v19.2, flattened into `data/attack/windows_analytics.csv` for the [Coverage](mapping.md) numbers. MITRE ATT&CK® is a registered trademark of The MITRE Corporation; used per the [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). | ATT&CK Terms of Use |

WinLogKit is not affiliated with or endorsed by Yamato Security, the ASD,
Microsoft or MITRE.

## Pointed to, not included

The docs mention these for jobs the kit deliberately doesn't do. None of
them ships with the kit or is downloaded by it.

| Project | Why it's mentioned |
|---|---|
| [Yamato Security: WELA](https://github.com/Yamato-Security/WELA) | An independent, by-hand cross-check of your audit settings ([Commands](commands.md#cross-checking-with-wela-optional)). |
| [Yamato Security: Hayabusa](https://github.com/Yamato-Security/hayabusa) | Its `eid-metrics` command measures event volume per event ID during a pilot ([Safety](safety.md)). |
| [Microsoft Sysinternals: Autoruns](https://learn.microsoft.com/sysinternals/downloads/autoruns) | Inventories registry autostart entries, a gap native logging can't close ([Safety](safety.md#known-limits-stated-plainly)). |
| [Palantir: AutorunsToWinEventLog](https://github.com/palantir/windows-event-forwarding/tree/master/AutorunsToWinEventLog) | One way to write the Autoruns inventory to an event log for collection. |
| [Microsoft Security Compliance Toolkit: LGPO.exe](https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10) | Applies the generated GPO pack ([Deploy](deployment.md)). |

## Built with

| Tool | Used for |
|---|---|
| [MkDocs](https://www.mkdocs.org/) and [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/) | This site |
| [GitHub Actions](https://docs.github.com/actions) | Continuous integration, the docs site and release packaging |
| [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer) | Linting every script |
| [Microsoft DevSkim](https://github.com/microsoft/DevSkim) | Security scanning, reported through GitHub code scanning |
