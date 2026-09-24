# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Releases are tagged `vX.Y.Z` and published with a zip and a SHA256 checksum.

## [Unreleased]

### Added

- 🛡️ **Advanced audit policy can't be silently overridden.** A new Core setting turns on "Audit: Force audit policy subcategory settings to override audit policy category settings" (`SCENoApplyLegacyAuditPolicy`). It's Windows' default, but a policy that turns it off lets legacy category-level audit policy override every subcategory the kit applies; now Enable sets it, Test verifies it, and the Settings catalog and Group Policy pages map it. The role presets include it; ASD stays faithful to its script. [#71](https://github.com/spydisec/WinLogKit/issues/71)
- 🚨 **Test checks that CrashOnAuditFail is off.** It's on the never-do list and the kit never sets it, but another policy might; Test now fails if it's on, since a full Security log would then halt the host. [#75](https://github.com/spydisec/WinLogKit/issues/75)

### Fixed

- 🧯 **Failed log changes are reported as failures.** Enable sent `wevtutil` output to nowhere and never checked its exit code, so a log resize or enable that failed was reported as Changed (and `-Rollback` had the same gap). It now reports an Error with `wevtutil`'s own message and exits non-zero. [#70](https://github.com/spydisec/WinLogKit/issues/70)

## [2.1.0] - 2026-09-24

Simpler fleet delivery, documented setting by setting: Intune through the Settings catalog, a Group Policy path for every setting, and SMB auditing in the GPO pack. Plus PowerShell 7 logging, a disk-space check before you apply, verification that works in any Windows language, and an ATT&CK mapping with no gaps left unexplained.

**Upgrading from 2.0.x**

| If you used | Now |
|---|---|
| `fleet\New-IntuneRemediationPack.ps1`, or its remediations in Intune | Build a Settings catalog profile from the [Settings catalog](https://spydisec.github.io/WinLogKit/intune-csp/) page, then remove the old remediation from Intune. It keeps running until you do, but is no longer maintained. |
| A role preset (`Workstation`, `MemberServer`, `DomainController`) | Rerun Enable with it: the presets now also turn on PowerShell 7 script block logging. |
| Anything else | Unchanged: scripts, switches, presets and selection CSVs work as before. |

### Added

- 🐚 **PowerShell 7 is logged too.** Four new HighVolume settings make PowerShell 7 (`pwsh.exe`) follow the Windows PowerShell script block and module logging policies through its `UseWindowsPowerShellPolicySetting` option, so running `pwsh` instead of `powershell.exe` no longer escapes script block logging. The role presets turn on the two script block ones alongside the settings they follow; `ASD.csv` stays faithful to the ASD script, which predates PowerShell 7. [#44](https://github.com/spydisec/WinLogKit/issues/44)
- 🏛️ **Group Policy paths.** A new docs page lists where every kit setting lives in a Group Policy Object (advanced audit policy, Administrative Templates, Security Options) and what to set it to, plus what has no Group Policy template (most log sizes, the 32-bit copies, which Group Policy Preferences can still set, and AD CS). Generated from the settings table, like the Settings catalog page. The GPO pack's `registry.txt` now also carries SMB signing and encryption auditing, through its Lanman Server / Workstation policies. [#48](https://github.com/spydisec/WinLogKit/issues/48)
- 🗂️ **Settings catalog mapping.** A new docs page maps every kit setting to its Intune Settings catalog / Policy CSP equivalent, with the value to set and a link to Microsoft's page, and lists what has no CSP (most log sizes, the 32-bit and PowerShell 7 copies, AD CS). Outgoing NTLM auditing is deliberately left out: Microsoft documents that CSP's value 1 as "Deny all domain accounts", where the registry value 1 means "Audit all". Generated from the settings table, so it can't drift. [#47](https://github.com/spydisec/WinLogKit/issues/47)
- 💾 **Disk space check.** Enable (including `-WhatIf`) and Test now work out, per drive, how much more the selected logs can grow before they reach their maximum sizes, and warn when that would leave under 10% of the drive free or not fit at all, so a host that needs more disk is known before rollout rather than after. Warns only, never blocks or fails. [#51](https://github.com/spydisec/WinLogKit/issues/51)
- 🚨 **Unregistered PowerShell 7 event log caught.** `Test-LoggingBaseline.ps1` now fails `PowerShellCore/Operational` when PowerShell 7 is installed but its event log isn't registered (Store and zip installs), where it used to report it as not applicable, and says how to register it. [#44](https://github.com/spydisec/WinLogKit/issues/44)

### Changed

- 🎯 **ATT&CK mapping curated: nothing left Unmapped.** Every log source MITRE's analytics name is now mapped to the kit item that produces it or classified with a reason, and the self-checks fail if a refresh adds one that isn't. Four corrections where ATT&CK names the wrong log (shutdown 1074 is in System, Code Integrity 3033 in its own log) or the kit already collects the events (firewall rule changes in the Firewall log) make four more techniques observable: Core + HighVolume now reaches 283 techniques (was 279). The native ceiling is restated from the report's own classification (298, was quoted as 284), and the Coverage and Baselines numbers are regenerated and dated. `data\attack\README.md` now sets a refresh cadence and the steps. [#49](https://github.com/spydisec/WinLogKit/issues/49)
- 🧪 **Self-checks run on Pester 5.** The checks move to a Pester suite (`tests\Kit.Tests.ps1`, one test per check) so they can be named, filtered and reported one by one. `tests\Invoke-KitChecks.ps1` is still the command to run: it finds Pester 5, runs the suite and tells you how to install Pester if it's missing. Pester is a development and CI dependency only; the kit itself still needs no modules. [#50](https://github.com/spydisec/WinLogKit/issues/50)

### Fixed

- 🌍 **Verification works in any Windows language.** Test and Enable read audit policy from `auditpol /backup`'s numeric setting values instead of the `auditpol /get` text, which is translated on non-English Windows (only English said "Success and Failure"), so a correctly configured non-English host no longer fails its audit checks or gets re-applied on every run. [#45](https://github.com/spydisec/WinLogKit/issues/45)
- ↩️ **Rollback covers settings added by later versions.** The rollback copy is taken on the first run, so a setting added by a later kit version, like the PowerShell 7 ones, was left behind by `-Rollback`. Every later run now records any setting the copy doesn't know yet, in its current state, before changing anything. [#44](https://github.com/spydisec/WinLogKit/issues/44)

### Removed

- 📲 **Intune remediation pack.** Intune is now delivered through the Settings catalog only, with no scripts on endpoints ([ADR-003](docs/adr/0003-intune-settings-catalog-only.md)): `fleet\New-IntuneRemediationPack.ps1` is gone and the Deploy page points to the [Settings catalog](https://spydisec.github.io/WinLogKit/intune-csp/) page. Settings with no CSP (most log sizes and enablement, the 32-bit and PowerShell 7 copies of the PowerShell policies, outgoing NTLM auditing) aren't delivered by Intune; the page lists them, and `Enable-LoggingBaseline.ps1` run once on a device covers them. Remediations already in a tenant keep running but aren't maintained: replace them with a Settings catalog profile. [#63](https://github.com/spydisec/WinLogKit/issues/63)

## [2.0.0] - 2026-09-23

A scope reset ([ADR-002](docs/adr/0002-scope-and-simplification.md)): WinLogKit turns on the native Windows event logging that security monitoring needs, proves it is recording, and can undo it. Anything outside that (files outside the event log, downloads, source-side filtering, SIEM content) is gone. This is a major version because presets are renamed and scripts, switches and data folders are removed.

**Upgrading from 1.x**

| If you used | Now |
|---|---|
| `role_*.csv`, `spydi_*.csv` or `Microsoft_*.csv` presets | `Workstation.csv`, `MemberServer.csv`, `DomainController.csv` or `ASD.csv` (details under Changed) |
| `-IncludeOptional` | `-IncludeHighVolume` (the old switch still parses, warns and does nothing) |
| `New-WefSubscription.ps1 -Filter Baseline` or `Test-WefFilter.ps1` | The whole-channel subscription; filter at your SIEM's ingest layer |
| `report\Invoke-WELACheck.ps1` | Run WELA yourself if you want a second opinion |
| `report\Export-AttackCoverage.ps1` | `tools\Export-AttackCoverage.ps1` |
| The Autoruns add-on (`addons\`) | Removed; run `Install-AutorunsToWinEventLog.ps1 -Uninstall` from a 1.x copy first |
| PowerShell transcription settings | Removed; `-Rollback` or deleting the `Transcription` policy keys clears them |

### Added

- 🙏 **Credits page.** The docs site now lists every source WinLogKit is built from, what it takes from each and under which licence, the tools it points to without including, and the tooling used to build it. [#55](https://github.com/spydisec/WinLogKit/pull/55)
- 🧭 **Decision records in the repository.** Architecture decisions now live in `docs/adr/`: ADR-001 recorded after the fact for the 1.0 layout, and ADR-002 for this release. They stay on GitHub and are left off the docs site. [#37](https://github.com/spydisec/WinLogKit/pull/37), [#43](https://github.com/spydisec/WinLogKit/pull/43), [#55](https://github.com/spydisec/WinLogKit/pull/55)
- 🏷️ **Situational settings flag.** IPsec Driver auditing and the Crypto-DPAPI debug channel carry a `Situational` flag in the settings table, marking them opt-in because they only matter in some environments rather than because they are loud, so the Reference page labels them by their real volume. [#54](https://github.com/spydisec/WinLogKit/pull/54)

### Changed

- 🎯 **One clear goal.** The README opens with the kit's purpose in one sentence, leads the quick start with a role preset, and lists what is deliberately out of scope. Get started follows the same preset flow: preview, apply, verify. [#43](https://github.com/spydisec/WinLogKit/pull/43)
- 🧩 **Two tiers instead of three.** The Optional tier is gone and its two remaining items, the Crypto-DPAPI debug channel and IPsec Driver auditing, are now HighVolume, so `-IncludeHighVolume` also turns them on. Preset selections are unchanged. [#38](https://github.com/spydisec/WinLogKit/pull/38)
- 🗂️ **Four presets instead of ten.** One per host role plus ASD, so there is one answer to "which preset?". The role presets are renamed with identical selections, and the Microsoft client and server baselines remain only as reference data for the Reference page. [#39](https://github.com/spydisec/WinLogKit/pull/39)
    - `role_Workstation.csv`, `role_MemberServer.csv`, `role_DomainController.csv` become `Workstation.csv`, `MemberServer.csv`, `DomainController.csv` (same selections).
    - `spydi_Workstation_Minimal.csv` maps to `Workstation.csv`, which differs by one item: WFP connections instead of IPsec Driver.
    - `spydi_Server_Minimal.csv` maps to `MemberServer.csv` or `DomainController.csv`.
    - `spydi_*_Heavy.csv` maps to the role preset with the HighVolume rows you want flipped to Y in your copy.
    - `Microsoft_Client.csv` and `Microsoft_Server.csv` are narrower than the kit's Core tier; use `ASD.csv` or a role preset.
- 📋 **Reference page shows role presets.** The Minimal and Heavy columns become Wks, Mbr and DC, one for each role preset. The Refs and Volume columns match 1.0.0 for every setting. [#39](https://github.com/spydisec/WinLogKit/pull/39), [#54](https://github.com/spydisec/WinLogKit/pull/54)
- 📡 **Collection forwards whole channels.** `New-WefSubscription.ps1` now forwards every event of each selected channel. A filter inside the subscription runs on each source and drops events silently when it is wrong, so filtering belongs at your SIEM's ingest layer. `-Filter Channel` is still accepted; `-Filter Baseline` stops with a pointer to these notes. A deployed Baseline-filtered subscription should be regenerated and re-imported with `wecutil ss <name> /c:<file>`. [#41](https://github.com/spydisec/WinLogKit/pull/41)
- 🛠️ **Coverage report is a maintainer tool.** `Export-AttackCoverage.ps1` moves to `tools\`. It produces the numbers on the Coverage page and still works on any selection CSV, but deploying the kit doesn't need it, so the `report\` folder is gone. [#42](https://github.com/spydisec/WinLogKit/pull/42)
- 📚 **Simpler docs site.** Navigation follows a user's path (Get started, Baselines, Deploy, Collect) with Commands, Settings and Coverage grouped under Reference. Get started is one straight path with the execution-policy detail folded away, and Collect leads with setup and condenses the existing-collector checks. [#55](https://github.com/spydisec/WinLogKit/pull/55)
- ⚖️ **Licences stated accurately.** The README said all the Yamato sources were MIT. Yamato's EnableWindowsLogSettings is GPL-3.0; WELA and EventLog-Baseline-Guide are MIT. The README and the Credits page now say so. [#55](https://github.com/spydisec/WinLogKit/pull/55)
- 🔖 **DeepWiki badge.** The README carries a link to the project's DeepWiki page. [#33](https://github.com/spydisec/WinLogKit/pull/33)

### Deprecated

- ⏳ **`-IncludeOptional`.** Every script still accepts it, so existing command lines keep working, but it only prints a deprecation warning and selects nothing. It will be removed in a later release. [#38](https://github.com/spydisec/WinLogKit/pull/38)

### Fixed

- 🏷️ **Reference labels for the former Optional items.** Moving IPsec Driver and the DPAPI debug channel to HighVolume had relabelled them as high volume and as part of Yamato's set; they are back to their 1.0.0 labels. [#54](https://github.com/spydisec/WinLogKit/pull/54)
- 🧪 **Self-checks run from the release zip.** The zip ships `tests\` but not `docs\`, so the Reference page drift check failed there; it now skips with a message when `docs\` is absent. [#54](https://github.com/spydisec/WinLogKit/pull/54)
- 🔐 **Security policy scope.** SECURITY.md no longer lists a download path that doesn't exist, and says plainly that the scripts make no outbound requests while the WEF subscription you deploy forwards events by design. [#54](https://github.com/spydisec/WinLogKit/pull/54)
- 📖 **Docs match what the kit does.** Known limits now name the PowerShell 7 logging gap ([#44](https://github.com/spydisec/WinLogKit/issues/44)) and link the open work, the Coverage page no longer claims full PowerShell coverage, and Deploy notes the Intune pack hasn't been field-tested yet ([#46](https://github.com/spydisec/WinLogKit/issues/46)). [#55](https://github.com/spydisec/WinLogKit/pull/55)

### Removed

- 📝 **PowerShell transcription.** With no output folder set, every PowerShell session wrote a transcript into the user's Documents folder, which OneDrive then synced; doing it safely needs a folder, permissions, retention and a collection path of its own. Script block logging (4104) already records the code that ran. Old selection CSVs that list the rows are warned about and the rows ignored. [#36](https://github.com/spydisec/WinLogKit/pull/36), [#34](https://github.com/spydisec/WinLogKit/issues/34)
- 🧹 **AutorunsToWinEventLog add-on.** It downloaded Sysinternals `autorunsc` and installed a scheduled task, the one part of the kit that broke its no-download, no-agent rule. The Safety page points to Sysinternals Autoruns and Palantir's AutorunsToWinEventLog for anyone who needs that coverage. [#53](https://github.com/spydisec/WinLogKit/pull/53)
- 🎛️ **Source-side WEF filtering.** `-Filter Baseline`, the expected-event-ID sidecar, `fleet\Test-WefFilter.ps1`, `tools\Update-AuditSubcategoryEvents.ps1`, `data\wef\` and the `$BaselineWefSuppress` Suppress rules. Verify collection with `Test-LoggingBaseline.ps1 -WefRole Collector` or `-WefRole Source`. [#41](https://github.com/spydisec/WinLogKit/pull/41)
- 🔍 **WELA check.** `report\Invoke-WELACheck.ps1` downloaded a third-party tool, and `Test-LoggingBaseline.ps1` already verifies the live state. The Commands page keeps the notes on where WELA and the kit legitimately differ, and the kit now has no network action at all. [#40](https://github.com/spydisec/WinLogKit/pull/40)
- 📊 **Sentinel KQL page.** It sat past the kit's boundary, after the collector, and its queries were never validated against a workspace. [#40](https://github.com/spydisec/WinLogKit/pull/40)
- 🗄️ **Legacy coverage snapshot.** The second technique mapping kept only as a cross-check (`data\ossem\`, 917 KB) and the report's `-UseOssem` mode. The native ATT&CK mapping in `data\attack\` is unchanged. [#40](https://github.com/spydisec/WinLogKit/pull/40)

## [1.0.0] - 2026-09-04

The 1.0 restructure ([ADR-001](docs/adr/0001-v1-layout.md)): a docs cut, one copy of the shared helpers, and a layout that shows a new reader the three scripts they need. It is a major version because paths moved; no setting changed.

### Changed

- 📁 **New layout.** The fleet generators (`New-IntuneRemediationPack.ps1`, `New-GpoPack.ps1`, `New-WefSubscription.ps1`, `Test-WefFilter.ps1`) now live in `fleet\`, and the coverage report and WELA check in `report\`. The three host scripts stay at the root with the settings table and shared helpers, and output folders stay at the kit root wherever a script runs from. [#32](https://github.com/spydisec/WinLogKit/pull/32)
- ✏️ **Settings table renamed.** `LoggingBaseline.Settings.ps1` is now `WinLogKit.Settings.ps1` with the same contents; rename any modified copy you carry. [#32](https://github.com/spydisec/WinLogKit/pull/32)
- 🧰 **One copy of the shared helpers.** The admin check, host role and OS type probes, registry reads, the audit policy and SMB readers, selection-CSV loading and the tier logic now live in `WinLogKit.Common.ps1` instead of a copy in every script, and the self-checks fail if a function is defined twice. Every generated file now describes its source the same way. [#31](https://github.com/spydisec/WinLogKit/pull/31)
- ✅ **Selection CSVs checked before use.** A file that isn't a selection CSV, has an empty ItemType or Id, lists an item twice, or matches nothing in the settings table now stops the run with a message naming the problem, instead of an obscure error or a silent select-nothing. Rows for items the kit doesn't know are warned about and ignored, so older CSVs still work. [#31](https://github.com/spydisec/WinLogKit/pull/31)
- ✂️ **Docs cut.** The README fits on one screen and doubles as the site home page, and the site goes from 13 pages to 10: Collect absorbs the WEF parts of Deployment, Architecture merges into Coverage, the FAQ merges into Safety, and the Sentinel KQL page moves outside the navigation. [#30](https://github.com/spydisec/WinLogKit/pull/30)
- 🗺️ **Roadmap moves to issues.** `ROADMAP.md` is removed and planned work is tracked as GitHub issues; the release zip no longer ships it. [#30](https://github.com/spydisec/WinLogKit/pull/30)
- 🦅 **Built-in Sysmon noted.** The FAQ's Sysmon answer covers Sysmon as a built-in optional feature of Windows 11 and Windows Server 2025, per [Microsoft's Sysmon overview](https://learn.microsoft.com/windows/security/operating-system-security/sysmon/overview). [#30](https://github.com/spydisec/WinLogKit/pull/30)

## [0.11.0] - 2026-09-04

### Added

- 🎯 **WEF filtering matched to the baseline.** `New-WefSubscription.ps1 -Filter Baseline` narrows the Security channel to the event IDs the baseline's audit subcategories can produce, from Microsoft's documented lists, plus the always-on log-tamper events, packed under the 32-expression cap per query. It refuses to build a filter for a subcategory it has no documented IDs for, `-Validate` parses every query locally, and a sidecar CSV records what the subscription should deliver. Suppress rules can be set in the settings table and ship empty. [#28](https://github.com/spydisec/WinLogKit/pull/28), [#29](https://github.com/spydisec/WinLogKit/pull/29)
- 🔬 **Filter proof on the collector.** `Test-WefFilter.ps1` shows whether the filter is in effect from evidence: unexpected event IDs in ForwardedEvents, the deployed query against the generated file, and the equivalent Sentinel KQL. [#28](https://github.com/spydisec/WinLogKit/pull/28)
- 📖 **Filtering guide.** The WEC Collector page explains how the XPath subset works, the two-gate contract and the four confirmation checks, and CI checks the snapshot and the generated query. [#28](https://github.com/spydisec/WinLogKit/pull/28)

## [0.10.1] - 2026-09-03

### Changed

- 🤝 **Add-on credited properly.** The Autoruns add-on's docs and script headers present it as WinLogKit's own implementation of the idea, with Palantir's AutorunsToWinEventLog credited and its MIT notice kept. No functional change. [#27](https://github.com/spydisec/WinLogKit/pull/27)

## [0.10.0] - 2026-09-03

### Added

- 🧷 **AutorunsToWinEventLog add-on.** An optional, separate extra for the Persistence gap: a daily SYSTEM scheduled task runs Sysinternals `autorunsc` and writes every autostart entry to an `Autoruns` event log for collection. It verifies the binary's signature before running it as SYSTEM, keeps hashes and signatures, handles UTF-8, and supports `-WhatIf`, `-Status`, `-Uninstall` and `-RunNow`. Inspired by Palantir's MIT-licensed tool. [#26](https://github.com/spydisec/WinLogKit/pull/26)

## [0.9.0] - 2026-09-02

### Added

- 📥 **WEC Collector page.** How to read an existing collector: subscription anatomy, wide-open queries, delivery modes, reconciling registered sources, ForwardedEvents health and the classic silent failures. [#24](https://github.com/spydisec/WinLogKit/pull/24)
- 📊 **Sentinel KQL page.** Which table forwarded events land in, a four-layer check that the agent collects ForwardedEvents, and a query pack covering fleet inventory, collection method per source, silent collectors, domain controller paths, latency and volume. [#24](https://github.com/spydisec/WinLogKit/pull/24), [#25](https://github.com/spydisec/WinLogKit/pull/25)

### Changed

- 🐚 **PowerShell 7 is first-class.** The docs and CONTRIBUTING say plainly that both engines are supported and tested in CI, with Windows PowerShell 5.1 as the compatibility floor because it ships with Windows and [Intune remediations run under it](https://learn.microsoft.com/intune/intune-service/fundamentals/remediations). [#23](https://github.com/spydisec/WinLogKit/pull/23)

## [0.8.0] - 2026-08-31

### Added

- 📋 **Reference page.** One generated table of every setting: key event IDs, log size default and target, volume weight, which reference baselines ask for it, and preset membership. It is drift-checked in CI, so it can't go stale. [#21](https://github.com/spydisec/WinLogKit/pull/21)
- 🤝 **Community files.** CONTRIBUTING, SECURITY (private vulnerability reporting), issue templates including a field report for real volume data, and a PR checklist. [#22](https://github.com/spydisec/WinLogKit/pull/22)

### Changed

- 🎨 **Docs look and readability.** A new site theme with a credited stylesheet, a readability pass, and hand-drawn SVG diagrams replacing Mermaid, which rendered as unreadable strips. [#17](https://github.com/spydisec/WinLogKit/pull/17), [#18](https://github.com/spydisec/WinLogKit/pull/18), [#20](https://github.com/spydisec/WinLogKit/pull/20)
- 🚪 **README as a front door.** The README is trimmed to a quick start and pointers, with the detailed content moved into the docs rather than deleted. [#22](https://github.com/spydisec/WinLogKit/pull/22)
- 🛰️ **IPsec Driver description corrected.** Events 5478-5480 and 5483-5485 are IPsec service start/stop and filter-processing events, per Microsoft's [advanced audit policy reference](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration), not driver integrity failures.

### Fixed

- 🛡️ **Registry writes can't wipe sibling values.** After reviewing an upstream WELA bug where `New-Item -Force` wiped existing registry values, every kit registry write goes through `Registry::SetValue`, and a CI check keeps it that way. The WELA download was also made forward-compatible. [#19](https://github.com/spydisec/WinLogKit/pull/19)

## [0.7.0] - 2026-08-31

### Added

- 📸 **Snapshots before every apply.** Every real apply after the first saves a timestamped copy of the current state (audit policy backup plus channel, registry and SMB state) before changing anything, so moving between baselines leaves a record. The first-run capture and `-Rollback` are unchanged. [#15](https://github.com/spydisec/WinLogKit/pull/15)
- ⚖️ **Blended Minimal and Heavy baselines.** Presets combining ASD, Microsoft and Yamato on two axes, role (Server or Workstation) and volume (Minimal or Heavy), with a per-group source table and a decision diagram in the docs. [#14](https://github.com/spydisec/WinLogKit/pull/14)
- 🏠 **Landing page rewrite.** The docs landing page was rewritten after a UX copy review, which also fixed buttons that rendered as literal markup.

## [0.6.0] - 2026-08-31

### Added

- 🗺️ **Native ATT&CK mapping.** The coverage report joins a snapshot of MITRE ATT&CK Enterprise v19.2 (detection strategies to Windows analytics to log sources and event codes) through a kit-curated event map, with NotNative and Unmapped statuses so limits and curation gaps stay visible. With 472 Windows techniques mapped and a native-logging ceiling of 284, Core reaches 162 and Core plus HighVolume 279. [#12](https://github.com/spydisec/WinLogKit/pull/12)
- 🧱 **Architecture page.** A diagram of the kit's one mechanism: snapshots in, the settings table, host and fleet artefacts, events out to a collector. [#12](https://github.com/spydisec/WinLogKit/pull/12)

### Fixed

- 📦 **Release zip contents.** The zip left out `data\`, `presets\`, `tools\` and `tests\`, so coverage and presets failed from a zip install; it now carries them. [#12](https://github.com/spydisec/WinLogKit/pull/12)

## [0.5.0] - 2026-08-31

### Added

- 👥 **Per-role presets.** Workstation, member server and domain controller presets: Core plus the high-value items each role can afford, with every hold-back justified by the settings table's risk notes and documented. [#10](https://github.com/spydisec/WinLogKit/pull/10)
- 🔓 **Execution policy help.** Getting Started explains the "running scripts is disabled" blocker with the least invasive fixes first, per [about_Execution_Policies](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_execution_policies). [#9](https://github.com/spydisec/WinLogKit/pull/9)

## [0.4.0] - 2026-08-31

### Added

- 🏢 **GPO delivery.** `New-GpoPack.ps1` generates an advanced audit policy `audit.csv` and an LGPO `registry.txt` from any selection, with reminders for what GPO packs can't carry. [#7](https://github.com/spydisec/WinLogKit/pull/7)
- 📡 **Central collection.** `New-WefSubscription.ps1` generates a source-initiated Windows Event Forwarding subscription from any selection, with collector and source setup printed, following [Microsoft's WEF guidance](https://learn.microsoft.com/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection). [#6](https://github.com/spydisec/WinLogKit/pull/6)
- 🔌 **WEF checks.** `Test-LoggingBaseline.ps1 -WefRole Source` or `-WefRole Collector` verifies the forwarding policy and WinRM on sources, and the collector service, ForwardedEvents size and loaded subscriptions on collectors. [#7](https://github.com/spydisec/WinLogKit/pull/7)
- 📈 **ATT&CK coverage report.** `Export-AttackCoverage.ps1` reports which techniques a selection makes observable, with a reason for each gap. [#7](https://github.com/spydisec/WinLogKit/pull/7)
- 📚 **Documentation site.** Getting started, commands, baselines, deployment, coverage and safety, published to GitHub Pages. [#7](https://github.com/spydisec/WinLogKit/pull/7)
- 📑 **Reference presets.** ASD, Microsoft client and Microsoft server baselines as selection CSVs, faithful to Yamato's [EventLog-Baseline-Guide](https://github.com/Yamato-Security/EventLog-Baseline-Guide) scripts and drift-checked in CI. [#6](https://github.com/spydisec/WinLogKit/pull/6)

## [0.3.0] - 2026-08-31

### Added

- 💻 **Windows 10 and 11 support.** Enable and Test detect workstation, server or domain controller and report role- or version-specific items as NOT APPLICABLE where they don't apply. [#3](https://github.com/spydisec/WinLogKit/pull/3)
- 📲 **Intune delivery.** `New-IntuneRemediationPack.ps1` compiles any selection into a self-contained detection and remediation pair for Intune. AD CS auditing is left out by design, because it needs a service restart. [#3](https://github.com/spydisec/WinLogKit/pull/3)
- 🛰️ **IPsec Driver auditing.** In [Microsoft's baseline recommendation](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations) but not Yamato's set, found by reviewing Yamato's EventLog-Baseline-Guide comparison. [#3](https://github.com/spydisec/WinLogKit/pull/3)

### Fixed

- 🔧 **Field-test fixes.** WELA staging, DevSkim TLS alerts, and a baseline tree view in the builder. [#4](https://github.com/spydisec/WinLogKit/pull/4)

## [0.2.0] - 2026-08-31

### Added

- 🪟 **Windows Server 2025 support.** Auditing of SMB peers that can't sign or encrypt (events 3021/3022 and 31998/31999), with the two SMB audit channels sized; reported NOT APPLICABLE on 2019 and 2022. [#1](https://github.com/spydisec/WinLogKit/pull/1)
- 🧱 **Baseline builder.** `New-LoggingBaseline.ps1` walks every setting with the kit's recommendation and a risk note, and writes a selection CSV you can edit in Excel. [#1](https://github.com/spydisec/WinLogKit/pull/1)
- 🎚️ **Apply exactly what you chose.** `-BaselineFile` on Enable and Test applies and verifies only the selected settings. [#1](https://github.com/spydisec/WinLogKit/pull/1)
- ⛔ **Never-do list.** Documentation of the settings the kit never touches (CrashOnAuditFail, do-not-overwrite retention, global object auditing, blanket SACLs), with risk notes on heavy settings. [#1](https://github.com/spydisec/WinLogKit/pull/1)
- ⚙️ **CI and releases.** Lint, self-checks on Windows PowerShell 5.1 and PowerShell 7, a security scan, zip releases with checksums on version tags, and Dependabot. [#1](https://github.com/spydisec/WinLogKit/pull/1), [#2](https://github.com/spydisec/WinLogKit/pull/2)

## [0.1.0] - 2026-08-31

### Added

- 🚀 **Initial release.** Yamato Security's logging baselines as an enable, test and roll back kit for Windows Server 2019 and 2022: tiered enablement, idempotent with `-WhatIf` and `-Rollback`, and read-only verification with PASS/FAIL per behaviour category and CSV output.
