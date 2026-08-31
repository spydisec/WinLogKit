# Changelog

All notable changes to WinLogKit. Versions follow [SemVer](https://semver.org/);
releases are tagged `vX.Y.Z` and published with a zip + SHA256 checksum.

## v0.7.0 - 2026-08-31

### Added
- Automatic pre-change snapshots: every real apply after the first now
  saves a timestamped snapshot of the current state
  (`Baseline\snapshots\<timestamp>\`: full auditpol backup + channel /
  registry / SMB state JSON) before changing anything, so moving between
  baselines leaves a point-in-time record. The protected first-run capture
  and `-Rollback` semantics are unchanged (rollback = undo the kit
  entirely; snapshot restore is documented as a manual step).
- Docs landing page rewritten per a UX copy review (hero with the stake
  above the fold, verb-first CTAs, outcome-led "Why" cards); enabling
  `attr_list` also fixed the landing buttons, which previously rendered as
  literal markup.
- spydi blended baselines (`presets/spydi_*`): ASD + Microsoft Client +
  Microsoft Server + Yamato blended on two axes - role (Server covering
  servers/DCs/WEF collectors with runtime DC-gating; Workstation for
  Windows 10/11) and volume (Minimal = the unanimous high-signal set +
  4688/cmdline + 4104 + IPsec Driver; Heavy = Minimal + WFP connections +
  Sensitive Privilege Use + ASD's module logging). Coverage: Workstation
  263/269, Server 273/279 of 472 (284 native ceiling; Server Heavy reaches
  the full native reach). Per-group source-and-events table and a
  Minimal-vs-Heavy decision diagram in the docs; drift-checked in CI.

## v0.6.0 - 2026-08-31

### Added
- Native ATT&CK mapping: `Export-AttackCoverage.ps1` now joins a snapshot
  derived from **current MITRE ATT&CK Enterprise v19.2** (detection
  strategies -> Windows analytics -> literal log sources and event codes)
  through a kit-curated event map (`data/attack/`, every row sourced).
  New statuses NotNative and Unmapped keep the limits and the curation
  worklist visible. MITRE attribution and OSSEM approach-credit in
  `data/attack/README.md`; `-UseOssem` retains the OSSEM-DM snapshot join
  as a cross-check. Reference numbers: 472 Windows techniques mapped,
  native-logging ceiling 284 (MITRE's analytics are Sysmon-first),
  Core 162, Core+HighVolume 279 of the 284 ceiling.
- Architecture page on the docs site with a mermaid diagram of the kit's
  one mechanism (snapshots in -> settings table -> host + fleet artefacts
  -> events out to collector/SIEM); mermaid rendering enabled site-wide.

### Fixed
- Release zip packaging omitted `data/`, `presets/`, `tools/` and `tests/`,
  so data-dependent scripts (coverage, presets) failed from a zip install
  (field-reported). The zip now carries them.

## v0.5.0 - 2026-08-31

### Added
- Per-role presets: `presets/role_Workstation.csv`, `role_MemberServer.csv`
  and `role_DomainController.csv` - the kit's recommended starting point per
  host role (Core plus the high-value items each role can afford), with every
  hold-back justified by the settings table's Risk metadata and the rationale
  documented per decision. ATT&CK coverage: Workstation 317/362, MemberServer
  299/362, DomainController 302/362. Starting points pending pilot volume
  data. Drift-checked in CI like the reference presets.
- Getting Started documents the PowerShell execution policy blocker with
  least-invasive-first fixes (field-reported; per
  [about_Execution_Policies](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_execution_policies)).

## v0.4.0 - 2026-08-31

### Added
- GPO delivery: `New-GpoPack.ps1` generates the advanced audit policy
  `audit.csv` (GUID-driven) and an LGPO-format `registry.txt` from any
  selection, with explicit reminders for what GPO packs deliberately
  exclude (channel sizing, NTLM security options, SMB auditing, AD CS).
- WEF plumbing verification: `Test-LoggingBaseline.ps1 -WefRole
  Source|Collector` checks the SubscriptionManager policy and WinRM on
  sources, and Wecsvc / ForwardedEvents sizing / loaded subscriptions on
  collectors.
- ATT&CK coverage reporting: `Export-AttackCoverage.ps1` joins a vendored,
  provenance-recorded [OSSEM-DM](https://github.com/OTRF/OSSEM-DM)
  snapshot (`data/ossem/`, MIT) against any selection and reports
  observable techniques with reasons for the gaps (NotSelected / NotInKit /
  RequiresSysmon). Reference numbers: Core 152/362, Core+HighVolume
  320/362 mapped Windows techniques.
- Documentation site (MkDocs Material, deployed to GitHub Pages by the
  Docs workflow): getting started, commands, baselines and presets, fleet
  deployment, coverage mapping, safety, FAQ.
- WEF/WEC central collection: `New-WefSubscription.ps1` generates a
  source-initiated Windows Event Forwarding subscription XML from the
  settings table or any baseline selection CSV (one query per selected
  channel), with collector (`winrm qc`, `wecutil`) and source (GPO
  SubscriptionManager) setup guidance printed, following
  [Microsoft's WEF intrusion-detection guidance](https://learn.microsoft.com/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection).
  The kit's pipeline boundary is documented: generate (kit) -> transport
  (WEF/WEC) -> ingest (SIEM, out of scope). Transport defaults live in the
  settings table (`$BaselineWefDefaults`).
- Reference baseline presets in `presets/`: ASD, Microsoft_Client and
  Microsoft_Server as selection CSVs usable with every `-BaselineFile`
  parameter, faithful to the `bat/` scripts in Yamato's
  [EventLog-Baseline-Guide](https://github.com/Yamato-Security/EventLog-Baseline-Guide),
  with documented faithfulness limits (see README "Reference baseline
  presets"). Regenerated by `tools/New-PresetBaselines.ps1` and
  drift-checked in CI.
- README updated for the v0.3.0 feature set (release/CHANGELOG pointers,
  files table, WEF and presets sections).

## v0.3.0 - 2026-08-31

### Added
- Windows 10 / 11 workstation support: host profile detection (workstation /
  server / domain controller) shown by Enable/Test, runtime NOT APPLICABLE
  gating for role- and version-specific items, README guidance (including
  Home edition notes).
- Intune delivery: `New-IntuneRemediationPack.ps1` compiles the settings
  table, or a New-LoggingBaseline.ps1 selection CSV, into a self-contained
  detection + remediation script pair (SYSTEM, 64-bit, Intune exit-code
  contract). AD CS AuditFilter excluded from packs by design (CertSvc
  restart).
- IPsec Driver audit subcategory (Optional tier) - present in
  [Microsoft's baseline recommendation](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations)
  but not the Yamato set; surfaced by reviewing Yamato's
  [EventLog-Baseline-Guide](https://github.com/Yamato-Security/EventLog-Baseline-Guide)
  comparison app, now credited in the README.
- Kit self-checks extended to generate and validate the Intune pack.

## v0.2.0 - 2026-08-31

### Added
- Windows Server 2025 support: new SMB signing/encryption capability auditing
  (`AuditClientDoesNotSupport*` / `AuditServerDoesNotSupport*` via the SMB
  configuration cmdlets, events 3021/3022 and 31998/31999) plus sizing for the
  `SMBServer/Audit` and `SmbClient/Audit` channels. OS-gated: reported
  NOT APPLICABLE on 2019/2022.
- `New-LoggingBaseline.ps1`: interactive baseline builder with the kit
  recommendation and per-item volume/stability risk notes; writes an
  Excel-editable selection CSV.
- `-BaselineFile` on Enable/Test: apply and verify exactly the selected set.
- Stability safety documentation (never-do list: CrashOnAuditFail,
  do-not-overwrite retention, global object access auditing, blanket SACLs),
  grounded in Microsoft documentation, with `Risk` metadata on heavy settings.
- SDLC: CI (PSScriptAnalyzer lint, kit self-checks on Windows PowerShell 5.1
  and PowerShell 7, DevSkim security scan), release workflow (zip + SHA256 on
  version tags), Dependabot for GitHub Actions, self-check harness in `tests/`.

### Notes
- On Windows Server 2025, NTLMv1 is removed by the OS and the SMB client
  supports NTLM blocking. The kit's NTLM settings remain audit-only and safe.

## v0.1.0 - 2026-08-31

- Initial release: Yamato Security logging baselines as an enable/test/verify
  kit for Windows Server 2019/2022. Tiered enablement (Core / HighVolume /
  Optional), idempotent with `-WhatIf` and `-Rollback`, read-only verification
  with per-category PASS/FAIL/NA and CSV output, WELA-based independent
  checking with archived evidence.
